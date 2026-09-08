/*
 * Nullroute — the query-log ring producer, netd side.
 *
 * Multi-producer (every netd DNS thread), single-consumer (the app),
 * overwrite-oldest, 4096 x 64 B records behind a one-page header.
 *
 * Logging is BEST EFFORT in the strongest sense the word has: if the ring cannot
 * be mapped, or its header is not ours, or the map keeps failing, logging turns
 * itself off permanently and filtering carries on completely unaffected. A
 * query is never blocked, slowed or failed because the log is unavailable.
 * Diagnostics reports the drops rather than pretending the log is complete.
 */
#define LOG_TAG "NullrouteFilter"

#include <errno.h>
#include <string.h>

#include <atomic>

#include <log/log.h>

#include "NrFilter.h"
#include "NrMap.h"
#include "NrRing.h"

namespace nr {

/* "NRRG" little-endian, the same convention as NR_MAGIC ("NRDX"). Not declared
 * in NrRing.h because the header describes the geometry, not the identity; the
 * value is documented in resolver-patch/README.md so the app-side reader and
 * nullroute_seed agree with it. */
#define NR_RING_MAGIC    0x4752524Eu
#define NR_RING_VERSION  1u

#define NR_RING_MAX_FAULTS 3u

/* The record area starts at sizeof(NrRingHeader) and the consumer (NrRingReader,
 * app side) computes the same offset from the same header. NrRing.h asserts the
 * record size but not the header's, and the two are an on-disk ABI between two
 * separately-built binaries: a header that is not exactly one page would put
 * every record at an offset the reader does not expect, and the log would be
 * silently unreadable rather than absent. Assert it where the arithmetic is. */
static_assert(sizeof(NrRingHeader) == 4096u, "ring header must be exactly one page");
static_assert(NR_RING_BYTES == sizeof(NrRingHeader) + NR_RING_SLOTS * NR_RING_REC,
              "NR_RING_BYTES must cover the header page plus every record");

enum RingState : uint32_t {
    RING_UNINIT = 0,
    RING_BUSY   = 1,
    RING_READY  = 2,
    RING_OFF    = 3,   /* terminal */
};

static std::atomic<uint32_t>      g_ring_state{RING_UNINIT};
static std::atomic<NrRingHeader*> g_ring{nullptr};
static std::atomic<uint64_t>      g_ring_retry_ms{0};
static uint32_t                   g_ring_faults   = 0;   /* under RING_BUSY only */
static uint32_t                   g_ring_backoff  = 0;   /* under RING_BUSY only */

static void ring_drop(NrControl* ctl) {
    if (ctl) __atomic_fetch_add(&ctl->ring_drops, 1u, __ATOMIC_RELAXED);
}

static void ring_fail(NrControl* ctl, const char* what, int e, bool hard) {
    ring_drop(ctl);
    if (hard) ++g_ring_faults;
    g_ring_backoff = g_ring_backoff ? (g_ring_backoff * 2u) : NR_BACKOFF_MIN_MS;
    if (g_ring_backoff > NR_BACKOFF_MAX_MS) g_ring_backoff = NR_BACKOFF_MAX_MS;
    g_ring_retry_ms.store(nr_mono_ms() + g_ring_backoff, std::memory_order_relaxed);

    if (g_ring_faults >= NR_RING_MAX_FAULTS) {
        ALOGE("ring: %s errno=%d, query logging disabled for this boot", what, e);
        g_ring_state.store(RING_OFF, std::memory_order_release);
    } else {
        ALOGW("ring: %s errno=%d, retry in %ums", what, e, g_ring_backoff);
        g_ring_state.store(RING_UNINIT, std::memory_order_release);
    }
}

/*
 * Lazily map ring.bin. Returns nullptr whenever the ring is not usable right
 * now, which the caller treats as "drop this record" and nothing more.
 *
 * EVERY nullptr return counts the drop. It would be easy to count only the ones
 * that come from a failing syscall, and the result would be Diagnostics showing
 * "3 dropped" over a boot in which the ring was disabled and tens of thousands
 * of records went nowhere — a log that looks complete and is not. The counter
 * exists precisely so the app can say the log is partial; letting it undercount
 * defeats it. One relaxed increment, on a path that is already off the fast one.
 *
 * Exactly one thread performs the open: the rest see RING_BUSY and skip. That
 * matters more here than elsewhere because this runs on the query path, and a
 * mutex would let one thread's mmap stall every other app's DNS.
 */
static NrRingHeader* ring_map(NrControl* ctl) {
    uint32_t st = g_ring_state.load(std::memory_order_acquire);
    if (st == RING_READY) return g_ring.load(std::memory_order_acquire);
    if (st != RING_UNINIT) {   /* OFF, or another thread is opening */
        ring_drop(ctl);
        return nullptr;
    }

    if (nr_mono_ms() < g_ring_retry_ms.load(std::memory_order_relaxed)) {
        ring_drop(ctl);   /* backing off after a failed open */
        return nullptr;
    }
    uint32_t expected = RING_UNINIT;
    if (!g_ring_state.compare_exchange_strong(expected, RING_BUSY, std::memory_order_acq_rel,
                                              std::memory_order_relaxed)) {
        ring_drop(ctl);   /* lost the race to another thread's open */
        return nullptr;
    }

    void*  addr = nullptr;
    size_t len  = 0;
    int    e    = 0;
    if (!nr_map_shared_rw(NR_PATH_RING, NR_RING_BYTES, &addr, &len, &e)) {
        /* ENOENT before nullroute_seed has run is expected, not a defect. */
        ring_fail(ctl, "map failed", e, e != ENOENT);
        return nullptr;
    }

    NrRingHeader* hdr = (NrRingHeader*)addr;
    const uint32_t magic = __atomic_load_n(&hdr->magic, __ATOMIC_ACQUIRE);
    const uint32_t ver   = __atomic_load_n(&hdr->version, __ATOMIC_RELAXED);
    if (magic == 0) {
        /* A freshly created, zero-filled ring. netd owns rw on this file (the app
         * only ever reads it), so stamping the header here rather than in the
         * seeder keeps the format knowledge on the writer's side. head stays 0. */
        __atomic_store_n(&hdr->version, NR_RING_VERSION, __ATOMIC_RELAXED);
        __atomic_store_n(&hdr->magic, NR_RING_MAGIC, __ATOMIC_RELEASE);
    } else if (magic != NR_RING_MAGIC || ver != NR_RING_VERSION) {
        /* Something else owns this file. Writing 64-byte records into it blind
         * would be the worst possible outcome, so stop permanently. Both header
         * fields are read BEFORE the unmap — logging them afterwards would be a
         * use-after-unmap, and SIGBUS in netd is a zygote restart. */
        nr_unmap_shared(addr, len);
        ALOGE("ring: magic=0x%08x version=%u not ours, query logging disabled", magic, ver);
        g_ring_state.store(RING_OFF, std::memory_order_release);
        ring_drop(ctl);
        return nullptr;
    }

    g_ring_faults  = 0;
    g_ring_backoff = 0;
    g_ring.store(hdr, std::memory_order_release);
    g_ring_state.store(RING_READY, std::memory_order_release);
    ALOGI("ring mapped (%zu bytes, %u slots)", len, (unsigned)NR_RING_SLOTS);
    return hdr;
}

void nr_ring_write(NrControl* ctl, uid_t uid, const Verdict& v, const char* name, size_t len) {
    const uint8_t lvl = ctl ? __atomic_load_n(&ctl->log_level, __ATOMIC_RELAXED) : 0;
    if (lvl == 0) return;
    if (lvl < 2 && v.kind == V_PASS) return;
    /* `name` is indexed by the truncation walk below and memcpy'd from. It is
     * non-null on every call site today, but this is a non-static entry point
     * declared in a header, and the cost of the guard is a branch that never
     * mispredicts. */
    if (name == nullptr) return;

    NrRingHeader* hdr = ring_map(ctl);
    if (!hdr) return;   /* ring_map already counted the drop */

    /* The whole of the multi-producer protocol: one relaxed fetch_add hands this
     * thread a slot nobody else will touch. No lock, no CAS retry loop, no
     * unbounded anything. */
    const uint64_t ticket = __atomic_fetch_add(&hdr->head, 1ull, __ATOMIC_RELAXED);
    NrLogRec* rec = (NrLogRec*)((uint8_t*)hdr + sizeof(NrRingHeader)) + (ticket % NR_RING_SLOTS);

    /* Invalidate before writing the body, publish after. The consumer reads seq,
     * reads the body, re-reads seq: a zero or a changed value means the record
     * was overwritten under it. Without the leading invalidate a reader could
     * see the OLD occupant's valid seq over a half-written new body. */
    __atomic_store_n(&rec->seq, 0ull, __ATOMIC_RELEASE);

    /*
     * Truncation keeps the TAIL of the name, advanced to the next label
     * boundary. The matched rule is always a suffix of the queried name, so the
     * tail is the part that explains the verdict; a head-truncated
     * "aaaa-bbbb-cccc-dddd-eeee-track" tells the user nothing. Consumers render
     * a leading ellipsis when flags bit0 is set.
     */
    uint8_t flags = 0;
    const char* src = name;
    size_t copy = len;
    if (copy > NR_RING_NAME) {
        size_t off = len - NR_RING_NAME;
        for (size_t i = off; i < len; ++i) {
            if (name[i] == '.') {
                off = i + 1;
                break;
            }
        }
        src   = name + off;
        copy  = len - off;
        if (copy > NR_RING_NAME) copy = NR_RING_NAME;
        flags = 1;
    }

    rec->ts_ms      = nr_now_ms();
    rec->uid        = (uint32_t)uid;
    rec->rule_group = v.group;
    rec->verdict    = (uint8_t)v.kind;
    rec->depth      = v.depth;
    rec->name_len   = (uint8_t)copy;
    rec->flags      = flags;
    memset(rec->name, 0, sizeof(rec->name));   /* never leak the previous occupant */
    memcpy(rec->name, src, copy);
    rec->_pad = 0;

    /* Release-store LAST. ticket + 1 so a never-written slot (seq == 0) is
     * always distinguishable from slot 0's first record. */
    __atomic_store_n(&rec->seq, ticket + 1ull, __ATOMIC_RELEASE);
}

}  // namespace nr
