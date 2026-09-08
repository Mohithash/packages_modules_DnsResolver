/*
 * Nullroute — NrFilter, the resolver-side filter singleton.
 *
 * See NrFilter.h for the constraints. The short version: nothing in this file
 * may allocate, lock, loop unboundedly or make a syscall on the query path, and
 * every failure falls open.
 */
#define LOG_TAG "NullrouteFilter"

#include "NrFilter.h"

#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/system_properties.h>

#include <log/log.h>

#include "NrMap.h"

namespace nr {

#define NR_PROP_KILL   "persist.sys.nullroute.kill"
#define NR_PROP_STATE  "sys.nullroute.filter"

/* The liveness probes live under this zone. `.invalid` is deliberately absent
 * from the matcher's skip-suffix list precisely so they can reach the index. */
#define NR_PROBE_ZONE  ".nullroute.invalid"

NrFilter g_filter;

/* ---------------------------------------------------------------------------
 * Kill switch — cached, never a property read per query.
 *
 * This is the correction to DivestOS's per-call GetIntProperty: a property read
 * walks the property area's hash trie and copies a value, and doing that on
 * every DNS lookup on the device is pure waste. What we actually need is a
 * change detector, and bionic already publishes one — a per-property serial that
 * is a single relaxed load in a mapping we already have.
 *
 * The globals are atomic only to keep the racing writes well-defined; every
 * thread that races writes the same value it read, so relaxed is sufficient.
 * ------------------------------------------------------------------------- */
static std::atomic<const prop_info*> g_kill_pi{nullptr};
static std::atomic<uint32_t> g_kill_serial{0};
static std::atomic<uint32_t> g_area_serial{UINT32_MAX};  /* forces the first find() */
static std::atomic<bool>     g_kill{false};
static std::atomic<bool>     g_kill_published{false};

static inline void nr_refresh_kill() {
    /*
     * The AREA serial is the outer gate, and it gates everything — including the
     * per-property serial read, which is why this is not simply an optimisation
     * for the not-yet-found case.
     *
     * bionic bumps the area serial in BOTH __system_property_add() and
     * __system_property_update(), so an unchanged area serial is proof that our
     * property did not change either. That matters because
     * __system_property_serial() is not merely a load: it spins on
     * __futex_wait() while a writer holds the property's dirty bit. The window is
     * microseconds and only while THIS property is mid-write, but "netd's DNS hot
     * path can block on init" is not a sentence that belongs in this file at all.
     *
     * Steady state is therefore exactly one acquire load of a page netd already
     * has mapped, per query, forever.
     *
     * (__system_property_area_serial() returns (uint32_t)-1 when the area is not
     * mapped, which is why UINT32_MAX is the initial value of g_area_serial: in
     * that state we stay quietly at "not killed" instead of retrying a lookup
     * that cannot succeed. A real serial starts at 0 and cannot reach -1.)
     */
    const uint32_t area = __system_property_area_serial();
    if (__builtin_expect(area == g_area_serial.load(std::memory_order_relaxed), 1)) return;
    g_area_serial.store(area, std::memory_order_relaxed);

    const prop_info* pi = g_kill_pi.load(std::memory_order_relaxed);
    if (pi == nullptr) {
        /* The property normally does not exist — it is only ever set by a user
         * digging themselves out of a bad build — so the trie lookup runs only
         * when something, somewhere, changed a property. */
        pi = __system_property_find(NR_PROP_KILL);
        if (!pi) {
            g_kill.store(false, std::memory_order_relaxed);
            return;
        }
        g_kill_pi.store(pi, std::memory_order_relaxed);
        g_kill_serial.store(UINT32_MAX, std::memory_order_relaxed);
    }

    const uint32_t s = __system_property_serial(pi);
    if (s == g_kill_serial.load(std::memory_order_relaxed)) return;
    g_kill_serial.store(s, std::memory_order_relaxed);

    bool killed = false;
    __system_property_read_callback(
            pi,
            [](void* cookie, const char*, const char* value, uint32_t) {
                *(bool*)cookie = (value[0] == '1' || value[0] == 't' || value[0] == 'y');
            },
            &killed);
    g_kill.store(killed, std::memory_order_relaxed);
}

/* ---------------------------------------------------------------------------
 * Health property. Callers MUST hold the slow lock: the dedup buffer is plain
 * memory, and __system_property_set() is a round trip to init that has no
 * business being executed by two DNS threads at once.
 * ------------------------------------------------------------------------- */
static char g_last_state[PROP_VALUE_MAX] = {0};

static void publishRaw(const char* value) {
    if (strncmp(g_last_state, value, sizeof(g_last_state)) == 0) return;
    strlcpy(g_last_state, value, sizeof(g_last_state));
    /* A blocking IPC on a query thread, but only ever at a genuine state change:
     * first map, a promotion, a mode toggle, a kill-switch flip, a fault. Over a
     * device's uptime that is a handful of calls total. It is worth the risk
     * because this property, the logcat tag and the two .invalid probes are the
     * only evidence that survives a failure to map control.bin — the counters in
     * that page cannot report their own death. */
    const int rc = __system_property_set(NR_PROP_STATE, value);
    ALOGI("state=%s", value);
    if (rc != 0) {
        /*
         * The set was refused — almost always a missing `set_prop(netd,
         * nullroute_prop)` or no property_contexts entry for this name.
         *
         * This has to be loud, because the symptom is not "the property is
         * wrong", it is "the property is EMPTY" — byte-identical to the
         * catastrophic case where no hooked resolver ever ran a query. Without
         * this line a triager reads an empty getprop and goes off rebuilding the
         * APEX, when the filter was working perfectly the whole time and the
         * defect was one line of policy.
         */
        ALOGE("could not publish %s=%s (rc=%d): the filter is RUNNING but cannot report its "
              "state — check set_prop(netd, nullroute_prop) and property_contexts",
              NR_PROP_STATE, value, rc);
    }
}

/* ------------------------------------------------------------------------- */

NrControl* NrFilter::controlPage() {
    NrControl* c = ctl_.load(std::memory_order_acquire);
    if (c) return c;
    if (state_.load(std::memory_order_relaxed) == ST_DISABLED) return nullptr;
    if (nr_mono_ms() < retry_at_ms_.load(std::memory_order_relaxed)) return nullptr;
    if (!slowTryLock()) return nullptr;

    c = ctl_.load(std::memory_order_acquire);
    if (c) {
        slowUnlock();
        return c;
    }

    void*  addr = nullptr;
    size_t len  = 0;
    int    e    = 0;
    if (!nr_map_shared_rw(NR_PATH_CONTROL, NR_CONTROL_BYTES, &addr, &len, &e)) {
        noteFault("control", e, nullptr);
        publishState(nullptr);
        slowUnlock();
        return nullptr;
    }

    ctl_len_ = len;
    NrControl* ctl = (NrControl*)addr;
    /* Announce the format version this resolver understands before anything
     * else. The app reads it and refuses to PROMOTE an index a stale resolver
     * could not read, which is what makes an app update unable to brick a
     * device that has not taken the matching mainline update. */
    __atomic_store_n(&ctl->filter_abi, NR_FMT_VERSION, __ATOMIC_RELEASE);
    ctl_.store(ctl, std::memory_order_release);
    state_.store(ST_READY, std::memory_order_release);
    faults_     = 0;
    backoff_ms_ = 0;
    retry_at_ms_.store(0, std::memory_order_relaxed);
    ALOGI("control page mapped (%zu bytes), abi=%u", len, (unsigned)NR_FMT_VERSION);
    publishState(ctl);
    slowUnlock();
    return ctl;
}

void NrFilter::slowPath(NrControl* ctl, uint64_t want, uint32_t epoch) {
    if (state_.load(std::memory_order_relaxed) == ST_DISABLED) return;

    /*
     * Backoff BEFORE the try-lock, not after it.
     *
     * While no index is mapped — the state every device is in until the user
     * picks a list, and the state a device with a rejected index stays in for
     * the whole boot — evaluate() reaches here on EVERY query. Taking the lock
     * first meant one contended read-modify-write on a single global cache line
     * per DNS lookup across every netd handler thread, purely to discover the
     * retry deadline had not expired. The deadline is the same one tested below
     * once the lock is held; this is that test, moved ahead of the cost.
     *
     * This is a FILTER only. The snapshot it reads can go stale between here and
     * the lock, so nothing is decided on it — everything below re-reads under the
     * lock, which is what stops two threads from each deciding to remap.
     *
     * An epoch change is never gated by the backoff: a mode toggle from the QS
     * tile must republish the health property now, not after a minute.
     */
    if (epoch == seen_epoch_.load(std::memory_order_relaxed) &&
        nr_mono_ms() < retry_at_ms_.load(std::memory_order_relaxed))
        return;

    /* Try-lock, never block: a DNS query must not wait on another query's mmap.
     * A thread that loses simply serves from the mapping already published, one
     * generation stale for a few microseconds. */
    if (!slowTryLock()) return;

    seen_epoch_.store(epoch, std::memory_order_relaxed);

    const bool no_index = (cur_.load(std::memory_order_relaxed) == nullptr);
    const bool gen_moved = (want != mapped_gen_.load(std::memory_order_relaxed) &&
                            want != remap_target_.load(std::memory_order_relaxed));
    if (!no_index && !gen_moved) {
        /* Only the config epoch moved — a mode toggle from the QS tile, a
         * response-mode change. Nothing to remap; just make the health property
         * tell the truth again. */
        publishState(ctl);
        slowUnlock();
        return;
    }

    if (nr_mono_ms() < retry_at_ms_.load(std::memory_order_relaxed)) {
        slowUnlock();
        return;
    }

    /* Unmap anything retired by an earlier promotion whose readers have all
     * drained. Doing it here, on the next slow path rather than at retire time,
     * is what guarantees no in-flight query loses its mapping. */
    nr_mapping_reclaim();

    NrMapError err{};
    NrMapping* nm = nr_mapping_open(NR_PATH_INDEX_CURRENT, &err);
    if (!nm) {
        /* Clear the target so the backoff — not the "already attempted this
         * generation" guard — decides when we try again. Without this a boot
         * where the seeder has not published yet would never retry. */
        remap_target_.store(UINT64_MAX, std::memory_order_relaxed);
        noteFault("index", err.errno_value, err.field);
        publishState(ctl);
        slowUnlock();
        return;   /* the PREVIOUS mapping, if any, stays live and authoritative */
    }

    NrMapping* old = cur_.exchange(nm, std::memory_order_seq_cst);
    if (old) nr_mapping_retire(old);

    mapped_gen_.store(nm->generation, std::memory_order_relaxed);
    /* Record the generation we were ASKED for, not the one we got. If the file
     * on disk carries a different generation than want_generation advertises,
     * mapped_gen_ never reaches `want` and the naive test would re-open the
     * index on every query forever. One attempt per distinct want is enough. */
    remap_target_.store(want, std::memory_order_relaxed);
    faults_      = 0;
    backoff_ms_  = 0;
    last_errno_  = 0;
    last_field_  = nullptr;
    retry_at_ms_.store(0, std::memory_order_relaxed);

    __atomic_store_n(&ctl->mapped_generation, nm->generation, __ATOMIC_RELEASE);
    __atomic_store_n(&ctl->last_map_ms, nr_now_ms(), __ATOMIC_RELEASE);
    __atomic_store_n(&ctl->filter_abi, NR_FMT_VERSION, __ATOMIC_RELEASE);
    __atomic_store_n(&ctl->fault_count, 0u, __ATOMIC_RELAXED);

    ALOGI("index mapped gen=%" PRIu64 " want=%" PRIu64 " bytes=%zu", nm->generation, want,
          nm->size);
    publishState(ctl);
    slowUnlock();
}

void NrFilter::noteFault(const char* what, int errno_value, const char* field) {
    last_errno_ = errno_value;
    last_field_ = field;

    /*
     * Soft vs hard, and why the distinction has to exist.
     *
     * ENOENT means the artefact has not been published yet — at first boot netd
     * (class main) can easily beat nullroute_seed (class core) to the first
     * query. Spending the three strikes on that race would permanently disable
     * the filter on a completely healthy device.
     *
     * "slots" means every pool slot is still draining readers; it is transient
     * by construction and self-heals on the next attempt.
     *
     * Everything else — EACCES from a missing SELinux `map` grant, a rejected
     * header, impossible table geometry — is a real defect that will not fix
     * itself, and three of them means we stop trying and say so.
     */
    const bool soft = (errno_value == ENOENT) || (field && strcmp(field, "slots") == 0);
    if (!soft) ++faults_;

    /* Telemetry, not the health signal. These counters are useful in Diagnostics
     * and useless when the page they live in is the thing that failed to map —
     * which is exactly why the property and the logcat line above exist. */
    NrControl* ctl = ctl_.load(std::memory_order_relaxed);
    if (ctl) {
        __atomic_fetch_add(&ctl->map_errors, 1u, __ATOMIC_RELAXED);
        __atomic_store_n(&ctl->fault_count, faults_, __ATOMIC_RELAXED);
    }

    backoff_ms_ = backoff_ms_ ? (backoff_ms_ * 2u) : NR_BACKOFF_MIN_MS;
    if (backoff_ms_ > NR_BACKOFF_MAX_MS) backoff_ms_ = NR_BACKOFF_MAX_MS;
    retry_at_ms_.store(nr_mono_ms() + backoff_ms_, std::memory_order_relaxed);

    if (field) {
        ALOGE("%s: rejected field=%s faults=%u retry_in=%ums", what, field, faults_, backoff_ms_);
    } else {
        ALOGE("%s: errno=%d (%s) faults=%u retry_in=%ums", what, errno_value,
              strerror(errno_value), faults_, backoff_ms_);
    }

    if (faults_ >= NR_MAX_FAULTS) {
        /* Terminal. Stop touching the filesystem for the life of this netd, and
         * stay fail-open. ctl_ is nulled but its mapping is deliberately NOT
         * unmapped: a query already holding the raw pointer must keep reading
         * valid memory. 128 KiB is a cheap price for that guarantee. */
        state_.store(ST_DISABLED, std::memory_order_release);
        ctl_.store(nullptr, std::memory_order_release);
        ALOGE("%s: %u faults, filter self-disabled for this boot (last: %s%s errno=%d)", what,
              faults_, field ? "field=" : "", field ? field : "", errno_value);
    }
}

void NrFilter::publishState(NrControl* ctl) {
    char buf[PROP_VALUE_MAX];

    if (state_.load(std::memory_order_relaxed) == ST_DISABLED) {
        publishRaw("disabled");
        return;
    }
    if (g_kill.load(std::memory_order_relaxed)) {
        publishRaw("killed");
        return;
    }
    if (!ctl) {
        snprintf(buf, sizeof(buf), "nomap:%d", last_errno_);
        publishRaw(buf);
        return;
    }
    if (__atomic_load_n(&ctl->mode, __ATOMIC_RELAXED) != NR_MODE_ENFORCE) {
        /* PAUSED and OFF both report "off". §3.4 defines exactly five values and
         * the app does not need a sixth to tell them apart — it wrote the mode. */
        publishRaw("off");
        return;
    }
    if (cur_.load(std::memory_order_relaxed) == nullptr) {
        if (last_field_) snprintf(buf, sizeof(buf), "badhdr:%s", last_field_);
        else             snprintf(buf, sizeof(buf), "nomap:%d", last_errno_);
        publishRaw(buf);
        return;
    }
    snprintf(buf, sizeof(buf), "ok:%" PRIu64, mapped_gen_.load(std::memory_order_relaxed));
    publishRaw(buf);
}

void NrFilter::onKillChanged() {
    if (!slowTryLock()) return;   /* another thread is already reporting it */
    publishState(ctl_.load(std::memory_order_acquire));
    g_kill_published.store(g_kill.load(std::memory_order_relaxed), std::memory_order_relaxed);
    slowUnlock();
}

Verdict NrFilter::evaluate(const char* host, uid_t uid) {
    Verdict pass{};   /* kind == V_PASS */

    if (__builtin_expect(state_.load(std::memory_order_relaxed) == ST_DISABLED, 0)) return pass;
    if (__builtin_expect(host == nullptr || host[0] == '\0', 0)) return pass;

    nr_refresh_kill();
    const bool killed = g_kill.load(std::memory_order_relaxed);
    if (__builtin_expect(killed != g_kill_published.load(std::memory_order_relaxed), 0))
        onKillChanged();
    if (__builtin_expect(killed, 0)) return pass;

    NrControl* ctl = ctl_.load(std::memory_order_acquire);
    if (__builtin_expect(ctl == nullptr, 0)) {
        ctl = controlPage();
        if (!ctl) return pass;
    }

    /* One cache line, already hot: want_generation and config_epoch share it. */
    const uint64_t want  = __atomic_load_n(&ctl->want_generation, __ATOMIC_ACQUIRE);
    const uint32_t epoch = __atomic_load_n(&ctl->config_epoch, __ATOMIC_RELAXED);

    NrMapping* cand = cur_.load(std::memory_order_seq_cst);
    if (__builtin_expect(cand == nullptr ||
                                 epoch != seen_epoch_.load(std::memory_order_relaxed) ||
                                 (want != mapped_gen_.load(std::memory_order_relaxed) &&
                                  want != remap_target_.load(std::memory_order_relaxed)),
                         0)) {
        slowPath(ctl, want, epoch);
        cand = cur_.load(std::memory_order_seq_cst);
    }
    if (__builtin_expect(cand == nullptr, 0)) return pass;

    /*
     * RCU-style acquire: take a reference, then confirm the mapping is still the
     * published one. The confirm is what makes it safe — a mapping that is still
     * `cur_` is one the publisher has not retired, and the publisher only unmaps
     * a retired mapping whose refcount has drained to zero.
     *
     * NrMapping control blocks come from a static pool and are never freed, so
     * even the losing iteration touches nothing but valid memory. The retry
     * count is hard-bounded: this loop runs inside netd, and a spin here is a
     * zygote restart loop.
     */
    NrMapping* m = nullptr;
    for (unsigned tries = 0; tries < 4u; ++tries) {
        nr_mapping_acquire(cand);
        if (cur_.load(std::memory_order_seq_cst) == cand) {
            m = cand;
            break;
        }
        nr_mapping_release(cand);
        cand = cur_.load(std::memory_order_seq_cst);
        if (!cand) return pass;
    }
    if (__builtin_expect(m == nullptr, 0)) return pass;   /* publisher churning; fail open */

    const size_t len = strnlen(host, NR_MAX_NAME + 1);
    Verdict v = nr_evaluate(m->index, *ctl, host, len, uid);
    nr_mapping_release(m);

    __atomic_fetch_add(&ctl->q_total, 1ull, __ATOMIC_RELAXED);
    if (__builtin_expect(v.kind == V_PASS, 1)) {
        __atomic_fetch_add(&ctl->q_passed, 1ull, __ATOMIC_RELAXED);
        return v;
    }
    if (v.kind == V_BLOCK) __atomic_fetch_add(&ctl->q_blocked, 1ull, __ATOMIC_RELAXED);

    /* Log the verdict we actually reached, before any response-mode rewrite:
     * the user asked why a domain was blocked, not which errno we chose. */
    const uint8_t lvl = __atomic_load_n(&ctl->log_level, __ATOMIC_RELAXED);
    if (lvl != 0) nr_ring_write(ctl, uid, v, host, len);

    /*
     * Sinkhole is expressed as a redirect to 0.0.0.0 so the hook sites only ever
     * have two cases to handle. It stays a compat escape hatch and never a
     * default: Linux treats connect() to 0.0.0.0 as INADDR_LOOPBACK, so the app
     * connects to itself instead of failing, and on an IPv6-only network the
     * numeric explore finds no matching family and the lookup degrades back to
     * the default block anyway.
     */
    if (v.kind == V_BLOCK &&
        __atomic_load_n(&ctl->response_mode, __ATOMIC_RELAXED) == NR_RESP_SINKHOLE) {
        v.kind   = V_REDIRECT;
        v.family = AF_INET;
        memset(v.addr, 0, sizeof(v.addr));
    }
    return v;
}

/* True for anything in the liveness-probe zone. Bounded, case-insensitive tail
 * compare; no allocation, no strlen of an unbounded buffer. */
static inline bool nr_is_probe_name(const char* name) {
    const size_t n = strnlen(name, NR_MAX_NAME + 1);
    const size_t z = sizeof(NR_PROBE_ZONE) - 1;
    return n > z && strncasecmp(name + (n - z), NR_PROBE_ZONE, z) == 0;
}

/*
 * Does this name have at least two labels, ignoring a trailing root dot?
 *
 * This is the loopback guard, and it is the reason H4 is safe at all.
 * /system/etc/hosts is not only the L0 blocklist: its first two lines are
 * `127.0.0.1 localhost` and `::1 ip6-localhost`, and on Android that file is the
 * ONLY thing that resolves them — the mainline resolver has no built-in
 * loopback special case, which is exactly why system/core/rootdir ships those
 * two lines. Skipping files_getaddrinfo() for a single-label name would send
 * `localhost` to a DNS server and break loopback resolution device-wide.
 *
 * A single label is also a name nr_canonicalize() refuses outright, so L1 could
 * never be authoritative for one. The two facts line up: exactly the names L1
 * cannot speak for are the names L0 must keep answering.
 */
static inline bool nr_has_two_labels(const char* name) {
    size_t n = strnlen(name, NR_MAX_NAME + 1);
    /* Strip EVERY trailing dot, not just one: "localhost.." must count as one
     * label for the same reason "localhost." does, and nr_canonicalize() strips
     * them all — a disagreement here is H4 superseding the hosts scan for a name
     * L1 then refuses to speak for. */
    while (n && name[n - 1] == '.') --n;
    for (size_t i = 0; i < n; ++i)
        if (name[i] == '.') return true;
    return false;
}

bool NrFilter::hostsLayerSuperseded(const char* name) {
    if (state_.load(std::memory_order_relaxed) == ST_DISABLED) return false;
    if (g_kill.load(std::memory_order_relaxed)) return false;

    /* No name means no way to tell `localhost` from an ad domain, so the scan
     * stands. H4 is a pure optimisation and is allowed to be inert; it is not
     * allowed to be wrong. */
    if (!name) return false;
    if (!nr_has_two_labels(name)) return false;
    /* The other half of "a name L1 could actually speak for", which the two-label
     * test alone does not cover: nr_canonicalize() refuses .local/.onion/.arpa/
     * .localhost outright, so evaluate() ALWAYS passes them and L1 is never
     * authoritative for one. Superseding the hosts scan for a name we have
     * already decided not to judge is the definition of a wrong H4. */
    if (nr_has_skip_suffix(name, strnlen(name, NR_MAX_NAME + 1))) return false;
    /* hosts-probe.nullroute.invalid is a literal line in /system/etc/hosts and
     * is the only proof that the L0 layer survived the build. Skipping the hosts
     * scan for it would fail probe B on a healthy device. */
    if (nr_is_probe_name(name)) return false;

    NrControl* ctl = ctl_.load(std::memory_order_acquire);
    if (!ctl) return false;
    if (__atomic_load_n(&ctl->mode, __ATOMIC_RELAXED) != NR_MODE_ENFORCE) return false;
    return cur_.load(std::memory_order_acquire) != nullptr;
}

int NrFilter::blockErrno() const {
    const NrControl* ctl = ctl_.load(std::memory_order_relaxed);
    if (!ctl) return EAI_NONAME;
    switch (__atomic_load_n(&ctl->response_mode, __ATOMIC_RELAXED)) {
        case NR_RESP_NODATA:
            return EAI_NODATA;
        case NR_RESP_NONAME:
        default:
            /* Byte-identical to a real NXDOMAIN, so a blocked app makes zero
             * connection attempts. Blocked answers never enter res_cache, so
             * un-blocking is instantaneous at the resolver. */
            return EAI_NONAME;
    }
}

/* ---- the surface nr_hook.h declares ------------------------------------- */

Verdict nr_filter_hook(const char* hostname, uid_t uid) {
    return g_filter.evaluate(hostname, uid);
}

bool nr_hosts_layer_superseded(const char* name) {
    return g_filter.hostsLayerSuperseded(name);
}

int nr_block_errno() {
    return g_filter.blockErrno();
}

}  // namespace nr
