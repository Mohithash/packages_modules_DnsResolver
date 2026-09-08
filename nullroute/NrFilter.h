/*
 * Nullroute — the filter singleton that lives inside netd.
 *
 * Copied verbatim into packages/modules/DnsResolver/nullroute/ by
 * resolver-patch/apply.sh. This is the ONLY new state the resolver fork carries;
 * everything else in the patch is four short hunks at the hook sites.
 *
 * Design constraints, all of them non-negotiable because netd's init stanza
 * carries `onrestart restart zygote` — a crash or a hang here is a UI/boot loop,
 * not merely a network outage:
 *
 *   - The hot path takes no lock, makes no syscall, allocates nothing and has no
 *     unbounded loop. Everything expensive (open, mmap, validate, property set)
 *     happens on the slow path, which runs roughly once a day.
 *   - Every failure falls OPEN. There is no code path in this class that can
 *     make a DNS lookup fail because of a Nullroute problem.
 *   - Health is reported OUT OF BAND, on `sys.nullroute.filter` and in logcat.
 *     It deliberately does not travel through control.bin: a counter that lives
 *     inside the page whose mapping is the single most likely thing to fail
 *     cannot report its own death.
 */
#ifndef NULLROUTE_RESOLVER_NR_FILTER_H
#define NULLROUTE_RESOLVER_NR_FILTER_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include <atomic>

#include "NrControl.h"
#include "NrMap.h"
#include "NrQuery.h"
#include "NrVerdict.h"

namespace nr {

/*
 * Maximum consecutive hard faults before the filter switches itself off for the
 * lifetime of the netd process and records why.
 *
 * A "hard" fault is an index that exists and cannot be used: mmap denied,
 * header rejected, table geometry impossible. A plain ENOENT is NOT a hard fault
 * — at first boot nullroute_seed may not have published yet, and burning the
 * three strikes on a race with the seeder would permanently disable the filter
 * on a perfectly healthy device.
 */
#define NR_MAX_FAULTS 3u

/* Retry ladder for the soft cases (index not published yet, control page not
 * created yet). Doubles from 1 s to the cap; monotonic clock, so a wall-clock
 * step cannot stall or storm it. */
#define NR_BACKOFF_MIN_MS  1000u
#define NR_BACKOFF_MAX_MS  60000u

class NrFilter {
public:
    /* Defaulted-and-constexpr on purpose. It makes the single instance
     * constant-initialised into .bss, so there is no static-initialisation order
     * dependency inside netd and no `__cxa_guard_acquire` on the query path. If
     * a future member breaks constant initialisation, this line stops compiling
     * rather than quietly introducing a guard variable. */
    constexpr NrFilter() = default;

    /* THE hook. Returns V_PASS for every failure, every disabled state and every
     * name the matcher cannot describe. `host` need not be NUL-terminated within
     * any particular bound; the length is taken with a hard cap. */
    Verdict evaluate(const char* host, uid_t uid);

    /*
     * H4: may files_getaddrinfo() skip its linear rescan of /system/etc/hosts?
     *
     * True only while L1 is genuinely authoritative — index mapped, kill switch
     * clear, mode ENFORCE — AND the name is one L1 could actually speak for.
     * Otherwise the L0 text layer must keep answering, because it is both the
     * fallback the degradation ladder ends on and the only resolver for two
     * names the device cannot live without.
     *
     * `name` is optional only so the argument-free form still compiles on a tree
     * whose parameter is called something else. Omitting it makes this ALWAYS
     * return false — H4 becomes a never-taken branch. That is deliberate: this
     * hunk buys ~79 us on a cold query and nothing else, so an inert H4 costs a
     * micro-optimisation while a wrong H4 costs `localhost`.
     *
     * Two names are exempted whatever the filter's state:
     *   - single-label names (`localhost`, `ip6-localhost`, NetBIOS names).
     *     /system/etc/hosts is the ONLY thing on Android that resolves loopback;
     *     the mainline resolver has no built-in special case for it.
     *   - anything under .nullroute.invalid. hosts-probe.nullroute.invalid is a
     *     literal line in that file and is the only evidence the L0 layer
     *     survived the build; superseding it would fail probe B on a healthy
     *     device and light the "built-in list missing" warning forever.
     *
     * KNOWN LIMITATION: skipping files_getaddrinfo() also skips the per-netId
     * customized hosts table (ResolverOptionsParcel.hosts, consulted at the end
     * of that function). AOSP documents that table as local-testing-only and it
     * is unset on a normal device, but a tree that starts using it must drop H4.
     */
    bool hostsLayerSuperseded(const char* name = nullptr);

    /* The errno a blocked lookup returns, from NrControl::response_mode.
     * NR_RESP_SINKHOLE never reaches here: evaluate() rewrites it into a
     * V_REDIRECT so the hook sites only ever handle two verdict kinds. */
    int blockErrno() const;

    /* Snapshot for the diagnostics path; not used on the query path. */
    uint64_t mappedGeneration() const { return mapped_gen_.load(std::memory_order_relaxed); }

private:
    enum State : uint32_t {
        ST_INIT     = 0,   /* control page not mapped yet */
        ST_READY    = 1,
        ST_DISABLED = 2,   /* terminal: NR_MAX_FAULTS reached */
    };

    /* Returns the control page, mapping it if this is the first call. nullptr
     * means "not available right now" — the caller passes. */
    NrControl* controlPage();

    /* Slow path: (re)map the index for generation `want`, republish state.
     * Entered under the try-lock; a thread that loses the try-lock simply keeps
     * serving from the mapping already published. */
    void slowPath(NrControl* ctl, uint64_t want, uint32_t epoch);

    void noteFault(const char* what, int errno_value, const char* field);

    /* Recompute and republish `sys.nullroute.filter`. `ctl` may be null — that
     * is itself a reportable state. Caller must hold the slow lock. */
    void publishState(NrControl* ctl);

    /* The kill switch flipped. Reached from the query path, which is why it
     * takes the try-lock and gives up rather than waiting. */
    void onKillChanged();

    /* Try-lock rather than a mutex: a DNS query must never block on another
     * query's mmap. Losing the race costs one extra generation of staleness for
     * a few microseconds. */
    bool slowTryLock() { return !slow_busy_.exchange(true, std::memory_order_acq_rel); }
    void slowUnlock()  { slow_busy_.store(false, std::memory_order_release); }

    std::atomic<uint32_t>   state_{ST_INIT};
    std::atomic<NrControl*> ctl_{nullptr};
    size_t                  ctl_len_{0};          /* slow path only */
    std::atomic<NrMapping*> cur_{nullptr};

    /* Generation actually mapped, and the generation the last remap attempt was
     * FOR. The second one is what stops a remap storm: if the app publishes
     * want=N but the file on disk carries generation M, mapped_gen_ never
     * reaches N and the naive `want != mapped_gen_` test would re-open the index
     * on every single query. One attempt per distinct `want` is enough. */
    std::atomic<uint64_t>   mapped_gen_{0};
    std::atomic<uint64_t>   remap_target_{UINT64_MAX};
    std::atomic<uint32_t>   seen_epoch_{0};

    std::atomic<bool>       slow_busy_{false};
    std::atomic<uint64_t>   retry_at_ms_{0};      /* monotonic ms */

    uint32_t                faults_{0};           /* slow path only */
    uint32_t                backoff_ms_{0};       /* slow path only */

    /* Why the last attempt failed, for `nomap:<errno>` / `badhdr:<field>`.
     * Exactly one is meaningful; `last_field_` always points at a string
     * literal, never at anything that can be freed. Slow path only. */
    int                     last_errno_{0};
    const char*             last_field_{nullptr};
};

/* The single instance. A namespace-scope object rather than a function-local
 * static, so no guard variable is tested on the query path. */
extern NrFilter g_filter;

/*
 * MPSC query-log producer — NrRingWriter.cpp.
 *
 * Best effort in the strongest sense: if the ring cannot be mapped, logging
 * disables itself permanently and filtering is completely unaffected. Drops are
 * counted in NrControl::ring_drops so Diagnostics can say the log is incomplete
 * rather than pretending otherwise.
 */
void nr_ring_write(NrControl* ctl, uid_t uid, const Verdict& v,
                   const char* name, size_t len);

}  // namespace nr
#endif /* NULLROUTE_RESOLVER_NR_FILTER_H */
