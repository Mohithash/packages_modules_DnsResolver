/*
 * Nullroute — H5's policy side: turn a collected CNAME chain into a verdict.
 *
 * The parsing is in NrCname.h and is fuzzed alone. Everything here is decision,
 * not decoding, and every constraint from NrFilter.h still applies unchanged: no
 * allocation, no lock, no recursion, no unbounded loop, and every failure falls
 * OPEN.
 *
 * ============================================================================
 *  WHY THIS FILE MAPS control.bin A SECOND TIME
 * ============================================================================
 *
 * The feature has to be off unless the user asked for it, and the switch lives
 * in NrControl::cname_uncloak — inside the control page, which NrFilter owns and
 * exposes to nobody (its controlPage() is private, and NrFilter.h is a file this
 * phase is not allowed to change).
 *
 * So this file opens its own read-only view of the same MAP_SHARED file. That is
 * cheap and coherent — same inode, same page cache, and cache line 0 is already
 * hot because NrFilter reads `mode` out of it on every single query — and it
 * keeps the gate's failure modes local: if this mapping never happens, the
 * feature stays off and NOTHING else about the resolver changes. A gate wired
 * through NrFilter would have made a mapping failure here into a filter problem
 * there.
 *
 * It fails CLOSED, which is the opposite of everywhere else in the project and
 * is deliberate. Fail-open elsewhere means "do not block", i.e. do not act on a
 * decision we are unsure of. Here the uncertain thing is whether the user
 * enabled the feature AT ALL, and defaulting a disabled feature to on because we
 * could not read the switch would be a behaviour change nobody asked for — which
 * is also, in effect, blocking on an unverified decision.
 */
#define LOG_TAG "NullrouteFilter"

#include "NrCname.h"

#include <errno.h>
#include <log/log.h>

#include <atomic>

#include "NrControl.h"
#include "NrMap.h"
#include "nr_hook.h"

namespace nr {

#ifdef NULLROUTE_ENABLED

/* Retry ladder for "the seeder has not published control.bin yet". Fixed rather
 * than doubling: unlike NrFilter's index mapping this is not on the critical
 * path for anything — the worst case of retrying too slowly is that a freshly
 * enabled toggle takes another minute to take effect at first boot. */
#define NR_CNAME_RETRY_MS 60000u

namespace {

enum : uint32_t {
    CTL_UNMAPPED = 0,
    CTL_READY    = 1,
    CTL_DEAD     = 2, /* terminal for this netd process */
};

/* Constant-initialised into .bss: no static-initialisation order dependency
 * inside netd and no guard variable on the answer path. */
std::atomic<NrControl*> g_ctl{nullptr};
std::atomic<uint32_t>   g_ctl_state{CTL_UNMAPPED};
std::atomic<bool>       g_ctl_busy{false};
std::atomic<uint64_t>   g_ctl_retry_at{0}; /* monotonic ms */

/*
 * The control page, mapping it on first use. nullptr means "not available right
 * now", and every caller treats that as "the feature is off".
 *
 * Try-lock rather than a mutex, for the same reason NrFilter uses one: a DNS
 * answer must never block on another thread's mmap. Losing the race costs one
 * answer that is not uncloaked.
 */
NrControl* cnameControl() {
    NrControl* c = g_ctl.load(std::memory_order_acquire);
    if (c != nullptr) return c;
    if (g_ctl_state.load(std::memory_order_relaxed) == CTL_DEAD) return nullptr;

    const uint64_t now = nr_mono_ms();
    if (now < g_ctl_retry_at.load(std::memory_order_relaxed)) return nullptr;
    if (g_ctl_busy.exchange(true, std::memory_order_acq_rel)) return nullptr;

    void*  addr = nullptr;
    size_t len  = 0;
    int    e    = 0;
    if (nr_map_shared_rw(NR_PATH_CONTROL, NR_CONTROL_BYTES, &addr, &len, &e)) {
        g_ctl.store(static_cast<NrControl*>(addr), std::memory_order_release);
        g_ctl_state.store(CTL_READY, std::memory_order_relaxed);
    } else if (e == ENOENT) {
        /* nullroute_seed has not published the page yet. That is a race with a
         * healthy device at first boot, not a fault — back off and retry. */
        g_ctl_retry_at.store(now + NR_CNAME_RETRY_MS, std::memory_order_relaxed);
    } else {
        /* Anything else (EACCES from a missing SELinux rule being the classic)
         * will not fix itself by being retried once a minute for the life of
         * netd. Say it once and stop. */
        ALOGW("cname uncloak disabled: control.bin map failed, errno=%d", e);
        g_ctl_state.store(CTL_DEAD, std::memory_order_relaxed);
    }

    g_ctl_busy.store(false, std::memory_order_release);
    return g_ctl.load(std::memory_order_acquire);
}

}  // namespace

bool nr_cname_uncloak_blocked(const uint8_t* ans, size_t ans_len, uid_t uid) {
    if (ans == nullptr || ans_len == 0u) return false;

    NrControl* ctl = cnameControl();
    if (ctl == nullptr) return false;
    if (__atomic_load_n(&ctl->cname_uncloak, __ATOMIC_RELAXED) == 0u) return false;

    /* ~2.6 KiB of stack: the chain plus read_name's temporaries. This runs on a
     * netd handler thread with a normal stack, and the bound is structural
     * (NR_CNAME_MAX_LINKS), not a function of the message. */
    NrCnameChain chain;
    if (nr_cname_collect(ans, ans_len, &chain) != NR_CNAME_OK) return false;

    for (uint8_t i = 0; i < chain.count; ++i) {
        /*
         * The SAME call H1, H2 and H3 make. Per-app policy, the kill switch, the
         * pause byte, the never-block floor, the redirect table and the
         * query-log ring therefore all behave identically on this path without a
         * line of policy being restated here — in particular an EXEMPT app's
         * answers are never dropped, which is the one thing a separate
         * implementation would have been most likely to get wrong.
         *
         * TELEMETRY COST, stated rather than hidden: each of these counts as a
         * query in NrControl::q_total and can write a ring record, so on a
         * device with uncloaking ON a single lookup can contribute up to
         * NR_CNAME_MAX_LINKS + 1 to the counters. That is the honest reading —
         * the matcher really did run that many times — but it does mean q_total
         * stops being "lookups" and becomes "evaluations" once this is enabled.
         * The log records are the useful half: they name the TRACKER, which is
         * the whole point of uncloaking and something no other hook can show.
         */
        const Verdict v = hook(chain.link[i].text, uid);

        /*
         * V_REDIRECT counts as a drop too. The redirect address belongs to the
         * tracker's name, not to the first-party name the caller asked about,
         * and rewriting an addrinfo list from inside a six-line hook site is not
         * something this seam can do correctly. Denying is the conservative
         * reading of a verdict that already says "do not let this resolve".
         */
        if (v.kind != V_PASS) return true;
    }
    return false;
}

#endif /* NULLROUTE_ENABLED */

}  // namespace nr
