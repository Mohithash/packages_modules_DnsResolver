/*
 * Nullroute — H3, the raw-query hook.
 *
 * ============================================================================
 *  WHERE THIS HANGS, AND WHY IT IS NOT res_nsend()
 * ============================================================================
 *
 * `android.net.DnsResolver.rawQuery()` reaches the resolver by exactly one road:
 *
 *     app -> DnsProxyListener's ResNSendCommand -> ResNSendHandler::run()
 *         -> resolv_res_nsend()          <-- the EXTERNAL entry point, hooked here
 *         -> res_nsend()                 <-- the INTERNAL one, NOT hooked
 *         -> the transports
 *
 * `res_nsend()` is also where every getaddrinfo() lookup ends up, by way of
 * res_nsearch()/res_nquery(). Hooking there would therefore evaluate each of
 * those a SECOND time — once at H1, where the hostname and the caller's uid are
 * both in hand, and again several frames later against a wire question the
 * resolver itself just built. That would double the matcher's cost on ~99% of
 * traffic, double-count every block in the query log and the control-page
 * counters, and produce a second verdict that H1 has already acted on.
 * `resolv_res_nsend()` has exactly one caller — the ResNSendCommand handler — so
 * hooking it covers the raw-query path completely and nothing else at all.
 *
 * SPEC §8.3 item 12 describes H3 as ~40 lines inside the handler. This is the
 * same hook one seam lower down, and the seam is worth the deviation: at the
 * handler we would have to base64-decode the command argument ourselves and then
 * reimplement the dnsproxyd reply framing (`sendBE32` + `sendLenAndData`) to
 * short-circuit it — attacker-influenced decoding plus a private wire protocol,
 * both of them things a permanent fork should not own. At `resolv_res_nsend()`
 * the contract is already exactly what we need: bytes in, bytes out, an rcode
 * out-parameter, and a return value that is a length. The hunk is eight lines
 * and mentions four identifiers.
 *
 * ============================================================================
 *  WHAT IT MAY DO
 * ============================================================================
 *
 * It runs inside netd. Every constraint from NrFilter.h applies unchanged: no
 * allocation, no lock, no recursion, no unbounded loop, and every failure falls
 * OPEN. The verdict itself comes from nr::hook(), the same call H1 and H2 make,
 * so per-app policy, the kill switch, the pause byte, the response mode, the
 * sinkhole rewrite and the query-log ring all behave identically on this path
 * without a line of policy being restated here.
 *
 * The whole of the untrusted parsing lives in nr_wire.h, which is fuzzed alone
 * (native/fuzz/nr_wire_fuzzer.cpp) precisely because this is the only place the
 * project reads network-shaped bytes.
 */
#define LOG_TAG "NullrouteFilter"

#include "nr_wire.h"

#include <netdb.h>
#include <string.h>
#include <sys/socket.h>

#include "nr_hook.h"

namespace nr {

#ifdef NULLROUTE_ENABLED

/*
 * TTL on everything we synthesize, and MINIMUM on the SOA that bounds negative
 * caching of a denial.
 *
 * Short on purpose. Blocked answers never enter res_cache — the hook returns
 * before dns_getaddrinfo() is reached — so un-blocking is instantaneous AT the
 * resolver. It is the caller's own cache we are negotiating with here, and a
 * user who taps "Allow this domain" should not wait an hour to see it work.
 */
#define NR_RESNSEND_TTL 60u

int nr_resnsend_hook(const uint8_t* msg, size_t msg_len, uid_t uid, uint8_t* ans, size_t ans_cap,
                     int* rcode) {
    if (msg == nullptr || ans == nullptr || rcode == nullptr) return 0;

    /* ~360 bytes of stack. This runs on a netd handler thread, not on a signal
     * stack or a tiny one, and it is bounded by construction (NR_WIRE_MAX_REPLY
     * covers the largest reply the codec can emit). */
    NrWireQuestion q;
    if (nr_wire_parse_query(msg, msg_len, &q) != NR_WIRE_OK) return 0;

    /*
     * CLASS IN only. A CH or HS question is not a name we have any policy about,
     * and answering one with a denial derived from an IN blocklist would be
     * inventing an answer rather than enforcing one.
     *
     * QTYPE is deliberately NOT filtered. NXDOMAIN is a statement about the NAME,
     * not about a record type, so a blocked domain is blocked for TXT and SVCB
     * exactly as it is for A — and letting an unusual QTYPE through would leave
     * an obvious hole for anything that wanted one.
     */
    if (q.qclass != NR_WIRE_CLASS_IN) return 0;
    if (q.name.len == 0) return 0; /* the root; nothing a blocklist can describe */

    const Verdict v = hook(q.name.text, uid);
    if (v.kind == V_PASS) return 0;

    uint8_t      reply[NR_WIRE_MAX_REPLY];
    const size_t cap = ans_cap < sizeof(reply) ? ans_cap : sizeof(reply);
    size_t       n   = 0;
    int          rc  = NR_WIRE_RCODE_NXDOMAIN;

    if (v.kind == V_REDIRECT) {
        /*
         * A redirect says the name EXISTS and resolves to this address, so the
         * only correct answer for a query of another type is NOERROR with no
         * records — NODATA. Returning NXDOMAIN there would assert the name does
         * not exist at all, which is both false and stickier: a caching client is
         * entitled to apply an NXDOMAIN to every type at once.
         */
        const size_t alen = (v.family == AF_INET6) ? 16u : 4u;
        const bool   type_matches = (v.family == AF_INET && q.qtype == NR_WIRE_TYPE_A) ||
                                  (v.family == AF_INET6 && q.qtype == NR_WIRE_TYPE_AAAA);
        rc = NR_WIRE_RCODE_NOERROR;
        n  = type_matches ? nr_wire_build_address(msg, &q, v.addr, alen, NR_RESNSEND_TTL, reply,
                                                  cap)
                          : nr_wire_build_denial(msg, &q, rc, NR_RESNSEND_TTL, reply, cap);
    } else {
        /*
         * V_BLOCK. blockErrno() is the same response-mode read H1 and H2 make;
         * mapping it here keeps one setting rather than two that can disagree:
         *   EAI_NONAME -> NXDOMAIN            (the default, a real "no such name")
         *   EAI_NODATA -> NOERROR, no answer  (gentler for apps that hard-fail)
         * NR_RESP_SINKHOLE never arrives as a block: NrFilter::evaluate() has
         * already rewritten it into a V_REDIRECT to 0.0.0.0, which is why the
         * sinkhole mode is filtered on this path too rather than silently not.
         */
        rc = (blockErrno() == EAI_NODATA) ? NR_WIRE_RCODE_NOERROR : NR_WIRE_RCODE_NXDOMAIN;
        n  = nr_wire_build_denial(msg, &q, rc, NR_RESNSEND_TTL, reply, cap);
    }

    /* The SOA form did not fit the caller's buffer. Degrade to header + question
     * rather than fall open: the policy has already reached a verdict, and
     * letting the query proceed would resolve, for real, a name we just decided
     * to intercept. */
    if (n == 0) n = nr_wire_build_bare(msg, &q, rc, reply, cap);
    if (n == 0) return 0; /* not even 12 bytes available; nothing left to do but pass */

    memcpy(ans, reply, n);
    *rcode = rc;
    return (int)n;
}

#endif /* NULLROUTE_ENABLED */

}  // namespace nr
