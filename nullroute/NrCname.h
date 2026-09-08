/*
 * Nullroute — H5, CNAME uncloaking.
 *
 * ============================================================================
 *  WHAT THIS IS FOR
 * ============================================================================
 *
 * A CNAME-cloaked tracker is delivered under a name that belongs to the site you
 * are actually visiting:
 *
 *     metrics.example.com.   CNAME  example.eulerian.net.
 *     example.eulerian.net.  A      1.2.3.4
 *
 * The QUESTION carries only `metrics.example.com`, which is on nobody's
 * blocklist and cannot be, because it is first-party by construction and differs
 * per site. H1/H2/H3 all decide on the question, so all three see nothing. The
 * tracker's real name appears for the first time in the RESPONSE — and that is
 * the only place it can be caught. Hence a hook that reads answers.
 *
 * The blocklists already ship the target side: NextDNS's cname-cloaking list is
 * a catalogue of exactly these endpoints, and it is in the default profile. So
 * this hunk does not need new rules, only a new place to apply the existing ones.
 *
 * ============================================================================
 *  WHY THE PARSER IS HERE, HEADER-ONLY, AND THE POLICY IS NOT
 * ============================================================================
 *
 * This runs inside netd, whose init stanza carries `onrestart restart zygote`.
 * A fault here is a UI/boot loop on a user's phone, not a failed lookup, and the
 * bytes are chosen by whatever answered the query — i.e. by the network. So the
 * split is the same one nr_wire.h makes and for the same reason:
 *
 *   - Everything that touches untrusted bytes is `static inline` in THIS header
 *     and depends on nothing but nr_wire.h. That is what lets
 *     native/fuzz/nr_cname_fuzzer.cpp build and fuzz it ALONE, with no index, no
 *     control page and no filter linked in — so a crash the fuzzer finds is a
 *     parser bug rather than a fixture bug.
 *   - Everything that reaches a verdict lives in NrCname.cpp, behind
 *     NULLROUTE_ENABLED, and is never seen by the fuzz target.
 *
 * THERE IS NO SECOND WIRE PARSER. Every name — the question we skip, every RR
 * owner, every CNAME target — is read by nr_wire_read_name(), which already owns
 * the compression-pointer loop guard, the label bounds and the presentation-form
 * rules. This file adds exactly one thing on top: the fixed-width RR walk
 * (TYPE CLASS TTL RDLENGTH) that gets from one name to the next.
 *
 * ============================================================================
 *  WHAT IT DELIBERATELY DOES NOT DO
 * ============================================================================
 *
 * It does not FOLLOW the chain. Following would mean matching each CNAME's owner
 * against the previous target — a graph walk over attacker-chosen edges, with
 * cycles to defend against and a termination argument to get right. It is also
 * unnecessary: a cloaked answer has the tracker's name as the TARGET of some
 * CNAME record in it, and every subsequent link's owner is a previous link's
 * target. Collecting every target in the answer section therefore sees the same
 * set of names a full walk would, in one forward pass, with no state and no
 * possible cycle.
 *
 * It reads the ANSWER section only. Authority and additional records are not
 * answers to the question and would only widen the attack surface.
 */
#ifndef NULLROUTE_RESOLVER_NR_CNAME_H
#define NULLROUTE_RESOLVER_NR_CNAME_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#include "nr_wire.h"

#define NR_CNAME_TYPE 5u

/* Longest chain we will collect. Real cloaking chains are one or two links; the
 * longest seen in the wild is around four. Each link is an NrWireName (256 B),
 * so this bound is also the stack budget: NrCnameChain is ~2 KiB, which is fine
 * on a netd handler thread and would not be on anything smaller. An answer with
 * more links than this is reported as `truncated` and NOT as a block — see
 * below. */
#define NR_CNAME_MAX_LINKS 8u

/* Records walked in the answer section, regardless of what ANCOUNT claims. This
 * is the loop bound: ANCOUNT is a 16-bit number chosen by whoever answered, and
 * a walk that trusted it would do 65535 name reads for a 20-byte packet. */
#define NR_CNAME_MAX_RECORDS 64u

/* Fixed-width part of every resource record: TYPE CLASS TTL RDLENGTH. */
#define NR_CNAME_RR_FIXED 10u

#ifdef __cplusplus
namespace nr {

/*
 * Callers treat everything except NR_CNAME_OK identically — there is no chain to
 * judge, so the answer passes through untouched. The cases are distinguished
 * because the fuzzer asserts different invariants for each.
 */
enum NrCnameStatus : uint8_t {
    NR_CNAME_OK = 0,       /* at least one CNAME target was collected           */
    NR_CNAME_NONE,         /* well-formed, but nothing to uncloak               */
    NR_CNAME_SHORT,        /* the message ends inside a field we must read      */
    NR_CNAME_MALFORMED,    /* impossible counts, a name we cannot render, ...   */
    NR_CNAME_NOT_A_REPLY,  /* QR clear or a non-QUERY opcode                    */
};

struct NrCnameChain {
    NrWireName link[NR_CNAME_MAX_LINKS];
    uint8_t    count;

    /*
     * "There were targets in this answer that we did not see" — more links than
     * NR_CNAME_MAX_LINKS, more records than NR_CNAME_MAX_RECORDS, or a target
     * whose bytes have no presentation form.
     *
     * It is REPORTING, not a verdict. Blocking on it would mean inventing a
     * decision about a name we could not read, which is the opposite of the
     * fail-open rule this whole subsystem is built on; and it would hand any
     * server a one-packet way to make Nullroute break arbitrary sites.
     */
    bool truncated;
};

/*
 * The record walk. Call nr_cname_collect() below, not this — it is split out
 * only so the wrapper can guarantee an all-or-nothing result.
 *
 * Collects every CNAME target in the answer section of `buf`.
 *
 * `buf`/`len` is a whole DNS reply — header, question, then the sections — which
 * is exactly what `res_target::answer` holds after res_searchN() returns.
 *
 * No allocation, no recursion, no unbounded loop, every read bounds-checked
 * against `len` before it happens and never against a length taken from the
 * message. `out` is caller-owned.
 *
 * KNOWN LIMITATION, on purpose: a name whose label bytes have no presentation
 * form (a space, a NUL, anything above 0x7E) makes nr_wire_read_name() decline,
 * and since the RR walk cannot step over a name it could not read, an
 * unprintable QUESTION or RR OWNER makes this whole function decline. That
 * fails OPEN — the answer is delivered unfiltered — and it does mean a hostile
 * server can dodge uncloaking by returning a name of that shape. The
 * alternative is a second, length-only name walker living next to the audited
 * one, which is a far worse trade inside netd than a miss on a name no CDN or
 * tracker endpoint actually has. mDNS service-instance names DO have this shape,
 * which is another reason to decline rather than to guess.
 */
static inline NrCnameStatus nr_cname_walk(const uint8_t* buf, size_t len, NrCnameChain* out) {
    if (!buf || !out) return NR_CNAME_MALFORMED;
    /* Own the initialisation rather than inheriting it from the wrapper. This is
     * a separately-callable entry point that both WRITES `out->count` and INDEXES
     * `out->link[out->count]` with it; a caller that reached it with a stack-junk
     * chain would write past the array before any bound in this function ran.
     * Two stores on a path that then walks a packet is not a cost worth trading
     * for that. */
    out->count     = 0;
    out->truncated = false;

    if (len < NR_WIRE_HEADER) return NR_CNAME_SHORT;
    if (len > NR_WIRE_MAX_MSG) return NR_CNAME_MALFORMED;

    const uint16_t flags = nr_wire_u16(buf + 2);
    if ((flags & 0x8000u) == 0u) return NR_CNAME_NOT_A_REPLY;            /* QR clear      */
    if (((flags >> 11) & 0x0Fu) != 0u) return NR_CNAME_NOT_A_REPLY;      /* opcode != QUERY */

    /* Any rcode but NOERROR means the answer section is not carrying records we
     * have a reason to trust; there is nothing to uncloak in a denial. */
    if ((flags & 0x000Fu) != 0u) return NR_CNAME_NONE;

    const uint16_t qdcount = nr_wire_u16(buf + 4);
    const uint16_t ancount = nr_wire_u16(buf + 6);
    if (qdcount > 1u) return NR_CNAME_MALFORMED; /* the resolver never asks more than one */
    if (ancount == 0u) return NR_CNAME_NONE;

    size_t p = NR_WIRE_HEADER;

    if (qdcount == 1u) {
        NrWireName qname;
        size_t     wire_end = 0;
        bool       saw_ptr  = false;
        const NrWireStatus st = nr_wire_read_name(buf, len, p, &qname, &wire_end, &saw_ptr);
        if (st == NR_WIRE_SHORT) return NR_CNAME_SHORT;
        if (st != NR_WIRE_OK) return NR_CNAME_MALFORMED;
        if (wire_end <= p || wire_end > len) return NR_CNAME_MALFORMED;
        if (len - wire_end < 4u) return NR_CNAME_SHORT; /* QTYPE + QCLASS */
        p = wire_end + 4u;
    }

    const unsigned records = ancount < NR_CNAME_MAX_RECORDS ? ancount : NR_CNAME_MAX_RECORDS;
    if (ancount > records) out->truncated = true;

    for (unsigned i = 0; i < records; ++i) {
        NrWireName owner;
        size_t     wire_end = 0;
        bool       saw_ptr  = false;
        const NrWireStatus st = nr_wire_read_name(buf, len, p, &owner, &wire_end, &saw_ptr);
        if (st == NR_WIRE_SHORT) return NR_CNAME_SHORT;
        if (st != NR_WIRE_OK) return NR_CNAME_MALFORMED;

        /* read_name always advances by at least one byte when it succeeds; the
         * loop's termination does not rest on that (NR_CNAME_MAX_RECORDS bounds
         * it either way), but a walk that could stand still would silently read
         * the same record `records` times. */
        if (wire_end <= p || wire_end > len) return NR_CNAME_MALFORMED;
        p = wire_end;

        if (len - p < NR_CNAME_RR_FIXED) return NR_CNAME_SHORT;
        const uint16_t rtype  = nr_wire_u16(buf + p);
        const uint16_t rclass = nr_wire_u16(buf + p + 2u);
        const uint16_t rdlen  = nr_wire_u16(buf + p + 8u);
        p += NR_CNAME_RR_FIXED;
        if (len - p < (size_t)rdlen) return NR_CNAME_SHORT;

        if (rtype == NR_CNAME_TYPE && rclass == NR_WIRE_CLASS_IN && rdlen != 0u) {
            if (out->count >= NR_CNAME_MAX_LINKS) {
                out->truncated = true;
                break;
            }
            NrWireName target;
            size_t     tgt_end = 0;
            bool       tgt_ptr = false;
            /* Bounded by `len`, not by RDLENGTH: a compression pointer inside
             * RDATA legitimately addresses back into the rest of the message,
             * and read_name's "strictly backwards" rule is what keeps that
             * safe. RDLENGTH still decides where the NEXT record starts, which
             * is why `p` advances by it below rather than by tgt_end. */
            const NrWireStatus ts =
                    nr_wire_read_name(buf, len, p, &target, &tgt_end, &tgt_ptr);
            if (ts == NR_WIRE_OK && target.len != 0u) {
                out->link[out->count++] = target;
            } else {
                /* One unreadable target does not invalidate the ones we did
                 * read, so keep going and say so. */
                out->truncated = true;
            }
        }
        p += rdlen;
    }

    return out->count ? NR_CNAME_OK : NR_CNAME_NONE;
}

/*
 * The entry point. Wraps the walk so that ANY non-OK return leaves `out` empty
 * rather than half-filled — a record walk that dies on record 4 has already
 * written links 1..3, and a caller that read them would be enforcing a policy
 * derived from an answer we just declared unreadable. Emptying it makes "did
 * this succeed" and "is there anything here" the same question, which is one
 * fewer thing for a hook site to get wrong.
 */
static inline NrCnameStatus nr_cname_collect(const uint8_t* buf, size_t len, NrCnameChain* out) {
    if (!buf || !out) return NR_CNAME_MALFORMED;
    out->count     = 0;
    out->truncated = false;

    const NrCnameStatus st = nr_cname_walk(buf, len, out);
    if (st != NR_CNAME_OK) {
        out->count     = 0;
        out->truncated = false;
    }
    return st;
}

/* ---------------------------------------------------------------------------
 * The policy side — defined in NrCname.cpp, declared here so the hook site
 * includes exactly one new header and the fuzz target includes exactly the file
 * the resolver does.
 * ------------------------------------------------------------------------- */

#ifdef NULLROUTE_ENABLED
bool nr_cname_uncloak_blocked(const uint8_t* ans, size_t ans_len, uid_t uid);
#endif

/*
 * H5. True means "this answer resolves onto a name the user blocks — drop it".
 *
 * Returns false for everything else, which includes every disabled state, every
 * unparseable answer and every internal failure: there is no path through this
 * call that can make a lookup fail because of Nullroute.
 *
 * It is OFF unless NrControl::cname_uncloak is set, so the default device pays
 * one relaxed byte load per answer and nothing else.
 */
inline bool cnameBlocked(const uint8_t* ans, size_t ans_len, uid_t uid) {
#ifdef NULLROUTE_ENABLED
    return nr_cname_uncloak_blocked(ans, ans_len, uid);
#else
    (void)ans;
    (void)ans_len;
    (void)uid;
    return false;
#endif
}

}  // namespace nr
#endif /* __cplusplus */
#endif /* NULLROUTE_RESOLVER_NR_CNAME_H */
