/*
 * Nullroute — the minimal DNS wire codec behind H3.
 *
 * This is the only place in the project that parses network-shaped bytes, and it
 * runs inside netd, whose init stanza carries `onrestart restart zygote`: a crash
 * here is a UI/boot loop on the user's phone, not a failed lookup (§10.1). The
 * bytes come from `android.net.DnsResolver.rawQuery()`, so any app on the device
 * chooses them, in full, with no adult supervision.
 *
 * The rules that follow from that, all of them structural rather than advisory:
 *
 *   - No allocation. Every output is a caller-owned fixed-size buffer.
 *   - No recursion. Compression pointers are followed by a loop, not by a call.
 *   - Every loop has a hard bound, and every read is bounds-checked against the
 *     caller's length before it happens — never against a length taken from the
 *     message itself.
 *   - No dependency on anything else in the project. That is what lets
 *     native/fuzz/nr_wire_fuzzer.cpp build and fuzz this file ALONE, with no
 *     index, no control page and no filter behind it, which in turn is what makes
 *     the fuzzer's crashes about the parser rather than about its fixtures.
 *
 * Header-only and `static inline` throughout for the same reason: the fuzz target
 * and the resolver compile literally the same code, so a bound that holds under
 * libFuzzer is the bound that ships.
 *
 * WHAT THIS IS NOT. It is not a general DNS library. It parses exactly one shape
 * — a single-question QUERY — and it emits exactly three — a denial, an address
 * answer, and a bare denial for the case where nothing else fits. Anything it
 * does not understand it declines, and declining always means H3 passes the query
 * through untouched.
 */
#ifndef NULLROUTE_RESOLVER_NR_WIRE_H
#define NULLROUTE_RESOLVER_NR_WIRE_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#define NR_WIRE_HEADER 12u /* ID FLAGS QDCOUNT ANCOUNT NSCOUNT ARCOUNT */

/* Whole-message ceiling. The resolver's own MAXPACKET is 8192, but the bound
 * that matters here is only that offsets stay well inside a size_t and that a
 * hostile length cannot be used to justify unbounded work. */
#define NR_WIRE_MAX_MSG 65535u

#define NR_WIRE_MAX_NAME   253u /* RFC 1035, presentation form, no trailing dot */
#define NR_WIRE_MAX_LABELS 128u /* unreachable given MAX_NAME; a second floor    */

/* A pointer may only point strictly backwards (enforced below), so the walk
 * cannot cycle no matter what. This budget bounds the WORK of a legal chain on
 * top of that — belt and braces, because the cost of being wrong is a hang
 * inside netd. */
#define NR_WIRE_MAX_JUMPS 4u

/*
 * Largest reply this codec can emit:
 *   12 header + 259 echoed question (255 max wire QNAME + QTYPE + QCLASS)
 *      + 76 SOA record  =  347.
 * 512 leaves margin without putting a page on the stack.
 */
#define NR_WIRE_MAX_REPLY 512u

#define NR_WIRE_CLASS_IN 1u

#define NR_WIRE_TYPE_A    1u
#define NR_WIRE_TYPE_SOA  6u
#define NR_WIRE_TYPE_AAAA 28u

#define NR_WIRE_RCODE_NOERROR  0
#define NR_WIRE_RCODE_NXDOMAIN 3

#ifdef __cplusplus
namespace nr {

/*
 * Why a status enum rather than a bool: H3 declines for several very different
 * reasons and the fuzzer asserts different invariants for each. Callers treat
 * everything except NR_WIRE_OK identically — pass the query through.
 */
enum NrWireStatus : uint8_t {
    NR_WIRE_OK = 0,
    NR_WIRE_SHORT,        /* the message ends inside a field we must read       */
    NR_WIRE_NOT_A_QUERY,  /* a response, a non-QUERY opcode, or QDCOUNT != 1    */
    NR_WIRE_MALFORMED,    /* reserved label type, forward/looping pointer, …    */
    NR_WIRE_COMPRESSED,   /* the QUESTION's QNAME used a compression pointer    */
    NR_WIRE_UNPRINTABLE,  /* a label byte the presentation form cannot carry    */
};

/* Presentation form: lowercase, dot-separated, no trailing root dot, NUL-terminated. */
struct NrWireName {
    char     text[NR_WIRE_MAX_NAME + 1];
    uint16_t len;
};

struct NrWireQuestion {
    NrWireName name;
    uint16_t   id;
    uint16_t   flags;
    uint16_t   qtype;
    uint16_t   qclass;
    uint32_t   q_off; /* always NR_WIRE_HEADER; named so the echo reads clearly */
    uint32_t   q_end; /* one past QCLASS — the question section's exact extent  */
};

static inline uint16_t nr_wire_u16(const uint8_t* p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

/*
 * Read one domain name starting at `pos`, into presentation form.
 *
 * `wire_end` receives one past the last byte the name occupies AT `pos` — which
 * is not the same as where the walk finished, once a compression pointer has
 * been followed. That distinction is the whole reason this returns it: the
 * question section's QTYPE/QCLASS sit at `wire_end`, and echoing the question
 * back means copying the bytes from `pos` to `wire_end`, not the bytes the name
 * happened to be assembled from.
 *
 * `saw_pointer` reports whether any compression pointer was followed. The caller
 * decides what that means; this function's job is only to survive it.
 *
 * TERMINATION IS STRUCTURAL. A pointer must target an offset strictly less than
 * its own, so every jump moves nearer the start of the message and the sequence
 * of jump origins is strictly decreasing. A cycle is therefore impossible before
 * the jump budget is even consulted. Between jumps the walk only ever moves
 * forward and every step is bounded by `len`.
 *
 * A LABEL BYTE THAT IS '.' IS REJECTED, not escaped. Two labels "a" "b" and one
 * label "a.b" would otherwise produce the same presentation string, and the
 * matcher decides at label boundaries — so accepting it would let one wire name
 * be evaluated as a different name. The ambiguity is removed at the door rather
 * than papered over downstream, and the cost is declining to filter a name no
 * ad or tracker endpoint has ever had.
 */
static inline NrWireStatus nr_wire_read_name(const uint8_t* buf, size_t len, size_t pos,
                                             NrWireName* out, size_t* wire_end,
                                             bool* saw_pointer) {
    out->text[0]  = '\0';
    out->len      = 0;
    *wire_end     = 0;
    *saw_pointer  = false;

    bool     have_end = false;
    unsigned jumps    = 0;
    unsigned labels   = 0;
    size_t   p        = pos;

    for (;;) {
        if (p >= len) return NR_WIRE_SHORT;
        const uint8_t b = buf[p];

        if ((b & 0xC0u) == 0xC0u) {
            if (p + 1u >= len) return NR_WIRE_SHORT;
            if (!have_end) {
                *wire_end = p + 2u;
                have_end  = true;
            }
            const size_t target = (size_t)((((uint16_t)(b & 0x3Fu)) << 8) | buf[p + 1u]);
            if (target >= p) return NR_WIRE_MALFORMED;   /* forward or self: never legal */
            if (++jumps > NR_WIRE_MAX_JUMPS) return NR_WIRE_MALFORMED;
            *saw_pointer = true;
            p            = target;
            continue;
        }
        if ((b & 0xC0u) != 0u) return NR_WIRE_MALFORMED; /* reserved label type (RFC 6891) */

        if (b == 0u) {
            if (!have_end) *wire_end = p + 1u;
            break;
        }

        if (++labels > NR_WIRE_MAX_LABELS) return NR_WIRE_MALFORMED;
        const size_t l = (size_t)b; /* <= 63: the two high bits are known clear */
        if (l > len - p - 1u) return NR_WIRE_SHORT;

        /* Length check BEFORE any byte is written, so a name that overruns the
         * presentation bound leaves the output untouched rather than partly
         * filled. `out->len` is the count so far; +1 is the separator. */
        const size_t need = out->len ? (size_t)out->len + 1u + l : l;
        if (need > NR_WIRE_MAX_NAME) return NR_WIRE_MALFORMED;

        if (out->len) out->text[out->len++] = '.';
        for (size_t i = 0; i < l; ++i) {
            uint8_t c = buf[p + 1u + i];
            if (c >= 'A' && c <= 'Z') c = (uint8_t)(c - 'A' + 'a');
            if (c < 0x21u || c > 0x7Eu || c == '.') return NR_WIRE_UNPRINTABLE;
            out->text[out->len++] = (char)c;
        }
        p += 1u + l;
    }

    out->text[out->len] = '\0';
    return NR_WIRE_OK;
}

/*
 * Parse a single-question QUERY.
 *
 * Returns NR_WIRE_COMPRESSED for a question whose QNAME uses a compression
 * pointer. Such a query is malformed by construction — there is nothing before
 * the question for a pointer to reference — and, more to the point, a question
 * we cannot echo back verbatim is a question we must not answer: the reply would
 * carry a pointer into bytes the reply does not contain. So the pointer walk
 * above runs (and is bounded), and then we decline anyway.
 */
static inline NrWireStatus nr_wire_parse_query(const uint8_t* buf, size_t len,
                                               NrWireQuestion* out) {
    if (!buf || !out) return NR_WIRE_MALFORMED;
    memset(out, 0, sizeof(*out));

    if (len < NR_WIRE_HEADER) return NR_WIRE_SHORT;
    if (len > NR_WIRE_MAX_MSG) return NR_WIRE_MALFORMED;

    out->id                = nr_wire_u16(buf + 0);
    out->flags             = nr_wire_u16(buf + 2);
    const uint16_t qdcount = nr_wire_u16(buf + 4);

    if (out->flags & 0x8000u) return NR_WIRE_NOT_A_QUERY;             /* QR: a response */
    if (((out->flags >> 11) & 0x0Fu) != 0u) return NR_WIRE_NOT_A_QUERY; /* opcode != QUERY */
    if (qdcount != 1u) return NR_WIRE_NOT_A_QUERY;

    size_t wire_end = 0;
    bool   saw_ptr  = false;
    const NrWireStatus st =
            nr_wire_read_name(buf, len, NR_WIRE_HEADER, &out->name, &wire_end, &saw_ptr);
    if (st != NR_WIRE_OK) return st;
    if (saw_ptr) return NR_WIRE_COMPRESSED;
    if (wire_end + 4u > len) return NR_WIRE_SHORT;

    out->qtype  = nr_wire_u16(buf + wire_end);
    out->qclass = nr_wire_u16(buf + wire_end + 2u);
    out->q_off  = NR_WIRE_HEADER;
    out->q_end  = (uint32_t)(wire_end + 4u);
    return NR_WIRE_OK;
}

/* ---------------------------------------------------------------------------
 * Emitting a reply
 *
 * A tiny append-only writer. Every put() is a no-op once the buffer is full and
 * the overflow is sticky, so a caller can write a whole record without checking
 * after each field and still cannot produce a truncated one — the final `ok` is
 * what decides whether anything is returned at all.
 * ------------------------------------------------------------------------- */

struct NrWireOut {
    uint8_t* buf;
    size_t   cap;
    size_t   n;
    bool     ok;
};

static inline void nr_wire_put(NrWireOut* o, const void* src, size_t n) {
    if (!o->ok) return;
    if (n > o->cap - o->n) { /* n <= cap is the loop invariant, so this cannot wrap */
        o->ok = false;
        return;
    }
    memcpy(o->buf + o->n, src, n);
    o->n += n;
}

static inline void nr_wire_put16(NrWireOut* o, uint16_t v) {
    const uint8_t b[2] = {(uint8_t)(v >> 8), (uint8_t)v};
    nr_wire_put(o, b, sizeof(b));
}

static inline void nr_wire_put32(NrWireOut* o, uint32_t v) {
    const uint8_t b[4] = {(uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v};
    nr_wire_put(o, b, sizeof(b));
}

/*
 * Header plus the question echoed byte-for-byte.
 *
 * RD is mirrored from the query and RA is set, because a client that asked for
 * recursion and got an answer with RD clear has been told something untrue about
 * its own question. AA is deliberately left clear: the SOA below is synthetic and
 * this resolver is authoritative for nothing.
 *
 * ARCOUNT is zero even when the query carried an EDNS0 OPT. Dropping OPT from a
 * synthesized answer costs the client its advertised buffer size and nothing else
 * — there is no truncation to negotiate around a 347-byte reply — and echoing an
 * OPT we did not generate would be worse than omitting one.
 */
static inline void nr_wire_begin_reply(NrWireOut* o, const uint8_t* q, const NrWireQuestion* qq,
                                       unsigned rcode, uint16_t ancount, uint16_t nscount) {
    const uint16_t flags =
            (uint16_t)(0x8000u | (qq->flags & 0x0100u) | 0x0080u | (uint16_t)(rcode & 0x0Fu));
    nr_wire_put16(o, qq->id);
    nr_wire_put16(o, flags);
    nr_wire_put16(o, 1); /* QDCOUNT — the echoed question */
    nr_wire_put16(o, ancount);
    nr_wire_put16(o, nscount);
    nr_wire_put16(o, 0); /* ARCOUNT */
    nr_wire_put(o, q + qq->q_off, (size_t)(qq->q_end - qq->q_off));
}

/*
 * NXDOMAIN (or NOERROR/NODATA) with a synthetic SOA in AUTHORITY.
 *
 * The SOA is not decoration. Without one, RFC 2308 gives a caching client no
 * bound at all on how long to remember the denial, and some cache for hours —
 * which would make "Allow this domain" appear not to work. MINIMUM is the same
 * short TTL as the record's own, so un-blocking takes effect within a minute
 * everywhere we cannot reach in to flush.
 *
 * Returns bytes written, or 0 if the reply did not fit in `cap`.
 */
static inline size_t nr_wire_build_denial(const uint8_t* q, const NrWireQuestion* qq,
                                          unsigned rcode, uint32_t ttl, uint8_t* out,
                                          size_t cap) {
    /* nullroute.invalid. and block.nullroute.invalid. in wire form. `.invalid`
     * is reserved by RFC 6761 precisely so a name can be guaranteed never to
     * resolve, which is what a synthetic zone apex should be. */
    static const uint8_t kMname[] = {9, 'n', 'u', 'l', 'l', 'r', 'o', 'u', 't', 'e',
                                     7, 'i', 'n', 'v', 'a', 'l', 'i', 'd', 0};
    static const uint8_t kRname[] = {5, 'b', 'l', 'o', 'c', 'k',
                                     9, 'n', 'u', 'l', 'l', 'r', 'o', 'u', 't', 'e',
                                     7, 'i', 'n', 'v', 'a', 'l', 'i', 'd', 0};

    NrWireOut o = {out, cap, 0, true};
    nr_wire_begin_reply(&o, q, qq, rcode, 0, 1);

    /* Owner name: a pointer to the question's QNAME at offset 12, which the
     * echo above has just placed there. */
    nr_wire_put16(&o, (uint16_t)(0xC000u | NR_WIRE_HEADER));
    nr_wire_put16(&o, (uint16_t)NR_WIRE_TYPE_SOA);
    nr_wire_put16(&o, (uint16_t)NR_WIRE_CLASS_IN);
    nr_wire_put32(&o, ttl);
    nr_wire_put16(&o, (uint16_t)(sizeof(kMname) + sizeof(kRname) + 20u));
    nr_wire_put(&o, kMname, sizeof(kMname));
    nr_wire_put(&o, kRname, sizeof(kRname));
    nr_wire_put32(&o, 1u);     /* SERIAL  */
    nr_wire_put32(&o, 3600u);  /* REFRESH */
    nr_wire_put32(&o, 600u);   /* RETRY   */
    nr_wire_put32(&o, 86400u); /* EXPIRE  */
    nr_wire_put32(&o, ttl);    /* MINIMUM — the negative-cache bound (RFC 2308) */

    return o.ok ? o.n : 0u;
}

/*
 * NOERROR with one A or AAAA answer. This is how a REDIRECT rule — including the
 * `idx-probe` liveness redirect and the per-app sinkhole compat mode — reaches a
 * caller that asked through rawQuery() rather than through getaddrinfo().
 *
 * Returns bytes written, or 0 for an address length that is not 4 or 16, or if
 * the reply did not fit in `cap`.
 */
static inline size_t nr_wire_build_address(const uint8_t* q, const NrWireQuestion* qq,
                                           const uint8_t* addr, size_t addr_len, uint32_t ttl,
                                           uint8_t* out, size_t cap) {
    if (addr_len != 4u && addr_len != 16u) return 0u;

    NrWireOut o = {out, cap, 0, true};
    nr_wire_begin_reply(&o, q, qq, NR_WIRE_RCODE_NOERROR, 1, 0);
    nr_wire_put16(&o, (uint16_t)(0xC000u | NR_WIRE_HEADER));
    nr_wire_put16(&o, (uint16_t)(addr_len == 4u ? NR_WIRE_TYPE_A : NR_WIRE_TYPE_AAAA));
    nr_wire_put16(&o, (uint16_t)NR_WIRE_CLASS_IN);
    nr_wire_put32(&o, ttl);
    nr_wire_put16(&o, (uint16_t)addr_len);
    nr_wire_put(&o, addr, addr_len);

    return o.ok ? o.n : 0u;
}

/*
 * Header plus the echoed question and nothing else — the last-resort denial for
 * an answer buffer too small to hold the SOA form.
 *
 * It exists so that "the caller gave us 100 bytes" degrades to a correct but
 * unhelpfully un-cacheable denial rather than to no denial at all. Falling open
 * there would let a name the policy has ALREADY decided to block go out to the
 * network — a silent filtering failure, which is the one outcome worse than a
 * loud one.
 */
static inline size_t nr_wire_build_bare(const uint8_t* q, const NrWireQuestion* qq,
                                        unsigned rcode, uint8_t* out, size_t cap) {
    NrWireOut o = {out, cap, 0, true};
    nr_wire_begin_reply(&o, q, qq, rcode, 0, 0);
    return o.ok ? o.n : 0u;
}

/* ---------------------------------------------------------------------------
 * H3 — the one entry point this unit exposes to the resolver.
 *
 * Declared here rather than in nr_hook.h so that the hook site includes exactly
 * one new header and the fuzz target includes exactly the same file the resolver
 * does. Defined in NrResSend.cpp.
 * ------------------------------------------------------------------------- */

#ifdef NULLROUTE_ENABLED
int nr_resnsend_hook(const uint8_t* msg, size_t msg_len, uid_t uid, uint8_t* ans, size_t ans_cap,
                     int* rcode);
#endif

/*
 * Returns 0 for "not ours — perform the real query", which is also what every
 * internal failure returns: there is no path through H3 that can make a raw
 * query fail because of Nullroute.
 *
 * A positive return is the length of a complete wire answer already written into
 * `ans`, with `*rcode` set to match. The caller returns it verbatim.
 */
inline int resNSend(const uint8_t* msg, size_t msg_len, uid_t uid, uint8_t* ans, size_t ans_cap,
                    int* rcode) {
#ifdef NULLROUTE_ENABLED
    return nr_resnsend_hook(msg, msg_len, uid, ans, ans_cap, rcode);
#else
    (void)msg;
    (void)msg_len;
    (void)uid;
    (void)ans;
    (void)ans_cap;
    (void)rcode;
    return 0;
#endif
}

}  // namespace nr
#endif /* __cplusplus */
#endif /* NULLROUTE_RESOLVER_NR_WIRE_H */
