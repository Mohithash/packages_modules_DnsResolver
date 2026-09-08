/*
 * Nullroute — the hook surface the resolver actually calls.
 *
 * This header exists to keep the permanent fork small and rebase-proof. Its one
 * rule: NOTHING here may name a resolver type or a resolver signature. The
 * `resolv_getaddrinfo()` prototype differs between AOSP main and its forks —
 * some carry a `std::optional<int> app_socket` parameter, some do not, and the
 * `NetworkDnsEventReported*` tail has moved before — so a hook that mentioned
 * any of that would break on a tree we have not seen. Everything below takes a
 * hostname and a uid, which have not changed since the resolver was moved into
 * a mainline module.
 *
 * The one deliberate exception is fillHostent(), which touches `struct hostent`.
 * That is a POSIX type, not a resolver type, and it is here rather than in
 * gethnamaddr.cpp so the H2 hunk stays six lines of call site instead of forty
 * lines of pointer arithmetic living in a file we have to rebase every year.
 *
 * Build switch: with NULLROUTE_ENABLED undefined every entry point below folds
 * to a constant and the linker never sees libnrfilter. That is what
 * `ro.nullroute.enabled=false` buys — a one-flag bisect of a ROM regression.
 */
#ifndef NULLROUTE_RESOLVER_NR_HOOK_H
#define NULLROUTE_RESOLVER_NR_HOOK_H

#include <arpa/inet.h>
#include <netdb.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "NrIndex.h"
#include "NrVerdict.h"

namespace nr {

#ifdef NULLROUTE_ENABLED
/* Defined in NrFilter.cpp. Out-of-line on purpose: the hook sites should carry
 * one call instruction, not an inlined copy of the filter's state machine. */
Verdict nr_filter_hook(const char* hostname, uid_t uid);
bool    nr_hosts_layer_superseded(const char* name);
int     nr_block_errno();
#endif

/*
 * H1 / H2. Returns V_PASS for everything the filter cannot or must not decide:
 * kill switch set, index not mapped, mode not ENFORCE, uid exempt, name is an IP
 * literal or a reserved suffix, any internal fault. There is no path through
 * this call that can make a lookup fail.
 */
inline Verdict hook(const char* hostname, uid_t uid) {
#ifdef NULLROUTE_ENABLED
    return nr_filter_hook(hostname, uid);
#else
    (void)hostname;
    (void)uid;
    return Verdict{};
#endif
}

/*
 * H4. May files_getaddrinfo() skip its linear rescan of /system/etc/hosts?
 *
 * PASS THE QUERIED NAME. Without it this returns false unconditionally and the
 * hunk is a never-taken branch, because a predicate that cannot see the name
 * cannot tell `localhost` — which /system/etc/hosts is the only resolver for on
 * Android — from an ad domain. The default argument exists so the two-line form
 * still compiles on a tree whose parameter is named something else; it is a
 * compile aid, not a supported configuration.
 */
inline bool hostsLayerSuperseded(const char* name = nullptr) {
#ifdef NULLROUTE_ENABLED
    return nr_hosts_layer_superseded(name);
#else
    (void)name;
    return false;
#endif
}

/* The errno a blocked lookup returns: EAI_NONAME (NXDOMAIN-equivalent, the
 * default) or EAI_NODATA, per NrControl::response_mode. The sinkhole response
 * never surfaces here — the filter rewrites it into a V_REDIRECT so a hook site
 * only ever handles V_BLOCK and V_REDIRECT. */
inline int blockErrno() {
#ifdef NULLROUTE_ENABLED
    return nr_block_errno();
#else
    return EAI_NONAME;
#endif
}

/* Presentation form of a V_REDIRECT address, for explore_numeric(). */
inline bool formatAddr(const Verdict& v, char* buf, size_t buflen) {
    if (v.kind != V_REDIRECT || !buf || buflen < INET6_ADDRSTRLEN) return false;
    return inet_ntop(v.family, v.addr, buf, (socklen_t)buflen) != nullptr;
}

/*
 * Lay a V_REDIRECT answer into the caller-owned hostent + scratch buffer that
 * the gethostbyname path hands us.
 *
 * H2 needs this because `getent hosts` and every legacy gethostbyname() caller
 * reach the resolver here and not through getaddrinfo — without it the
 * idx-probe liveness check would report "not filtering" on a device where the
 * filter is working perfectly.
 *
 * Layout in `buf`, all of it pointer-aligned so a caller that casts
 * h_addr_list[0] to `struct in_addr*` is not doing an unaligned load:
 *
 *     [pad][ char* aliases[1] ][ char* addrs[2] ][ raw address ][ name\0 ]
 *
 * Returns 0 on success (and sets *result), an EAI_* code otherwise. It never
 * writes past buflen and never returns a partially built hostent.
 */
inline int fillHostent(const Verdict& v, const char* name, int af, struct hostent* hp, char* buf,
                       size_t buflen, struct hostent** result) {
    if (v.kind != V_REDIRECT || !name || !hp || !buf || !result) return EAI_FAIL;
    if (af != v.family) return EAI_NODATA;   /* redirect is for the other family */

    const size_t alen = (af == AF_INET6) ? 16u : 4u;
    const size_t nlen = strnlen(name, NR_MAX_NAME);

    const size_t align = sizeof(char*);
    const size_t pad   = (align - ((uintptr_t)buf % align)) % align;
    const size_t need  = pad + sizeof(char*) * 3u + alen + nlen + 1u;
    if (need > buflen) return EAI_MEMORY;

    char*  p       = buf + pad;
    char** aliases = (char**)p;
    p += sizeof(char*);
    char** addrs = (char**)p;
    p += sizeof(char*) * 2u;
    char* addr = p;
    p += alen;
    char* nm = p;

    memcpy(addr, v.addr, alen);
    memcpy(nm, name, nlen);
    nm[nlen] = '\0';
    aliases[0] = nullptr;
    addrs[0]   = addr;
    addrs[1]   = nullptr;

    hp->h_name      = nm;
    hp->h_aliases   = aliases;
    hp->h_addrtype  = af;
    hp->h_length    = (int)alen;
    hp->h_addr_list = addrs;
    *result = hp;
    return 0;
}

}  // namespace nr
#endif /* NULLROUTE_RESOLVER_NR_HOOK_H */
