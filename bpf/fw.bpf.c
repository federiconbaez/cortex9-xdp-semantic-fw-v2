// SPDX-License-Identifier: Apache-2.0
/* cortex9-xdp-semantic-fw-v2: XDP program that parses the DNS QNAME
 * (UDP/53), the TLS ClientHello SNI (TCP/443) and the HTTP/1.x Host
 * header (TCP/80) at their REAL offsets and drops packets whose name
 * falls under a denylisted domain, plus a pre-registered DNS
 * tunnelling heuristic.
 *
 * Fixes against v1 (cortex9-xdp-semantic-firewall):
 *  - no fixed 192-byte window: the L4 payload (up to SCRATCH bytes) is
 *    copied with bpf_xdp_load_bytes() and parsed by bpf_loop() callbacks,
 *    so a Host header after 263+ bytes of real headers is still found;
 *  - no free-text keyword matching: only structured names are matched,
 *    and only on label boundaries (see fw_common.h), which is what keeps
 *    the false-positive rate bounded.
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "fw_common.h"

char _license[] SEC("license") = "GPL";

/* All loop state lives in the per-CPU map value, NOT on the stack: the
 * verifier does not track map-value contents precisely, so bpf_loop()
 * callback states converge after one pass instead of exploding. */
struct loopst {
	/* generic cursor */
	__u32 pos, n, end, len, off;
	/* dns */
	__u32 left, nlen, maxlab;
	/* results / flags */
	__u32 done, bad, trunc, found, eoh, state, start, hit;
	__u64 h;
};

struct scratch {
	__u8 pkt[SCRATCH];
	__u8 name[NAME_MAX_LEN];
	struct loopst st;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct scratch);
} scratch_map SEC(".maps");

/* key: reversed-FNV of a denylisted domain; value: rule id */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1 << 18);
	__type(key, __u64);
	__type(value, __u32);
} deny SEC(".maps");

/* L3 baseline: IPv4 source address blocklist */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1 << 16);
	__type(key, __u32);
	__type(value, __u32);
} deny_ip4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, S_MAX);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

/* last verdict reason, read by the measurement runner */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} last_reason SEC(".maps");

static __always_inline void stat_inc(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&stats, &idx);
	if (v)
		*v += 1;
}

static __always_inline void set_reason(__u32 r)
{
	__u32 z = 0;
	__u32 *v = bpf_map_lookup_elem(&last_reason, &z);
	if (v)
		*v = r;
}

static __always_inline struct scratch *get_scratch(void)
{
	__u32 z = 0;
	return bpf_map_lookup_elem(&scratch_map, &z);
}

static __always_inline __u32 rd8(const struct scratch *s, __u32 off)
{
	return s->pkt[off & SCRATCH_MASK];
}

static __always_inline __u32 rd16(const struct scratch *s, __u32 off)
{
	return (rd8(s, off) << 8) | rd8(s, off + 1);
}

/* ---------- suffix match: one right-to-left pass ---------- */
static long match_cb(__u64 i, void *unused)
{
	struct scratch *s = get_scratch();
	if (!s)
		return 1;
	struct loopst *st = &s->st;
	if (i >= st->nlen)
		return 1;
	__u32 j = st->nlen - 1 - (__u32)i;
	__u8 c = s->name[j & NAME_MASK];
	if (c == '.') {
		__u64 k = st->h;
		if (bpf_map_lookup_elem(&deny, &k)) {
			st->hit = 1;
			return 1;
		}
	}
	st->h = (st->h ^ c) * FNV_PRIME;
	return 0;
}

static __always_inline int name_denied(struct scratch *s, __u32 nlen)
{
	if (nlen == 0 || nlen > NAME_MAX_LEN)
		return 0;
	s->st.nlen = nlen;
	s->st.h = FNV_OFFSET;
	s->st.hit = 0;
	bpf_loop(NAME_MAX_LEN, match_cb, NULL, 0);
	if (s->st.hit)
		return 1;
	__u64 k = s->st.h;
	return bpf_map_lookup_elem(&deny, &k) != 0;
}

/* ---------- copy a name from pkt[off..off+len) lowercased ---------- */
static long copy_cb(__u64 i, void *unused)
{
	struct scratch *s = get_scratch();
	if (!s)
		return 1;
	struct loopst *st = &s->st;
	if (i >= st->len)
		return 1;
	__u32 p = st->off + (__u32)i;
	if (p >= st->n) {
		st->trunc = 1;
		return 1;
	}
	s->name[i & NAME_MASK] = fw_lower(s->pkt[p & SCRATCH_MASK]);
	return 0;
}

/* returns name length (0 on failure); strips one trailing dot; sets st.trunc */
static __always_inline __u32 copy_name(struct scratch *s, __u32 off, __u32 len, __u32 n)
{
	s->st.trunc = 0;
	if (len == 0 || len >= NAME_MAX_LEN)
		return 0;
	s->st.off = off;
	s->st.len = len;
	s->st.n = n;
	bpf_loop(NAME_MAX_LEN, copy_cb, NULL, 0);
	if (s->st.trunc)
		return 0;
	if (s->name[(len - 1) & NAME_MASK] == '.')
		len--;
	return len;
}

/* ---------- DNS QNAME ---------- */
static long dns_cb(__u64 i, void *unused)
{
	struct scratch *s = get_scratch();
	if (!s)
		return 1;
	struct loopst *d = &s->st;
	if (d->pos >= d->n) {
		d->trunc = 1;
		return 1;
	}
	__u8 c = s->pkt[d->pos & SCRATCH_MASK];
	d->pos++;
	if (d->left == 0) {
		if (c == 0) {
			d->done = 1;
			return 1;
		}
		if (c > 63) { /* compression pointer / reserved: not in a query */
			d->bad = 1;
			return 1;
		}
		if (d->nlen > 0) {
			if (d->nlen >= NAME_MAX_LEN - 1) {
				d->bad = 1;
				return 1;
			}
			s->name[d->nlen & NAME_MASK] = '.';
			d->nlen++;
		}
		d->left = c;
		if (c > d->maxlab)
			d->maxlab = c;
		return 0;
	}
	if (d->nlen >= NAME_MAX_LEN - 1) {
		d->bad = 1;
		return 1;
	}
	s->name[d->nlen & NAME_MASK] = fw_lower(c);
	d->nlen++;
	d->left--;
	return 0;
}

static __always_inline int check_dns(struct scratch *s, __u32 n)
{
	if (n < 17)
		return R_PASS;
	/* header: QR must be 0 (query), opcode 0, QDCOUNT >= 1 */
	if (rd8(s, 2) & 0xF8)
		return R_PASS;
	if (rd16(s, 4) == 0)
		return R_PASS;
	stat_inc(S_DNS);
	struct loopst *d = &s->st;
	d->pos = 12;
	d->n = n;
	d->left = 0;
	d->nlen = 0;
	d->maxlab = 0;
	d->done = 0;
	d->bad = 0;
	d->trunc = 0;
	bpf_loop(NAME_MAX_LEN + 64, dns_cb, NULL, 0);
	if (d->bad || !d->done) {
		stat_inc(d->trunc ? S_TRUNC : S_MALFORMED);
		return R_PASS;
	}
	__u32 nlen = d->nlen, maxlab = d->maxlab;
	if (name_denied(s, nlen))
		return R_DENY_DNS;
	if (maxlab >= TUN_LABEL || nlen >= TUN_TOTAL)
		return R_TUNNEL;
	return R_PASS;
}

/* ---------- TLS ClientHello SNI ---------- */
static long ext_cb(__u64 i, void *unused)
{
	struct scratch *s = get_scratch();
	if (!s)
		return 1;
	struct loopst *e = &s->st;
	if (e->pos + 4 > e->end)
		return 1; /* no more extensions */
	if (e->pos + 4 > e->n) {
		e->trunc = 1;
		return 1;
	}
	__u32 type = rd16(s, e->pos);
	__u32 len = rd16(s, e->pos + 2);
	if (type == 0) { /* server_name: list_len(2) type(1) name_len(2) name */
		if (e->pos + 9 > e->n) {
			e->trunc = 1;
			return 1;
		}
		if (rd8(s, e->pos + 6) != 0) /* not host_name */
			return 1;
		e->len = rd16(s, e->pos + 7);
		e->off = e->pos + 9;
		e->found = 1;
		return 1;
	}
	e->pos += 4 + len;
	return 0;
}

static __always_inline int check_tls(struct scratch *s, __u32 n)
{
	if (n < 44 || rd8(s, 0) != 0x16 || rd8(s, 1) != 0x03 || rd8(s, 5) != 0x01)
		return R_PASS;
	stat_inc(S_TLS);
	__u32 pos = 43;
	pos += 1 + rd8(s, pos);                    /* session id    */
	if (pos + 2 > n)
		goto trunc;
	pos += 2 + rd16(s, pos);                   /* cipher suites */
	if (pos + 1 > n)
		goto trunc;
	pos += 1 + rd8(s, pos);                    /* compression   */
	if (pos + 2 > n)
		goto trunc;
	struct loopst *e = &s->st;
	e->end = pos + 2 + rd16(s, pos);
	e->pos = pos + 2;
	e->n = n;
	e->trunc = 0;
	e->found = 0;
	bpf_loop(64, ext_cb, NULL, 0);
	if (e->trunc)
		goto trunc;
	if (!e->found)
		return R_PASS;
	__u32 off = e->off, len = e->len;
	__u32 nlen = copy_name(s, off, len, n);
	if (s->st.trunc)
		goto trunc;
	if (name_denied(s, nlen))
		return R_DENY_SNI;
	return R_PASS;
trunc:
	stat_inc(S_TRUNC);
	return R_PASS;
}

/* ---------- HTTP/1.x Host ---------- */
static long host_cb(__u64 i, void *unused)
{
	struct scratch *s = get_scratch();
	if (!s)
		return 1;
	struct loopst *h = &s->st;
	__u32 p = (__u32)i;
	if (p + 6 >= h->n)
		return 1;
	if (s->pkt[p & SCRATCH_MASK] != '\n')
		return 0;
	__u8 c1 = s->pkt[(p + 1) & SCRATCH_MASK];
	if (c1 == '\r' || c1 == '\n') { /* end of headers */
		h->eoh = 1;
		return 1;
	}
	if (fw_lower(c1) == 'h' &&
	    fw_lower(s->pkt[(p + 2) & SCRATCH_MASK]) == 'o' &&
	    fw_lower(s->pkt[(p + 3) & SCRATCH_MASK]) == 's' &&
	    fw_lower(s->pkt[(p + 4) & SCRATCH_MASK]) == 't' &&
	    s->pkt[(p + 5) & SCRATCH_MASK] == ':') {
		h->found = 1;
		h->pos = p + 6;
		return 1;
	}
	return 0;
}

static long hval_cb(__u64 i, void *unused)
{
	struct scratch *s = get_scratch();
	if (!s)
		return 1;
	struct loopst *v = &s->st;
	if (v->pos >= v->n) {
		v->trunc = 1;
		return 1;
	}
	__u8 c = s->pkt[v->pos & SCRATCH_MASK];
	if (v->state == 0) { /* skip optional whitespace */
		if (c == ' ' || c == '\t') {
			v->pos++;
			return 0;
		}
		v->state = 1;
		v->start = v->pos;
	}
	if (c == ':' || c == '\r' || c == '\n' || c == ' ' || c == '\t') {
		v->state = 2;
		return 1;
	}
	v->len++;
	v->pos++;
	return 0;
}

static __always_inline int is_http_method(struct scratch *s)
{
	__u32 w = (rd8(s, 0) << 24) | (rd8(s, 1) << 16) | (rd8(s, 2) << 8) | rd8(s, 3);
	return w == 0x47455420 /* "GET " */ || w == 0x504f5354 /* POST */ ||
	       w == 0x50555420 /* "PUT " */ || w == 0x48454144 /* HEAD */ ||
	       w == 0x44454c45 /* DELE */ || w == 0x4f505449 /* OPTI */ ||
	       w == 0x50415443 /* PATC */;
}

static __always_inline int check_http(struct scratch *s, __u32 n)
{
	if (n < 16 || !is_http_method(s))
		return R_PASS;
	stat_inc(S_HTTP);
	struct loopst *h = &s->st;
	h->n = n;
	h->found = 0;
	h->eoh = 0;
	bpf_loop(SCRATCH, host_cb, NULL, 0);
	if (!h->found) {
		if (!h->eoh)
			stat_inc(S_TRUNC);
		return R_PASS;
	}
	/* h->pos already points at the value; reuse the cursor */
	h->state = 0;
	h->len = 0;
	h->start = 0;
	h->trunc = 0;
	bpf_loop(NAME_MAX_LEN + 16, hval_cb, NULL, 0);
	if (h->state != 2 || h->len == 0) {
		stat_inc(h->trunc ? S_TRUNC : S_MALFORMED);
		return R_PASS;
	}
	__u32 start = h->start, len = h->len;
	if (rd8(s, start) == '[') /* IPv6 literal */
		return R_PASS;
	__u32 nlen = copy_name(s, start, len, n);
	if (name_denied(s, nlen))
		return R_DENY_HOST;
	return R_PASS;
}

/* ---------- L2/L3/L4 ---------- */
struct l4info {
	__u32 proto, payoff, dport;
	__u32 saddr4;
};

static __always_inline int parse_l4(struct xdp_md *ctx, struct l4info *li)
{
	void *data = (void *)(long)ctx->data;
	void *end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > end)
		return -1;
	__u32 off = sizeof(*eth);
	__u16 proto = eth->h_proto;
	if (proto == bpf_htons(ETH_P_8021Q)) {
		if (data + off + 4 > end)
			return -1;
		proto = *(__u16 *)(data + off + 2);
		off += 4;
	}
	if (proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = data + off;
		if ((void *)(ip + 1) > end)
			return -1;
		if (ip->ihl < 5)
			return -1;
		if (ip->frag_off & bpf_htons(0x3FFF)) {
			stat_inc(S_FRAG);
			return -1;
		}
		li->proto = ip->protocol;
		li->saddr4 = ip->saddr;
		off += ip->ihl * 4;
	} else if (proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = data + off;
		if ((void *)(ip6 + 1) > end)
			return -1;
		li->proto = ip6->nexthdr; /* extension headers: not parsed -> PASS */
		off += sizeof(*ip6);
	} else {
		return -1;
	}
	off &= 0xffff;
	if (li->proto == IPPROTO_UDP) {
		struct udphdr *u = data + off;
		if ((void *)(u + 1) > end)
			return -1;
		li->dport = bpf_ntohs(u->dest);
		li->payoff = off + sizeof(*u);
	} else if (li->proto == IPPROTO_TCP) {
		struct tcphdr *t = data + off;
		if ((void *)(t + 1) > end)
			return -1;
		if (t->doff < 5)
			return -1;
		li->dport = bpf_ntohs(t->dest);
		li->payoff = off + t->doff * 4;
	} else {
		return -1;
	}
	return 0;
}

SEC("xdp")
int xdp_semfw(struct xdp_md *ctx)
{
	stat_inc(S_PKTS);
	set_reason(R_PASS);
	struct l4info li = {};
	if (parse_l4(ctx, &li) < 0)
		return XDP_PASS;
	int kind;
	if (li.proto == IPPROTO_UDP && li.dport == 53)
		kind = 1;
	else if (li.proto == IPPROTO_TCP && li.dport == 443)
		kind = 2;
	else if (li.proto == IPPROTO_TCP && li.dport == 80)
		kind = 3;
	else
		return XDP_PASS;

	__u32 plen = (__u32)(ctx->data_end - ctx->data);
	if (li.payoff >= plen)
		return XDP_PASS;
	__u32 n = plen - li.payoff;
	if (n > SCRATCH)
		n = SCRATCH;
	if (n < 1)
		return XDP_PASS;
	/* make [1, SCRATCH] provable to the verifier (identity for valid n) */
	n -= 1;
	asm volatile("" : "+r"(n));
	n &= SCRATCH_MASK;
	n += 1;
	struct scratch *s = get_scratch();
	if (!s)
		return XDP_PASS;
	if (bpf_xdp_load_bytes(ctx, li.payoff, s->pkt, n) < 0)
		return XDP_PASS;

	int r;
	if (kind == 1)
		r = check_dns(s, n);
	else if (kind == 2)
		r = check_tls(s, n);
	else
		r = check_http(s, n);

	set_reason(r);
	switch (r) {
	case R_DENY_DNS: stat_inc(S_DROP_DNS); return XDP_DROP;
	case R_DENY_SNI: stat_inc(S_DROP_SNI); return XDP_DROP;
	case R_DENY_HOST: stat_inc(S_DROP_HOST); return XDP_DROP;
	case R_TUNNEL: stat_inc(S_DROP_TUNNEL); return XDP_DROP;
	}
	return XDP_PASS;
}

/* L3 baseline for the throughput ratio: drop by IPv4 source address. */
SEC("xdp")
int xdp_l3(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > end)
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > end)
		return XDP_PASS;
	__u32 k = ip->saddr;
	if (bpf_map_lookup_elem(&deny_ip4, &k))
		return XDP_DROP;
	return XDP_PASS;
}
