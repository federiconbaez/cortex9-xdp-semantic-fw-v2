/* SPDX-License-Identifier: Apache-2.0 */
/* Shared between the XDP program and userspace (loader, measure).
 *
 * Denylist key = FNV-1a 64 over the lowercase domain read RIGHT-TO-LEFT
 * (reversed bytes). Scanning a name from its last byte to its first and
 * looking up the running hash every time we reach a '.' (or the start)
 * yields the key of every label-aligned suffix in ONE pass: "a.evil.com"
 * probes "com", "evil.com", "a.evil.com". Matching is therefore exact on
 * label boundaries, so "notevil.com" never matches a rule for "evil.com"
 * (the substring false positive that sank the first version). */
#pragma once

#define SCRATCH      2048u  /* bytes of L4 payload inspected (power of 2) */
#define SCRATCH_MASK (SCRATCH - 1u)
#define NAME_MAX_LEN 256u   /* RFC 1035 name limit is 255 */
#define NAME_MASK    (NAME_MAX_LEN - 1u)

#define FNV_OFFSET 0xcbf29ce484222325ULL
#define FNV_PRIME  0x100000001b3ULL

/* Pre-registered DNS tunnelling heuristic (docs/PREREGISTRO.md).
 * Fixed BEFORE generating or measuring the corpus; never tuned after. */
#define TUN_LABEL 50u   /* any single label >= 50 bytes            */
#define TUN_TOTAL 150u  /* or the whole QNAME >= 150 bytes         */

enum verdict_reason {
	R_PASS = 0,
	R_DENY_DNS = 1,
	R_DENY_SNI = 2,
	R_DENY_HOST = 3,
	R_TUNNEL = 4,
};

enum stat_idx {
	S_PKTS = 0,
	S_DNS,
	S_TLS,
	S_HTTP,
	S_DROP_DNS,
	S_DROP_SNI,
	S_DROP_HOST,
	S_DROP_TUNNEL,
	S_TRUNC,     /* name/extension continued past inspected bytes */
	S_MALFORMED, /* parsed protocol but structure invalid -> PASS */
	S_FRAG,      /* IP fragment -> PASS (not reassembled)         */
	S_MAX,
};

static inline unsigned char fw_lower(unsigned char c)
{
	return (c >= 'A' && c <= 'Z') ? (unsigned char)(c + 32) : c;
}
