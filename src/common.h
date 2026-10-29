/* SPDX-License-Identifier: Apache-2.0 */
#pragma once
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "../bpf/fw_common.h"

/* Same key as the XDP program: FNV-1a 64 over the reversed lowercase name. */
static inline uint64_t domain_key(const char *d)
{
	size_t n = strlen(d);
	while (n && d[n - 1] == '.')
		n--;
	uint64_t h = FNV_OFFSET;
	for (size_t i = n; i-- > 0;)
		h = (h ^ (uint8_t)fw_lower((unsigned char)d[i])) * FNV_PRIME;
	return h;
}

/* Load a denylist (one domain per line, '#' comments) into map fd. */
static inline int load_denylist(int map_fd, const char *path)
{
	FILE *f = fopen(path, "r");
	if (!f) {
		perror(path);
		return -1;
	}
	char line[512];
	uint32_t id = 0;
	int n = 0;
	while (fgets(line, sizeof line, f)) {
		char *p = line;
		while (*p == ' ' || *p == '\t')
			p++;
		if (*p == '#' || *p == '\n' || *p == 0)
			continue;
		p[strcspn(p, " \t\r\n")] = 0;
		uint64_t k = domain_key(p);
		id++;
		if (bpf_map_update_elem(map_fd, &k, &id, BPF_ANY)) {
			perror("deny map update");
			fclose(f);
			return -1;
		}
		n++;
	}
	fclose(f);
	return n;
}

/* Minimal pcap (LINKTYPE_ETHERNET) reader. */
struct pcap_rd {
	FILE *f;
	int swap;
};

static inline int pcap_open(struct pcap_rd *r, const char *path)
{
	uint32_t gh[6];
	r->f = fopen(path, "rb");
	if (!r->f) {
		perror(path);
		return -1;
	}
	if (fread(gh, 4, 6, r->f) != 6)
		return -1;
	if (gh[0] == 0xa1b2c3d4)
		r->swap = 0;
	else if (gh[0] == 0xd4c3b2a1)
		r->swap = 1;
	else {
		fprintf(stderr, "%s: not a pcap\n", path);
		return -1;
	}
	return 0;
}

static inline uint32_t sw32(uint32_t v, int s)
{
	return s ? __builtin_bswap32(v) : v;
}

/* returns captured length, 0 on EOF, -1 on error */
static inline int pcap_next(struct pcap_rd *r, uint8_t *buf, size_t cap)
{
	uint32_t rh[4];
	size_t got = fread(rh, 4, 4, r->f);
	if (got == 0)
		return 0;
	if (got != 4)
		return -1;
	uint32_t incl = sw32(rh[2], r->swap);
	if (incl > cap)
		return -1;
	if (fread(buf, 1, incl, r->f) != incl)
		return -1;
	return (int)incl;
}
