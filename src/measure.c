// SPDX-License-Identifier: Apache-2.0
/* measure: run every packet of a pcap through the REAL xdp_semfw bytecode
 * with BPF_PROG_TEST_RUN and print one verdict line per packet:
 *     <index>,<xdp_action>,<reason>
 * xdp_action: 1 = XDP_DROP, 2 = XDP_PASS.
 *
 * bench mode: time xdp_semfw and xdp_l3 on each packet with repeat=R and
 * print ns/packet (kernel-reported duration of the program run).
 *
 * Exits non-zero (loudly) if the object cannot be opened, verified or
 * loaded: a silent skip is never reported as a measurement. */
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "common.h"

static int die(const char *m)
{
	fprintf(stderr, "FATAL: %s (errno=%d %s)\n", m, errno, strerror(errno));
	exit(2);
}

static struct bpf_object *load_obj(const char *obj, const char *deny)
{
	struct bpf_object *o = bpf_object__open_file(obj, NULL);
	if (!o || libbpf_get_error(o))
		die("bpf_object__open_file");
	if (bpf_object__load(o))
		die("bpf_object__load (verifier rejected or no privilege)");
	int dfd = bpf_object__find_map_fd_by_name(o, "deny");
	if (dfd < 0)
		die("map deny");
	int n = load_denylist(dfd, deny);
	if (n <= 0)
		die("empty or unreadable denylist");
	fprintf(stderr, "denylist: %d entries\n", n);
	return o;
}

static int prog_fd(struct bpf_object *o, const char *name)
{
	struct bpf_program *p = bpf_object__find_program_by_name(o, name);
	if (!p)
		die(name);
	return bpf_program__fd(p);
}

int main(int argc, char **argv)
{
	if (argc < 5) {
		fprintf(stderr,
			"usage: %s verdicts <fw.bpf.o> <denylist> <corpus.pcap>\n"
			"       %s bench <fw.bpf.o> <denylist> <corpus.pcap> [repeat] [l3_deny_ip...]\n",
			argv[0], argv[0]);
		return 2;
	}
	const char *mode = argv[1];
	struct bpf_object *o = load_obj(argv[2], argv[3]);
	int fw = prog_fd(o, "xdp_semfw");
	int rmap = bpf_object__find_map_fd_by_name(o, "last_reason");
	struct pcap_rd rd;
	if (pcap_open(&rd, argv[4]))
		die("pcap_open");
	static uint8_t pkt[65536];
	int len, idx = 0;

	if (!strcmp(mode, "verdicts")) {
		while ((len = pcap_next(&rd, pkt, sizeof pkt)) > 0) {
			LIBBPF_OPTS(bpf_test_run_opts, t, .data_in = pkt,
				    .data_size_in = (uint32_t)len, .repeat = 1);
			if (bpf_prog_test_run_opts(fw, &t))
				die("bpf_prog_test_run_opts");
			uint32_t z = 0, reason[256] = { 0 };
			/* percpu map: test_run runs on the current CPU; take max */
			bpf_map_lookup_elem(rmap, &z, reason);
			uint32_t r = 0;
			int ncpu = libbpf_num_possible_cpus();
			for (int c = 0; c < ncpu && c < 256; c++)
				if (reason[c] > r)
					r = reason[c];
			uint32_t zero[256] = { 0 };
			bpf_map_update_elem(rmap, &z, zero, BPF_ANY);
			printf("%d,%u,%u\n", idx++, t.retval, r);
		}
		if (len < 0)
			die("pcap read");
		fprintf(stderr, "verdicts: %d packets\n", idx);
		return 0;
	}

	if (!strcmp(mode, "bench")) {
		int repeat = argc > 5 ? atoi(argv[5]) : 10000;
		int l3 = prog_fd(o, "xdp_l3");
		int ipfd = bpf_object__find_map_fd_by_name(o, "deny_ip4");
		uint32_t one = 1;
		for (int i = 6; i < argc; i++) {
			struct in_addr a;
			if (inet_pton(AF_INET, argv[i], &a) == 1)
				bpf_map_update_elem(ipfd, &a.s_addr, &one, BPF_ANY);
		}
		printf("index,len,semfw_ns,l3_ns\n");
		while ((len = pcap_next(&rd, pkt, sizeof pkt)) > 0) {
			LIBBPF_OPTS(bpf_test_run_opts, a, .data_in = pkt,
				    .data_size_in = (uint32_t)len, .repeat = repeat);
			LIBBPF_OPTS(bpf_test_run_opts, b, .data_in = pkt,
				    .data_size_in = (uint32_t)len, .repeat = repeat);
			if (bpf_prog_test_run_opts(fw, &a) || bpf_prog_test_run_opts(l3, &b))
				die("bench test_run");
			printf("%d,%d,%u,%u\n", idx++, len, a.duration, b.duration);
		}
		return 0;
	}
	fprintf(stderr, "unknown mode %s\n", mode);
	return 2;
}
