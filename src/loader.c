// SPDX-License-Identifier: Apache-2.0
/* Attach xdp_semfw to an interface. Default: XDP_FLAGS_SKB_MODE
 * (xdpgeneric). --native requests DRV mode. Exits non-zero if load or
 * attach fails — never a silent skip. With --once, attach, print OK and
 * detach immediately (for CI smoke). */
#include <errno.h>
#include <net/if.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/if_link.h>
#include "common.h"

static volatile sig_atomic_t stop;
static void on_sig(int s) { (void)s; stop = 1; }

static int die(const char *m)
{
	fprintf(stderr, "FATAL: %s (errno=%d %s)\n", m, errno, strerror(errno));
	return 2;
}

int main(int argc, char **argv)
{
	int native = 0, once = 0, argi = 1;
	while (argi < argc && argv[argi][0] == '-') {
		if (!strcmp(argv[argi], "--native"))
			native = 1;
		else if (!strcmp(argv[argi], "--once"))
			once = 1;
		else {
			fprintf(stderr, "unknown flag %s\n", argv[argi]);
			return 2;
		}
		argi++;
	}
	if (argc - argi != 3) {
		fprintf(stderr,
			"usage: %s [--native] [--once] <fw.bpf.o> <denylist> <iface>\n",
			argv[0]);
		return 2;
	}
	const char *obj = argv[argi], *deny = argv[argi + 1], *iface = argv[argi + 2];
	unsigned ifindex = if_nametoindex(iface);
	if (!ifindex)
		return die("if_nametoindex");

	struct bpf_object *o = bpf_object__open_file(obj, NULL);
	if (!o || libbpf_get_error(o))
		return die("bpf_object__open_file");
	if (bpf_object__load(o))
		return die("bpf_object__load");
	int dfd = bpf_object__find_map_fd_by_name(o, "deny");
	if (dfd < 0)
		return die("map deny");
	int n = load_denylist(dfd, deny);
	if (n <= 0)
		return die("empty denylist");
	fprintf(stderr, "denylist: %d entries\n", n);

	struct bpf_program *p = bpf_object__find_program_by_name(o, "xdp_semfw");
	if (!p)
		return die("prog xdp_semfw");
	int flags = native ? XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;
	if (bpf_xdp_attach(ifindex, bpf_program__fd(p), flags, NULL))
		return die(native ? "attach native" : "attach xdpgeneric");
	fprintf(stderr, "OK attached xdp_semfw on %s (%s)\n", iface,
		native ? "native" : "xdpgeneric");
	if (once) {
		bpf_xdp_detach(ifindex, flags, NULL);
		return 0;
	}
	signal(SIGINT, on_sig);
	signal(SIGTERM, on_sig);
	while (!stop)
		pause();
	bpf_xdp_detach(ifindex, flags, NULL);
	fprintf(stderr, "detached\n");
	return 0;
}
