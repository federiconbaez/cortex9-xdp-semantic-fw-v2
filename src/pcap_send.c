// SPDX-License-Identifier: Apache-2.0
/* Blast every frame of a pcap out a raw AF_PACKET socket. */
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "common.h"

int main(int argc, char **argv)
{
	if (argc != 3) {
		fprintf(stderr, "usage: %s <corpus.pcap> <iface>\n", argv[0]);
		return 2;
	}
	unsigned ifi = if_nametoindex(argv[2]);
	if (!ifi) {
		perror("if_nametoindex");
		return 2;
	}
	int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (s < 0) {
		perror("socket");
		return 2;
	}
	struct sockaddr_ll ll = { .sll_family = AF_PACKET,
				  .sll_protocol = htons(ETH_P_ALL),
				  .sll_ifindex = (int)ifi };
	if (bind(s, (void *)&ll, sizeof ll)) {
		perror("bind");
		return 2;
	}
	struct pcap_rd rd;
	if (pcap_open(&rd, argv[1]))
		return 2;
	static unsigned char pkt[65536];
	int len, n = 0;
	while ((len = pcap_next(&rd, pkt, sizeof pkt)) > 0) {
		if (send(s, pkt, (size_t)len, 0) < 0) {
			perror("send");
			return 2;
		}
		n++;
	}
	fprintf(stderr, "sent %d frames on %s\n", n, argv[2]);
	return 0;
}
