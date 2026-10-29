# SPDX-License-Identifier: Apache-2.0
CLANG ?= clang
CC    ?= gcc
CFLAGS = -O2 -Wall -Wextra -Ibpf -Isrc
BPF_CFLAGS = -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu -Ibpf -Wall

.PHONY: all clean data corpus measure baseline test ci-xdp

all: bin/measure bin/loader bin/pcap_send bpf/fw.bpf.o

bin:
	mkdir -p bin

bpf/fw.bpf.o: bpf/fw.bpf.c bpf/fw_common.h
	$(CLANG) $(BPF_CFLAGS) -c bpf/fw.bpf.c -o bpf/fw.bpf.o

bin/measure: src/measure.c src/common.h bpf/fw_common.h | bin
	$(CC) $(CFLAGS) -o $@ src/measure.c -lbpf -lelf -lz

bin/loader: src/loader.c src/common.h bpf/fw_common.h | bin
	$(CC) $(CFLAGS) -o $@ src/loader.c -lbpf -lelf -lz

bin/pcap_send: src/pcap_send.c src/common.h bpf/fw_common.h | bin
	$(CC) $(CFLAGS) -o $@ src/pcap_send.c -lbpf -lelf -lz

data:
	@mkdir -p data
	@echo "re-download Tranco + urlhaus-filter (see data/SOURCES.md)"
	curl -fsSL -o data/tranco.zip https://tranco-list.eu/top-1m.csv.zip
	curl -fsSL -o data/urlhaus-filter-domains.txt \
	  https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains.txt

corpus: data/denylist.txt data/legit-domains.txt
	python3 harness/gen_corpus.py

# Authoritative measurement: real bytecode via BPF_PROG_TEST_RUN.
measure: all
	@mkdir -p results
	sudo -E ./bin/measure verdicts bpf/fw.bpf.o data/denylist.txt corpus/corpus.pcap \
	  > results/verdicts.csv
	python3 harness/baseline_string.py --pcap corpus/corpus.pcap --deny data/denylist.txt \
	  -o results/baseline.csv
	python3 harness/eval.py results/verdicts.csv --baseline results/baseline.csv \
	  --out results/summary.json; echo "eval_exit=$$?"

baseline: corpus
	python3 harness/baseline_string.py --pcap corpus/corpus.pcap --deny data/denylist.txt \
	  -o results/baseline.csv

# CI / local: load+attach must succeed or the job FAILS.
ci-xdp: all
	@set -e; \
	ip link add c9ci0 type veth peer name c9ci1; \
	ip link set c9ci0 up; ip link set c9ci1 up; \
	./bin/loader --once bpf/fw.bpf.o data/denylist.txt c9ci0; \
	ip link del c9ci0; \
	echo "ci-xdp: attach OK"

test: all
	python3 harness/test_unit.py

clean:
	rm -rf bin bpf/fw.bpf.o results/verdicts.csv results/baseline.csv
