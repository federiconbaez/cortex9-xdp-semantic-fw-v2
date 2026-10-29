# Data sources (actually downloaded)

| File | Source | Retrieved (ART) | SHA-256 | License |
|------|--------|-----------------|---------|---------|
| `tranco.zip` (not committed; regenerated via `make data`) | https://tranco-list.eu/top-1m.csv.zip (list id ZJ8PG) | 2026-10-29 00:49 ART | 6e26a38784bbf6203ccff8283d22db656fa2e2d96515cbb7df3c9c1b920e4936 | MIT (Tranco) |
| `urlhaus-filter-domains.txt` | https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains.txt | 2026-10-29 00:49 ART | 9d122ac13e2710401b5ed1eb283cf27cf4b195fe321a0bd5bce1752e2db18343 | CC0 + MIT (malware-filter); URLhaus upstream CC0 |
| `denylist.txt` | first 200 of the domain-only subset of the urlhaus-filter file, sorted by sha256, excluding Tranco top-10k collisions | derived | see file | same |
| `legit-domains.txt` | first 5000 Tranco domains that do not collide with the denylist | derived | see file | MIT |

`top-1m.csv` and the zip are NOT committed (large); regenerate with `make data`.
The denylist and legit lists ARE committed so the corpus is reproducible without re-downloading.
