# Scorecard

routez against the best of nginx and HAProxy on every metric measured, worst first. 41 losses, 6 ties, 76 wins.

Runs read:

- h3: `bench-h3-full` (routez 859f04d-dirty, 2026-09-20T17:04Z)
- hostile: `bench-host3` (routez eda4756-dirty, 2026-09-20T17:50Z)
- http: `bench-smoke-2` (routez 0e5c6a4-dirty, 2026-09-20T16:22Z)
- l4: `bench-l4-full` (routez fdc1eb6-dirty, 2026-09-20T17:20Z)
- soak: `bench-soak` (routez 53d2011, 2026-09-20T17:55Z)

`ratio` is how many times better routez is, so below 1 is a loss; a figure that can be negative is compared by direction instead. A TIE is a metric whose min–max ranges across rounds overlap: the difference is inside the noise.

| | Suite | Row | Params | Metric | routez | best other | | ratio |
|---|---|---|---|---|---|---|---|---|
| LOSS | hostile | handshake-rsa | conns=256, workers=3 | CPU ms/1k req | 4,455.00 ms | 870.00 ms | nginx | 0.20× |
| LOSS | hostile | handshake-rsa | conns=256, workers=3 | handshakes/s | 0.7k | 3.2k | nginx | 0.20× |
| LOSS | hostile | idle | conns=256, workers=3 | KB/conn | 2.0 KB | 0.5 KB | nginx | 0.26× |
| LOSS | h3 | h3-static-1m | conns=64, workers=3 | req/s | 0.8k | 2.8k | nginx | 0.27×† |
| LOSS | h3 | h3-static-1m | conns=64, workers=3 | CPU ms/1k req | 3,822.16 ms | 1,058.04 ms | nginx | 0.28×† |
| LOSS | l4 | tcp-bulk | conns=256, workers=3 | CPU ms/1k req | 604.94 ms | 171.95 ms | HAProxy | 0.28×† |
| LOSS | h3 | h3-static | conns=64, workers=3 | req/s | 77k | 232k | nginx | 0.33× |
| LOSS | h3 | h3-static | conns=64, workers=3 | CPU ms/1k req | 38.70 ms | 12.87 ms | nginx | 0.33× |
| LOSS | h3 | h3-return | conns=64, workers=3 | req/s | 34k | 80k | nginx | 0.42× |
| LOSS | http | fileset | conns=256, workers=3 | req/s | 94k | 213k | nginx | 0.44× |
| LOSS | h3 | h3-proxy | conns=64, workers=3 | req/s | 91k | 200k | HAProxy | 0.45× |
| LOSS | http | fileset | conns=256, workers=3 | CPU ms/1k req | 29.86 ms | 14.30 ms | nginx | 0.48× |
| LOSS | h3 | h3-proxy | conns=64, workers=3 | CPU ms/1k req | 30.80 ms | 14.91 ms | HAProxy | 0.48× |
| LOSS | hostile | storm | conns=256, workers=3 | throughput kept | 27% | 54% | HAProxy | 0.50× |
| LOSS | hostile | handshake-ecdsa | conns=256, workers=3 | CPU ms/1k req | 565.00 ms | 291.67 ms | nginx | 0.52× |
| LOSS | l4 | tcp-bulk | conns=256, workers=3 | p50 | 49.47 ms | 25.92 ms | HAProxy | 0.52×† |
| LOSS | h3 | h3-return-m10 | conns=64, workers=3 | CPU ms/1k req | 6.16 ms | 3.30 ms | nginx | 0.54× |
| LOSS | h3 | h3-return-m10 | conns=64, workers=3 | req/s | 475k | 867k | nginx | 0.55× |
| LOSS | l4 | tcp-bulk | conns=256, workers=3 | req/s | 4.9k | 8.7k | HAProxy | 0.57×† |
| LOSS | hostile | handshake-ecdsa | conns=256, workers=3 | handshakes/s | 4.8k | 8.2k | nginx | 0.58× |
| LOSS | http | gzip | conns=256, workers=3 | CPU ms/1k req | 736.61 ms | 505.44 ms | nginx | 0.69×† |
| LOSS | http | gzip | conns=256, workers=3 | req/s | 4.1k | 6.0k | nginx | 0.69×† |
| LOSS | l4 | tcp-conn | conns=256, workers=3 | req/s | 63k | 88k | nginx | 0.72× |
| LOSS | l4 | tcp-conn | conns=256, workers=3 | CPU ms/1k req | 47.26 ms | 33.95 ms | nginx | 0.72× |
| LOSS | l4 | tcp-conn | conns=256, workers=3 | p99 | 10.95 ms | 7.87 ms | nginx | 0.72× |
| LOSS | h3 | h3-return | conns=64, workers=3 | CPU ms/1k req | 22.83 ms | 16.56 ms | nginx | 0.73× |
| LOSS | hostile | failover | conns=256, workers=3 | max | 39.10 ms | 28.44 ms | HAProxy | 0.73× |
| LOSS | l4 | tcp-conn | conns=256, workers=3 | p50 | 3.63 ms | 2.64 ms | nginx | 0.73× |
| LOSS | hostile | storm | conns=256, workers=3 | CPU ms/1k req | 15.82 ms | 11.74 ms | nginx | 0.74× |
| LOSS | hostile | reload | conns=256, workers=3 | max | 18.94 ms | 14.42 ms | nginx | 0.76× |
| LOSS | hostile | storm | conns=256, workers=3 | req/s | 187k | 235k | nginx | 0.80× |
| LOSS | http | static-1m | conns=256, workers=3 | CPU ms/1k req | 86.30 ms | 76.67 ms | nginx | 0.89× |
| LOSS | http | static-1m | conns=256, workers=3 | req/s | 35k | 38k | nginx | 0.90× |
| LOSS | http | static-100k | conns=256, workers=3 | req/s | 174k | 191k | nginx | 0.91× |
| LOSS | http | static-100k | conns=256, workers=3 | CPU ms/1k req | 17.21 ms | 15.72 ms | nginx | 0.91× |
| LOSS | http | static-100m | conns=256, workers=3 | req/s | 0.3k | 0.3k | nginx | 0.92× |
| LOSS | http | static | conns=256, workers=3 | req/s | 303k | 317k | nginx | 0.96× |
| LOSS | http | static | conns=256, workers=3 | CPU ms/1k req | 9.91 ms | 9.48 ms | nginx | 0.96× |
| LOSS | hostile | idle | conns=256, workers=3 | throughput kept | 100% | 101% | HAProxy | 0.99× |
| LOSS | hostile | reload | conns=256, workers=3 | errors | 765 | 0 | HAProxy | by direction |
| LOSS | soak | mixed | minutes=2, workers=3 | RSS growth | 6.7 KB/min | -352.3 KB/min | HAProxy | by direction |
| TIE | l4 | udp-flows | conns=256, workers=3 | p50 | 0.42 ms | 0.42 ms | nginx | 1.00× |
| TIE | l4 | udp-flows | conns=256, workers=3 | p99 | 4.61 ms | 4.61 ms | nginx | 1.00× |
| TIE | l4 | udp-rtt | conns=256, workers=3 | p99 | 1.54 ms | 1.54 ms | nginx | 1.00× |
| TIE | l4 | udp-rtt | conns=256, workers=3 | packets/s | 20k | 20k | nginx | 1.00× |
| TIE | l4 | udp-flood | conns=256, workers=3 | p99 | 0.18 ms | 0.19 ms | nginx | 1.09× |
| TIE | l4 | udp-flows | conns=256, workers=3 | CPU ms/1k req | 93.77 ms | 108.04 ms | nginx | 1.15× |
| WIN | soak | mixed | minutes=2, workers=3 | fd drift | -897 | -487 | HAProxy | by direction |
| WIN | l4 | udp-flows | conns=256, workers=3 | packets/s | 0.3k | 0.3k | nginx | 1.01× |
| WIN | l4 | tcp-small | conns=256, workers=3 | req/s | 351k | 345k | nginx | 1.02×† |
| WIN | http | not-modified | conns=256, workers=3 | CPU ms/1k req | 6.32 ms | 6.43 ms | nginx | 1.02× |
| WIN | http | not-modified | conns=256, workers=3 | req/s | 476k | 466k | nginx | 1.02× |
| WIN | l4 | udp-flood | conns=256, workers=3 | packets/s | 15k | 15k | nginx | 1.03× |
| WIN | l4 | tcp-small | conns=256, workers=3 | p50 | 0.69 ms | 0.71 ms | nginx | 1.03×† |
| WIN | l4 | tcp-small | conns=256, workers=3 | CPU ms/1k req | 8.33 ms | 8.62 ms | nginx | 1.03×† |
| WIN | http | bigheaders | conns=256, workers=3 | CPU ms/1k req | 9.78 ms | 10.15 ms | HAProxy | 1.04× |
| WIN | http | bigheaders | conns=256, workers=3 | req/s | 308k | 295k | HAProxy | 1.04× |
| WIN | hostile | slowhead | conns=256, workers=3 | throughput kept | 104% | 99% | HAProxy | 1.05× |
| WIN | l4 | udp-rtt | conns=256, workers=3 | p50 | 0.12 ms | 0.13 ms | nginx | 1.07× |
| WIN | http | static-100m | conns=256, workers=3 | CPU ms/1k req | 5,958.97 ms | 6,403.01 ms | nginx | 1.07× |
| WIN | l4 | udp-flood | conns=256, workers=3 | p50 | 0.10 ms | 0.11 ms | nginx | 1.08× |
| WIN | l4 | tcp-small | conns=256, workers=3 | p99 | 1.10 ms | 1.19 ms | nginx | 1.08×† |
| WIN | http | static-1k | conns=256, workers=3 | CPU ms/1k req | 8.22 ms | 8.99 ms | nginx | 1.09× |
| WIN | http | static-1k | conns=256, workers=3 | req/s | 365k | 334k | nginx | 1.09× |
| WIN | http | precompressed | conns=256, workers=3 | req/s | 349k | 316k | nginx | 1.10× |
| WIN | http | precompressed | conns=256, workers=3 | CPU ms/1k req | 8.58 ms | 9.48 ms | nginx | 1.10× |
| WIN | hostile | idle | conns=256, workers=3 | CPU ms/1k req | 4.48 ms | 5.26 ms | nginx | 1.17× |
| WIN | http | return | conns=256, workers=3 | req/s | 651k | 534k | nginx | 1.22× |
| WIN | http | return | conns=256, workers=3 | CPU ms/1k req | 4.60 ms | 5.62 ms | nginx | 1.22× |
| WIN | hostile | reload | conns=256, workers=3 | CPU ms/1k req | 4.18 ms | 5.17 ms | nginx | 1.24× |
| WIN | hostile | slowhead | conns=256, workers=3 | CPU ms/1k req | 4.29 ms | 5.37 ms | nginx | 1.25× |
| WIN | hostile | failover | conns=256, workers=3 | CPU ms/1k req | 11.45 ms | 14.87 ms | nginx | 1.30× |
| WIN | h3 | h1-static | conns=64, workers=3 | CPU ms/1k req | 14.68 ms | 19.10 ms | nginx | 1.30× |
| WIN | http | proxy | conns=256, workers=3 | req/s | 265k | 201k | nginx | 1.32× |
| WIN | http | tls-handshake | conns=256, workers=3 | req/s | 17k | 13k | nginx | 1.33×† |
| WIN | h3 | h1-static | conns=64, workers=3 | req/s | 202k | 152k | nginx | 1.33× |
| WIN | http | proxy | conns=256, workers=3 | CPU ms/1k req | 11.18 ms | 14.96 ms | nginx | 1.34× |
| WIN | l4 | tcp-bulk | conns=256, workers=3 | p99 | 60.26 ms | 80.85 ms | nginx | 1.34× |
| WIN | http | tls-handshake | conns=256, workers=3 | CPU ms/1k req | 165.71 ms | 226.47 ms | nginx | 1.37×† |
| WIN | http | tls-static | conns=256, workers=3 | CPU ms/1k req | 14.64 ms | 20.01 ms | nginx | 1.37× |
| WIN | http | tls-static | conns=256, workers=3 | req/s | 206k | 150k | nginx | 1.37× |
| WIN | h3 | h1-proxy | conns=64, workers=3 | req/s | 242k | 171k | nginx | 1.41× |
| WIN | h3 | h1-proxy | conns=64, workers=3 | CPU ms/1k req | 11.79 ms | 17.34 ms | nginx | 1.47× |
| WIN | h3 | h3-static-1m | conns=64, workers=3 | RSS | 119.6 MB | 176.4 MB | nginx | 1.47×† |
| WIN | h3 | h1-return | conns=64, workers=3 | req/s | 504k | 340k | nginx | 1.48× |
| WIN | h3 | h1-return | conns=64, workers=3 | CPU ms/1k req | 5.80 ms | 8.63 ms | nginx | 1.49× |
| WIN | http | tls-static-1m | conns=256, workers=3 | req/s | 4.8k | 3.0k | nginx | 1.62× |
| WIN | http | tls-static-1m | conns=256, workers=3 | CPU ms/1k req | 623.10 ms | 1,017.21 ms | nginx | 1.63× |
| WIN | l4 | udp-rtt | conns=256, workers=3 | CPU ms/1k req | 15.70 ms | 26.80 ms | nginx | 1.71× |
| WIN | l4 | udp-flood | conns=256, workers=3 | CPU ms/1k req | 16.41 ms | 28.57 ms | nginx | 1.74× |
| WIN | http | notfound | conns=256, workers=3 | req/s | 562k | 309k | nginx | 1.81× |
| WIN | http | notfound | conns=256, workers=3 | CPU ms/1k req | 5.34 ms | 9.73 ms | nginx | 1.82× |
| WIN | http | tls-return | conns=256, workers=3 | req/s | 606k | 326k | nginx | 1.86× |
| WIN | http | tls-return | conns=256, workers=3 | CPU ms/1k req | 4.90 ms | 9.19 ms | nginx | 1.88× |
| WIN | h3 | h3-static | conns=64, workers=3 | RSS | 43.4 MB | 147.2 MB | nginx | 3.39× |
| WIN | h3 | h3-proxy | conns=64, workers=3 | RSS | 28.1 MB | 100.7 MB | HAProxy | 3.58× |
| WIN | http | tls-static | conns=256, workers=3 | RSS | 16.3 MB | 65.9 MB | nginx | 4.04× |
| WIN | h3 | h3-return | conns=64, workers=3 | RSS | 19.9 MB | 88.9 MB | HAProxy | 4.46× |
| WIN | http | fileset | conns=256, workers=3 | RSS | 9.8 MB | 47.1 MB | nginx | 4.82× |
| WIN | http | static | conns=256, workers=3 | RSS | 9.8 MB | 51.6 MB | nginx | 5.27× |
| WIN | http | pipeline | conns=256, workers=3 | CPU ms/1k req | 0.92 ms | 5.34 ms | nginx | 5.81× |
| WIN | http | pipeline | conns=256, workers=3 | req/s | 3266k | 562k | nginx | 5.81× |
| WIN | h3 | h3-return-m10 | conns=64, workers=3 | RSS | 17.0 MB | 99.5 MB | HAProxy | 5.85× |
| WIN | http | gzip | conns=256, workers=3 | RSS | 9.1 MB | 54.7 MB | nginx | 6.01×† |
| WIN | http | pipeline | conns=256, workers=3 | RSS | 8.2 MB | 52.5 MB | nginx | 6.40× |
| WIN | http | precompressed | conns=256, workers=3 | RSS | 7.0 MB | 46.6 MB | nginx | 6.62× |
| WIN | http | proxy | conns=256, workers=3 | RSS | 8.0 MB | 53.1 MB | nginx | 6.64× |
| WIN | http | static-1k | conns=256, workers=3 | RSS | 6.9 MB | 46.6 MB | nginx | 6.73× |
| WIN | http | tls-return | conns=256, workers=3 | RSS | 9.1 MB | 64.9 MB | HAProxy | 7.13× |
| WIN | http | bigheaders | conns=256, workers=3 | RSS | 7.4 MB | 52.9 MB | nginx | 7.13× |
| WIN | http | not-modified | conns=256, workers=3 | RSS | 6.4 MB | 46.6 MB | nginx | 7.24× |
| WIN | soak | mixed | minutes=2, workers=3 | RSS | 12.1 MB | 88.1 MB | HAProxy | 7.29× |
| WIN | http | notfound | conns=256, workers=3 | RSS | 6.3 MB | 46.6 MB | nginx | 7.34× |
| WIN | http | return | conns=256, workers=3 | RSS | 6.3 MB | 46.4 MB | nginx | 7.34× |
| WIN | http | tls-handshake | conns=256, workers=3 | RSS | 9.5 MB | 73.2 MB | nginx | 7.70×† |
| WIN | http | tls-static-1m | conns=256, workers=3 | RSS | 8.3 MB | 64.4 MB | nginx | 7.72× |
| WIN | hostile | slowhead | conns=256, workers=3 | KB/conn | 1.2 KB | 9.5 KB | nginx | 7.74× |
| WIN | http | static-1m | conns=256, workers=3 | RSS | 6.0 MB | 46.5 MB | nginx | 7.76× |
| WIN | http | static-100k | conns=256, workers=3 | RSS | 6.4 MB | 52.8 MB | nginx | 8.22× |
| WIN | h3 | h1-proxy | conns=64, workers=3 | RSS | 9.1 MB | 83.8 MB | HAProxy | 9.23× |
| WIN | http | static-100m | conns=256, workers=3 | RSS | 5.8 MB | 53.8 MB | nginx | 9.25× |
| WIN | h3 | h1-return | conns=64, workers=3 | RSS | 7.7 MB | 79.1 MB | HAProxy | 10.32× |
| WIN | h3 | h1-static | conns=64, workers=3 | RSS | 9.6 MB | 121.0 MB | nginx | 12.63× |

† a round of this row carried: 148 UDP datagrams the kernel dropped; 2896 UDP datagrams the kernel dropped; 3476 UDP datagrams the kernel dropped; 72 UDP datagrams the kernel dropped; errors: 19 timeout; rig 100% busy; rig 97% busy; rig 98% busy; rig 99% busy. Read those lines as untrusted.
