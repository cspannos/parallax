# Q-CRY-5 consensus bytes per height (ADR 0031)

**Host:** Apple M4 Pro, 14 cores, Darwin. Process not pinned.
**Binary:** `PLX_M4_WIRE=1 cargo run -p m4-scale --release`. Localhost TCP, broadcast, 20 empty heights, secured intent gossip in every mode.
Bytes are summed over receivers (= sent), per height. `signed` = votes, proposals, liveness; `finality` = hybrid finality signatures to collectors.

| n | mode | signed msgs/h | signed KB/h | finality KB/h | total KB/h | vs hybrid | node p50 ms | node p95 ms |
|---|---|---|---|---|---|---|---|---|
| 4 | classical | 27 | 4.5 | 0.0 | 4.5 | — | 44 | 54 |
| 4 | hybrid | 27 | 93.9 | 0.0 | 93.9 | 1.0× | 50 | 64 |
| 4 | tiered k=2 | 27 | 4.5 | 20.4 | 24.9 | 3.8× | 39 | 54 |
| 4 | tiered k=1 | 27 | 4.5 | 10.3 | 14.8 | 6.3× | 44 | 54 |
| 7 | classical | 90 | 14.6 | 0.0 | 14.6 | — | 75 | 97 |
| 7 | hybrid | 90 | 312.4 | 0.0 | 312.4 | 1.0× | 79 | 100 |
| 7 | tiered k=3 | 90 | 14.6 | 61.3 | 75.9 | 4.1× | 71 | 90 |
| 7 | tiered k=1 | 90 | 14.6 | 20.6 | 35.2 | 8.9× | 72 | 93 |
| 10 | classical | 189 | 30.2 | 0.0 | 30.2 | — | 97 | 128 |
| 10 | hybrid | 189 | 655.6 | 0.0 | 655.6 | 1.0× | 102 | 129 |
| 10 | tiered k=4 | 189 | 30.2 | 122.0 | 152.2 | 4.3× | 96 | 130 |
| 10 | tiered k=1 | 189 | 30.2 | 30.5 | 60.7 | 10.8× | 94 | 119 |
| 20 | classical | 779 | 122.3 | 0.0 | 122.3 | — | 178 | 238 |
| 20 | hybrid | 777 | 2693.4 | 0.0 | 2693.4 | 1.0× | 178 | 254 |
| 20 | tiered k=7 | 770 | 120.8 | 453.3 | 574.1 | 4.7× | 180 | 256 |
| 20 | tiered k=1 | 779 | 122.3 | 64.9 | 187.2 | 14.4× | 185 | 259 |
