# M2 replica — pass/fail (not a speed claim)

**Date:** 2026-09-30  
**Hardware:** local developer machine (same class as M1 benches).  
**What this is:** correctness of four replicas under crash, restart, delay, truncate, and corrupt WAL.  
**What this is not:** throughput, consensus, or a QUIC vs TCP measurement (Q-NET-1).

`SyncMode::Full` (`sync_all` per WAL record) is on for every M2 test. Do not cite these runs as CLOB speed.

## Pass criteria (met)

| Check | Evidence |
|---|---|
| Four in-process replicas, identical `I`, injected sleep, same roots/fills/settlement | `crates/replica/tests/m2_replicas.rs` `four_replicas_agree` |
| Four OS processes, same | `crates/replica/tests/m2_processes.rs` `four_processes_agree_with_delay` |
| Crash after WAL, before `apply`; restart replays | `crash_after_wal_replays_on_open` |
| Process kill + restart | `process_kill_and_restart_replays` |
| Truncated tail detected; prefix replayed; tail not applied | `truncated_wal_replays_prefix` |
| Flipped ciphertext byte → open refused | `corrupt_wal_refuses_to_open` |
| Rejects are WAL'd and replay | `rejects_are_logged_and_replay` |

## Not measured

- WAL append + fsync p50/p95/p99
- restart replay time vs log length
- four-node throughput

Those stay on the [performance](../performance.md) Phase 2 list until someone runs them with percentiles and device info.
