use super::*;

/// Kill stale agent processes from a previous session whose PID is still alive
/// but not tracked in the current `runtimes` map. Updates the record fields and
/// returns `true` if any records were modified.
pub fn kill_stale_tracked_processes(
    records: &mut [ManagedAgentRecord],
    runtimes: &HashMap<ManagedAgentRuntimeKey, ManagedAgentPairRuntime>,
    instance_id: &str,
) -> bool {
    kill_stale_tracked_processes_with(
        records,
        runtimes,
        |pid| process_has_buzz_marker(pid, instance_id),
        terminate_process,
    )
}

/// Injectable version of `kill_stale_tracked_processes` for testing.
/// `has_marker(pid)` returns true when the process carries this instance's
/// `BUZZ_MANAGED_AGENT` marker; `kill(pid)` performs the termination.
pub(crate) fn kill_stale_tracked_processes_with(
    records: &mut [ManagedAgentRecord],
    runtimes: &HashMap<ManagedAgentRuntimeKey, ManagedAgentPairRuntime>,
    has_marker: impl Fn(u32) -> bool,
    mut kill: impl FnMut(u32) -> Result<(), String>,
) -> bool {
    use crate::managed_agents::BackendKind;

    let mut changed = false;
    for record in records.iter_mut() {
        if record.backend != BackendKind::Local {
            continue;
        }
        let Some(pid) = record.runtime_pid else {
            continue;
        };
        if !runtimes.keys().any(|key| key.pubkey == record.pubkey) {
            // Name-gate is omitted intentionally: custom harnesses use arbitrary
            // binary names not in KNOWN_AGENT_BINARIES. BUZZ_MANAGED_AGENT is the
            // authoritative ownership proof; terminate only if it matches.
            if has_marker(pid) {
                let _ = kill(pid);
            }
            record.runtime_pid = None;
            record.last_stopped_at = Some(crate::util::now_iso());
            record.updated_at = crate::util::now_iso();
            changed = true;
        }
    }
    changed
}

/// Build the periodic orphan-sweep inputs — root PIDs to skip and generation
/// nonces to trust — from the runtime map, trusting only roots that are
/// provably alive on this tick.
///
/// A generation nonce is trusted only while a genuinely live current managed
/// root proves ownership, never because stale runtime bookkeeping still holds
/// it. Each runtime's child is probed with `try_wait()`, the authoritative,
/// PID-reuse-immune liveness check for that exact child:
/// - `Ok(None)`: the root is live — its PID and nonce enter the sweep inputs.
/// - `Ok(Some(status))`: the root died; it is reaped here (the background
///   sweep is the reaper) and the exit status is cached so the foreground
///   sync can still record the real exit code.
/// - `Err(_)`: the child was already reaped (e.g. by the foreground sync) or
///   its PID no longer belongs to it — dead either way, so its nonce is not
///   trusted.
///
/// Dead roots therefore stop exempting their detached descendants on the very
/// next periodic tick, without waiting for a foreground `list_managed_agents`
/// sync.
pub(crate) fn live_root_sweep_inputs(
    runtimes: &mut HashMap<ManagedAgentRuntimeKey, ManagedAgentPairRuntime>,
) -> (Vec<u32>, std::collections::HashSet<String>) {
    let mut skip_pids = Vec::new();
    let mut tracked_nonces = std::collections::HashSet::new();
    for runtime in runtimes.values_mut() {
        match runtime.child.try_wait() {
            // The root died: the background sweep is the reaper. Cache the
            // exit status so a later foreground sync records the real code.
            Ok(Some(status)) => {
                if runtime.reaped_exit_status.is_none() {
                    runtime.reaped_exit_status = Some(status);
                }
            }
            // The root is live: its PID and nonce enter the sweep inputs.
            Ok(None) => {
                skip_pids.push(runtime.child.id());
                tracked_nonces.insert(runtime.start_nonce.clone());
            }
            // Already reaped, or the PID no longer belongs to this child:
            // dead either way, so the nonce is not trusted.
            Err(_) => {}
        }
    }
    (skip_pids, tracked_nonces)
}

pub fn sync_managed_agent_processes(
    records: &mut [ManagedAgentRecord],
    runtimes: &mut HashMap<ManagedAgentRuntimeKey, ManagedAgentPairRuntime>,
    _instance_id: &str,
) -> (bool, Vec<String>) {
    let mut changed = false;
    let mut exited = Vec::new();

    for (key, runtime) in runtimes.iter_mut() {
        let status = match runtime.child.try_wait() {
            Ok(status) => status,
            Err(error) => match runtime.reaped_exit_status {
                // The background sweep already reaped this child, so the
                // `ECHILD` from a second `try_wait` is expected; the captured
                // exit status is authoritative and the record keeps the real
                // exit code instead of an inspect error.
                Some(status) => Some(status),
                None => {
                    if let Some(record) = records
                        .iter_mut()
                        .find(|record| record.pubkey == key.pubkey)
                    {
                        record.updated_at = now_iso();
                        record.last_error =
                            Some(format!("failed to inspect process state: {error}"));
                        record.last_error_code = None;
                    }
                    changed = true;
                    exited.push(key.clone());
                    continue;
                }
            },
        };

        let Some(status) = status else {
            continue;
        };

        if let Some(record) = records
            .iter_mut()
            .find(|record| record.pubkey == key.pubkey)
        {
            record.updated_at = now_iso();
            record.last_stopped_at = Some(now_iso());
            record.last_exit_code = status.code();
            let log_err = if status.success() {
                None
            } else {
                Some(
                    super::super::meaningful_agent_error_from_log(&runtime.log_path)
                        .unwrap_or_else(|| super::super::storage::AgentLogError {
                            message: format!("harness exited with status {status}"),
                            code: None,
                        }),
                )
            };
            record.last_error = log_err.as_ref().map(|e| e.message.clone());
            record.last_error_code = log_err.as_ref().and_then(|e| e.code);
        }

        changed = true;
        exited.push(key.clone());
    }

    let exited_pubkeys: Vec<String> = exited.iter().map(|key| key.pubkey.clone()).collect();
    for key in exited {
        runtimes.remove(&key);
    }

    // `runtime_pid` is legacy bookkeeping. Pair runtimes and receipts are the
    // authoritative lifecycle source; migration cleanup is handled separately.
    for record in records.iter_mut() {
        if record.runtime_pid.take().is_some() {
            record.updated_at = now_iso();
            changed = true;
        }
    }

    (changed, exited_pubkeys)
}
