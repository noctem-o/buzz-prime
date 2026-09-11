//! Real process-table coverage for generation-aware orphan ownership.
//!
//! These tests deliberately use detached `/bin/sleep` descendants rather than
//! only exercising the decision helper. The child process is reparented and
//! put in its own session, which is the lifecycle shape that originally made
//! ancestry-only ownership falsely reclaim a live managed worker.

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::HashSet;
    use std::process::{Child, Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    use uuid::Uuid;

    struct Harness {
        root: Option<Child>,
        detached_pid: u32,
        pid_file: std::path::PathBuf,
    }

    impl Harness {
        fn spawn(instance_id: &str, nonce: Option<&str>, keep_root: bool) -> Self {
            let pid_file = std::env::temp_dir().join(format!(
                "buzz-orphan-generation-{}-{}.pid",
                std::process::id(),
                Uuid::new_v4()
            ));
            let script = if keep_root {
                r#"setsid /bin/sh -c 'printf "%s\n" "$$" > "$0"; exec /bin/sleep 30' "$1" &
exec /bin/sleep 30"#
            } else {
                r#"setsid /bin/sh -c 'printf "%s\n" "$$" > "$0"; exec /bin/sleep 30' "$1" &
exit 0"#
            };
            let mut command = Command::new("/bin/sh");
            command
                .arg("-c")
                .arg(script)
                .arg("buzz-generation-root")
                .arg(&pid_file)
                .env("BUZZ_MANAGED_AGENT", instance_id)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            if let Some(nonce) = nonce {
                command.env("BUZZ_MANAGED_AGENT_START_NONCE", nonce);
            } else {
                command.env_remove("BUZZ_MANAGED_AGENT_START_NONCE");
            }
            let root = command.spawn().expect("spawn generation root");
            let detached_pid = wait_for_pid(&pid_file);
            assert!(
                process_is_running(detached_pid),
                "detached child {detached_pid} did not remain live"
            );
            Self {
                root: Some(root),
                detached_pid,
                pid_file,
            }
        }

        fn root_pid(&self) -> u32 {
            self.root.as_ref().expect("root child handle").id()
        }

        fn wait_root(&mut self) {
            self.root
                .take()
                .expect("root child handle")
                .wait()
                .expect("wait generation root");
        }
    }

    impl Drop for Harness {
        fn drop(&mut self) {
            unsafe {
                // setsid makes the detached worker the process-group leader.
                libc::kill(-(self.detached_pid as libc::pid_t), libc::SIGKILL);
                libc::kill(self.detached_pid as libc::pid_t, libc::SIGKILL);
            }
            if let Some(mut root) = self.root.take() {
                let _ = root.kill();
                let _ = root.wait();
            }
            let _ = std::fs::remove_file(&self.pid_file);
        }
    }

    fn wait_for_pid(path: &std::path::Path) -> u32 {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Ok(contents) = std::fs::read_to_string(path) {
                if let Ok(pid) = contents.trim().parse::<u32>() {
                    return pid;
                }
            }
            assert!(Instant::now() < deadline, "timed out waiting for {path:?}");
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn process_is_running(pid: u32) -> bool {
        unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
    }

    fn collect(instance_id: &str, skip_pids: &[u32], tracked_nonces: &[&str]) -> HashSet<u32> {
        let tracked_nonces = tracked_nonces
            .iter()
            .map(|nonce| (*nonce).to_string())
            .collect::<HashSet<_>>();
        crate::managed_agents::runtime::orphan_sweep::collect_same_instance_orphans_with_tracked_nonces(
            instance_id,
            skip_pids,
            &tracked_nonces,
        )
    }

    #[test]
    fn real_linux_collector_reclaims_stale_generation_and_spares_current_generation() {
        let instance_id = format!("buzz-test-instance-{}", Uuid::new_v4());
        let nonce_a = format!("generation-a-{}", Uuid::new_v4());
        let nonce_b = format!("generation-b-{}", Uuid::new_v4());
        let mut root_a = Harness::spawn(&instance_id, Some(&nonce_a), false);
        let root_b = Harness::spawn(&instance_id, Some(&nonce_b), true);
        root_a.wait_root();

        let orphans = collect(&instance_id, &[root_b.root_pid()], &[&nonce_b]);
        assert!(
            orphans.contains(&root_a.detached_pid),
            "detached N1 child must be reclaimable after generation B replaces A: {orphans:?}"
        );
        assert!(
            !orphans.contains(&root_b.detached_pid),
            "detached N2 child must be spared while root B is tracked: {orphans:?}"
        );
        assert!(
            !orphans.contains(&root_b.root_pid()),
            "the tracked root itself must be spared: {orphans:?}"
        );
    }

    #[test]
    fn real_linux_collector_applies_marker_and_exact_live_nonce_gates() {
        let instance_id = format!("buzz-test-instance-{}", Uuid::new_v4());
        let foreign_instance = format!("foreign-instance-{}", Uuid::new_v4());
        let current_nonce = format!("current-{}", Uuid::new_v4());
        let stale_nonce = format!("stale-{}", Uuid::new_v4());

        // A matching current root is explicitly tracked by PID and is spared;
        // its detached child is spared only by the exact current nonce.
        let tracked_root = Harness::spawn(&instance_id, Some(&current_nonce), true);
        let matching = Harness::spawn(&instance_id, Some(&current_nonce), false);
        let mismatched = Harness::spawn(&instance_id, Some(&stale_nonce), false);
        let missing = Harness::spawn(&instance_id, None, false);
        let foreign = Harness::spawn(&foreign_instance, Some(&current_nonce), false);

        let current = collect(&instance_id, &[tracked_root.root_pid()], &[&current_nonce]);
        assert!(!current.contains(&tracked_root.root_pid()));
        assert!(
            !current.contains(&matching.detached_pid),
            "matching nonce with a live tracked root generation must be spared: {current:?}"
        );
        assert!(
            current.contains(&mismatched.detached_pid),
            "mismatched nonce must be reclaimable: {current:?}"
        );
        assert!(
            current.contains(&missing.detached_pid),
            "missing nonce must be reclaimable: {current:?}"
        );
        assert!(
            !current.contains(&foreign.detached_pid),
            "foreign BUZZ_MANAGED_AGENT instance must not be claimed: {current:?}"
        );

        // Once the live root's nonce is removed from the tracked-generation
        // set, a formerly valid detached child is reclaimable again.
        let no_live_generation = collect(&instance_id, &[], &[]);
        assert!(
            no_live_generation.contains(&matching.detached_pid),
            "historical nonce must not confer indefinite liveness: {no_live_generation:?}"
        );
    }

    // ── R1 witness: dead-root liveness gating bound to the production seam ──
    //
    // The periodic loop in `lib.rs` builds its sweep inputs through
    // `managed_agents::live_root_sweep_inputs` under the runtime lock. These
    // tests feed real root/descendant processes through that exact function
    // and the real two-tick grace sweep — no foreground
    // `list_managed_agents` sync ever runs between ticks.

    /// Build a runtime-map entry the way the spawn path does, around a real
    /// `Child` handle, so the sweep-input builder probes the real process.
    fn pair_runtime_for(
        child: Child,
        nonce: &str,
    ) -> (
        crate::managed_agents::ManagedAgentRuntimeKey,
        crate::managed_agents::ManagedAgentPairRuntime,
    ) {
        let key = crate::managed_agents::ManagedAgentRuntimeKey::new(
            "cc".repeat(32),
            "wss://relay.example",
        )
        .expect("runtime key fixture");
        let process = crate::managed_agents::ManagedAgentProcess {
            child,
            log_path: Default::default(),
            spawn_config: crate::managed_agents::spawn_snapshot::prospective_spawn_config_snapshot(
                &super::super::test_fixtures::fixture(
                    crate::managed_agents::types::RespondTo::default(),
                    vec![],
                    None,
                ),
                &[],
                &[],
                "wss://relay.example",
                &Default::default(),
                false,
                crate::managed_agents::AcpSessionPolicy::Channel,
            ),
            setup_mode: false,
            adapter_availability: None,
            start_nonce: nonce.to_string(),
            #[cfg(windows)]
            job: None,
        };
        (
            key,
            crate::managed_agents::ManagedAgentPairRuntime::starting(process),
        )
    }

    fn sweep_tick(
        instance_id: &str,
        skip_pids: &[u32],
        prev: &HashSet<u32>,
        tracked_nonces: &HashSet<String>,
    ) -> HashSet<u32> {
        crate::managed_agents::runtime::orphan_sweep::sweep_system_agent_processes_with_grace_and_tracked_nonces(
            instance_id,
            skip_pids,
            prev,
            tracked_nonces,
        )
    }

    fn wait_for_exit(pid: u32) {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if !process_is_running(pid) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "process {pid} did not exit within the grace window"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn dead_root_stale_nonce_becomes_reclaimable_without_foreground_sync() {
        let instance_id = format!("buzz-test-instance-{}", Uuid::new_v4());
        let nonce = format!("generation-{}", Uuid::new_v4());
        // The root exits on its own while the runtime map keeps holding its
        // (now dead) child handle — exactly the stale bookkeeping R1
        // describes. No foreground sync runs between ticks.
        let mut harness = Harness::spawn(&instance_id, Some(&nonce), false);
        let root_child = harness.root.take().expect("root child handle");
        let root_pid = root_child.id();
        let (key, runtime) = pair_runtime_for(root_child, &nonce);
        let mut runtimes = std::collections::HashMap::from([(key, runtime)]);

        // Tick 1: the production input builder must not trust the dead
        // root's nonce (nor skip its pid). The descendant becomes a reclaim
        // candidate, but the two-tick grace keeps it alive this tick.
        let (skip_pids, tracked_nonces) =
            crate::managed_agents::live_root_sweep_inputs(&mut runtimes);
        assert!(
            !tracked_nonces.contains(&nonce),
            "dead root's stale nonce must not be trusted without a live root: {tracked_nonces:?}"
        );
        assert!(!skip_pids.contains(&root_pid));
        let tick1 = sweep_tick(&instance_id, &skip_pids, &HashSet::new(), &tracked_nonces);
        assert!(
            tick1.contains(&harness.detached_pid),
            "detached descendant retaining the stale nonce must be a reclaim candidate: {tick1:?}"
        );
        assert!(
            process_is_running(harness.detached_pid),
            "two-tick grace must keep the descendant alive on the first tick"
        );

        // Tick 2: still no foreground sync. The same stale map entry must
        // produce no trust, the grace window closes, and the descendant is
        // reclaimed.
        let (skip_pids, tracked_nonces) =
            crate::managed_agents::live_root_sweep_inputs(&mut runtimes);
        assert!(
            !tracked_nonces.contains(&nonce),
            "stale nonce must not resurface on later ticks: {tracked_nonces:?}"
        );
        let tick2 = sweep_tick(&instance_id, &skip_pids, &tick1, &tracked_nonces);
        assert!(tick2.contains(&harness.detached_pid));
        wait_for_exit(harness.detached_pid);
        assert!(
            !process_is_running(harness.detached_pid),
            "descendant must be reclaimed on the second tick with no foreground sync"
        );
    }

    #[test]
    fn live_root_keeps_protecting_detached_descendant_across_sweep_ticks() {
        let instance_id = format!("buzz-test-instance-{}", Uuid::new_v4());
        let nonce = format!("generation-{}", Uuid::new_v4());
        // Root stays live; its detached worker keeps the same nonce.
        let mut harness = Harness::spawn(&instance_id, Some(&nonce), true);
        let root_pid = harness.root_pid();
        let root_child = harness.root.take().expect("root child handle");
        let (key, runtime) = pair_runtime_for(root_child, &nonce);
        let mut runtimes = std::collections::HashMap::from([(key, runtime)]);

        let (skip_pids, tracked_nonces) =
            crate::managed_agents::live_root_sweep_inputs(&mut runtimes);
        assert!(
            skip_pids.contains(&root_pid),
            "live root pid must enter the skip list: {skip_pids:?}"
        );
        assert!(
            tracked_nonces.contains(&nonce),
            "live root's nonce must be trusted: {tracked_nonces:?}"
        );
        let tick1 = sweep_tick(&instance_id, &skip_pids, &HashSet::new(), &tracked_nonces);
        assert!(
            !tick1.contains(&harness.detached_pid),
            "live root must keep protecting its detached descendant: {tick1:?}"
        );
        let (skip_pids, tracked_nonces) =
            crate::managed_agents::live_root_sweep_inputs(&mut runtimes);
        let tick2 = sweep_tick(&instance_id, &skip_pids, &tick1, &tracked_nonces);
        assert!(!tick2.contains(&harness.detached_pid));
        assert!(
            process_is_running(harness.detached_pid),
            "live root must keep protecting its detached descendant across ticks"
        );

        // Tear down the live root; `Harness::drop` reaps the detached worker.
        if let Some(runtime) = runtimes.values_mut().next() {
            let _ = runtime.child.kill();
            let _ = runtime.child.wait();
        }
    }

    #[test]
    fn already_reaped_root_is_not_trusted_by_sweep_inputs() {
        let instance_id = format!("buzz-test-instance-{}", Uuid::new_v4());
        let nonce = format!("generation-{}", Uuid::new_v4());
        let mut harness = Harness::spawn(&instance_id, Some(&nonce), false);
        let root_pid = harness.root_pid();
        // Foreground-sync-shaped reaping: the child is waited on before the
        // sweep probes it, so the probe hits the same ECHILD branch that a
        // reused PID would — neither may keep the nonce trusted.
        let mut root_child = harness.root.take().expect("root child handle");
        root_child.wait().expect("reap generation root");
        let (key, runtime) = pair_runtime_for(root_child, &nonce);
        let mut runtimes = std::collections::HashMap::from([(key, runtime)]);

        let (skip_pids, tracked_nonces) =
            crate::managed_agents::live_root_sweep_inputs(&mut runtimes);
        assert!(
            !tracked_nonces.contains(&nonce),
            "an already-reaped (or PID-reused) root must not keep its nonce trusted: {tracked_nonces:?}"
        );
        assert!(!skip_pids.contains(&root_pid));
    }

    #[test]
    fn background_reap_preserves_real_exit_status_for_foreground_sync() {
        let instance_id = format!("buzz-test-instance-{}", Uuid::new_v4());
        let nonce = format!("generation-{}", Uuid::new_v4());
        let mut harness = Harness::spawn(&instance_id, Some(&nonce), false);
        let root_child = harness.root.take().expect("root child handle");
        let (key, runtime) = pair_runtime_for(root_child, &nonce);
        let mut runtimes = std::collections::HashMap::from([(key.clone(), runtime)]);

        // Background sweep reaps the dead root and caches its exit status.
        let (_skip_pids, _tracked_nonces) =
            crate::managed_agents::live_root_sweep_inputs(&mut runtimes);

        // A later foreground sync must record the real exit status (the root
        // shell exits 0), not a "failed to inspect process state" error.
        let mut record = super::super::test_fixtures::fixture(
            crate::managed_agents::types::RespondTo::default(),
            vec![],
            None,
        );
        record.pubkey = key.pubkey.clone();
        let mut records = vec![record];
        let (changed, exited) = crate::managed_agents::sync_managed_agent_processes(
            &mut records,
            &mut runtimes,
            &instance_id,
        );
        assert!(
            changed && exited.len() == 1,
            "sync must process the background-reaped root: {exited:?}"
        );
        assert!(runtimes.is_empty(), "sync must remove the exited runtime");
        assert!(records[0].last_stopped_at.is_some());
        assert_eq!(records[0].last_exit_code, Some(0));
        assert!(
            records[0].last_error.is_none(),
            "real exit status must not be reported as an inspect error: {:?}",
            records[0].last_error
        );
    }
}
