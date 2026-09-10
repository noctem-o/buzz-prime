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
}
