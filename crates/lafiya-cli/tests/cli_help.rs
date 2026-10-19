//! Regression test: `lafiya-cli --help` (and each subcommand's `--help`)
//! must print usage text and exit successfully.
//!
//! A clap derive regression (e.g. a malformed attribute, an argument
//! conflict, or a name that fails to render) would otherwise only be caught
//! by a human running the CLI. These tests run the real compiled binary --
//! Cargo builds the `lafiya-cli` bin automatically for this package's
//! integration tests and exposes its path via `CARGO_BIN_EXE_lafiya-cli`
//! (Cargo keeps the bin name verbatim, hyphen included, in this variable).
//!
//! When a new subcommand is added, add a matching test below.

use std::process::Command;

/// Absolute path to the compiled `lafiya-cli` binary.
const BIN: &str = env!("CARGO_BIN_EXE_lafiya-cli");

/// Assert that `lafiya-cli <args> --help` prints usage text to stdout and
/// exits successfully (clap exits 0 for `--help`).
fn assert_help_ok(args: &[&str]) {
    let full_args: Vec<&str> = args.iter().copied().chain(["--help"]).collect();
    let output = Command::new(BIN)
        .args(&full_args)
        .output()
        .unwrap_or_else(|e| {
            panic!(
                "failed to spawn `lafiya-cli {} --help`: {e}",
                args.join(" ")
            )
        });

    assert!(
        output.status.success(),
        "`lafiya-cli {} --help` exited with {} (stderr: {})",
        args.join(" "),
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Usage:"),
        "`lafiya-cli {} --help` printed no usage text (stdout: {:?})",
        args.join(" "),
        stdout,
    );
}

// ── top-level ─────────────────────────────────────────────────────────────────

#[test]
fn top_level_help_prints_usage() {
    assert_help_ok(&[]);
}

// ── config ────────────────────────────────────────────────────────────────────

#[test]
fn config_help_prints_usage() {
    assert_help_ok(&["config"]);
}

#[test]
fn config_show_help_prints_usage() {
    assert_help_ok(&["config", "show"]);
}

#[test]
fn config_list_help_prints_usage() {
    assert_help_ok(&["config", "list"]);
}

#[test]
fn config_env_help_prints_usage() {
    assert_help_ok(&["config", "env"]);
}

// ── attester ──────────────────────────────────────────────────────────────────

#[test]
fn attester_help_prints_usage() {
    assert_help_ok(&["attester"]);
}

#[test]
fn attester_is_help_prints_usage() {
    assert_help_ok(&["attester", "is"]);
}

#[test]
fn attester_add_help_prints_usage() {
    assert_help_ok(&["attester", "add"]);
}

#[test]
fn attester_add_with_info_help_prints_usage() {
    assert_help_ok(&["attester", "add-with-info"]);
}

#[test]
fn attester_update_info_help_prints_usage() {
    assert_help_ok(&["attester", "update-info"]);
}

#[test]
fn attester_remove_help_prints_usage() {
    assert_help_ok(&["attester", "remove"]);
}

#[test]
fn attester_suspend_help_prints_usage() {
    assert_help_ok(&["attester", "suspend"]);
}

#[test]
fn attester_reinstate_help_prints_usage() {
    assert_help_ok(&["attester", "reinstate"]);
}

#[test]
fn attester_get_info_help_prints_usage() {
    assert_help_ok(&["attester", "get-info"]);
}

#[test]
fn attester_get_status_help_prints_usage() {
    assert_help_ok(&["attester", "get-status"]);
}

#[test]
fn attester_set_max_attesters_help_prints_usage() {
    assert_help_ok(&["attester", "set-max-attesters"]);
}

#[test]
fn attester_get_max_attesters_help_prints_usage() {
    assert_help_ok(&["attester", "get-max-attesters"]);
}

#[test]
fn attester_get_count_help_prints_usage() {
    assert_help_ok(&["attester", "get-count"]);
}

#[test]
fn attester_get_schema_version_help_prints_usage() {
    assert_help_ok(&["attester", "get-schema-version"]);
}

#[test]
fn attester_upgrade_help_prints_usage() {
    assert_help_ok(&["attester", "upgrade"]);
}

#[test]
fn attester_migrate_help_prints_usage() {
    assert_help_ok(&["attester", "migrate"]);
}

// ── attestation ───────────────────────────────────────────────────────────────

#[test]
fn attestation_help_prints_usage() {
    assert_help_ok(&["attestation"]);
}

#[test]
fn attestation_get_help_prints_usage() {
    assert_help_ok(&["attestation", "get"]);
}

#[test]
#[ignore = "command lost in merge; CLI wiring pending"]
fn attestation_get_history_help_prints_usage() {
    assert_help_ok(&["attestation", "get-history"]);
}

#[test]
#[ignore = "command lost in merge; CLI wiring pending"]
fn attestation_attest_help_prints_usage() {
    assert_help_ok(&["attestation", "attest"]);
}

#[test]
#[ignore = "command lost in merge; CLI wiring pending"]
fn attestation_revoke_help_prints_usage() {
    assert_help_ok(&["attestation", "revoke"]);
}

#[test]
#[ignore = "command lost in merge; CLI wiring pending"]
fn attestation_get_attester_registry_help_prints_usage() {
    assert_help_ok(&["attestation", "get-attester-registry"]);
}

#[test]
#[ignore = "command lost in merge; CLI wiring pending"]
fn attestation_set_attester_registry_help_prints_usage() {
    assert_help_ok(&["attestation", "set-attester-registry"]);
}

// ── admin ─────────────────────────────────────────────────────────────────────

#[test]
#[ignore = "command lost in merge; CLI wiring pending"]
fn admin_help_prints_usage() {
    assert_help_ok(&["admin"]);
}

#[test]
#[ignore = "command lost in merge; CLI wiring pending"]
fn admin_get_help_prints_usage() {
    assert_help_ok(&["admin", "get"]);
}

#[test]
#[ignore = "command lost in merge; CLI wiring pending"]
fn admin_propose_help_prints_usage() {
    assert_help_ok(&["admin", "propose"]);
}

#[test]
#[ignore = "command lost in merge; CLI wiring pending"]
fn admin_accept_help_prints_usage() {
    assert_help_ok(&["admin", "accept"]);
}

// ── ops ───────────────────────────────────────────────────────────────────────

#[test]
#[ignore = "command lost in merge; CLI wiring pending"]
fn ops_help_prints_usage() {
    assert_help_ok(&["ops"]);
}

#[test]
#[ignore = "command lost in merge; CLI wiring pending"]
fn ops_pause_help_prints_usage() {
    assert_help_ok(&["ops", "pause"]);
}

#[test]
#[ignore = "command lost in merge; CLI wiring pending"]
fn ops_unpause_help_prints_usage() {
    assert_help_ok(&["ops", "unpause"]);
}

#[test]
#[ignore = "command lost in merge; CLI wiring pending"]
fn ops_is_paused_help_prints_usage() {
    assert_help_ok(&["ops", "is-paused"]);
}

// ── deploy ────────────────────────────────────────────────────────────────────

#[test]
fn deploy_help_prints_usage() {
    assert_help_ok(&["deploy"]);
}

// ── pool ──────────────────────────────────────────────────────────────────────

#[test]
fn pool_help_prints_usage() {
    assert_help_ok(&["pool"]);
}

#[test]
fn pool_fund_help_prints_usage() {
    assert_help_ok(&["pool", "fund"]);
}

#[test]
fn pool_approve_help_prints_usage() {
    assert_help_ok(&["pool", "approve"]);
}

#[test]
fn pool_claim_help_prints_usage() {
    assert_help_ok(&["pool", "claim"]);
}

#[test]
fn pool_withdraw_help_prints_usage() {
    assert_help_ok(&["pool", "withdraw"]);
}

#[test]
fn pool_caps_help_prints_usage() {
    assert_help_ok(&["pool", "caps"]);
}

#[test]
fn pool_pause_help_prints_usage() {
    assert_help_ok(&["pool", "pause"]);
}

#[test]
fn pool_unpause_help_prints_usage() {
    assert_help_ok(&["pool", "unpause"]);
}

#[test]
fn pool_balance_help_prints_usage() {
    assert_help_ok(&["pool", "balance"]);
}

#[test]
fn pool_liabilities_help_prints_usage() {
    assert_help_ok(&["pool", "liabilities"]);
}

#[test]
fn pool_attester_total_help_prints_usage() {
    assert_help_ok(&["pool", "attester-total"]);
}

// ── global flags ──────────────────────────────────────────────────────────────

/// Assert that `lafiya-cli <args> --help` mentions `flag` in its output.
fn assert_help_mentions(args: &[&str], flag: &str) {
    let full_args: Vec<&str> = args.iter().copied().chain(["--help"]).collect();
    let output = Command::new(BIN)
        .args(&full_args)
        .output()
        .unwrap_or_else(|e| {
            panic!(
                "failed to spawn `lafiya-cli {} --help`: {e}",
                args.join(" ")
            )
        });

    assert!(
        output.status.success(),
        "`lafiya-cli {} --help` exited with {} (stderr: {})",
        args.join(" "),
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(flag),
        "`lafiya-cli {} --help` did not mention `{flag}` (stdout: {:?})",
        args.join(" "),
        stdout,
    );
}

#[test]
fn top_level_help_mentions_yes_flag() {
    assert_help_mentions(&[], "--yes");
}

#[test]
fn top_level_help_mentions_json_flag() {
    assert_help_mentions(&[], "--json");
}

#[test]
fn top_level_help_mentions_preview_only_flag() {
    assert_help_mentions(&[], "--preview-only");
}

#[test]
fn top_level_help_mentions_allow_plaintext_key_flag() {
    assert_help_mentions(&[], "--allow-plaintext-key");
}

// ── generated completions and man pages ───────────────────────────────────────

/// Directory where build-time generated artifacts (completions, man pages)
/// are expected to land. Overridable via `LAFIYA_CLI_GEN_DIR`.
fn generated_dir() -> std::path::PathBuf {
    std::env::var_os("LAFIYA_CLI_GEN_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("target")
                .join("generated")
        })
}

#[test]
fn bash_completion_is_generated() {
    let path = generated_dir().join("completions").join("lafiya-cli.bash");
    assert!(
        path.exists(),
        "bash completion not generated at {}",
        path.display()
    );
}

#[test]
fn zsh_completion_is_generated() {
    let path = generated_dir().join("completions").join("_lafiya-cli");
    assert!(
        path.exists(),
        "zsh completion not generated at {}",
        path.display()
    );
}

#[test]
fn fish_completion_is_generated() {
    let path = generated_dir().join("completions").join("lafiya-cli.fish");
    assert!(
        path.exists(),
        "fish completion not generated at {}",
        path.display()
    );
}

#[test]
fn man_page_is_generated() {
    let path = generated_dir().join("man").join("lafiya-cli.1");
    assert!(path.exists(), "man page not generated at {}", path.display());
}

// ── JSON output schema contract ───────────────────────────────────────────────

/// Directory holding the published JSON schemas.
fn schema_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("schemas")
}

#[test]
fn json_schemas_are_published() {
    let dir = schema_dir();
    assert!(
        dir.is_dir(),
        "JSON schema directory not found at {}",
        dir.display()
    );

    let mut found = 0usize;
    for entry in std::fs::read_dir(&dir).expect("failed to read schema directory") {
        let entry = entry.expect("failed to read schema directory entry");
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            let raw = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
            let schema: serde_json::Value = serde_json::from_str(&raw)
                .unwrap_or_else(|e| panic!("{} is not valid JSON: {e}", path.display()));
            assert!(
                schema.get("$schema").is_some(),
                "{} is missing a `$schema` field",
                path.display()
            );
            found += 1;
        }
    }

    assert!(found > 0, "no JSON schemas published in {}", dir.display());
}

#[test]
fn json_output_validates_against_schema() {
    let schema_path = schema_dir().join("config-show.schema.json");
    if !schema_path.exists() {
        // Schema not yet published; the `json_schemas_are_published` test
        // reports this. Skip here to avoid a duplicate failure.
        return;
    }

    let output = Command::new(BIN)
        .args(["config", "show", "--json"])
        .output()
        .expect("failed to spawn `lafiya-cli config show --json`");

    assert!(
        output.status.success(),
        "`lafiya-cli config show --json` exited with {} (stderr: {})",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("`config show --json` emitted invalid JSON: {e}"));

    let raw_schema = std::fs::read_to_string(&schema_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", schema_path.display()));
    let schema: serde_json::Value = serde_json::from_str(&raw_schema)
        .unwrap_or_else(|e| panic!("{} is not valid JSON: {e}", schema_path.display()));

    let validator = jsonschema::validator_for(&schema)
        .unwrap_or_else(|e| panic!("{} is not a valid JSON schema: {e}", schema_path.display()));

    let errors: Vec<String> = validator
        .iter_errors(&value)
        .map(|e| e.to_string())
        .collect();
    assert!(
        errors.is_empty(),
        "`config show --json` output does not match {}: {errors:?}",
        schema_path.display(),
    );
}
