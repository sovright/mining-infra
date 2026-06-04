//! Censorship-policy loading and enforcement for the JD Client.
//!
//! The product principle is: **silently accepting a policy we don't enforce
//! is the one unforgivable failure mode.**  Any inclusion mode other than
//! `include-all` causes `load_policy` to return `Err`, which main.rs turns
//! into a non-zero exit.  Sections that are present but not yet enforced
//! produce loud `WARN`-level messages (surfaced by the caller via
//! `Policy::deferred_warnings`).

use std::path::{Path, PathBuf};

use serde::Deserialize;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// The only inclusion mode we enforce today.
#[derive(Debug, PartialEq, Eq)]
pub enum InclusionMode {
    IncludeAll,
}

/// A parsed, enforcement-scoped censorship policy.
#[derive(Debug)]
pub struct Policy {
    /// Always `IncludeAll` today — other modes refuse startup.
    pub mode: InclusionMode,
    /// Human-readable labels of sections/keys that are present in the file
    /// but are not yet enforced.  The caller should emit a WARN per entry.
    pub deferred_warnings: Vec<String>,
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("policy file not found: {0}")]
    NotFound(PathBuf),

    #[error("failed to read policy file {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to parse policy file: {0}")]
    Parse(String),

    #[error("policy file must declare [inclusion] mode")]
    MissingMode,

    #[error("inclusion mode '{0}' is not yet supported — refuse to start")]
    UnsupportedMode(String),
}

// ---------------------------------------------------------------------------
// Conventional container path (can be overridden in tests)
// ---------------------------------------------------------------------------

/// The path that the sovereignty bundle mounts the policy file to inside the
/// container.  Operators do not need to pass `--policy` when using the
/// standard Docker image.
pub const CONVENTIONAL_POLICY_PATH: &str = "/etc/jdc/policy.toml";

// ---------------------------------------------------------------------------
// Path resolution (pure function — easy to unit-test)
// ---------------------------------------------------------------------------

/// Resolve the effective policy path:
/// 1. Explicit path from `--policy` / `JDC_POLICY` wins.
/// 2. Otherwise probe `conventional`.
/// 3. If neither exists, return `None` (no policy, unchanged behaviour).
pub fn resolve_policy_path(explicit: Option<&Path>, conventional: &Path) -> Option<PathBuf> {
    if let Some(p) = explicit {
        return Some(p.to_owned());
    }
    if conventional.exists() {
        return Some(conventional.to_owned());
    }
    None
}

// ---------------------------------------------------------------------------
// Raw TOML deserialization
// ---------------------------------------------------------------------------

/// Loose top-level shape — we only care about `[inclusion]` strictly; every
/// other top-level key is either tolerated with a warning or explicitly
/// handled.
#[derive(Deserialize, Debug, Default)]
struct RawPolicy {
    #[serde(default)]
    inclusion: Option<RawInclusion>,

    #[serde(default)]
    attestation: Option<toml::Value>,

    /// Catch-all for any other top-level keys so serde doesn't reject them.
    #[serde(flatten)]
    extra: std::collections::BTreeMap<String, toml::Value>,
}

#[derive(Deserialize, Debug)]
struct RawInclusion {
    mode: Option<String>,

    /// Old-bundle section — tolerate + warn.
    #[serde(default)]
    preferences: Option<toml::Value>,

    /// Old-bundle section — tolerate + warn.
    #[serde(default)]
    guarantees: Option<toml::Value>,

    /// Unknown keys inside [inclusion].
    #[serde(flatten)]
    extra: std::collections::BTreeMap<String, toml::Value>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Load and validate a policy file.
///
/// Returns `Err` if:
/// - The file does not exist (when an explicit path was given).
/// - The file cannot be read or parsed.
/// - `[inclusion] mode` is missing.
/// - `[inclusion] mode` has a value other than `"include-all"`.
pub fn load_policy(path: &Path) -> Result<Policy, PolicyError> {
    if !path.exists() {
        return Err(PolicyError::NotFound(path.to_owned()));
    }

    let text = std::fs::read_to_string(path).map_err(|e| PolicyError::Io {
        path: path.to_owned(),
        source: e,
    })?;

    let raw: RawPolicy = toml::from_str(&text).map_err(|e| PolicyError::Parse(e.to_string()))?;

    let inclusion = raw.inclusion.ok_or(PolicyError::MissingMode)?;

    let mode_str = inclusion.mode.ok_or(PolicyError::MissingMode)?;

    let mode = match mode_str.as_str() {
        "include-all" => InclusionMode::IncludeAll,
        other => return Err(PolicyError::UnsupportedMode(other.to_owned())),
    };

    let mut deferred_warnings = Vec::new();

    // Deferred: [attestation]
    if raw.attestation.is_some() {
        deferred_warnings.push("attestation".to_string());
    }

    // Deferred: [inclusion.preferences]
    if inclusion.preferences.is_some() {
        deferred_warnings.push("inclusion.preferences".to_string());
    }

    // Deferred: [inclusion.guarantees]
    if inclusion.guarantees.is_some() {
        deferred_warnings.push("inclusion.guarantees".to_string());
    }

    // Deferred: unknown keys inside [inclusion] (excluding known ones)
    for key in inclusion.extra.keys() {
        deferred_warnings.push(format!("inclusion.{key} (unknown key)"));
    }

    // Forward-compat: unknown top-level sections (not inclusion, not attestation)
    for key in raw.extra.keys() {
        deferred_warnings.push(format!("{key} (unknown top-level section)"));
    }

    Ok(Policy {
        mode,
        deferred_warnings,
    })
}

// ---------------------------------------------------------------------------
// Tests — written BEFORE implementation (TDD)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // ------------------------------------------------------------------
    // resolve_policy_path tests
    // ------------------------------------------------------------------

    #[test]
    fn resolve_explicit_wins_over_conventional() {
        let explicit = NamedTempFile::new().unwrap();
        let conventional = NamedTempFile::new().unwrap();
        let result = resolve_policy_path(Some(explicit.path()), conventional.path());
        assert_eq!(result, Some(explicit.path().to_owned()));
    }

    #[test]
    fn resolve_explicit_returned_even_if_not_exists() {
        // The caller passes an explicit path that doesn't exist — resolve
        // returns it; load_policy will turn it into NotFound.
        let conventional = NamedTempFile::new().unwrap();
        let nonexistent = PathBuf::from("/tmp/__no_such_policy_test_file__.toml");
        let result = resolve_policy_path(Some(&nonexistent), conventional.path());
        assert_eq!(result, Some(nonexistent));
    }

    #[test]
    fn resolve_falls_back_to_conventional_when_exists() {
        let conventional = NamedTempFile::new().unwrap();
        let result = resolve_policy_path(None, conventional.path());
        assert_eq!(result, Some(conventional.path().to_owned()));
    }

    #[test]
    fn resolve_returns_none_when_neither_exists() {
        let nonexistent = PathBuf::from("/tmp/__no_such_conventional_policy__.toml");
        let result = resolve_policy_path(None, &nonexistent);
        assert!(result.is_none());
    }

    // ------------------------------------------------------------------
    // load_policy: error cases
    // ------------------------------------------------------------------

    #[test]
    fn load_missing_file_errors() {
        let path = PathBuf::from("/tmp/__missing_policy_file__.toml");
        let err = load_policy(&path).unwrap_err();
        assert!(
            matches!(err, PolicyError::NotFound(_)),
            "expected NotFound, got: {err}"
        );
    }

    #[test]
    fn load_missing_inclusion_section_errors() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "[attestation]\nfoo = 1").unwrap();
        let err = load_policy(f.path()).unwrap_err();
        assert!(
            matches!(err, PolicyError::MissingMode),
            "expected MissingMode, got: {err}"
        );
    }

    #[test]
    fn load_missing_mode_key_errors() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "[inclusion]\n# no mode key").unwrap();
        let err = load_policy(f.path()).unwrap_err();
        assert!(
            matches!(err, PolicyError::MissingMode),
            "expected MissingMode, got: {err}"
        );
    }

    #[test]
    fn load_unsupported_mode_errors_with_message() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "[inclusion]\nmode = \"exclude-list\"").unwrap();
        let err = load_policy(f.path()).unwrap_err();
        match &err {
            PolicyError::UnsupportedMode(m) => {
                assert_eq!(m, "exclude-list");
            }
            other => panic!("expected UnsupportedMode, got: {other}"),
        }
        let msg = err.to_string();
        assert!(msg.contains("not yet supported"), "msg: {msg}");
    }

    // ------------------------------------------------------------------
    // load_policy: success + deferred warnings
    // ------------------------------------------------------------------

    #[test]
    fn load_include_all_ok_no_warnings() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "[inclusion]\nmode = \"include-all\"").unwrap();
        let policy = load_policy(f.path()).unwrap();
        assert_eq!(policy.mode, InclusionMode::IncludeAll);
        assert!(
            policy.deferred_warnings.is_empty(),
            "expected no warnings, got: {:?}",
            policy.deferred_warnings
        );
    }

    #[test]
    fn load_attestation_section_produces_warning() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(
            f,
            "[inclusion]\nmode = \"include-all\"\n[attestation]\nscheme = \"tls\""
        )
        .unwrap();
        let policy = load_policy(f.path()).unwrap();
        assert_eq!(policy.mode, InclusionMode::IncludeAll);
        assert!(
            policy
                .deferred_warnings
                .iter()
                .any(|w| w.contains("attestation")),
            "expected attestation warning, got: {:?}",
            policy.deferred_warnings
        );
    }

    #[test]
    fn load_inclusion_preferences_produces_warning() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(
            f,
            "[inclusion]\nmode = \"include-all\"\n[inclusion.preferences]\nmin_fee_rate = 1"
        )
        .unwrap();
        let policy = load_policy(f.path()).unwrap();
        assert!(
            policy
                .deferred_warnings
                .iter()
                .any(|w| w.contains("inclusion.preferences")),
            "expected inclusion.preferences warning, got: {:?}",
            policy.deferred_warnings
        );
    }

    #[test]
    fn load_inclusion_guarantees_produces_warning() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(
            f,
            "[inclusion]\nmode = \"include-all\"\n[inclusion.guarantees]\ncoinbase = true"
        )
        .unwrap();
        let policy = load_policy(f.path()).unwrap();
        assert!(
            policy
                .deferred_warnings
                .iter()
                .any(|w| w.contains("inclusion.guarantees")),
            "expected inclusion.guarantees warning, got: {:?}",
            policy.deferred_warnings
        );
    }

    #[test]
    fn load_unknown_top_level_section_produces_warning() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(
            f,
            "[inclusion]\nmode = \"include-all\"\n[future_feature]\nfoo = \"bar\""
        )
        .unwrap();
        let policy = load_policy(f.path()).unwrap();
        assert!(
            policy
                .deferred_warnings
                .iter()
                .any(|w| w.contains("future_feature")),
            "expected future_feature warning, got: {:?}",
            policy.deferred_warnings
        );
    }

    #[test]
    fn load_unknown_inclusion_key_produces_warning() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "[inclusion]\nmode = \"include-all\"\nunknown_key = 42").unwrap();
        let policy = load_policy(f.path()).unwrap();
        assert!(
            policy
                .deferred_warnings
                .iter()
                .any(|w| w.contains("inclusion.unknown_key")),
            "expected inclusion.unknown_key warning, got: {:?}",
            policy.deferred_warnings
        );
    }

    #[test]
    fn load_multiple_deferred_sections() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(
            f,
            "[inclusion]\nmode = \"include-all\"\n[inclusion.preferences]\nrate = 1\n[attestation]\nscheme = \"tls\""
        )
        .unwrap();
        let policy = load_policy(f.path()).unwrap();
        assert_eq!(policy.mode, InclusionMode::IncludeAll);
        let warnings = &policy.deferred_warnings;
        assert!(
            warnings.iter().any(|w| w.contains("attestation")),
            "missing attestation: {:?}",
            warnings
        );
        assert!(
            warnings.iter().any(|w| w.contains("inclusion.preferences")),
            "missing inclusion.preferences: {:?}",
            warnings
        );
    }
}
