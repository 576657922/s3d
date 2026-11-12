use std::fs;
use std::path::{Path, PathBuf};

use s3d_types::{AccountRecord, ObjectOwnership, OwnerInfo, SecretKey, DEFAULT_MAX_OBJECT_SIZE};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ServerConfig {
    pub listen: String,
    pub admin_listen: String,
    pub data_dir: PathBuf,
    pub region: String,
    pub credentials_file: PathBuf,
    pub base_domain: String,
    pub max_object_size: u64,
    pub max_buckets_per_account: usize,
    pub default_object_ownership: String,
    pub group_commit_window_ms: u64,
    pub group_commit_max_batch: usize,
    pub segment_size: u64,
    pub wal_file_size: u64,
    pub checkpoint_wal_bytes: u64,
    pub checkpoint_interval: String,
    pub gc_live_ratio: f64,
    pub completed_upload_retention: String,
    pub max_connections: usize,
    pub log_format: String,
    pub reserved_disk_bytes: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:8000".to_string(),
            admin_listen: "127.0.0.1:9000".to_string(),
            data_dir: PathBuf::from("./data"),
            region: "us-east-1".to_string(),
            credentials_file: PathBuf::from("./credentials.toml"),
            base_domain: String::new(),
            max_object_size: DEFAULT_MAX_OBJECT_SIZE,
            max_buckets_per_account: 10_000,
            default_object_ownership: "BucketOwnerEnforced".to_string(),
            group_commit_window_ms: 1,
            group_commit_max_batch: 64,
            segment_size: 1024 * 1024 * 1024,
            wal_file_size: 256 * 1024 * 1024,
            checkpoint_wal_bytes: 256 * 1024 * 1024,
            checkpoint_interval: "10m".to_string(),
            gc_live_ratio: 0.5,
            completed_upload_retention: "24h".to_string(),
            max_connections: 1024,
            log_format: "json".to_string(),
            reserved_disk_bytes: 2 * 1024 * 1024 * 1024,
        }
    }
}

impl ServerConfig {
    pub fn from_toml_str(raw: &str) -> Result<Self, String> {
        let cfg: Self = toml::from_str(raw).map_err(|e| format!("invalid config TOML: {e}"))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn load_file(path: &Path) -> Result<Self, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("failed to read config {}: {e}", path.display()))?;
        Self::from_toml_str(&content)
    }

    pub fn parsed_object_ownership(&self) -> Result<ObjectOwnership, String> {
        match self.default_object_ownership.as_str() {
            "BucketOwnerEnforced" => Ok(ObjectOwnership::BucketOwnerEnforced),
            "ObjectWriter" => Ok(ObjectOwnership::ObjectWriter),
            "BucketOwnerPreferred" => Ok(ObjectOwnership::BucketOwnerPreferred),
            other => Err(format!(
                "invalid default_object_ownership '{other}'; expected BucketOwnerEnforced, ObjectWriter, or BucketOwnerPreferred"
            )),
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        let _ = self.parsed_object_ownership()?;
        if self.region.trim().is_empty() {
            return Err("region cannot be empty".into());
        }
        if self.max_connections == 0 {
            return Err("max_connections must be >= 1".into());
        }
        if !(0.0..=1.0).contains(&self.gc_live_ratio) {
            return Err("gc_live_ratio must be in 0.0..=1.0".into());
        }
        if !matches!(self.log_format.as_str(), "json" | "pretty" | "compact") {
            return Err(format!("unsupported log_format '{}'", self.log_format));
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCredentialsFile {
    accounts: Vec<RawAccount>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAccount {
    user_id: String,
    display_name: String,
    #[serde(default)]
    email: String,
    access_key: String,
    secret_key: String,
}

/// Load `credentials.toml`, enforcing `0600` file permissions (`NFR-7`).
pub fn load_credentials_file(path: &Path) -> Result<Vec<AccountRecord>, String> {
    let meta = fs::metadata(path)
        .map_err(|e| format!("failed to stat credentials file {}: {e}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = meta.mode() & 0o777;
        if mode != 0o600 {
            return Err(format!(
                "credentials file {} has insecure permissions {:04o}; must be 0600 (NFR-7)",
                path.display(),
                mode
            ));
        }
    }

    let content = fs::read_to_string(path)
        .map_err(|e| format!("failed to read credentials file {}: {e}", path.display()))?;
    let parsed: RawCredentialsFile = toml::from_str(&content)
        .map_err(|e| format!("invalid credentials TOML {}: {e}", path.display()))?;

    if parsed.accounts.is_empty() {
        return Err("credentials file contains 0 accounts".into());
    }

    let mut out = Vec::with_capacity(parsed.accounts.len());
    for acc in parsed.accounts {
        if acc.access_key.is_empty() || acc.secret_key.is_empty() || acc.user_id.is_empty() {
            return Err("account record has empty user_id, access_key, or secret_key".into());
        }
        out.push(AccountRecord {
            owner: OwnerInfo {
                user_id: acc.user_id,
                display_name: acc.display_name,
                email: acc.email,
            },
            access_key: acc.access_key,
            secret_key: SecretKey::new(acc.secret_key),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_config_field_rejected_nfr15() {
        let bad = r#"
            listen = "127.0.0.1:8000"
            typo_unknown_option = 42
        "#;
        assert!(ServerConfig::from_toml_str(bad).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn credentials_file_must_be_0600_nfr7() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let cred_path = dir.path().join("credentials.toml");
        fs::write(
            &cred_path,
            r#"
[[accounts]]
user_id = "u1"
display_name = "User 1"
email = "u1@example.com"
access_key = "AK1"
secret_key = "SK1"
"#,
        )
        .unwrap();

        fs::set_permissions(&cred_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_credentials_file(&cred_path).is_err());

        fs::set_permissions(&cred_path, fs::Permissions::from_mode(0o600)).unwrap();
        let accounts = load_credentials_file(&cred_path).unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(format!("{:?}", accounts[0].secret_key), "[REDACTED]");
    }
}
