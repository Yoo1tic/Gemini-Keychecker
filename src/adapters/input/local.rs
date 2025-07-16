use anyhow::Result;
use std::{
    collections::HashSet, 
    fs, 
    path::Path, 
    str::FromStr,
};
use crate::types::ApiKey;

/// Load and validate API keys from a file
/// Returns a vector of unique, valid API keys
pub fn load_keys(path: &Path) -> Result<Vec<ApiKey>> {
    let keys_txt = fs::read_to_string(path)?;
    // Use HashSet to automatically deduplicate keys
    let unique_keys_set: HashSet<&str> = keys_txt
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .collect();

    let mut keys = Vec::new();
    let mut valid_keys_for_backup = Vec::new();

    for key_str in unique_keys_set {
        match ApiKey::from_str(key_str) {
            Ok(api_key) => {
                keys.push(api_key.clone());
                valid_keys_for_backup.push(api_key.as_str().to_string());
            }
            Err(e) => eprintln!("Skipping invalid key: {}", e),
        }
    }

    // Write validated keys to backup.txt
    let backup_content = valid_keys_for_backup.join("\n");
    if let Err(e) = fs::write("backup.txt", backup_content) {
        eprintln!("Failed to write backup file: {}", e);
    } else {
        println!(
            "Backup file created with {} valid keys",
            valid_keys_for_backup.len()
        );
    }

    Ok(keys)
}