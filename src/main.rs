use anyhow::Result;
use async_stream::stream;
use futures::{pin_mut, stream::StreamExt};
use gemini_keychecker::config::{KeyCheckerConfig, client_builder};
use gemini_keychecker::key_validator::validate_key_with_retry;
use gemini_keychecker::types::ApiKey;
use std::{
    collections::HashSet, fs, io::Write, path::Path, str::FromStr, thread::spawn, time::Instant,
};

/// Load and validate API keys from a file
/// Returns a vector of unique, valid API keys
fn load_keys(path: &Path) -> Result<Vec<ApiKey>> {
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

/// Main function - orchestrates the key validation process
#[tokio::main]
async fn main() -> Result<()> {
    let start_time = Instant::now();
    let conf = KeyCheckerConfig::load_config().unwrap();
    let keys = load_keys(&conf.input_path)?;
    let client = client_builder(&conf)?;

    // Create channel for streaming keys from producer to consumer
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<ApiKey>();
    let stream = stream! {
        while let Some(item) = rx.recv().await {
            yield item;
        }
    };

    // Spawn producer thread to send keys through channel
    spawn(move || {
        for key in keys {
            if let Err(e) = tx.send(key) {
                eprintln!("Failed to send key: {}", e);
            }
        }
    });

    // Create stream to validate keys concurrently
    let valid_keys_stream = stream
        .map(|key| validate_key_with_retry(&client, &conf.api_host, key))
        .buffer_unordered(conf.concurrency)
        .filter_map(|r| async { r });
    pin_mut!(valid_keys_stream);

    // Open output file for writing valid keys
    let mut output_file = fs::File::create(&conf.output_path)?;

    // Process validated keys and write to output file
    while let Some(valid_key) = valid_keys_stream.next().await {
        println!("Valid key found: {}", valid_key.as_str());
        if let Err(e) = writeln!(output_file, "{}", valid_key.as_str()) {
            eprintln!("Failed to write key to output file: {}", e);
        }
    }

    println!("Total Elapsed Time: {:?}", start_time.elapsed());
    Ok(())
}
