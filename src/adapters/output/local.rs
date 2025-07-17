use crate::types::ApiKey;
use anyhow::Result;
use std::{fs, io::Write};
use tokio::io::{AsyncWriteExt, BufWriter};
use toml::Value;

// Write valid key to output file
pub async fn write_keys_txt_file(
    file: &mut BufWriter<tokio::fs::File>,
    key: &ApiKey,
) -> Result<()> {
    file.write_all(key.as_str().as_bytes()).await?;
    Ok(())
}

// Write valid key to output file in Clewdr format
pub fn write_keys_clewdr_format(file: &mut fs::File, key: &ApiKey) -> Result<()> {
    let mut table = toml::value::Table::new();
    table.insert("key".to_string(), Value::String(key.as_str().to_string()));

    let gemini_keys = Value::Array(vec![Value::Table(table)]);
    let mut root = toml::value::Table::new();
    root.insert("gemini_keys".to_string(), gemini_keys);

    let toml_string = toml::to_string(&Value::Table(root))?;
    write!(file, "{}", toml_string)?;
    Ok(())
}
