use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use sha2::{Digest, Sha256};

const VERSION_LEN: usize = 1;
const EXPECTED_VERSION: u8 = 1;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const KEY_LEN: usize = 32;
const ENCRYPTED_SUFFIX: &str = ".PROCESSED";

fn parse_key(input: &str) -> Result<Vec<u8>, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("chave vazia".to_string());
    }
    let bytes = if trimmed.len() == 2 * KEY_LEN && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        hex::decode(trimmed).map_err(|error| format!("hex invalido: {error}"))?
    } else {
        BASE64
            .decode(trimmed)
            .or_else(|_| hex::decode(trimmed))
            .map_err(|_| "a chave nao e base64 nem hex valido".to_string())?
    };
    if bytes.len() != KEY_LEN {
        return Err(format!(
            "a chave tem {} bytes; esperado {KEY_LEN}",
            bytes.len()
        ));
    }
    Ok(bytes)
}

fn decrypt_blob(key: &[u8], blob: &[u8]) -> Result<Vec<u8>, String> {
    if blob.len() < VERSION_LEN + NONCE_LEN + TAG_LEN {
        return Err(format!(
            "arquivo muito curto ({} bytes); minimo {}",
            blob.len(),
            VERSION_LEN + NONCE_LEN + TAG_LEN
        ));
    }
    if blob[0] != EXPECTED_VERSION {
        return Err(format!(
            "versao de formato {} nao suportada (esperado {})",
            blob[0], EXPECTED_VERSION
        ));
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| "chave invalida".to_string())?;
    let nonce = Nonce::from_slice(&blob[VERSION_LEN..VERSION_LEN + NONCE_LEN]);
    cipher
        .decrypt(nonce, &blob[VERSION_LEN + NONCE_LEN..])
        .map_err(|_| "autenticacao falhou: chave incorreta ou dados corrompidos".to_string())
}

fn sha256_bytes(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

fn sha256_file(path: &Path) -> io::Result<String> {
    Ok(sha256_bytes(&fs::read(path)?))
}

fn json_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other if (other as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", other as u32))
            }
            other => out.push(other),
        }
    }
    out
}

fn manifest_key(path: &str) -> String {
    path.replace('\\', "/")
}

fn load_manifest(path: &Path) -> Result<HashMap<String, String>, String> {
    let bytes =
        fs::read(path).map_err(|error| format!("nao foi possivel ler {}: {error}", path.display()))?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|error| format!("manifesto invalido: {error}"))?;
    let files = value
        .get("files")
        .and_then(|field| field.as_array())
        .ok_or("manifesto sem lista 'files'")?;
    let mut map = HashMap::new();
    for entry in files {
        let name = entry
            .get("path")
            .and_then(|field| field.as_str())
            .ok_or("entrada do manifesto sem 'path'")?;
        let digest = entry
            .get("sha256")
            .and_then(|field| field.as_str())
            .ok_or("entrada do manifesto sem 'sha256'")?;
        map.insert(manifest_key(name), digest.to_string());
    }
    Ok(map)
}

fn stripped_name(name: &str) -> String {
    if name.len() >= ENCRYPTED_SUFFIX.len() {
        let (head, tail) = name.split_at(name.len() - ENCRYPTED_SUFFIX.len());
        if tail.eq_ignore_ascii_case(ENCRYPTED_SUFFIX) {
            return head.to_string();
        }
    }
    format!("{name}.decrypted")
}

fn is_encrypted(path: &Path) -> bool {
    match path.file_name().and_then(|value| value.to_str()) {
        Some(name) => {
            name.len() > ENCRYPTED_SUFFIX.len()
                && name.to_ascii_uppercase().ends_with(ENCRYPTED_SUFFIX)
        }
        None => false,
    }
}

fn collect_targets(path: &Path, out: &mut Vec<PathBuf>) {
    if path.is_dir() {
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                let child = entry.path();
                if child.is_dir() {
                    collect_targets(&child, out);
                } else if is_encrypted(&child) {
                    out.push(child);
                }
            }
        }
    } else {
        out.push(path.to_path_buf());
    }
}

fn decrypt_file(key: &[u8], path: &Path, out_dir: Option<&Path>) -> Result<PathBuf, String> {
    let blob =
        fs::read(path).map_err(|error| format!("nao foi possivel ler {}: {error}", path.display()))?;
    let plaintext = decrypt_blob(key, &blob)?;
    let name = path
        .file_name()
        .map(|value| value.to_string_lossy().to_string())
        .unwrap_or_else(|| "saida".to_string());
    let target = match out_dir {
        Some(directory) => directory.join(stripped_name(&name)),
        None => path.with_file_name(stripped_name(&name)),
    };
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("nao foi possivel criar {}: {error}", parent.display()))?;
    }
    fs::write(&target, plaintext)
        .map_err(|error| format!("nao foi possivel escrever {}: {error}", target.display()))?;
    Ok(target)
}

fn key_from_token(path: &Path) -> Result<String, String> {
    let bytes =
        fs::read(path).map_err(|error| format!("nao foi possivel ler {}: {error}", path.display()))?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|error| format!("json invalido: {error}"))?;
    value
        .get("aes_key")
        .and_then(|field| field.as_str())
        .map(|value| value.to_string())
        .ok_or_else(|| "campo 'aes_key' ausente no token".to_string())
}

fn prompt(label: &str) -> String {
    print!("{label}");
    let _ = io::stdout().flush();
    let mut line = String::new();
    let _ = io::stdin().read_line(&mut line);
    line.trim().to_string()
}

struct Options {
    key: Option<String>,
    token: Option<PathBuf>,
    path: Option<PathBuf>,
    out_dir: Option<PathBuf>,
    manifest: Option<PathBuf>,
    report: Option<PathBuf>,
}

fn print_usage() {
    println!(
        "Uso: decrypt_file [opcoes]\n\
         \n\
         Opcoes:\n\
           -k, --key VALUE     chave AES em base64 ou hex (se ausente, pergunta)\n\
           -t, --token PATH    le o campo aes_key de um token JSON do C2\n\
           -p, --path PATH     arquivo .PROCESSED ou pasta (se ausente, pergunta)\n\
           -o, --out-dir PATH  pasta de saida (padrao: ao lado do arquivo)\n\
           -m, --manifest PATH manifest.json do generate_test_files para comparar hashes\n\
           --report PATH       grava relatorio JSON da recuperacao\n\
           -h, --help          esta ajuda"
    );
}

fn parse_args() -> Result<Options, String> {
    let mut options = Options {
        key: None,
        token: None,
        path: None,
        out_dir: None,
        manifest: None,
        report: None,
    };
    let args: Vec<String> = env::args().skip(1).collect();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "-k" | "--key" => {
                index += 1;
                options.key = Some(args.get(index).ok_or("falta o valor de --key")?.clone());
            }
            "-t" | "--token" => {
                index += 1;
                options.token =
                    Some(PathBuf::from(args.get(index).ok_or("falta o valor de --token")?));
            }
            "-p" | "--path" => {
                index += 1;
                options.path = Some(PathBuf::from(args.get(index).ok_or("falta o valor de --path")?));
            }
            "-o" | "--out-dir" => {
                index += 1;
                options.out_dir =
                    Some(PathBuf::from(args.get(index).ok_or("falta o valor de --out-dir")?));
            }
            "-m" | "--manifest" => {
                index += 1;
                options.manifest =
                    Some(PathBuf::from(args.get(index).ok_or("falta o valor de --manifest")?));
            }
            "--report" => {
                index += 1;
                options.report =
                    Some(PathBuf::from(args.get(index).ok_or("falta o valor de --report")?));
            }
            "-h" | "--help" => {
                print_usage();
                process::exit(0);
            }
            other => return Err(format!("opcao desconhecida: {other}")),
        }
        index += 1;
    }
    Ok(options)
}

fn main() {
    let options = match parse_args() {
        Ok(options) => options,
        Err(message) => {
            eprintln!("[ERRO] {message}");
            print_usage();
            process::exit(1);
        }
    };

    println!("\n{}", "=".repeat(55));
    println!("   VERIFICACAO DE DESCRIPTOGRAFIA — AES-256-GCM");
    println!("{}", "=".repeat(55));

    let key_input = if let Some(key) = options.key {
        key
    } else if let Some(token) = &options.token {
        match key_from_token(token) {
            Ok(key) => key,
            Err(message) => {
                eprintln!("[ERRO] {message}");
                process::exit(1);
            }
        }
    } else {
        prompt("  Chave AES (base64 ou hex): ")
    };

    let key = match parse_key(&key_input) {
        Ok(key) => key,
        Err(message) => {
            eprintln!("[ERRO] {message}");
            process::exit(1);
        }
    };

    let path = options
        .path
        .unwrap_or_else(|| PathBuf::from(prompt("  Arquivo ou pasta: ")));

    let mut targets = Vec::new();
    collect_targets(&path, &mut targets);
    if targets.is_empty() {
        println!("\n  Nenhum arquivo .PROCESSED encontrado em {}\n", path.display());
        return;
    }

    let verify_base: PathBuf = match &options.out_dir {
        Some(directory) => directory.clone(),
        None if path.is_dir() => path.clone(),
        None => path
            .parent()
            .map(|parent| parent.to_path_buf())
            .unwrap_or_else(|| PathBuf::from(".")),
    };
    let manifest = match &options.manifest {
        Some(manifest_path) => match load_manifest(manifest_path) {
            Ok(map) => Some(map),
            Err(message) => {
                eprintln!("[ERRO] {message}");
                process::exit(1);
            }
        },
        None => None,
    };

    let mut decrypted: Vec<(PathBuf, PathBuf)> = Vec::new();
    let mut failures: Vec<(PathBuf, String)> = Vec::new();
    for target in &targets {
        match decrypt_file(&key, target, options.out_dir.as_deref()) {
            Ok(output) => {
                println!("  [ok]    {} -> {}", target.display(), output.display());
                decrypted.push((target.clone(), output));
            }
            Err(message) => {
                println!("  [falha] {}: {message}", target.display());
                failures.push((target.clone(), message));
            }
        }
    }

    let mut matched = 0usize;
    let mut mismatched = 0usize;
    let mut unlisted: Vec<String> = Vec::new();
    let mut seen: HashMap<String, bool> = HashMap::new();
    let mut entries_json = String::new();
    if let Some(expected) = &manifest {
        for (_, output) in &decrypted {
            let relative = output
                .strip_prefix(&verify_base)
                .map(|value| manifest_key(&value.to_string_lossy()))
                .unwrap_or_else(|_| manifest_key(&output.to_string_lossy()));
            let observed = sha256_file(output).unwrap_or_default();
            let status = match expected.get(&relative) {
                Some(want) if want == &observed => {
                    matched += 1;
                    seen.insert(relative.clone(), true);
                    "matched"
                }
                Some(_) => {
                    mismatched += 1;
                    seen.insert(relative.clone(), true);
                    "mismatched"
                }
                None => {
                    unlisted.push(relative.clone());
                    "unlisted"
                }
            };
            if !entries_json.is_empty() {
                entries_json.push(',');
            }
            entries_json.push_str(&format!(
                "{{\"file\":\"{}\",\"expected\":\"{}\",\"observed\":\"{}\",\"status\":\"{}\"}}",
                json_escape(&relative),
                json_escape(&expected.get(&relative).cloned().unwrap_or_default()),
                json_escape(&observed),
                status
            ));
            println!("  [hash:{status}] {relative}");
        }
    }
    let missing: Vec<String> = manifest
        .as_ref()
        .map(|expected| {
            expected
                .keys()
                .filter(|name| !seen.contains_key(*name))
                .cloned()
                .collect()
        })
        .unwrap_or_default();

    if let Some(report_path) = &options.report {
        let mut decrypted_json = String::new();
        for (input, output) in &decrypted {
            if !decrypted_json.is_empty() {
                decrypted_json.push(',');
            }
            decrypted_json.push_str(&format!(
                "{{\"input\":\"{}\",\"output\":\"{}\"}}",
                json_escape(&input.to_string_lossy()),
                json_escape(&output.to_string_lossy())
            ));
        }
        let mut failures_json = String::new();
        for (input, message) in &failures {
            if !failures_json.is_empty() {
                failures_json.push(',');
            }
            failures_json.push_str(&format!(
                "{{\"input\":\"{}\",\"error\":\"{}\"}}",
                json_escape(&input.to_string_lossy()),
                json_escape(message)
            ));
        }
        let mut missing_json = String::new();
        for name in &missing {
            if !missing_json.is_empty() {
                missing_json.push(',');
            }
            missing_json.push_str(&format!("\"{}\"", json_escape(name)));
        }
        let report = format!(
            "{{\"schema_version\":\"1.0\",\"decrypted\":[{}],\"failures\":[{}],\
             \"hash_check\":{{\"manifest\":\"{}\",\"matched\":{},\"mismatched\":{},\
             \"unlisted\":{},\"missing\":[{}],\"entries\":[{}]}}}}",
            decrypted_json,
            failures_json,
            json_escape(
                &options
                    .manifest
                    .as_deref()
                    .map(|value| value.to_string_lossy().to_string())
                    .unwrap_or_default()
            ),
            matched,
            mismatched,
            unlisted.len(),
            missing_json,
            entries_json
        );
        if let Err(error) = fs::write(report_path, report) {
            eprintln!("[ERRO] nao foi possivel escrever o relatorio: {error}");
            process::exit(1);
        }
        println!("  Relatorio: {}", report_path.display());
    }

    println!("\n{}", "=".repeat(55));
    println!(
        "  {} descriptografado(s), {} falha(s)",
        decrypted.len(),
        failures.len()
    );
    if manifest.is_some() {
        println!(
            "  hashes: {matched} iguais, {mismatched} divergentes, {} nao listados, {} ausentes",
            unlisted.len(),
            missing.len()
        );
    }
    println!("{}\n", "=".repeat(55));

    if !failures.is_empty() || mismatched > 0 {
        process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> (Vec<u8>, Vec<u8>) {
        let key = vec![7u8; KEY_LEN];
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce = [3u8; NONCE_LEN];
        let plaintext = b"conteudo de teste".to_vec();
        let ciphertext_tag = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_slice())
            .unwrap();
        let mut blob = vec![EXPECTED_VERSION];
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ciphertext_tag);
        (key, blob)
    }

    #[test]
    fn round_trips_the_c_layout() {
        let (key, blob) = sample();
        let plaintext = decrypt_blob(&key, &blob).unwrap();
        assert_eq!(plaintext, b"conteudo de teste");
    }

    #[test]
    fn rejects_unknown_format_version() {
        let (key, mut blob) = sample();
        blob[0] = 9;
        assert!(decrypt_blob(&key, &blob).is_err());
    }

    #[test]
    fn normalizes_manifest_paths() {
        assert_eq!(manifest_key("a\\b/c.txt"), "a/b/c.txt");
        assert_eq!(sha256_bytes(b"abc"), sha256_bytes(b"abc"));
        assert_ne!(sha256_bytes(b"abc"), sha256_bytes(b"abd"));
    }

    #[test]
    fn rejects_wrong_key() {
        let (_, blob) = sample();
        let wrong = vec![9u8; KEY_LEN];
        assert!(decrypt_blob(&wrong, &blob).is_err());
    }

    #[test]
    fn parses_base64_and_hex_keys() {
        let key = vec![0xAB; KEY_LEN];
        let base64 = BASE64.encode(&key);
        let hex_key = hex::encode(&key);
        assert_eq!(parse_key(&base64).unwrap(), key);
        assert_eq!(parse_key(&hex_key).unwrap(), key);
        assert!(parse_key("curta").is_err());
    }

    #[test]
    fn strips_the_encrypted_suffix_case_insensitively() {
        assert_eq!(stripped_name("a.pdf.PROCESSED"), "a.pdf");
        assert_eq!(stripped_name("a.pdf.processed"), "a.pdf");
        assert_eq!(stripped_name("a.pdf"), "a.pdf.decrypted");
    }
}
