use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{self, Command};
use std::time::Instant;

const ENCRYPTED_EXTS: &[&str] = &[
    "wncry", "locky", "enc", "locked", "crypted", "crypt", "encrypted", "ransomware",
];

const RANSOM_NOTES: &[&str] = &[
    "#_LEIA_ME_WNCRY_#.txt",
    "LEIA_ME.txt",
    "READ_ME.txt",
    "_INSTRUCOES_RESGATE.html",
    "HOW_TO_DECRYPT.txt",
    "YOUR_FILES_ARE_ENCRYPTED.txt",
];

fn ok(message: &str) {
    println!("  [ ok ] {}", message);
}

fn skip(message: &str) {
    println!("  [skip] {}", message);
}

fn warn(message: &str) {
    println!("  [aviso] {}", message);
}

fn title(message: &str) {
    println!("{}", "-".repeat(64));
    println!("  {}", message);
    println!("{}", "-".repeat(64));
}

fn home_dir() -> PathBuf {
    if let Ok(value) = env::var("USERPROFILE") {
        if !value.is_empty() {
            return PathBuf::from(value);
        }
    }
    env::var("HOME").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("."))
}

fn temp_dir() -> PathBuf {
    for key in ["TEMP", "TMP"] {
        if let Ok(value) = env::var(key) {
            if !value.is_empty() {
                return PathBuf::from(value);
            }
        }
    }
    if cfg!(windows) {
        PathBuf::from("C:\\Windows\\Temp")
    } else {
        PathBuf::from("/tmp")
    }
}

fn scan_roots() -> Vec<PathBuf> {
    #[allow(unused_mut)]
    let mut roots = vec![home_dir(), temp_dir()];
    #[cfg(not(windows))]
    {
        roots.push(PathBuf::from("/tmp"));
        roots.push(PathBuf::from("/mnt"));
    }
    roots
}

fn is_encrypted(path: &Path) -> bool {
    match path.extension().and_then(|value| value.to_str()) {
        Some(extension) => {
            let lowered = extension.to_ascii_lowercase();
            ENCRYPTED_EXTS.iter().any(|candidate| *candidate == lowered)
        }
        None => false,
    }
}

fn is_ransom_note(path: &Path) -> bool {
    match path.file_name().and_then(|value| value.to_str()) {
        Some(name) => RANSOM_NOTES.contains(&name),
        None => false,
    }
}

fn collect_files(root: &Path, out: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(_) => continue,
        };
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            collect_files(&path, out);
        } else if file_type.is_file() {
            out.push(path);
        }
    }
}

fn delete_directory(path: &Path, label: &str) {
    if path.exists() {
        match fs::remove_dir_all(path) {
            Ok(_) => ok(&format!("{}: {}", label, path.display())),
            Err(error) => warn(&format!("Falha ao remover {}: {}", path.display(), error)),
        }
    } else {
        skip(&format!("Não encontrado: {}", path.display()));
    }
}

fn delete_file(path: &Path, label: &str) {
    if path.exists() {
        match fs::remove_file(path) {
            Ok(_) => ok(label),
            Err(error) => warn(&format!("Falha ao remover {}: {}", path.display(), error)),
        }
    }
}

fn clean_test_dir(test_dir: &Path) {
    title("1 — Pasta de arquivos de teste");
    delete_directory(test_dir, "Pasta de teste");
}

fn clean_attack_residues() {
    title("2 — Resquícios de ataque no sistema");
    let mut removed = 0usize;

    for root in scan_roots() {
        if !root.exists() {
            continue;
        }
        let mut files = Vec::new();
        collect_files(&root, &mut files);
        for file in files {
            if is_encrypted(&file) || is_ransom_note(&file) {
                if fs::remove_file(&file).is_ok() {
                    removed += 1;
                }
            }
        }
    }

    let master_key = temp_dir().join(".master.key");
    if master_key.exists() {
        match fs::remove_file(&master_key) {
            Ok(_) => {
                removed += 1;
                ok(&format!("Chave mestra do ransomware ({}) removida.", master_key.display()));
            }
            Err(error) => warn(&format!("Falha ao remover {}: {}", master_key.display(), error)),
        }
    }

    let session_token = temp_dir().join(".session.token");
    if session_token.exists() {
        match fs::remove_file(&session_token) {
            Ok(_) => {
                removed += 1;
                ok(&format!("Token de sessao com a chave ({}) removido.", session_token.display()));
            }
            Err(error) => warn(&format!("Falha ao remover {}: {}", session_token.display(), error)),
        }
    }

    if removed > 0 {
        ok(&format!("{} arquivo(s) de ataque removidos do sistema.", removed));
    } else {
        skip("Nenhum arquivo de ataque encontrado.");
    }
}

fn clean_c2_log(root: &Path) {
    title("3 — Log do servidor C2");
    delete_file(&root.join("c2_events.json"), "Log do C2 (c2_events.json)");
}

#[cfg(not(windows))]
fn clean_persistence(root: &Path) {
    title("4 — Persistência no crontab");
    let output = match Command::new("crontab").arg("-l").output() {
        Ok(output) => output,
        Err(_) => {
            skip("Comando 'crontab' não disponível neste sistema.");
            return;
        }
    };

    if !output.status.success() || output.stdout.iter().all(|byte| byte.is_ascii_whitespace()) {
        skip("Crontab vazio.");
        return;
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let root_marker = root.to_string_lossy();
    let original: Vec<&str> = text.lines().collect();
    let cleaned: Vec<&str> = original
        .iter()
        .copied()
        .filter(|line| !line.contains(root_marker.as_ref()) && !line.contains("output/result_"))
        .collect();

    let removed = original.len() - cleaned.len();
    if removed == 0 {
        skip("Nenhuma entrada de persistência no crontab.");
        return;
    }

    if cleaned.is_empty() {
        let _ = Command::new("crontab").arg("-r").status();
    } else {
        let mut payload = cleaned.join("\n");
        payload.push('\n');
        if let Ok(mut child) = Command::new("crontab")
            .arg("-")
            .stdin(process::Stdio::piped())
            .spawn()
        {
            if let Some(stdin) = child.stdin.as_mut() {
                let _ = stdin.write_all(payload.as_bytes());
            }
            let _ = child.wait();
        }
    }
    ok(&format!("{} entrada(s) de persistência removidas do crontab.", removed));
}

#[cfg(windows)]
fn clean_persistence(root: &Path) {
    title("4 — Persistência no registro (Run)");
    let keys = [
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    ];
    let root_marker = root.to_string_lossy().to_lowercase();
    let mut removed = 0usize;

    for key in keys {
        let output = match Command::new("reg").args(["query", key]).output() {
            Ok(output) => output,
            Err(_) => continue,
        };
        if !output.status.success() {
            continue;
        }
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("HKEY") {
                continue;
            }
            let name = match trimmed.split_whitespace().next() {
                Some(name) => name,
                None => continue,
            };
            let lowered = trimmed.to_lowercase();
            if lowered.contains(&root_marker)
                || lowered.contains("output/result_")
                || lowered.contains("output\\result_")
                || lowered.contains("mssecsvc")
            {
                if Command::new("reg")
                    .args(["delete", key, "/v", name, "/f"])
                    .status()
                    .map(|status| status.success())
                    .unwrap_or(false)
                {
                    removed += 1;
                }
            }
        }
    }

    if removed > 0 {
        ok(&format!("{} entrada(s) de persistência removidas do registro.", removed));
    } else {
        skip("Nenhuma entrada de persistência encontrada no registro.");
    }
}

fn clean_pycache(root: &Path) {
    title("5 — Cache Python");
    let mut removed = 0usize;

    fn walk(directory: &Path, removed: &mut usize) {
        let entries = match fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(_) => return,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(_) => continue,
            };
            if file_type.is_dir() {
                if path.file_name().and_then(|value| value.to_str()) == Some("__pycache__") {
                    if fs::remove_dir_all(&path).is_ok() {
                        *removed += 1;
                    }
                    continue;
                }
                walk(&path, removed);
            } else if file_type.is_file()
                && path.extension().and_then(|value| value.to_str()) == Some("pyc")
                && fs::remove_file(&path).is_ok()
            {
                *removed += 1;
            }
        }
    }

    walk(root, &mut removed);
    if removed > 0 {
        ok(&format!("{} item(ns) de cache Python removidos.", removed));
    }
}

struct Options {
    test_dir: PathBuf,
    root: PathBuf,
    force: bool,
}

fn parse_args() -> Options {
    let mut test_dir = home_dir().join("Documentos_Teste");
    let mut root = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let mut force = false;

    let args: Vec<String> = env::args().skip(1).collect();
    let mut index = 0;
    while index < args.len() {
        let argument = args[index].as_str();
        match argument {
            "-d" | "--dest" => {
                index += 1;
                if let Some(value) = args.get(index) {
                    test_dir = PathBuf::from(value);
                }
            }
            "-r" | "--root" => {
                index += 1;
                if let Some(value) = args.get(index) {
                    root = PathBuf::from(value);
                }
            }
            "-f" | "--force" => force = true,
            "-h" | "--help" => {
                print_usage();
                process::exit(0);
            }
            other if other.starts_with('-') => {
                eprintln!("[ERRO] opcao desconhecida: {}", other);
                print_usage();
                process::exit(1);
            }
            _ => {}
        }
        index += 1;
    }

    Options { test_dir, root, force }
}

fn print_usage() {
    println!(
        "Uso: reset_vm [opcoes]\n\
         \n\
         Opcoes:\n\
           -d, --dest PATH    pasta de teste a remover (padrao: ~/Documentos_Teste)\n\
           -r, --root PATH    raiz do projeto (padrao: diretorio atual)\n\
           -f, --force        pula a confirmacao interativa\n\
           -h, --help         esta ajuda"
    );
}

fn confirm(test_dir: &Path) -> bool {
    println!("\n  O que será limpo:");
    println!("    • Pasta de teste   : {}", test_dir.display());
    println!("    • Arquivos .wncry, .locky, notas de resgate");
    println!("    • Log C2           : c2_events.json");
    println!("    • Persistência     : crontab (Linux) / registro Run (Windows)");
    print!("\n  Confirma? [s/N]: ");
    let _ = io::stdout().flush();

    let mut answer = String::new();
    if io::stdin().read_line(&mut answer).is_err() {
        return false;
    }
    matches!(answer.trim().to_ascii_lowercase().as_str(), "s" | "sim" | "y" | "yes")
}

fn main() {
    let options = parse_args();

    println!("{}", "=".repeat(64));
    println!("  LIMPEZA DA VM DE LABORATORIO");
    println!("{}", "=".repeat(64));

    if !options.force && !confirm(&options.test_dir) {
        println!("\n  Cancelado.\n");
        return;
    }

    let started = Instant::now();
    clean_test_dir(&options.test_dir);
    clean_attack_residues();
    clean_c2_log(&options.root);
    clean_persistence(&options.root);
    clean_pycache(&options.root);

    println!("\n{}", "-".repeat(64));
    println!("  conclusao : limpeza concluida em {:.1}s", started.elapsed().as_secs_f64());
    println!("{}\n", "=".repeat(64));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_encrypted_extensions_case_insensitively() {
        assert!(is_encrypted(Path::new("/x/a.pdf.wncry")));
        assert!(is_encrypted(Path::new("/x/a.pdf.WNCRY")));
        assert!(is_encrypted(Path::new("/x/a.locky")));
        assert!(!is_encrypted(Path::new("/x/a.pdf")));
        assert!(!is_encrypted(Path::new("/x/wncry")));
    }

    #[test]
    fn detects_ransom_notes_by_exact_name() {
        assert!(is_ransom_note(Path::new("/x/LEIA_ME.txt")));
        assert!(is_ransom_note(Path::new("/x/#_LEIA_ME_WNCRY_#.txt")));
        assert!(!is_ransom_note(Path::new("/x/leia_me.txt")));
    }
}
