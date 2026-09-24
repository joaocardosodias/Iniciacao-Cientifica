use std::collections::HashSet;
use std::env;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;

const FOLDER_TREE: &[&str] = &[
    "Documentos/Financeiro/2023",
    "Documentos/Financeiro/2024",
    "Documentos/Financeiro/2025",
    "Documentos/Financeiro/Notas Fiscais",
    "Documentos/Financeiro/Extratos Bancários",
    "Documentos/RH/Contratos",
    "Documentos/RH/Folha de Pagamento",
    "Documentos/RH/Currículos",
    "Documentos/Jurídico/Contratos Clientes",
    "Documentos/Jurídico/Contratos Fornecedores",
    "Documentos/Jurídico/LGPD",
    "Documentos/Projetos/Alpha",
    "Documentos/Projetos/Beta",
    "Documentos/Projetos/Confidencial",
    "Documentos/Clientes/Ativos",
    "Documentos/Clientes/Inativos",
    "Desktop/Relatórios",
    "Desktop/Reuniões",
    "Downloads/Recebidos",
    "Pictures/Capturas",
];

const EXTENSIONS: &[&str] = &[".xlsx", ".docx", ".pdf", ".txt"];
const EXT_WEIGHTS: &[u32] = &[35, 30, 20, 15];

const FINANCEIRO: &[&str] = &[
    "Balancete", "DRE", "Fluxo_de_Caixa", "Orcamento", "Fatura",
    "Nota_Fiscal", "Extrato", "Recibo", "Planilha_Custos", "Budget",
];
const RH: &[&str] = &[
    "Contrato_CLT", "Folha_Pagamento", "Ficha_Cadastral", "Ferias",
    "Rescisao", "Admissao", "Curriculo", "Avaliacao_Desempenho",
];
const JURIDICO: &[&str] = &[
    "Contrato_Prestacao", "Acordo_NDA", "Termo_Confidencialidade",
    "Procuracao", "Ata_Reuniao", "Politica_Privacidade", "LGPD_Conformidade",
];
const PROJETOS: &[&str] = &[
    "Escopo_Projeto", "Cronograma", "Requisitos", "Arquitetura",
    "Proposta_Tecnica", "Ata_Sprint", "Roadmap", "Kickoff",
];
const GERAL: &[&str] = &[
    "Relatorio", "Apresentacao", "Resumo", "Documento", "Arquivo",
    "Notas", "Backup_Dados", "Planilha", "Memorando", "Oficio",
];

const LAST_NAMES: &[&str] = &[
    "Silva", "Santos", "Oliveira", "Souza", "Rodrigues", "Ferreira",
    "Alves", "Pereira", "Lima", "Gomes", "Costa", "Ribeiro", "Martins",
    "Carvalho", "Almeida", "Lopes", "Soares", "Fernandes", "Vieira", "Barbosa",
];

const COMPANIES: &[&str] = &[
    "NovaPay Tecnologia", "Globex Sistemas", "Acme Logistica", "Vertex Cloud",
    "Delta Financeira", "Orion Servicos", "Meridian Corp", "Atlas Infraestrutura",
];

const WORDS: &[&str] = &[
    "sistema", "processo", "arquivo", "cliente", "relatorio", "dados",
    "empresa", "usuario", "servico", "projeto", "equipe", "gestao",
    "financeiro", "contrato", "documento", "registro", "controle", "acesso",
    "recurso", "plataforma", "operacao", "resultado", "indicador", "fluxo",
    "unidade", "setor", "politica", "prazo", "revisao", "analise", "padrao",
    "integracao", "seguranca", "auditoria", "conformidade", "infraestrutura",
];

fn os_random_u64() -> u64 {
    let mut buf = [0u8; 8];
    if let Ok(mut file) = File::open("/dev/urandom") {
        if file.read_exact(&mut buf).is_ok() {
            return u64::from_le_bytes(buf);
        }
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E3779B97F4A7C15);
    nanos ^ (process::id() as u64).wrapping_mul(0x9E3779B97F4A7C15)
}

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }

    fn range(&mut self, lo: i64, hi: i64) -> i64 {
        if hi <= lo {
            lo
        } else {
            lo + (self.next_u64() % (hi - lo) as u64) as i64
        }
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }

    fn weighted_extension(&mut self) -> usize {
        let total: u32 = EXT_WEIGHTS.iter().sum();
        let mut point = (self.next_u64() % total as u64) as u32;
        for (index, weight) in EXT_WEIGHTS.iter().enumerate() {
            if point < *weight {
                return index;
            }
            point -= *weight;
        }
        EXTENSIONS.len() - 1
    }
}

fn sentence(rng: &mut Rng) -> String {
    let count = 6 + rng.below(8);
    let mut text = String::new();
    for index in 0..count {
        if index > 0 {
            text.push(' ');
        }
        text.push_str(rng.pick(WORDS));
    }
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => text,
    }
}

fn paragraph(rng: &mut Rng) -> String {
    let count = 2 + rng.below(4);
    let mut text = String::new();
    for index in 0..count {
        if index > 0 {
            text.push(' ');
        }
        text.push_str(&sentence(rng));
    }
    text
}

fn random_filename(rng: &mut Rng) -> String {
    let pools: [&[&str]; 5] = [FINANCEIRO, RH, JURIDICO, PROJETOS, GERAL];
    let pool = rng.pick(&pools);
    let prefix = rng.pick(pool);
    let suffix = match rng.below(5) {
        0 => format!("{:04}{:02}{:02}", rng.range(2018, 2026), rng.range(1, 13), rng.range(1, 29)),
        1 => format!("{}", rng.range(100, 10000)),
        2 => rng.pick(LAST_NAMES).to_string(),
        3 => format!("v{}", rng.range(1, 6)),
        _ => format!("rev{}", rng.range(1, 4)),
    };
    format!("{}_{}", prefix, suffix)
}

fn xml_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(ch),
        }
    }
    out
}

fn crc32_table() -> &'static [u32; 256] {
    static TABLE: OnceLock<[u32; 256]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut table = [0u32; 256];
        for (index, slot) in table.iter_mut().enumerate() {
            let mut value = index as u32;
            for _ in 0..8 {
                value = if value & 1 != 0 {
                    0xEDB88320 ^ (value >> 1)
                } else {
                    value >> 1
                };
            }
            *slot = value;
        }
        table
    })
}

fn crc32(data: &[u8]) -> u32 {
    let table = crc32_table();
    let mut crc = 0xFFFF_FFFFu32;
    for byte in data {
        crc = table[((crc ^ *byte as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

struct Zip {
    data: Vec<u8>,
    entries: Vec<(String, u32, u32, u32)>,
}

impl Zip {
    fn new() -> Self {
        Zip { data: Vec::new(), entries: Vec::new() }
    }

    fn add(&mut self, name: &str, content: &[u8]) {
        let offset = self.data.len() as u32;
        let crc = crc32(content);
        let size = content.len() as u32;
        let name_bytes = name.as_bytes();
        self.data.extend_from_slice(&0x0403_4B50u32.to_le_bytes());
        self.data.extend_from_slice(&20u16.to_le_bytes());
        self.data.extend_from_slice(&0u16.to_le_bytes());
        self.data.extend_from_slice(&0u16.to_le_bytes());
        self.data.extend_from_slice(&0u16.to_le_bytes());
        self.data.extend_from_slice(&0u16.to_le_bytes());
        self.data.extend_from_slice(&crc.to_le_bytes());
        self.data.extend_from_slice(&size.to_le_bytes());
        self.data.extend_from_slice(&size.to_le_bytes());
        self.data.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        self.data.extend_from_slice(&0u16.to_le_bytes());
        self.data.extend_from_slice(name_bytes);
        self.data.extend_from_slice(content);
        self.entries.push((name.to_string(), crc, size, offset));
    }

    fn finish(mut self) -> Vec<u8> {
        let central_start = self.data.len() as u32;
        for (name, crc, size, offset) in &self.entries {
            let name_bytes = name.as_bytes();
            self.data.extend_from_slice(&0x0201_4B50u32.to_le_bytes());
            self.data.extend_from_slice(&20u16.to_le_bytes());
            self.data.extend_from_slice(&20u16.to_le_bytes());
            self.data.extend_from_slice(&0u16.to_le_bytes());
            self.data.extend_from_slice(&0u16.to_le_bytes());
            self.data.extend_from_slice(&0u16.to_le_bytes());
            self.data.extend_from_slice(&0u16.to_le_bytes());
            self.data.extend_from_slice(&crc.to_le_bytes());
            self.data.extend_from_slice(&size.to_le_bytes());
            self.data.extend_from_slice(&size.to_le_bytes());
            self.data.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
            self.data.extend_from_slice(&0u16.to_le_bytes());
            self.data.extend_from_slice(&0u16.to_le_bytes());
            self.data.extend_from_slice(&0u16.to_le_bytes());
            self.data.extend_from_slice(&0u16.to_le_bytes());
            self.data.extend_from_slice(&0u32.to_le_bytes());
            self.data.extend_from_slice(&offset.to_le_bytes());
            self.data.extend_from_slice(name_bytes);
        }
        let central_size = self.data.len() as u32 - central_start;
        let count = self.entries.len() as u16;
        self.data.extend_from_slice(&0x0605_4B50u32.to_le_bytes());
        self.data.extend_from_slice(&0u16.to_le_bytes());
        self.data.extend_from_slice(&0u16.to_le_bytes());
        self.data.extend_from_slice(&count.to_le_bytes());
        self.data.extend_from_slice(&count.to_le_bytes());
        self.data.extend_from_slice(&central_size.to_le_bytes());
        self.data.extend_from_slice(&central_start.to_le_bytes());
        self.data.extend_from_slice(&0u16.to_le_bytes());
        self.data
    }
}

fn content_types_xlsx() -> &'static str {
    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Default Extension=\"xml\" ContentType=\"application/xml\"/><Override PartName=\"/xl/workbook.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml\"/><Override PartName=\"/xl/worksheets/sheet1.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml\"/></Types>"
}

fn rels_xlsx() -> &'static str {
    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"xl/workbook.xml\"/></Relationships>"
}

fn workbook_xlsx() -> &'static str {
    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\"><sheets><sheet name=\"Dados\" sheetId=\"1\" r:id=\"rId1\"/></sheets></workbook>"
}

fn workbook_rels_xlsx() -> &'static str {
    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet\" Target=\"worksheets/sheet1.xml\"/></Relationships>"
}

fn build_xlsx(rng: &mut Rng) -> Vec<u8> {
    let headers = ["Nome", "Valor", "Data", "Departamento"];
    let mut sheet = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><sheetData>",
    );
    sheet.push_str("<row r=\"1\">");
    for (column, header) in headers.iter().enumerate() {
        sheet.push_str(&format!(
            "<c r=\"{}1\" t=\"inlineStr\"><is><t>{}</t></is></c>",
            (b'A' + column as u8) as char,
            header
        ));
    }
    sheet.push_str("</row>");

    let rows = 20 + rng.below(80);
    for row in 0..rows {
        let row_number = row + 2;
        sheet.push_str(&format!("<row r=\"{}\">", row_number));
        for column in 0..headers.len() {
            let reference = format!("{}{}", (b'A' + column as u8) as char, row_number);
            match column {
                0 => sheet.push_str(&format!(
                    "<c r=\"{}\" t=\"inlineStr\"><is><t>{}</t></is></c>",
                    reference,
                    xml_escape(rng.pick(LAST_NAMES))
                )),
                1 => sheet.push_str(&format!("<c r=\"{}\"><v>{}</v></c>", reference, rng.range(1000, 150000))),
                2 => sheet.push_str(&format!(
                    "<c r=\"{}\" t=\"inlineStr\"><is><t>{:04}-{:02}-{:02}</t></is></c>",
                    reference,
                    rng.range(2018, 2026),
                    rng.range(1, 13),
                    rng.range(1, 29)
                )),
                _ => sheet.push_str(&format!(
                    "<c r=\"{}\" t=\"inlineStr\"><is><t>{}</t></is></c>",
                    reference,
                    xml_escape(rng.pick(COMPANIES))
                )),
            }
        }
        sheet.push_str("</row>");
    }
    sheet.push_str("</sheetData></worksheet>");

    let mut zip = Zip::new();
    zip.add("[Content_Types].xml", content_types_xlsx().as_bytes());
    zip.add("_rels/.rels", rels_xlsx().as_bytes());
    zip.add("xl/workbook.xml", workbook_xlsx().as_bytes());
    zip.add("xl/_rels/workbook.xml.rels", workbook_rels_xlsx().as_bytes());
    zip.add("xl/worksheets/sheet1.xml", sheet.as_bytes());
    zip.finish()
}

fn content_types_docx() -> &'static str {
    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/><Default Extension=\"xml\" ContentType=\"application/xml\"/><Override PartName=\"/word/document.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml\"/></Types>"
}

fn rels_docx() -> &'static str {
    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"><Relationship Id=\"rId1\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument\" Target=\"word/document.xml\"/></Relationships>"
}

fn build_docx(rng: &mut Rng) -> Vec<u8> {
    let mut body = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"><w:body>",
    );
    body.push_str(&format!(
        "<w:p><w:r><w:t>{}</w:t></w:r></w:p>",
        xml_escape(&format!("{} - {:04}-{:02}-{:02}", rng.pick(COMPANIES), rng.range(2018, 2026), rng.range(1, 13), rng.range(1, 29)))
    ));
    let count = 3 + rng.below(6);
    for _ in 0..count {
        body.push_str(&format!(
            "<w:p><w:r><w:t>{}</w:t></w:r></w:p>",
            xml_escape(&paragraph(rng))
        ));
    }
    body.push_str("</w:body></w:document>");

    let mut zip = Zip::new();
    zip.add("[Content_Types].xml", content_types_docx().as_bytes());
    zip.add("_rels/.rels", rels_docx().as_bytes());
    zip.add("word/document.xml", body.as_bytes());
    zip.finish()
}

fn pdf_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '(' => out.push_str("\\("),
            ')' => out.push_str("\\)"),
            '\\' => out.push_str("\\\\"),
            '\n' | '\r' => out.push(' '),
            _ => out.push(ch),
        }
    }
    out
}

fn build_pdf(rng: &mut Rng) -> Vec<u8> {
    let mut content = String::from("BT\n/F1 12 Tf\n50 790 Td\n16 TL\n");
    content.push_str(&format!("({}) Tj\nT*\n", pdf_escape(&format!("{} - Relatorio", rng.pick(COMPANIES)))));
    let lines = 8 + rng.below(20);
    for _ in 0..lines {
        content.push_str(&format!("({}) Tj\nT*\n", pdf_escape(&sentence(rng))));
    }
    content.push_str("ET\n");

    let objects = vec![
        "<</Type/Catalog/Pages 2 0 R>>".to_string(),
        "<</Type/Pages/Kids[3 0 R]/Count 1>>".to_string(),
        "<</Type/Page/Parent 2 0 R/MediaBox[0 0 595 842]/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>".to_string(),
        format!("<</Length {}>>\nstream\n{}endstream", content.len(), content),
        "<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>".to_string(),
    ];

    let mut document = String::from("%PDF-1.4\n");
    let mut offsets = Vec::new();
    for (index, object) in objects.iter().enumerate() {
        offsets.push(document.len());
        document.push_str(&format!("{} 0 obj\n{}\nendobj\n", index + 1, object));
    }
    let xref_offset = document.len();
    document.push_str(&format!("xref\n0 {}\n", objects.len() + 1));
    document.push_str("0000000000 65535 f \n");
    for offset in &offsets {
        document.push_str(&format!("{:010} 00000 n \n", offset));
    }
    document.push_str(&format!(
        "trailer\n<</Size {}/Root 1 0 R>>\nstartxref\n{}\n%%EOF\n",
        objects.len() + 1,
        xref_offset
    ));
    document.into_bytes()
}

fn write_txt(path: &Path, rng: &mut Rng) -> io::Result<()> {
    let mut text = format!(
        "{} - {}\nData: {:04}-{:02}-{:02}\nAutor: {}\n\n",
        rng.pick(COMPANIES),
        xml_escape(&sentence(rng)),
        rng.range(2018, 2026),
        rng.range(1, 13),
        rng.range(1, 29),
        rng.pick(LAST_NAMES),
    );
    let count = 2 + rng.below(5);
    for index in 0..count {
        if index > 0 {
            text.push('\n');
        }
        text.push_str(&paragraph(rng));
        text.push('\n');
    }
    fs::write(path, text)
}

fn write_simple(path: &Path, rng: &mut Rng) -> io::Result<()> {
    let size = 4096 + rng.below(127 * 1024);
    let mut buffer = vec![0u8; size];
    let mut seed = rng.next_u64();
    for chunk in buffer.chunks_mut(8) {
        seed ^= seed >> 12;
        seed ^= seed << 25;
        seed ^= seed >> 27;
        let bytes = seed.wrapping_mul(0x2545F4914F6CDD1D).to_le_bytes();
        let length = chunk.len().min(8);
        chunk[..length].copy_from_slice(&bytes[..length]);
    }
    fs::write(path, buffer)
}

fn write_real(path: &Path, extension: usize, rng: &mut Rng) -> io::Result<()> {
    match extension {
        0 => fs::write(path, build_xlsx(rng)),
        1 => fs::write(path, build_docx(rng)),
        2 => fs::write(path, build_pdf(rng)),
        _ => write_txt(path, rng),
    }
}

#[derive(Clone)]
struct Task {
    path: PathBuf,
    extension: usize,
    source: Option<PathBuf>,
}

fn process(task: &Task, mode: u8, rng: &mut Rng) -> io::Result<()> {
    match mode {
        2 => {
            if let Some(source) = &task.source {
                fs::copy(source, &task.path).map(|_| ())
            } else {
                Ok(())
            }
        }
        1 => write_simple(&task.path, rng),
        _ => write_real(&task.path, task.extension, rng),
    }
}

fn build_tasks(folders: &[PathBuf], total: usize, rng: &mut Rng) -> Vec<Task> {
    let mut reserved: HashSet<String> = HashSet::new();
    let mut tasks = Vec::with_capacity(total);
    for _ in 0..total {
        let folder = rng.pick(folders);
        let extension = rng.weighted_extension();
        let name = random_filename(rng);
        let mut path = folder.join(format!("{}{}", name, EXTENSIONS[extension]));
        let mut counter = 1;
        while path.exists() || reserved.contains(&path.to_string_lossy().to_string()) {
            path = folder.join(format!("{}_{}{}", name, counter, EXTENSIONS[extension]));
            counter += 1;
        }
        reserved.insert(path.to_string_lossy().to_string());
        tasks.push(Task { path, extension, source: None });
    }
    tasks
}

struct Options {
    dest: PathBuf,
    count: usize,
    workers: usize,
    mode: u8,
    template_pool: usize,
}

fn parse_args() -> Options {
    let mut dest: Option<PathBuf> = None;
    let mut count = 5000usize;
    let mut workers = 0usize;
    let mut mode = 0u8;
    let mut template_pool = 40usize;

    let args: Vec<String> = env::args().skip(1).collect();
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        match arg {
            "-n" | "--count" => {
                index += 1;
                count = args.get(index).and_then(|v| v.parse().ok()).unwrap_or(count);
            }
            "-w" | "--workers" => {
                index += 1;
                workers = args.get(index).and_then(|v| v.parse().ok()).unwrap_or(workers);
            }
            "-S" | "--simple" => mode = 1,
            "-T" | "--template" => mode = 2,
            "--template-pool" => {
                index += 1;
                template_pool = args.get(index).and_then(|v| v.parse().ok()).unwrap_or(template_pool);
            }
            "-h" | "--help" => {
                print_usage();
                process::exit(0);
            }
            other if other.starts_with('-') => {
                eprintln!("[ERRO] opcao desconhecida: {}", other);
                print_usage();
                process::exit(1);
            }
            other => dest = Some(PathBuf::from(other)),
        }
        index += 1;
    }

    let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let dest = dest.unwrap_or_else(|| PathBuf::from(home).join("Documentos_Teste"));
    Options { dest, count, workers, mode, template_pool }
}

fn print_usage() {
    println!(
        "Uso: generate_test_files [DESTINO] [opcoes]\n\
         \n\
         Opcoes:\n\
           -n, --count N        total de arquivos (padrao: 5000)\n\
           -w, --workers N      threads (padrao: todos os nucleos)\n\
           -S, --simple         bytes aleatorios em vez de formatos reais\n\
           -T, --template       copia um pool realista (formatos validos)\n\
               --template-pool N  modelos por extensao no modo template (padrao: 40)\n\
           -h, --help           esta ajuda"
    );
}

fn prepare_templates(directory: &Path, per_extension: usize, rng: &mut Rng) -> io::Result<Vec<Vec<PathBuf>>> {
    let mut pools = vec![Vec::new(); EXTENSIONS.len()];
    for extension in 0..EXTENSIONS.len() {
        for index in 0..per_extension {
            let path = directory.join(format!(
                "{}_{}{}",
                EXTENSIONS[extension].trim_start_matches('.'),
                index,
                EXTENSIONS[extension]
            ));
            write_real(&path, extension, rng)?;
            pools[extension].push(path);
        }
    }
    Ok(pools)
}

fn main() {
    let options = parse_args();
    let mode = options.mode;
    let count = options.count;

    let base = options.dest.clone();
    let mut folders = Vec::with_capacity(FOLDER_TREE.len());
    for relative in FOLDER_TREE {
        let folder = base.join(relative);
        if let Err(error) = fs::create_dir_all(&folder) {
            eprintln!("[ERRO] nao foi possivel criar {}: {}", folder.display(), error);
            process::exit(1);
        }
        folders.push(folder);
    }

    let workers = if options.workers == 0 {
        thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
    } else {
        options.workers
    };

    let mut rng = Rng::new(os_random_u64());
    let mut tasks = build_tasks(&folders, count, &mut rng);

    let mut templates_dir: Option<PathBuf> = None;
    if mode == 2 {
        let directory = env::temp_dir().join(format!(
            "gen_templates_{}_{}",
            process::id(),
            rng.next_u64()
        ));
        if let Err(error) = fs::create_dir_all(&directory) {
            eprintln!("[ERRO] nao foi possivel criar {}: {}", directory.display(), error);
            process::exit(1);
        }
        match prepare_templates(&directory, options.template_pool, &mut rng) {
            Ok(pools) => {
                for task in tasks.iter_mut() {
                    let pool = &pools[task.extension];
                    task.source = Some(pool[rng.below(pool.len())].clone());
                }
            }
            Err(error) => {
                eprintln!("[ERRO] falha ao preparar modelos: {}", error);
                process::exit(1);
            }
        }
        templates_dir = Some(directory);
    }

    let mode_label = match mode {
        2 => "template",
        1 => "simple",
        _ => "real",
    };
    println!("\n[+] Destino  : {}", base.display());
    println!("[+] Pastas   : {}", folders.len());
    println!("[+] Arquivos : {}", count);
    println!("[+] Modo     : {} | workers: {}\n", mode_label, workers);

    let tasks = Arc::new(tasks);
    let next = Arc::new(AtomicUsize::new(0));
    let done = Arc::new(AtomicUsize::new(0));
    let errors = Arc::new(AtomicUsize::new(0));
    let output_lock = Arc::new(Mutex::new(()));
    let base_seed = os_random_u64();
    let total = tasks.len();

    let mut handles = Vec::new();
    for worker in 0..workers {
        let tasks = Arc::clone(&tasks);
        let next = Arc::clone(&next);
        let done = Arc::clone(&done);
        let errors = Arc::clone(&errors);
        let output_lock = Arc::clone(&output_lock);
        handles.push(thread::spawn(move || {
            let mut rng = Rng::new(base_seed ^ (worker as u64 + 1).wrapping_mul(0x9E3779B97F4A7C15));
            loop {
                let index = next.fetch_add(1, Ordering::Relaxed);
                if index >= tasks.len() {
                    break;
                }
                let task = &tasks[index];
                if let Err(error) = process(task, mode, &mut rng) {
                    errors.fetch_add(1, Ordering::Relaxed);
                    let _guard = output_lock.lock().unwrap();
                    println!("\n  [WARN] {}: {}", task.path.display(), error);
                }
                let completed = done.fetch_add(1, Ordering::Relaxed) + 1;
                if completed % 100 == 0 || completed == total {
                    let filled = (30 * completed) / total.max(1);
                    let bar = format!("{}{}", "█".repeat(filled), "░".repeat(30 - filled));
                    let _guard = output_lock.lock().unwrap();
                    print!("\r  [{}] {:5.1}%  ({}/{})", bar, completed as f64 / total.max(1) as f64 * 100.0, completed, total);
                    let _ = io::stdout().flush();
                }
            }
        }));
    }

    for handle in handles {
        let _ = handle.join();
    }

    if let Some(directory) = templates_dir {
        let _ = fs::remove_dir_all(directory);
    }

    let failed = errors.load(Ordering::Relaxed);
    println!("\n\n[✓] Concluído! {} arquivo(s) criados, {} erro(s).\n", count.saturating_sub(failed), failed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_known_vector() {
        assert_eq!(crc32(b"123456789"), 0xCBF43926);
    }

    #[test]
    fn xlsx_is_valid_zip_container() {
        let mut rng = Rng::new(12345);
        let bytes = build_xlsx(&mut rng);
        assert_eq!(&bytes[0..4], b"PK\x03\x04");
        assert!(bytes.windows(4).any(|w| w == b"PK\x01\x02"));
        assert!(bytes.windows(4).any(|w| w == b"PK\x05\x06"));
    }

    #[test]
    fn pdf_has_header_and_trailer() {
        let mut rng = Rng::new(7);
        let bytes = build_pdf(&mut rng);
        assert!(bytes.starts_with(b"%PDF-1.4"));
        assert!(bytes.ends_with(b"%%EOF\n"));
    }

    #[test]
    fn build_tasks_reserve_unique_paths() {
        let mut rng = Rng::new(99);
        let folder = env::temp_dir();
        let tasks = build_tasks(&[folder], 200, &mut rng);
        let unique: HashSet<_> = tasks.iter().map(|t| t.path.clone()).collect();
        assert_eq!(tasks.len(), 200);
        assert_eq!(unique.len(), 200);
    }
}
