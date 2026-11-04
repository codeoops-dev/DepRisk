//! deprisk-reach: the DepRisk reachability analyzer for C#. Reads one request (JSON) on stdin, writes one result (JSON) on
//! stdout. Exit codes: 0 success, 2 invalid request or unreadable root, 101 internal error.

mod analyze;
mod discover;
mod program;
mod protocol;
mod reach;
mod targets;

use protocol::*;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::path::Path;

const MAX_REQUEST_BYTES: u64 = 256 * 1024 * 1024;
const MAX_TOTAL_SOURCE_BYTES: usize = 512 * 1024 * 1024;
const MAX_DIAGNOSTICS: usize = 200;

/// Text safe to put in a message: printable ASCII only, bounded.
pub fn safe(text: &str) -> String {
    text.chars().take(120).map(|c| if c.is_ascii_graphic() || c == ' ' { c } else { '?' }).collect()
}

fn main() {
    let code = std::thread::Builder::new().stack_size(512 * 1024 * 1024).spawn(run).map(|h| h.join().unwrap_or(101)).unwrap_or(101);
    std::process::exit(code);
}

fn fail(message: &str) -> i32 {
    eprintln!("deprisk-reach: {message}");
    2
}

fn run() -> i32 {
    let mut input = String::new();
    if std::io::stdin().take(MAX_REQUEST_BYTES + 1).read_to_string(&mut input).is_err() {
        return fail("cannot read the request from stdin");
    }
    if input.len() as u64 > MAX_REQUEST_BYTES {
        return fail("request too large");
    }
    let request: Request = match serde_json::from_str(&input) {
        Ok(r) => r,
        Err(e) => return fail(&format!("invalid request: {e}")),
    };
    match execute(&request) {
        Ok(output) => {
            let mut stdout = std::io::stdout().lock();
            if serde_json::to_writer(&mut stdout, &output).is_err() || stdout.write_all(b"\n").is_err() {
                return fail("cannot write the result");
            }
            0
        }
        Err(message) => fail(&message),
    }
}

pub fn execute(request: &Request) -> Result<Output, String> {
    if request.schema_version != SCHEMA_VERSION {
        return Err(format!("unsupported schemaVersion {} (this analyzer reads {})", request.schema_version, SCHEMA_VERSION));
    }
    if !matches!(request.entrypoints.mode.as_str(), "auto" | "public-api" | "none") {
        return Err(format!("unknown entrypoints mode '{}'", safe(&request.entrypoints.mode)));
    }
    let index = targets::TargetIndex::build(&request.targets)?;
    let root = Path::new(&request.root);
    let discovery = discover::discover(root, request.limits.max_files)?;

    let mut diagnostics: Vec<Diagnostic> = Vec::new();
    let mut stats = Stats::default();
    let mut incomplete = false;
    for (path, reason) in &discovery.skipped {
        stats.files_skipped += 1;
        push(&mut diagnostics, Some(path.clone()), reason.clone());
    }

    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&tree_sitter_c_sharp::LANGUAGE.into()).map_err(|e| format!("grammar error: {e}"))?;
    let file_timeout = std::time::Duration::from_millis(request.limits.file_timeout_ms);

    let mut parsed: Vec<program::Parsed> = Vec::new();
    let mut digest_lines = String::new();
    let mut total = 0usize;
    for file in &discovery.files {
        let too_big = std::fs::metadata(&file.path).map(|m| m.len() as usize > request.limits.max_file_bytes).unwrap_or(true);
        if too_big {
            stats.files_skipped += 1;
            incomplete = true;
            push(&mut diagnostics, Some(file.rel.clone()), "file too large or unreadable; not analyzed".to_string());
            continue;
        }
        let Ok(bytes) = std::fs::read(&file.path) else {
            stats.files_skipped += 1;
            incomplete = true;
            push(&mut diagnostics, Some(file.rel.clone()), "unreadable; not analyzed".to_string());
            continue;
        };
        total += bytes.len();
        let _ = writeln!(digest_lines, "{}  {}", hex(&Sha256::digest(&bytes)), file.rel);
        if total > MAX_TOTAL_SOURCE_BYTES {
            return Err("sources exceed the total size limit".to_string());
        }
        let src = String::from_utf8_lossy(&bytes).to_string();
        parser.reset();
        match parse_with_deadline(&mut parser, &src, file_timeout) {
            Some(tree) => {
                let has_error = tree.root_node().has_error();
                if has_error {
                    stats.files_with_errors += 1;
                    incomplete = true;
                    push(&mut diagnostics, Some(file.rel.clone()), "syntax the parser could not read completely".to_string());
                }
                stats.files += 1;
                parsed.push(program::Parsed { rel: file.rel.clone(), src, tree });
            }
            None => {
                stats.files_skipped += 1;
                incomplete = true;
                push(&mut diagnostics, Some(file.rel.clone()), "parse timed out; not analyzed".to_string());
            }
        }
    }

    let prog = program::Program::collect(&parsed);
    let graph = analyze::analyze(&prog, &parsed, &index);
    let entries = reach::entrypoints(&prog, &request.entrypoints, &mut diagnostics);
    let results = reach::label_targets(&prog, &parsed, &graph, &index, &request.targets, &entries, &reach::Completeness { incomplete });

    stats.types = prog.types.len();
    stats.methods = prog.methods.len();
    stats.edges = graph.edges.iter().map(|e| e.len()).sum();
    stats.entrypoints = entries.iter().filter(|e| prog.methods[e.method].kind != program::MethodKind::Init).count();
    stats.reflection_sites = graph.reflection_sites;

    let mut shown: Vec<EntrypointOut> = entries
        .iter()
        .filter(|e| prog.methods[e.method].kind != program::MethodKind::Init)
        .map(|e| EntrypointOut { method: prog.methods[e.method].id.clone(), kind: e.kind.to_string() })
        .collect();
    shown.sort_by(|a, b| a.method.cmp(&b.method));
    shown.truncate(200);

    Ok(Output {
        schema_version: SCHEMA_VERSION,
        analyzer: AnalyzerInfo { name: "deprisk-reach", version: env!("CARGO_PKG_VERSION") },
        language: "csharp",
        source_digest: hex(&Sha256::digest(digest_lines.as_bytes())),
        stats,
        entrypoints: shown,
        results,
        diagnostics,
    })
}

/// Parses `src`, giving up (None) once `timeout` has passed. tree-sitter reports progress while it parses; the callback is
/// where the deadline is enforced (this replaces the timeout setter that tree-sitter 0.26 removed).
fn parse_with_deadline(parser: &mut tree_sitter::Parser, src: &str, timeout: std::time::Duration) -> Option<tree_sitter::Tree> {
    let bytes = src.as_bytes();
    let deadline = std::time::Instant::now() + timeout;
    let mut expired = |_: &tree_sitter::ParseState| {
        if std::time::Instant::now() >= deadline {
            std::ops::ControlFlow::Break(())
        } else {
            std::ops::ControlFlow::Continue(())
        }
    };
    let mut read = |offset: usize, _: tree_sitter::Point| -> &[u8] { bytes.get(offset..).unwrap_or(&[]) };
    let options = tree_sitter::ParseOptions::new().progress_callback(&mut expired);
    parser.parse_with_options(&mut read, None, Some(options))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn push(list: &mut Vec<Diagnostic>, file: Option<String>, message: String) {
    if list.len() < MAX_DIAGNOSTICS {
        list.push(Diagnostic { file, message });
    }
}
