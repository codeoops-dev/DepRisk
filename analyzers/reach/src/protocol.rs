//! The JSON protocol between the DepRisk CLI and this analyzer (ADR 0012).
//! One request on stdin, one result on stdout. Both carry `schemaVersion`; an unknown version is rejected, never guessed.

use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Request {
    pub schema_version: u32,
    /// Directory with the sources. Everything below it is analyzed as one program.
    pub root: String,
    #[serde(default)]
    pub entrypoints: EntrypointSpec,
    pub targets: Vec<Target>,
    #[serde(default)]
    pub limits: Limits,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct EntrypointSpec {
    /// `auto` (Main, top-level statements, controllers, hosted services), `public-api` (public members of public types:
    /// for libraries), or `none` (only `explicit`).
    #[serde(default = "default_mode")]
    pub mode: String,
    /// Fully qualified method names (`Namespace.Type.Method`; all overloads), added to the mode's entrypoints.
    #[serde(default)]
    pub explicit: Vec<String>,
}

impl Default for EntrypointSpec {
    fn default() -> Self {
        EntrypointSpec { mode: default_mode(), explicit: Vec::new() }
    }
}

fn default_mode() -> String {
    "auto".to_string()
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Target {
    /// Opaque key the result is reported under (the CLI uses advisory id and package).
    pub key: String,
    /// `Namespace.Type.Member`, `Namespace.Type.#ctor`, or `Namespace.Type.*` (any member, including constructors).
    pub symbols: Vec<String>,
    /// True if the list is claimed to contain every public way to reach the flaw. Only then can the result be `unreachable`.
    pub complete: bool,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Limits {
    #[serde(default = "default_max_files")]
    pub max_files: usize,
    #[serde(default = "default_max_file_bytes")]
    pub max_file_bytes: usize,
    /// Parse time limit per file.
    #[serde(default = "default_file_timeout_ms")]
    pub file_timeout_ms: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { max_files: default_max_files(), max_file_bytes: default_max_file_bytes(), file_timeout_ms: default_file_timeout_ms() }
    }
}

fn default_max_files() -> usize {
    20_000
}
fn default_max_file_bytes() -> usize {
    2 * 1024 * 1024
}
fn default_file_timeout_ms() -> u64 {
    5_000
}

pub const MAX_TARGETS: usize = 100_000;
pub const MAX_SYMBOLS_PER_TARGET: usize = 10_000;

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Output {
    pub schema_version: u32,
    pub analyzer: AnalyzerInfo,
    pub language: &'static str,
    /// SHA-256 over the lines `<sha256 of the file>  <relative path>` of every source file that was read, in path order:
    /// the identity of exactly what was analyzed.
    pub source_digest: String,
    pub stats: Stats,
    pub entrypoints: Vec<EntrypointOut>,
    pub results: Vec<TargetResult>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Serialize, Debug)]
pub struct AnalyzerInfo {
    pub name: &'static str,
    pub version: &'static str,
}

#[derive(Serialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct Stats {
    pub files: usize,
    pub files_skipped: usize,
    /// Files with syntax the parser could not fully read (the analysis of such a file may miss edges).
    pub files_with_errors: usize,
    pub types: usize,
    pub methods: usize,
    pub edges: usize,
    pub entrypoints: usize,
    pub reflection_sites: usize,
}

#[derive(Serialize, Debug)]
pub struct EntrypointOut {
    pub method: String,
    pub kind: String,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TargetResult {
    pub key: String,
    /// `reachable`, `possibly-reachable`, `unreachable`, or `unknown`.
    pub label: &'static str,
    /// Why: `static-path`, `dynamic-path`, `no-path`, or one of the reasons for `unknown`
    /// (`no-symbols`, `no-entrypoints`, `symbol-list-incomplete`, `incomplete-analysis`, `unresolved-reflection`,
    /// `unresolved-receiver`).
    pub reason: &'static str,
    pub path: Vec<PathEdge>,
    /// For `reachable` and `possibly-reachable`: the symbol that was reached.
    pub symbol: Option<String>,
}

#[derive(Serialize, Debug, Clone)]
pub struct PathEdge {
    pub from: String,
    pub to: String,
    /// `static` or `dynamic`.
    pub kind: &'static str,
    pub file: Option<String>,
    pub line: Option<usize>,
}

#[derive(Serialize, Debug, Clone)]
pub struct Diagnostic {
    pub file: Option<String>,
    pub message: String,
}
