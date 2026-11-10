//! Finding the C# source files below a root, with bounds suitable for untrusted trees: symlinks are never followed,
//! build output and tool directories are not entered, depth and file count are limited, and the result is sorted.

use std::fs;
use std::path::{Path, PathBuf};

pub struct SourceFile {
    /// Path relative to the root, with forward slashes.
    pub rel: String,
    pub path: PathBuf,
}

/// What a file name means for the language being analyzed.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FileClass {
    /// Source code of the language.
    Source,
    /// A manifest the analysis reads (`package.json`, `tsconfig.json`).
    Manifest,
    /// Code of a kind this analyzer cannot read (a framework's single-file components): the analysis is incomplete if one exists.
    Foreign,
    Ignore,
}

pub struct Discovery {
    pub files: Vec<SourceFile>,
    pub manifests: Vec<SourceFile>,
    pub foreign: Vec<String>,
    /// Files and directories that were not read, with the reason.
    pub skipped: Vec<(String, String)>,
}

const SKIPPED_DIRS: [&str; 6] = ["bin", "obj", ".git", "node_modules", ".deprisk", ".vs"];
const MAX_DEPTH: usize = 64;
const MAX_MANIFESTS: usize = 5_000;

pub fn discover(root: &Path, max_files: usize) -> Result<Discovery, String> {
    discover_with(root, max_files, |name| if name.ends_with(".cs") { FileClass::Source } else { FileClass::Ignore })
}

pub fn discover_with(root: &Path, max_files: usize, classify: impl Fn(&str) -> FileClass) -> Result<Discovery, String> {
    let meta = fs::symlink_metadata(root).map_err(|e| format!("cannot read root: {e}"))?;
    if !meta.is_dir() {
        return Err("root is not a directory".to_string());
    }

    let mut files = Vec::new();
    let mut manifests = Vec::new();
    let mut foreign = Vec::new();
    let mut skipped = Vec::new();
    let mut stack: Vec<(PathBuf, usize)> = vec![(root.to_path_buf(), 0)];

    while let Some((dir, depth)) = stack.pop() {
        let mut entries: Vec<_> = match fs::read_dir(&dir) {
            Ok(rd) => rd.filter_map(|e| e.ok()).collect(),
            Err(e) => {
                skipped.push((relative(root, &dir), format!("unreadable directory: {e}")));
                continue;
            }
        };
        entries.sort_by_key(|e| e.file_name());

        for entry in entries {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            let Ok(meta) = fs::symlink_metadata(&path) else { continue };

            if meta.file_type().is_symlink() {
                skipped.push((relative(root, &path), "symbolic link not followed".to_string()));
            } else if meta.is_dir() {
                if SKIPPED_DIRS.iter().any(|d| d.eq_ignore_ascii_case(&name)) {
                    continue;
                }
                if depth + 1 > MAX_DEPTH {
                    skipped.push((relative(root, &path), "directory nesting too deep".to_string()));
                } else {
                    stack.push((path, depth + 1));
                }
            } else if meta.is_file() {
                match classify(&name.to_ascii_lowercase()) {
                    FileClass::Source => {
                        if files.len() >= max_files {
                            return Err(format!("more than {max_files} source files (limit)"));
                        }
                        files.push(SourceFile { rel: relative(root, &path), path });
                    }
                    FileClass::Manifest => {
                        if manifests.len() < MAX_MANIFESTS {
                            manifests.push(SourceFile { rel: relative(root, &path), path });
                        }
                    }
                    FileClass::Foreign => foreign.push(relative(root, &path)),
                    FileClass::Ignore => {}
                }
            }
        }
    }

    files.sort_by(|a, b| a.rel.cmp(&b.rel));
    manifests.sort_by(|a, b| a.rel.cmp(&b.rel));
    foreign.sort();
    skipped.sort();
    Ok(Discovery { files, manifests, foreign, skipped })
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root).unwrap_or(path).to_string_lossy().replace('\\', "/")
}
