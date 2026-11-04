//! Finding the C# source files below a root, with bounds suitable for untrusted trees: symlinks are never followed,
//! build output and tool directories are not entered, depth and file count are limited, and the result is sorted.

use std::fs;
use std::path::{Path, PathBuf};

pub struct SourceFile {
    /// Path relative to the root, with forward slashes.
    pub rel: String,
    pub path: PathBuf,
}

pub struct Discovery {
    pub files: Vec<SourceFile>,
    /// Files and directories that were not read, with the reason.
    pub skipped: Vec<(String, String)>,
}

const SKIPPED_DIRS: [&str; 6] = ["bin", "obj", ".git", "node_modules", ".deprisk", ".vs"];
const MAX_DEPTH: usize = 64;

pub fn discover(root: &Path, max_files: usize) -> Result<Discovery, String> {
    let meta = fs::symlink_metadata(root).map_err(|e| format!("cannot read root: {e}"))?;
    if !meta.is_dir() {
        return Err("root is not a directory".to_string());
    }

    let mut files = Vec::new();
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
            } else if meta.is_file() && name.to_ascii_lowercase().ends_with(".cs") {
                if files.len() >= max_files {
                    return Err(format!("more than {max_files} source files (limit)"));
                }
                files.push(SourceFile { rel: relative(root, &path), path });
            }
        }
    }

    files.sort_by(|a, b| a.rel.cmp(&b.rel));
    skipped.sort();
    Ok(Discovery { files, skipped })
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root).unwrap_or(path).to_string_lossy().replace('\\', "/")
}
