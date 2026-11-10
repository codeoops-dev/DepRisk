//! The JavaScript and TypeScript front end (ADR 0019): what the sources declare. Modules, functions, classes, imports, and
//! exports are read here; the bodies are read by `jsflow.rs`. Like the C# front end there is no type checker: names, imports,
//! and declared or inferred types decide what a call refers to, and everything else is over-approximated or left `unknown`.

use crate::discover::FileClass;
use crate::program::text;
use std::collections::{HashMap, HashSet};
use tree_sitter::{Node, Tree};

pub const MAX_DEPTH: usize = 300;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Lang {
    Js,
    Ts,
    Tsx,
}

pub struct JsFile {
    pub rel: String,
    pub src: String,
    pub tree: Tree,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FuncKind {
    ModuleInit,
    Function,
    Method,
    Ctor,
    ClassInit,
    Accessor,
}

pub struct Func {
    pub id: String,
    pub file: usize,
    pub class: Option<usize>,
    pub is_static: bool,
    pub kind: FuncKind,
    pub decorated: bool,
}

/// A byte range of a node, to find it again in the tree.
type ByteRange = (usize, usize);
/// A field declaration or parameter property: name, type annotation, initializer.
type FieldNode = (String, Option<ByteRange>, Option<ByteRange>);

#[derive(Clone, Debug, PartialEq)]
pub enum Base {
    None,
    Project(usize),
    Ext(String, Vec<String>),
    Unknown,
}

pub struct Class {
    pub name: String,
    pub file: usize,
    pub extends: Option<(usize, usize)>,
    pub base: Base,
    pub methods: HashMap<String, Vec<usize>>,
    pub statics: HashMap<String, Vec<usize>>,
    pub ctor: Option<usize>,
    pub init: usize,
    pub fields: HashMap<String, Ty>,
    pub derived: Vec<usize>,
    pub decorated: bool,
    /// Field declarations and parameter properties whose type is read after the module scopes exist: (name, annotation, value).
    field_nodes: Vec<FieldNode>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Ty {
    Class(usize),
    Ext(String, Vec<String>),
}

#[derive(Clone, Debug, PartialEq)]
pub enum ImportWhat {
    Named(String),
    Default,
    Namespace,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Binding {
    Func(usize),
    Class(usize),
    Instance(Ty),
    /// A value of an external package: the module and the member path from its exports (`default` for the default export).
    Ext(String, Vec<String>),
    /// A project module's exports object.
    Module(usize),
    /// Something a project module exports, not looked up yet.
    Import(usize, ImportWhat),
    /// A Node.js built-in module.
    Builtin(String),
    Opaque,
}

#[derive(Clone, Debug)]
pub enum Export {
    Local(String),
    Bind(Binding),
}

pub struct FileInfo {
    pub init: usize,
    pub scope: HashMap<String, Binding>,
    pub exports: HashMap<String, Export>,
    pub star_from: Vec<usize>,
    /// `Object.assign(module.exports, ...)` and the like: the exports cannot be listed.
    pub opaque_exports: bool,
    pub imported_by: usize,
    /// Every package specifier this file imports or requires (for matching calls on receivers of unknown type).
    pub ext_specs: HashSet<String>,
    pub reassigned: HashSet<String>,
}

pub enum Spec {
    Project(usize),
    Ext(String),
    Builtin(String),
    /// Not code (a JSON file, a stylesheet, an image).
    Ignore,
    /// Might be code of the project that could not be found (a path alias, a workspace package, a missing file).
    Unresolved(String),
}

#[derive(Default)]
pub struct Js {
    pub files: Vec<FileInfo>,
    pub funcs: Vec<Func>,
    pub classes: Vec<Class>,
    pub by_pos: HashMap<(usize, usize, usize), usize>,
    pub class_by_pos: HashMap<(usize, usize, usize), usize>,
    /// Functions a call on a receiver of unknown type might reach, by member name.
    pub by_name: HashMap<String, Vec<usize>>,
    pub accessors: HashMap<String, Vec<usize>>,
    rel_index: HashMap<String, usize>,
    manifest_main: HashMap<String, String>,
    package_names: HashSet<String>,
    /// Packages of this repository (a monorepo's workspaces): name to directory.
    package_dirs: HashMap<String, Vec<String>>,
    root_entries: HashSet<String>,
    alias_prefixes: Vec<String>,
}

pub fn classify(name: &str) -> FileClass {
    if name.ends_with(".d.ts") || name.ends_with(".d.mts") || name.ends_with(".d.cts") {
        return FileClass::Ignore;
    }
    match name.rsplit_once('.').map(|(_, e)| e) {
        Some("js" | "jsx" | "mjs" | "cjs" | "ts" | "mts" | "cts" | "tsx") => FileClass::Source,
        Some("vue" | "svelte" | "astro") => FileClass::Foreign,
        Some("json") if name == "package.json" || name.starts_with("tsconfig") || name.starts_with("jsconfig") => FileClass::Manifest,
        _ => FileClass::Ignore,
    }
}

pub fn lang_of(rel: &str) -> Lang {
    let lower = rel.to_ascii_lowercase();
    if lower.ends_with(".tsx") {
        Lang::Tsx
    } else if lower.ends_with(".ts") || lower.ends_with(".mts") || lower.ends_with(".cts") {
        Lang::Ts
    } else {
        Lang::Js
    }
}

pub fn line(node: Node) -> usize {
    node.start_position().row + 1
}

const BUILTINS: &[&str] = &[
    "assert",
    "async_hooks",
    "buffer",
    "child_process",
    "cluster",
    "console",
    "constants",
    "crypto",
    "dgram",
    "diagnostics_channel",
    "dns",
    "domain",
    "events",
    "fs",
    "http",
    "http2",
    "https",
    "inspector",
    "module",
    "net",
    "os",
    "path",
    "perf_hooks",
    "process",
    "punycode",
    "querystring",
    "readline",
    "repl",
    "stream",
    "string_decoder",
    "sys",
    "timers",
    "tls",
    "trace_events",
    "tty",
    "url",
    "util",
    "v8",
    "vm",
    "wasi",
    "worker_threads",
    "zlib",
    "fs/promises",
    "path/posix",
    "path/win32",
    "stream/promises",
    "stream/web",
    "timers/promises",
    "util/types",
    "dns/promises",
    "readline/promises",
    "assert/strict",
    "test",
    "sea",
    "sqlite",
    "buffer/",
    "events/",
    "util/",
    "url/",
    "punycode/",
    "string_decoder/",
];

const ASSET_EXTENSIONS: &[&str] = &[
    "json", "css", "scss", "sass", "less", "svg", "png", "jpg", "jpeg", "gif", "webp", "ico", "avif", "woff", "woff2", "ttf", "otf", "eot",
    "mp3", "mp4", "webm", "md", "txt", "html",
];

const SOURCE_EXTENSIONS: &[&str] = &["js", "jsx", "mjs", "cjs", "ts", "tsx", "mts", "cts"];

fn is_builtin(spec: &str) -> bool {
    spec.starts_with("node:") || BUILTINS.contains(&spec)
}

pub fn package_name(spec: &str) -> &str {
    let mut parts = spec.splitn(3, '/');
    let first = parts.next().unwrap_or(spec);
    if first.starts_with('@') {
        match parts.next() {
            Some(second) => &spec[..first.len() + 1 + second.len()],
            None => first,
        }
    } else {
        first
    }
}

fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_string()
    } else {
        format!("{dir}/{name}")
    }
}

fn normalize(dir: &str, rel: &str) -> Option<String> {
    let mut parts: Vec<&str> = if dir.is_empty() { Vec::new() } else { dir.split('/').collect() };
    for p in rel.split('/') {
        match p {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            other => parts.push(other),
        }
    }
    Some(parts.join("/"))
}

/// Strips `//` and `/* */` comments and trailing commas, which tsconfig files may contain, so that serde_json can read them.
fn lenient_json(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let (mut i, mut in_string) = (0, false);
    while i < chars.len() {
        let c = chars[i];
        if in_string {
            out.push(c);
            if c == '\\' && i + 1 < chars.len() {
                out.push(chars[i + 1]);
                i += 1;
            } else if c == '"' {
                in_string = false;
            }
        } else if c == '"' {
            in_string = true;
            out.push(c);
        } else if c == '/' && chars.get(i + 1) == Some(&'/') {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        } else if c == '/' && chars.get(i + 1) == Some(&'*') {
            i += 2;
            while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                i += 1;
            }
            i += 2;
            continue;
        } else {
            out.push(c);
        }
        i += 1;
    }
    // Trailing commas before } or ].
    let bytes: Vec<char> = out.chars().collect();
    let mut cleaned = String::with_capacity(bytes.len());
    for (k, &c) in bytes.iter().enumerate() {
        if c == ',' {
            let next = bytes[k + 1..].iter().find(|x| !x.is_whitespace());
            if matches!(next, Some('}') | Some(']')) {
                continue;
            }
        }
        cleaned.push(c);
    }
    cleaned
}

impl Js {
    /// Reads the manifests (names of workspace packages, `main`, path aliases) and the file index. Returns the diagnostics and whether
    /// something that matters could not be read.
    pub fn new(files: &[(String, usize)], manifests: &[(String, String)]) -> (Js, Vec<String>, bool) {
        let mut js = Js::default();
        let mut notes = Vec::new();
        let mut incomplete = false;

        for (i, (rel, _)) in files.iter().enumerate() {
            js.rel_index.insert(rel.clone(), i);
            let first = rel.split('/').next().unwrap_or(rel);
            let stem = first.rsplit_once('.').map(|(s, _)| s).unwrap_or(first);
            js.root_entries.insert(stem.to_string());
        }

        for (rel, content) in manifests {
            let dir = rel.rsplit_once('/').map(|(d, _)| d).unwrap_or("").to_string();
            let name = rel.rsplit('/').next().unwrap_or(rel);
            let Ok(value) = serde_json::from_str::<serde_json::Value>(&lenient_json(content)) else {
                if content.contains("\"paths\"") || content.contains("\"baseUrl\"") {
                    notes.push(format!("{rel}: cannot read this configuration, so path aliases are unknown"));
                    incomplete = true;
                }
                continue;
            };
            if name == "package.json" {
                if let Some(n) = value.get("name").and_then(|v| v.as_str()) {
                    js.package_names.insert(n.to_string());
                    js.package_dirs.entry(n.to_string()).or_default().push(dir.clone());
                }
                if let Some(m) = value.get("main").and_then(|v| v.as_str()) {
                    js.manifest_main.insert(dir, m.to_string());
                }
            } else if let Some(opts) = value.get("compilerOptions") {
                if let Some(paths) = opts.get("paths").and_then(|v| v.as_object()) {
                    for key in paths.keys() {
                        let prefix = key.trim_end_matches('*');
                        if !prefix.is_empty() {
                            js.alias_prefixes.push(prefix.to_string());
                        }
                    }
                }
                if let Some(base) = opts.get("baseUrl").and_then(|v| v.as_str()) {
                    if let Some(b) = normalize(&dir, base) {
                        // With a base URL, any directory below it can be the start of an import.
                        js.alias_prefixes.push(if b.is_empty() { String::new() } else { format!("{b}/") });
                        if b.is_empty() {
                            // Same as root entries, which are checked anyway.
                        }
                    }
                }
            }
        }
        (js, notes, incomplete)
    }

    fn is_alias(&self, spec: &str) -> bool {
        if spec.starts_with("@/") || spec.starts_with('~') || spec.starts_with('#') {
            return true;
        }
        let pkg = package_name(spec);
        if self.root_entries.contains(pkg) || self.package_names.contains(pkg) {
            return true;
        }
        self.alias_prefixes.iter().any(|p| !p.is_empty() && spec.starts_with(p.as_str()))
    }

    fn candidates(&self, base: &str) -> Vec<String> {
        let mut out = vec![base.to_string()];
        let stem = SOURCE_EXTENSIONS.iter().find_map(|e| base.strip_suffix(&format!(".{e}")));
        for stem in stem.into_iter().chain(std::iter::once(base)) {
            for e in SOURCE_EXTENSIONS.iter() {
                out.push(format!("{stem}.{e}"));
            }
        }
        for e in SOURCE_EXTENSIONS.iter() {
            out.push(join(base, &format!("index.{e}")));
        }
        out
    }

    /// Where the code of a package of this repository starts: its `main` (or the source folder that a build folder stands for), then
    /// `index` and `src/index`.
    fn entry_candidates(&self, dir: &str) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(main) = self.manifest_main.get(dir) {
            if let Some(m) = normalize(dir, main) {
                out.extend(self.candidates(&m));
            }
            let relative = main.trim_start_matches("./");
            for built in ["dist/", "build/", "lib/", "out/"] {
                if let Some(rest) = relative.strip_prefix(built) {
                    if let Some(m) = normalize(dir, &format!("src/{rest}")) {
                        out.extend(self.candidates(&m));
                    }
                }
            }
        }
        out.extend(self.candidates(&join(dir, "index")));
        out.extend(self.candidates(&join(dir, "src/index")));
        out
    }

    pub fn resolve_spec(&self, from: &str, spec: &str) -> Spec {
        let relative = spec == "." || spec == ".." || spec.starts_with("./") || spec.starts_with("../");
        if relative {
            let dir = from.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
            let Some(base) = normalize(dir, spec) else { return Spec::Unresolved("leaves the analyzed tree".to_string()) };
            let mut tries = self.candidates(&base);
            if let Some(main) = self.manifest_main.get(&base) {
                if let Some(m) = normalize(&base, main) {
                    tries.extend(self.candidates(&m));
                }
            }
            for t in tries {
                if let Some(&i) = self.rel_index.get(&t) {
                    return Spec::Project(i);
                }
            }
            let ext = spec.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
            if ASSET_EXTENSIONS.contains(&ext.as_str()) {
                return Spec::Ignore;
            }
            return Spec::Unresolved("not found among the analyzed files".to_string());
        }
        if is_builtin(spec) {
            return Spec::Builtin(spec.trim_start_matches("node:").to_string());
        }
        if spec.starts_with('/') {
            return Spec::Unresolved("absolute path".to_string());
        }
        let pkg = package_name(spec);
        if let Some(dirs) = self.package_dirs.get(pkg) {
            let sub = spec[pkg.len()..].trim_start_matches('/');
            // The same name can appear more than once (a repository's root package and a workspace): the first that has code wins.
            for dir in dirs {
                let tries = if sub.is_empty() {
                    self.entry_candidates(dir)
                } else {
                    match normalize(dir, sub) {
                        Some(b) => self.candidates(&b),
                        None => Vec::new(),
                    }
                };
                for t in tries {
                    if let Some(&i) = self.rel_index.get(&t) {
                        return Spec::Project(i);
                    }
                }
            }
            return Spec::Unresolved("a package of this repository whose code was not found (built output only?)".to_string());
        }
        if self.is_alias(spec) {
            return Spec::Unresolved("may be a path alias or a package of this repository".to_string());
        }
        Spec::Ext(spec.to_string())
    }

    pub fn module_binding(&self, from: &str, spec: &str) -> Binding {
        match self.resolve_spec(from, spec) {
            Spec::Project(f) => Binding::Module(f),
            Spec::Ext(s) => Binding::Ext(s, Vec::new()),
            Spec::Builtin(b) => Binding::Builtin(b),
            _ => Binding::Opaque,
        }
    }

    // ---- bindings, exports, and the pure part of resolving a name ---------------------------------------------------------------

    pub fn resolve(&self, b: &Binding, depth: usize) -> Binding {
        match b {
            Binding::Import(file, what) if depth < 8 => match what {
                ImportWhat::Namespace => Binding::Module(*file),
                ImportWhat::Named(n) => self.export_binding(*file, n, depth + 1),
                ImportWhat::Default => match self.export_binding(*file, "default", depth + 1) {
                    Binding::Opaque if !self.files[*file].exports.contains_key("default") => Binding::Module(*file),
                    other => other,
                },
            },
            Binding::Import(..) => Binding::Opaque,
            other => other.clone(),
        }
    }

    pub fn export_binding(&self, file: usize, name: &str, depth: usize) -> Binding {
        if depth > 8 {
            return Binding::Opaque;
        }
        let info = &self.files[file];
        match info.exports.get(name) {
            Some(Export::Local(n)) => info.scope.get(n).map(|b| self.resolve(b, depth + 1)).unwrap_or(Binding::Opaque),
            Some(Export::Bind(b)) => self.resolve(b, depth + 1),
            None => {
                for &f in &info.star_from {
                    let b = self.export_binding(f, name, depth + 1);
                    if b != Binding::Opaque {
                        return b;
                    }
                }
                Binding::Opaque
            }
        }
    }

    pub fn member_of(&self, b: &Binding, name: &str) -> Binding {
        match self.resolve(b, 0) {
            Binding::Ext(spec, mut path) => {
                path.push(name.to_string());
                Binding::Ext(spec, path)
            }
            Binding::Module(f) => self.export_binding(f, name, 0),
            Binding::Instance(Ty::Class(c)) => match self.classes[c].fields.get(name) {
                Some(t) => Binding::Instance(t.clone()),
                None => Binding::Opaque,
            },
            _ => Binding::Opaque,
        }
    }

    /// The value of an expression that can be read without running anything: names of the module scope, member chains, `require`
    /// of a literal, `new`, casts.
    pub fn eval_simple(&self, rel: &str, node: Node, src: &str, scope: &HashMap<String, Binding>, depth: usize) -> Binding {
        if depth > 16 {
            return Binding::Opaque;
        }
        match node.kind() {
            "identifier" => scope.get(text(node, src)).map(|b| self.resolve(b, 0)).unwrap_or(Binding::Opaque),
            "member_expression" => {
                let (Some(o), Some(p)) = (node.child_by_field_name("object"), node.child_by_field_name("property")) else {
                    return Binding::Opaque;
                };
                let b = self.eval_simple(rel, o, src, scope, depth + 1);
                self.member_of(&b, text(p, src))
            }
            "call_expression" => {
                let Some(f) = node.child_by_field_name("function") else { return Binding::Opaque };
                if f.kind() == "identifier" && text(f, src) == "require" && !scope.contains_key("require") {
                    if let Some(spec) = literal_argument(node, src) {
                        return self.module_binding(rel, &spec);
                    }
                }
                Binding::Opaque
            }
            "new_expression" => {
                let Some(c) = node.child_by_field_name("constructor") else { return Binding::Opaque };
                match self.eval_simple(rel, c, src, scope, depth + 1) {
                    Binding::Class(c) => Binding::Instance(Ty::Class(c)),
                    Binding::Ext(s, p) => Binding::Instance(Ty::Ext(s, p)),
                    _ => Binding::Opaque,
                }
            }
            "parenthesized_expression" | "non_null_expression" | "await_expression" => match node.named_child(0) {
                Some(inner) => self.eval_simple(rel, inner, src, scope, depth + 1),
                None => Binding::Opaque,
            },
            "as_expression" | "satisfies_expression" => match node.named_child(1).and_then(|t| self.type_of(t, src, scope)) {
                Some(t) => Binding::Instance(t),
                None => node.named_child(0).map(|n| self.eval_simple(rel, n, src, scope, depth + 1)).unwrap_or(Binding::Opaque),
            },
            _ => Binding::Opaque,
        }
    }

    /// The type a TypeScript annotation names, when it names a class of the project or of a package.
    pub fn type_of(&self, node: Node, src: &str, scope: &HashMap<String, Binding>) -> Option<Ty> {
        match node.kind() {
            "type_annotation" => node.named_child(0).and_then(|n| self.type_of(n, src, scope)),
            "type_identifier" | "identifier" => match self.resolve(scope.get(text(node, src))?, 0) {
                Binding::Class(c) => Some(Ty::Class(c)),
                Binding::Ext(s, p) => Some(Ty::Ext(s, p)),
                _ => None,
            },
            "nested_type_identifier" | "member_expression" => {
                let module = node.child_by_field_name("module").or_else(|| node.child_by_field_name("object"))?;
                let name = node.child_by_field_name("name").or_else(|| node.child_by_field_name("property"))?;
                let base = self.eval_simple("", module, src, scope, 0);
                match self.member_of(&base, text(name, src)) {
                    Binding::Class(c) => Some(Ty::Class(c)),
                    Binding::Ext(s, p) => Some(Ty::Ext(s, p)),
                    _ => None,
                }
            }
            "generic_type" => node.child_by_field_name("name").and_then(|n| self.type_of(n, src, scope)),
            "parenthesized_type" => node.named_child(0).and_then(|n| self.type_of(n, src, scope)),
            "union_type" => {
                let mut found = None;
                let mut c = node.walk();
                for child in node.named_children(&mut c) {
                    if matches!(child.kind(), "literal_type" | "predefined_type") && matches!(text(child, src), "null" | "undefined") {
                        continue;
                    }
                    if found.is_some() {
                        return None;
                    }
                    found = Some(self.type_of(child, src, scope)?);
                }
                found
            }
            _ => None,
        }
    }

    // ---- collecting -------------------------------------------------------------------------------------------------------------

    fn alloc(
        &mut self,
        used: &mut HashSet<String>,
        file: usize,
        rel: &str,
        base: String,
        node: Node,
        f: impl FnOnce(String) -> Func,
    ) -> usize {
        let mut id = format!("{rel}::{base}");
        if used.contains(&id) {
            id = format!("{id}@{}", line(node));
        }
        let mut n = 2;
        while used.contains(&id) {
            id = format!("{rel}::{base}@{}#{n}", line(node));
            n += 1;
        }
        used.insert(id.clone());
        let idx = self.funcs.len();
        self.funcs.push(f(id));
        let _ = file;
        idx
    }

    pub fn collect_file(&mut self, file: usize, rel: &str, src: &str, root: Node, used: &mut HashSet<String>) {
        let init = self.alloc(used, file, rel, "<module>".to_string(), root, |id| Func {
            id,
            file,
            class: None,
            is_static: false,
            kind: FuncKind::ModuleInit,
            decorated: false,
        });
        self.files.push(FileInfo {
            init,
            scope: HashMap::new(),
            exports: HashMap::new(),
            star_from: Vec::new(),
            opaque_exports: false,
            imported_by: 0,
            ext_specs: HashSet::new(),
            reassigned: assigned_names(root, src),
        });
        let mut c = Collector { file, rel, src, used };
        c.walk(self, root, None, false, 0);
    }

    /// After every file is collected: module scopes and exports (they need the other files' indexes), then classes and fields.
    pub fn link(&mut self, trees: &[JsFile]) {
        for (i, f) in trees.iter().enumerate() {
            let root = f.tree.root_node();
            let scope = self.prebind(i, &f.rel, root, &f.src, &self.files[i].reassigned.clone());
            self.files[i].scope = scope;
            self.collect_exports(i, &f.rel, root, &f.src);
        }
        // Who imports whom: the roots of the program are the modules nobody imports.
        for (i, f) in trees.iter().enumerate() {
            let mut targets = HashSet::new();
            let mut specs = HashSet::new();
            gather_specs(f.tree.root_node(), &f.src, &mut specs, 0);
            for s in specs {
                match self.resolve_spec(&f.rel, &s) {
                    Spec::Project(t) if t != i => {
                        targets.insert(t);
                    }
                    Spec::Ext(e) => {
                        self.files[i].ext_specs.insert(e);
                    }
                    _ => {}
                }
            }
            for t in targets {
                self.files[t].imported_by += 1;
            }
        }
        // Bases and field types are read in the module scope of the file that declares the class.
        for c in 0..self.classes.len() {
            let file = self.classes[c].file;
            let f = &trees[file];
            let scope = self.files[file].scope.clone();
            if let Some((s, e)) = self.classes[c].extends {
                if let Some(node) = f.tree.root_node().descendant_for_byte_range(s, e) {
                    let b = self.eval_simple(&f.rel, node, &f.src, &scope, 0);
                    self.classes[c].base = match b {
                        Binding::Class(b) if b != c => Base::Project(b),
                        Binding::Ext(s, p) => Base::Ext(s, p),
                        _ => Base::Unknown,
                    };
                }
            }
        }
        for c in 0..self.classes.len() {
            if let Base::Project(b) = self.classes[c].base {
                self.classes[b].derived.push(c);
            }
        }
        for c in 0..self.classes.len() {
            let file = self.classes[c].file;
            let f = &trees[file];
            let scope = self.files[file].scope.clone();
            let nodes = self.classes[c].field_nodes.clone();
            for (name, annotation, value) in nodes {
                let root = f.tree.root_node();
                let mut ty =
                    annotation.and_then(|(s, e)| root.descendant_for_byte_range(s, e)).and_then(|n| self.type_of(n, &f.src, &scope));
                if ty.is_none() {
                    if let Some(node) = value.and_then(|(s, e)| root.descendant_for_byte_range(s, e)) {
                        ty = match self.eval_simple(&f.rel, node, &f.src, &scope, 0) {
                            Binding::Instance(t) => Some(t),
                            _ => None,
                        };
                    }
                }
                if let Some(t) = ty {
                    self.classes[c].fields.insert(name, t);
                }
            }
        }
    }

    /// The names a statement list declares, as bindings: functions and classes (hoisted), imports and `require`s, and variables
    /// whose value can be read without running anything. Variables that are assigned again stay unknown.
    pub fn prebind(&self, file: usize, rel: &str, container: Node, src: &str, reassigned: &HashSet<String>) -> HashMap<String, Binding> {
        let mut scope: HashMap<String, Binding> = HashMap::new();
        let mut c = container.walk();
        let children: Vec<Node> = container.named_children(&mut c).collect();
        // Imports and classes first: later declarations may refer to them.
        for pass in 0..2 {
            for stmt in &children {
                let mut node = *stmt;
                if node.kind() == "export_statement" {
                    if let Some(d) = node.child_by_field_name("declaration").or_else(|| node.child_by_field_name("value")) {
                        node = d;
                    } else {
                        continue;
                    }
                }
                let pos = (file, node.start_byte(), node.end_byte());
                match node.kind() {
                    "import_statement" if pass == 0 => self.bind_import(file, rel, node, src, &mut scope),
                    "function_declaration" | "generator_function_declaration" if pass == 0 => {
                        if let (Some(n), Some(&f)) = (node.child_by_field_name("name"), self.by_pos.get(&pos)) {
                            scope.insert(text(n, src).to_string(), Binding::Func(f));
                        }
                    }
                    "class_declaration" | "abstract_class_declaration" if pass == 0 => {
                        if let (Some(n), Some(&c)) = (node.child_by_field_name("name"), self.class_by_pos.get(&pos)) {
                            scope.insert(text(n, src).to_string(), Binding::Class(c));
                        }
                    }
                    "lexical_declaration" | "variable_declaration" if pass == 1 => {
                        let is_const = node.child(0).map(|k| k.kind() == "const").unwrap_or(false);
                        let mut dc = node.walk();
                        for d in node.named_children(&mut dc) {
                            if d.kind() != "variable_declarator" {
                                continue;
                            }
                            let (Some(name), Some(value)) = (d.child_by_field_name("name"), d.child_by_field_name("value")) else {
                                continue;
                            };
                            let value = unwrap_expr(value);
                            let b = match value.kind() {
                                "function_expression" | "generator_function" | "arrow_function" | "function" => self
                                    .by_pos
                                    .get(&(file, value.start_byte(), value.end_byte()))
                                    .map(|&f| Binding::Func(f))
                                    .unwrap_or(Binding::Opaque),
                                "class" => self
                                    .class_by_pos
                                    .get(&(file, value.start_byte(), value.end_byte()))
                                    .map(|&c| Binding::Class(c))
                                    .unwrap_or(Binding::Opaque),
                                _ => self.eval_simple(rel, value, src, &scope, 0),
                            };
                            match name.kind() {
                                "identifier" => {
                                    let n = text(name, src);
                                    if !is_const && reassigned.contains(n) {
                                        scope.insert(n.to_string(), Binding::Opaque);
                                    } else if b != Binding::Opaque {
                                        scope.insert(n.to_string(), b);
                                    }
                                }
                                "object_pattern" => {
                                    let mut pc = name.walk();
                                    for p in name.named_children(&mut pc) {
                                        match p.kind() {
                                            "shorthand_property_identifier_pattern" => {
                                                let n = text(p, src);
                                                let m = self.member_of(&b, n);
                                                scope.insert(
                                                    n.to_string(),
                                                    if reassigned.contains(n) && !is_const { Binding::Opaque } else { m },
                                                );
                                            }
                                            "pair_pattern" => {
                                                if let (Some(k), Some(v)) = (p.child_by_field_name("key"), p.child_by_field_name("value")) {
                                                    if v.kind() == "identifier" {
                                                        let n = text(v, src);
                                                        let m = self.member_of(&b, text(k, src));
                                                        scope.insert(
                                                            n.to_string(),
                                                            if reassigned.contains(n) && !is_const { Binding::Opaque } else { m },
                                                        );
                                                    }
                                                }
                                            }
                                            _ => {}
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        scope
    }

    fn bind_import(&self, file: usize, rel: &str, node: Node, src: &str, scope: &mut HashMap<String, Binding>) {
        if is_type_only(node) {
            return;
        }
        let Some(source) = node.child_by_field_name("source") else {
            // `import x = require('y')`
            let mut c = node.walk();
            let clause = node.named_children(&mut c).find(|n| n.kind() == "import_require_clause");
            if let Some(clause) = clause {
                if let (Some(name), Some(source)) = (clause.named_child(0), clause.child_by_field_name("source")) {
                    let spec = string_value(source, src);
                    scope.insert(text(name, src).to_string(), self.module_binding(rel, &spec));
                }
            }
            return;
        };
        let spec = string_value(source, src);
        let resolved = self.resolve_spec(rel, &spec);
        let make = |what: ImportWhat| -> Binding {
            match &resolved {
                Spec::Project(f) => Binding::Import(*f, what),
                Spec::Ext(s) => match what {
                    ImportWhat::Namespace => Binding::Ext(s.clone(), Vec::new()),
                    ImportWhat::Default => Binding::Ext(s.clone(), vec!["default".to_string()]),
                    ImportWhat::Named(n) => Binding::Ext(s.clone(), vec![n]),
                },
                Spec::Builtin(b) => Binding::Builtin(b.clone()),
                _ => Binding::Opaque,
            }
        };
        let _ = file;
        let mut c = node.walk();
        let Some(clause) = node.named_children(&mut c).find(|n| n.kind() == "import_clause") else { return };
        let mut cc = clause.walk();
        for part in clause.named_children(&mut cc) {
            match part.kind() {
                "identifier" => {
                    scope.insert(text(part, src).to_string(), make(ImportWhat::Default));
                }
                "namespace_import" => {
                    if let Some(n) = part.named_child(0) {
                        scope.insert(text(n, src).to_string(), make(ImportWhat::Namespace));
                    }
                }
                "named_imports" => {
                    let mut sc = part.walk();
                    for spec_node in part.named_children(&mut sc) {
                        if spec_node.kind() != "import_specifier" || is_type_only(spec_node) {
                            continue;
                        }
                        let Some(name) = spec_node.child_by_field_name("name") else { continue };
                        let local = spec_node.child_by_field_name("alias").unwrap_or(name);
                        scope.insert(text(local, src).to_string(), make(ImportWhat::Named(text(name, src).to_string())));
                    }
                }
                _ => {}
            }
        }
    }

    fn collect_exports(&mut self, file: usize, rel: &str, root: Node, src: &str) {
        let mut c = root.walk();
        let stmts: Vec<Node> = root.named_children(&mut c).collect();
        let mut exports: HashMap<String, Export> = HashMap::new();
        let mut star_from = Vec::new();
        let mut opaque = false;
        let scope = self.files[file].scope.clone();

        for stmt in stmts {
            match stmt.kind() {
                "export_statement" => {
                    if is_type_only(stmt) {
                        continue;
                    }
                    let source = stmt.child_by_field_name("source").map(|s| string_value(s, src));
                    let mut ec = stmt.walk();
                    let children: Vec<Node> = stmt.named_children(&mut ec).collect();
                    if let Some(decl) = stmt.child_by_field_name("declaration") {
                        match decl.kind() {
                            "function_declaration"
                            | "generator_function_declaration"
                            | "class_declaration"
                            | "abstract_class_declaration" => {
                                if let Some(n) = decl.child_by_field_name("name") {
                                    exports.insert(text(n, src).to_string(), Export::Local(text(n, src).to_string()));
                                    if stmt.children(&mut stmt.walk()).any(|k| k.kind() == "default") {
                                        exports.insert("default".to_string(), Export::Local(text(n, src).to_string()));
                                    }
                                }
                            }
                            "lexical_declaration" | "variable_declaration" => {
                                let mut dc = decl.walk();
                                for d in decl.named_children(&mut dc) {
                                    if let Some(n) = d.child_by_field_name("name").filter(|n| n.kind() == "identifier") {
                                        exports.insert(text(n, src).to_string(), Export::Local(text(n, src).to_string()));
                                    }
                                }
                            }
                            _ => {}
                        }
                    } else if let Some(value) = stmt.child_by_field_name("value") {
                        let b = self.default_export_binding(file, rel, value, src, &scope);
                        exports.insert("default".to_string(), b);
                    } else if let Some(clause) = children.iter().find(|n| n.kind() == "export_clause") {
                        let mut cc = clause.walk();
                        for sp in clause.named_children(&mut cc) {
                            if sp.kind() != "export_specifier" || is_type_only(sp) {
                                continue;
                            }
                            let Some(name) = sp.child_by_field_name("name") else { continue };
                            let exported = text(sp.child_by_field_name("alias").unwrap_or(name), src).to_string();
                            let local = text(name, src);
                            match &source {
                                Some(spec) => {
                                    let b = match self.resolve_spec(rel, spec) {
                                        Spec::Project(f) => Binding::Import(
                                            f,
                                            if local == "default" { ImportWhat::Default } else { ImportWhat::Named(local.to_string()) },
                                        ),
                                        Spec::Ext(s) => Binding::Ext(s, vec![local.to_string()]),
                                        _ => Binding::Opaque,
                                    };
                                    exports.insert(exported, Export::Bind(b));
                                }
                                None => {
                                    exports.insert(exported, Export::Local(local.to_string()));
                                }
                            }
                        }
                    } else if let Some(spec) = source {
                        // `export * from './x'` and `export * as ns from './x'`
                        if let Spec::Project(f) = self.resolve_spec(rel, &spec) {
                            let named = children.iter().find(|n| n.kind() == "namespace_export").and_then(|n| n.named_child(0));
                            match named {
                                Some(ns) => {
                                    exports.insert(text(ns, src).to_string(), Export::Bind(Binding::Module(f)));
                                }
                                None => star_from.push(f),
                            }
                        }
                    }
                }
                "expression_statement" => {
                    let Some(expr) = stmt.named_child(0) else { continue };
                    self.collect_cjs(file, rel, expr, src, &scope, &mut exports, &mut opaque);
                }
                _ => {}
            }
        }
        let info = &mut self.files[file];
        info.exports = exports;
        info.star_from = star_from;
        info.opaque_exports = opaque;
    }

    fn default_export_binding(&self, file: usize, rel: &str, value: Node, src: &str, scope: &HashMap<String, Binding>) -> Export {
        let value = unwrap_expr(value);
        let pos = (file, value.start_byte(), value.end_byte());
        match value.kind() {
            "function_declaration"
            | "function_expression"
            | "generator_function"
            | "arrow_function"
            | "function"
            | "generator_function_declaration" => {
                self.by_pos.get(&pos).map(|&f| Export::Bind(Binding::Func(f))).unwrap_or(Export::Bind(Binding::Opaque))
            }
            "class" | "class_declaration" => {
                self.class_by_pos.get(&pos).map(|&c| Export::Bind(Binding::Class(c))).unwrap_or(Export::Bind(Binding::Opaque))
            }
            "identifier" => Export::Local(text(value, src).to_string()),
            _ => Export::Bind(self.eval_simple(rel, value, src, scope, 0)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn collect_cjs(
        &self,
        file: usize,
        rel: &str,
        expr: Node,
        src: &str,
        scope: &HashMap<String, Binding>,
        exports: &mut HashMap<String, Export>,
        opaque: &mut bool,
    ) {
        match expr.kind() {
            "assignment_expression" => {
                let (Some(left), Some(right)) = (expr.child_by_field_name("left"), expr.child_by_field_name("right")) else { return };
                let l = text(left, src);
                if l == "module.exports" {
                    let right = unwrap_expr(right);
                    if right.kind() == "object" {
                        let mut c = right.walk();
                        for p in right.named_children(&mut c) {
                            match p.kind() {
                                "shorthand_property_identifier" => {
                                    exports.insert(text(p, src).to_string(), Export::Local(text(p, src).to_string()));
                                }
                                "pair" => {
                                    if let (Some(k), Some(v)) = (p.child_by_field_name("key"), p.child_by_field_name("value")) {
                                        let key = text(k, src).trim_matches(|c| c == '"' || c == '\'').to_string();
                                        exports.insert(key, self.default_export_binding(file, rel, v, src, scope));
                                    }
                                }
                                "method_definition" => {
                                    if let (Some(k), Some(&f)) =
                                        (p.child_by_field_name("name"), self.by_pos.get(&(file, p.start_byte(), p.end_byte())))
                                    {
                                        exports.insert(text(k, src).to_string(), Export::Bind(Binding::Func(f)));
                                    }
                                }
                                "spread_element" => *opaque = true,
                                _ => {}
                            }
                        }
                    } else {
                        exports.insert("default".to_string(), self.default_export_binding(file, rel, right, src, scope));
                    }
                } else if let Some(name) = l.strip_prefix("module.exports.").or_else(|| l.strip_prefix("exports.")) {
                    if !name.contains(['.', '[', '(']) {
                        exports.insert(name.to_string(), self.default_export_binding(file, rel, right, src, scope));
                    }
                } else if l.starts_with("exports[") || l.starts_with("module.exports[") {
                    *opaque = true;
                }
            }
            "call_expression" => {
                let t = text(expr, src);
                if t.starts_with("Object.assign(module.exports")
                    || t.starts_with("Object.assign(exports")
                    || t.starts_with("Object.defineProperty(exports")
                    || t.starts_with("Object.defineProperty(module.exports")
                {
                    *opaque = true;
                }
            }
            _ => {}
        }
    }

    pub fn find_method(&self, class: usize, name: &str, statics: bool) -> Vec<usize> {
        let mut c = class;
        for _ in 0..64 {
            let map = if statics { &self.classes[c].statics } else { &self.classes[c].methods };
            if let Some(v) = map.get(name) {
                return v.clone();
            }
            match self.classes[c].base {
                Base::Project(b) => c = b,
                _ => break,
            }
        }
        Vec::new()
    }

    /// The first external base class on the way up, if there is one.
    pub fn external_base(&self, class: usize) -> Option<(String, Vec<String>)> {
        let mut c = class;
        for _ in 0..64 {
            match &self.classes[c].base {
                Base::Project(b) => c = *b,
                Base::Ext(s, p) => return Some((s.clone(), p.clone())),
                _ => return None,
            }
        }
        None
    }

    pub fn descendants(&self, class: usize) -> Vec<usize> {
        let mut out = Vec::new();
        let mut stack = vec![class];
        let mut seen = HashSet::new();
        while let Some(c) = stack.pop() {
            for &d in &self.classes[c].derived {
                if seen.insert(d) {
                    out.push(d);
                    stack.push(d);
                }
            }
        }
        out
    }
}

pub fn is_type_only(node: Node) -> bool {
    let mut c = node.walk();
    let found = node.children(&mut c).take(3).any(|k| !k.is_named() && k.kind() == "type");
    found
}

pub fn unwrap_expr(mut node: Node) -> Node {
    for _ in 0..16 {
        match node.kind() {
            "parenthesized_expression"
            | "non_null_expression"
            | "await_expression"
            | "as_expression"
            | "satisfies_expression"
            | "type_assertion" => match node.named_child(0) {
                Some(n) if node.kind() != "type_assertion" => node = n,
                Some(_) => match node.named_child(node.named_child_count().saturating_sub(1) as u32) {
                    Some(n) => node = n,
                    None => return node,
                },
                None => return node,
            },
            _ => return node,
        }
    }
    node
}

/// The text of a string literal without substitutions; None for anything else.
pub fn string_value(node: Node, src: &str) -> String {
    let raw = text(node, src);
    raw.trim_matches(|c| c == '"' || c == '\'' || c == '`').to_string()
}

pub fn literal_text(node: Node, src: &str) -> Option<String> {
    match node.kind() {
        "string" => Some(string_value(node, src)),
        "template_string" => {
            let mut c = node.walk();
            let has_sub = node.named_children(&mut c).any(|n| n.kind() == "template_substitution");
            if has_sub {
                None
            } else {
                Some(string_value(node, src))
            }
        }
        _ => None,
    }
}

/// The literal first argument of a call (`require('x')`), if it has one.
pub fn literal_argument(call: Node, src: &str) -> Option<String> {
    let args = call.child_by_field_name("arguments")?;
    if args.named_child_count() != 1 {
        return None;
    }
    literal_text(args.named_child(0)?, src)
}

fn gather_specs(node: Node, src: &str, out: &mut HashSet<String>, depth: usize) {
    if depth > MAX_DEPTH {
        return;
    }
    match node.kind() {
        "import_statement" | "export_statement" => {
            if let Some(s) = node.child_by_field_name("source") {
                out.insert(string_value(s, src));
            }
            let mut c = node.walk();
            for ch in node.named_children(&mut c) {
                if ch.kind() == "import_require_clause" {
                    if let Some(s) = ch.child_by_field_name("source") {
                        out.insert(string_value(s, src));
                    }
                }
            }
        }
        "call_expression" => {
            if let Some(f) = node.child_by_field_name("function") {
                if (f.kind() == "identifier" && text(f, src) == "require") || f.kind() == "import" {
                    if let Some(s) = literal_argument(node, src) {
                        out.insert(s);
                    }
                }
            }
        }
        _ => {}
    }
    let mut c = node.walk();
    for ch in node.named_children(&mut c) {
        gather_specs(ch, src, out, depth + 1);
    }
}

/// Names that are assigned after their declaration anywhere in the tree (so a value read at the declaration may not be the value used).
pub fn assigned_names(root: Node, src: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    let mut stack = vec![root];
    while let Some(n) = stack.pop() {
        match n.kind() {
            "assignment_expression" | "augmented_assignment_expression" => {
                if let Some(l) = n.child_by_field_name("left") {
                    collect_pattern_names(l, src, &mut out);
                }
            }
            "update_expression" => {
                if let Some(a) = n.child_by_field_name("argument") {
                    collect_pattern_names(a, src, &mut out);
                }
            }
            "for_in_statement" => {
                if let Some(l) = n.child_by_field_name("left") {
                    collect_pattern_names(l, src, &mut out);
                }
            }
            _ => {}
        }
        let mut c = n.walk();
        stack.extend(n.named_children(&mut c));
    }
    out
}

pub fn collect_pattern_names(node: Node, src: &str, out: &mut HashSet<String>) {
    match node.kind() {
        "identifier" | "shorthand_property_identifier_pattern" | "shorthand_property_identifier" => {
            out.insert(text(node, src).to_string());
        }
        "member_expression" | "subscript_expression" | "call_expression" => {}
        _ => {
            let mut c = node.walk();
            for ch in node.named_children(&mut c) {
                collect_pattern_names(ch, src, out);
            }
        }
    }
}

// ---- the collecting walk ------------------------------------------------------------------------------------------------------

struct Collector<'a> {
    file: usize,
    rel: &'a str,
    src: &'a str,
    used: &'a mut HashSet<String>,
}

fn property_name(node: Node, src: &str) -> String {
    match node.kind() {
        "string" => string_value(node, src),
        "computed_property_name" => "<computed>".to_string(),
        _ => text(node, src).to_string(),
    }
}

impl Collector<'_> {
    fn walk(&mut self, js: &mut Js, node: Node, hint: Option<(String, bool)>, decorated: bool, depth: usize) {
        if depth > MAX_DEPTH {
            return;
        }
        let kind = node.kind();
        match kind {
            "function_declaration"
            | "generator_function_declaration"
            | "function_expression"
            | "generator_function"
            | "function"
            | "arrow_function" => {
                let (name, by_name) = match node.child_by_field_name("name") {
                    Some(n) => (text(n, self.src).to_string(), false),
                    None => match &hint {
                        Some((h, p)) => (h.clone(), *p),
                        None => (format!("<anonymous@{}>", line(node)), false),
                    },
                };
                let idx = self.func(js, node, name.clone(), None, false, FuncKind::Function, false);
                if by_name {
                    js.by_name.entry(name).or_default().push(idx);
                }
                self.children(js, node, depth);
            }
            "method_definition" => {
                // Object literal methods; class methods are handled with their class.
                let name = node.child_by_field_name("name").map(|n| property_name(n, self.src)).unwrap_or_default();
                let idx = self.func(js, node, name.clone(), None, false, FuncKind::Function, false);
                js.by_name.entry(name.clone()).or_default().push(idx);
                if is_accessor(node) {
                    js.accessors.entry(name).or_default().push(idx);
                }
                self.children(js, node, depth);
            }
            "class_declaration" | "class" | "abstract_class_declaration" => self.class(js, node, decorated, depth),
            "export_statement" => {
                let mut c = node.walk();
                let has_decorator = node.children(&mut c).any(|k| k.kind() == "decorator");
                let mut c2 = node.walk();
                for ch in node.named_children(&mut c2) {
                    self.walk(js, ch, None, has_decorator, depth + 1);
                }
            }
            "variable_declarator" => {
                let name = node.child_by_field_name("name").filter(|n| n.kind() == "identifier").map(|n| text(n, self.src).to_string());
                let mut c = node.walk();
                for ch in node.named_children(&mut c) {
                    let h = if ch.kind() == "identifier" || Some(ch.id()) != node.child_by_field_name("value").map(|v| v.id()) {
                        None
                    } else {
                        name.clone().map(|n| (n, false))
                    };
                    self.walk(js, ch, h, false, depth + 1);
                }
            }
            "pair" => {
                let key = node.child_by_field_name("key").map(|k| property_name(k, self.src));
                let mut c = node.walk();
                for ch in node.named_children(&mut c) {
                    let h = if Some(ch.id()) == node.child_by_field_name("value").map(|v| v.id()) {
                        key.clone().map(|k| (k, true))
                    } else {
                        None
                    };
                    self.walk(js, ch, h, false, depth + 1);
                }
            }
            "assignment_expression" => {
                let left = node.child_by_field_name("left");
                let name = left
                    .filter(|l| l.kind() == "member_expression")
                    .and_then(|l| l.child_by_field_name("property"))
                    .map(|p| text(p, self.src).to_string());
                let mut c = node.walk();
                for ch in node.named_children(&mut c) {
                    let h = if Some(ch.id()) == node.child_by_field_name("right").map(|v| v.id()) {
                        name.clone().map(|n| (n, true))
                    } else {
                        None
                    };
                    self.walk(js, ch, h, false, depth + 1);
                }
            }
            _ => self.children(js, node, depth),
        }
    }

    fn children(&mut self, js: &mut Js, node: Node, depth: usize) {
        let mut c = node.walk();
        for ch in node.named_children(&mut c) {
            self.walk(js, ch, None, false, depth + 1);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn func(
        &mut self,
        js: &mut Js,
        node: Node,
        name: String,
        class: Option<usize>,
        is_static: bool,
        kind: FuncKind,
        decorated: bool,
    ) -> usize {
        let base = match class {
            Some(c) => format!("{}.{}", js.classes[c].name, name),
            None => name,
        };
        let file = self.file;
        let idx = js.alloc(self.used, file, self.rel, base, node, |id| Func { id, file, class, is_static, kind, decorated });
        js.by_pos.insert((file, node.start_byte(), node.end_byte()), idx);
        idx
    }

    fn class(&mut self, js: &mut Js, node: Node, decorated_by_export: bool, depth: usize) {
        let name =
            node.child_by_field_name("name").map(|n| text(n, self.src).to_string()).unwrap_or_else(|| format!("<class@{}>", line(node)));
        let mut c = node.walk();
        let decorated = decorated_by_export || node.children(&mut c).any(|k| k.kind() == "decorator");

        let extends = {
            let mut cc = node.walk();
            let heritage = node.named_children(&mut cc).find(|n| n.kind() == "class_heritage");
            heritage.and_then(|h| {
                let mut hc = h.walk();
                let first = h.named_children(&mut hc).next();
                first.and_then(|f| {
                    if f.kind() == "extends_clause" {
                        f.child_by_field_name("value")
                    } else if f.kind() == "implements_clause" {
                        None
                    } else {
                        Some(f)
                    }
                })
            })
        };

        let ci = js.classes.len();
        js.classes.push(Class {
            name: name.clone(),
            file: self.file,
            extends: extends.map(|e| (e.start_byte(), e.end_byte())),
            base: Base::None,
            methods: HashMap::new(),
            statics: HashMap::new(),
            ctor: None,
            init: 0,
            fields: HashMap::new(),
            derived: Vec::new(),
            decorated,
            field_nodes: Vec::new(),
        });
        js.class_by_pos.insert((self.file, node.start_byte(), node.end_byte()), ci);
        let init = self.func(js, node, "<init>".to_string(), Some(ci), false, FuncKind::ClassInit, decorated);
        js.classes[ci].init = init;

        let mut bc = node.walk();
        let body = node.named_children(&mut bc).find(|n| n.kind() == "class_body");
        // The extends expression and the decorators can contain functions too.
        let mut oc = node.walk();
        for ch in node.named_children(&mut oc) {
            if ch.kind() != "class_body" && ch.kind() != "type_identifier" && ch.kind() != "identifier" {
                self.walk(js, ch, None, false, depth + 1);
            }
        }
        let Some(body) = body else { return };
        let mut mc = body.walk();
        // A decorator before a member is a sibling of it in the class body (not its child).
        let mut decorator_before = false;
        for member in body.named_children(&mut mc) {
            if member.kind() == "decorator" {
                decorator_before = true;
                self.walk(js, member, None, false, depth + 1);
                continue;
            }
            let preceded = std::mem::take(&mut decorator_before);
            let is_static = {
                let mut k = member.walk();
                let found = member.children(&mut k).any(|t| !t.is_named() && t.kind() == "static");
                found
            };
            let mut dc = member.walk();
            let member_decorated = preceded || member.named_children(&mut dc).any(|t| t.kind() == "decorator");
            match member.kind() {
                "method_definition" => {
                    let mname = member.child_by_field_name("name").map(|n| property_name(n, self.src)).unwrap_or_default();
                    let is_ctor = mname == "constructor" && !is_static;
                    let kind = if is_ctor {
                        FuncKind::Ctor
                    } else if is_accessor(member) {
                        FuncKind::Accessor
                    } else {
                        FuncKind::Method
                    };
                    let idx = self.func(js, member, mname.clone(), Some(ci), is_static, kind, member_decorated);
                    if is_ctor {
                        js.classes[ci].ctor = Some(idx);
                        self.parameter_properties(js, ci, member);
                    } else if is_static {
                        js.classes[ci].statics.entry(mname.clone()).or_default().push(idx);
                    } else {
                        js.classes[ci].methods.entry(mname.clone()).or_default().push(idx);
                    }
                    js.by_name.entry(mname.clone()).or_default().push(idx);
                    if kind == FuncKind::Accessor {
                        js.accessors.entry(mname).or_default().push(idx);
                    }
                    self.children(js, member, depth);
                }
                "field_definition" | "public_field_definition" => {
                    let fname = member
                        .child_by_field_name("property")
                        .or_else(|| member.child_by_field_name("name"))
                        .map(|n| property_name(n, self.src))
                        .unwrap_or_default();
                    let value = member.child_by_field_name("value");
                    let annotation = member.child_by_field_name("type");
                    if !is_static {
                        js.classes[ci].field_nodes.push((
                            fname.clone(),
                            annotation.map(|n| (n.start_byte(), n.end_byte())),
                            value.map(|n| (n.start_byte(), n.end_byte())),
                        ));
                    }
                    let mut vc = member.walk();
                    for ch in member.named_children(&mut vc) {
                        let is_value = Some(ch.id()) == value.map(|v| v.id());
                        let unwrapped = if is_value { unwrap_expr(ch) } else { ch };
                        if is_value
                            && matches!(unwrapped.kind(), "arrow_function" | "function_expression" | "function" | "generator_function")
                        {
                            // `handle = () => {}`: a method that is bound to its instance.
                            let idx = self.func(js, unwrapped, fname.clone(), Some(ci), is_static, FuncKind::Method, member_decorated);
                            if is_static {
                                js.classes[ci].statics.entry(fname.clone()).or_default().push(idx);
                            } else {
                                js.classes[ci].methods.entry(fname.clone()).or_default().push(idx);
                            }
                            js.by_name.entry(fname.clone()).or_default().push(idx);
                            self.children(js, unwrapped, depth);
                        } else {
                            self.walk(js, ch, None, false, depth + 1);
                        }
                    }
                }
                _ => self.walk(js, member, None, false, depth + 1),
            }
        }
    }

    /// `constructor(private api: Api)`: a field with a declared type.
    fn parameter_properties(&mut self, js: &mut Js, ci: usize, ctor: Node) {
        let Some(params) = ctor.child_by_field_name("parameters") else { return };
        let mut c = params.walk();
        for p in params.named_children(&mut c) {
            if !matches!(p.kind(), "required_parameter" | "optional_parameter") {
                continue;
            }
            let mut pc = p.walk();
            let has_modifier = p.named_children(&mut pc).any(|k| k.kind() == "accessibility_modifier");
            let mut rc = p.walk();
            let readonly = p.children(&mut rc).any(|k| !k.is_named() && k.kind() == "readonly");
            if !has_modifier && !readonly {
                continue;
            }
            if let Some(pattern) = p.child_by_field_name("pattern").filter(|n| n.kind() == "identifier") {
                let annotation = p.child_by_field_name("type");
                js.classes[ci].field_nodes.push((
                    text(pattern, self.src).to_string(),
                    annotation.map(|n| (n.start_byte(), n.end_byte())),
                    None,
                ));
            }
        }
    }
}

fn is_accessor(method: Node) -> bool {
    let mut c = method.walk();
    let found = method.children(&mut c).any(|t| !t.is_named() && (t.kind() == "get" || t.kind() == "set"));
    found
}
