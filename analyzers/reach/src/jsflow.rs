//! JavaScript and TypeScript (ADR 0019): the bodies. Walks every function once, resolves what each call refers to by names,
//! imports, declared and inferred types, and records edges in the same graph the C# front end produces, so that labeling is shared.
//! What cannot be resolved is over-approximated (callbacks, receivers of unknown type) or marked as uncertain (`eval`, computed
//! calls, dynamic `require`, imports that may be project code the analyzer cannot find).

use crate::analyze::{Dest, Edge, EdgeKind, Graph, Uncertainty};
use crate::discover;
use crate::js::*;
use crate::program::text;
use crate::protocol::*;
use crate::reach::{self, Entry, Names};
use crate::targets::TargetIndex;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use tree_sitter::Node;

const MAX_DIAGNOSTICS: usize = 200;
const MAX_TOTAL_SOURCE_BYTES: usize = 512 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;

// ---- symbols ---------------------------------------------------------------------------------------------------------------------

/// `package::path`, `package::*`, `package::Type.*`.
pub struct JsSym {
    pub spec: String,
    pub path: Vec<String>,
    pub wild: bool,
    pub module_star: bool,
}

fn is_ident(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_' || c == '$')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
}

pub fn parse_symbol(symbol: &str) -> Result<JsSym, String> {
    let bad = |why: &str| Err(format!("invalid JavaScript symbol '{}': {why}", crate::safe(symbol)));
    if symbol.len() > 512 {
        return bad("longer than 512 characters");
    }
    let Some((spec, rest)) = symbol.split_once("::") else { return bad("expected package::path") };
    let spec_ok = !spec.is_empty()
        && spec.len() <= 214
        && !spec.starts_with(['.', '/'])
        && !spec.contains("..")
        && !spec.contains("//")
        && spec.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@' | '/' | '~'));
    if !spec_ok {
        return bad("the package must be an npm package name or specifier");
    }
    if rest == "*" {
        return Ok(JsSym { spec: spec.to_string(), path: Vec::new(), wild: false, module_star: true });
    }
    let mut segments: Vec<&str> = rest.split('.').collect();
    let wild = segments.last() == Some(&"*");
    if wild {
        segments.pop();
    }
    if segments.is_empty() || !segments.iter().all(|s| is_ident(s)) {
        return bad("the path must be identifiers separated by dots, optionally ending in .*");
    }
    Ok(JsSym { spec: spec.to_string(), path: segments.iter().map(|s| s.to_string()).collect(), wild, module_star: false })
}

fn split_symbol(symbol: &str) -> Result<(String, Option<String>), String> {
    let s = parse_symbol(symbol)?;
    if s.module_star {
        return Ok((s.spec, None));
    }
    if s.wild {
        return Ok((format!("{}::{}", s.spec, s.path.join(".")), None));
    }
    let (last, parent) = s.path.split_last().expect("non-empty");
    Ok((format!("{}::{}", s.spec, parent.join(".")), Some(last.clone())))
}

fn sym_matches(s: &JsSym, candidates: &[Vec<String>], ctor: bool, import_only: bool) -> bool {
    if s.module_star {
        return true;
    }
    if import_only {
        return false;
    }
    candidates.iter().any(|c| {
        if !c.starts_with(&s.path) {
            return false;
        }
        !s.wild || c.len() > s.path.len() || ctor
    })
}

// ---- the walk --------------------------------------------------------------------------------------------------------------------

enum Pending<'a> {
    Func(Node<'a>, usize),
    Class(Node<'a>, usize),
}

struct Flow<'a> {
    js: &'a Js,
    files: &'a [JsFile],
    targets: &'a TargetIndex,
    syms: &'a [JsSym],
    by_spec: HashMap<String, Vec<usize>>,
    edges: Vec<Vec<Edge>>,
    uncertain: Vec<Vec<Uncertainty>>,
    reflection_sites: usize,
    seen: HashSet<(usize, bool, usize, bool)>,
    analyzed: Vec<bool>,
    file: usize,
    cur: usize,
    class: Option<usize>,
    in_static: bool,
    scopes: Vec<HashMap<String, Binding>>,
    local_assigned: HashSet<String>,
    pending: Vec<Pending<'a>>,
    depth: usize,
    diagnostics: Vec<Diagnostic>,
    diag_seen: HashSet<String>,
}

fn skip_kind(kind: &str) -> bool {
    (kind.contains("type") && kind != "type_assertion")
        || matches!(
            kind,
            "interface_declaration"
                | "ambient_declaration"
                | "function_signature"
                | "method_signature"
                | "abstract_method_signature"
                | "property_signature"
                | "call_signature"
                | "construct_signature"
                | "index_signature"
                | "comment"
                | "decorator_member_expression"
                | "jsx_closing_element"
                | "jsx_text"
                | "string_fragment"
        )
}

impl<'a> Flow<'a> {
    fn src(&self) -> &'a str {
        &self.files[self.file].src
    }

    fn rel(&self) -> &'a str {
        &self.files[self.file].rel
    }

    fn edge(&mut self, to: Dest, kind: EdgeKind, line: usize) {
        let key = (
            self.cur,
            matches!(to, Dest::Sym(_)),
            match to {
                Dest::Method(m) | Dest::Sym(m) => m,
            },
            kind == EdgeKind::Dynamic,
        );
        if self.seen.insert(key) {
            self.edges[self.cur].push(Edge { to, kind, line });
        }
    }

    fn uncertainty(&mut self, u: Uncertainty) {
        if !self.uncertain[self.cur].contains(&u) {
            self.uncertain[self.cur].push(u);
        }
    }

    fn reflection(&mut self) {
        self.reflection_sites += 1;
        self.uncertainty(Uncertainty::Reflection);
    }

    fn note(&mut self, message: String) {
        if self.diagnostics.len() < MAX_DIAGNOSTICS && self.diag_seen.insert(format!("{}|{message}", self.rel())) {
            self.diagnostics.push(Diagnostic { file: Some(self.rel().to_string()), message });
        }
    }

    fn lookup(&self, name: &str) -> Option<Binding> {
        self.scopes.iter().rev().find_map(|s| s.get(name)).map(|b| self.js.resolve(b, 0))
    }

    fn declare(&mut self, name: &str, b: Binding) {
        if let Some(s) = self.scopes.last_mut() {
            s.insert(name.to_string(), b);
        }
    }

    fn merged_scope(&self) -> HashMap<String, Binding> {
        let mut m = HashMap::new();
        for s in &self.scopes {
            for (k, v) in s {
                m.insert(k.clone(), v.clone());
            }
        }
        m
    }

    fn this_binding(&self) -> Binding {
        match self.class {
            Some(c) if self.in_static => Binding::Class(c),
            Some(c) => Binding::Instance(Ty::Class(c)),
            None => Binding::Opaque,
        }
    }

    fn type_binding(&self, annotation: Node<'a>) -> Option<Binding> {
        let scope = self.merged_scope();
        self.js.type_of(annotation, self.src(), &scope).map(Binding::Instance)
    }

    // ---- references to packages ----------------------------------------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    fn reference(&mut self, spec: &str, path: &[String], ctor: bool, call: bool, import_only: bool, kind: EdgeKind, line: usize) {
        let mut candidates = vec![path.to_vec()];
        if path.first().map(|s| s == "default").unwrap_or(false) && path.len() > 1 {
            candidates.push(path[1..].to_vec());
        }
        if path.is_empty() && call {
            candidates.push(vec!["default".to_string()]);
        }
        let min_len = package_name(spec).len();
        let mut prefix = spec.to_string();
        let mut hits = Vec::new();
        loop {
            if let Some(list) = self.by_spec.get(&prefix) {
                let sub = prefix != spec;
                for &i in list {
                    if sub || sym_matches(&self.syms[i], &candidates, ctor, import_only) {
                        hits.push(i);
                    }
                }
            }
            match prefix.rfind('/') {
                Some(p) if p >= min_len => prefix.truncate(p),
                _ => break,
            }
        }
        for i in hits {
            self.edge(Dest::Sym(i), kind, line);
        }
    }

    fn file_imports(&self, spec: &str) -> bool {
        self.js.files[self.file].ext_specs.iter().any(|e| e == spec || e.starts_with(&format!("{spec}/")))
    }

    /// A call (or access) on a receiver whose type is unknown: any project member of that name, and the members of imported
    /// packages of that name; a member of a package this file does not import is uncertain.
    fn unknown_receiver(&mut self, name: &str, line: usize, call: bool) {
        let js = self.js;
        let list = if call { js.by_name.get(name) } else { js.accessors.get(name) };
        for &f in list.into_iter().flatten() {
            self.edge(Dest::Method(f), EdgeKind::Dynamic, line);
        }
        for &s in self.targets.with_member(name) {
            let spec = self.syms[s].spec.clone();
            if self.file_imports(&spec) {
                self.edge(Dest::Sym(s), EdgeKind::Dynamic, line);
            } else {
                self.uncertainty(Uncertainty::NameMatch(s));
            }
        }
    }

    fn import_edge(&mut self, spec: &str, line: usize) {
        match self.js.resolve_spec(self.rel(), spec) {
            Spec::Project(f) => self.edge(Dest::Method(self.js.files[f].init), EdgeKind::Static, line),
            Spec::Ext(s) => self.reference(&s, &[], false, false, true, EdgeKind::Static, line),
            Spec::Builtin(_) | Spec::Ignore => {}
            Spec::Unresolved(reason) => {
                self.uncertainty(Uncertainty::Incomplete);
                self.note(format!("import '{}' not followed: {reason}", crate::safe(spec)));
            }
        }
    }

    // ---- escapes and calls ---------------------------------------------------------------------------------------------------

    fn escape(&mut self, b: &Binding, line: usize) {
        match self.js.resolve(b, 0) {
            Binding::Func(i) => self.edge(Dest::Method(i), EdgeKind::Dynamic, line),
            Binding::Class(c) => self.class_edges(c, EdgeKind::Dynamic, line),
            Binding::Instance(Ty::Class(c)) => {
                let mut cur = c;
                for _ in 0..64 {
                    let ids: Vec<usize> = self.js.classes[cur].methods.values().flatten().copied().collect();
                    for m in ids {
                        self.edge(Dest::Method(m), EdgeKind::Dynamic, line);
                    }
                    match self.js.classes[cur].base {
                        Base::Project(b) => cur = b,
                        _ => break,
                    }
                }
            }
            Binding::Ext(s, p) if p.is_empty() || p == ["default"] => self.reference_all(&s, line),
            Binding::Ext(s, p) => self.reference(&s, &p, false, false, false, EdgeKind::Dynamic, line),
            _ => {}
        }
    }

    /// A value of a package that a module exposes (`exports.json = bodyParser.json`): importers can call it without a path the
    /// analysis follows, so it counts as used. Project functions need no such edge: importers are followed by name.
    fn escape_external(&mut self, b: &Binding, line: usize) {
        if matches!(self.js.resolve(b, 0), Binding::Ext(..)) {
            self.escape(b, line);
        }
    }

    /// Everything in the symbol list that belongs to a package (the module object itself is passed on or exported).
    fn reference_all(&mut self, spec: &str, line: usize) {
        let min_len = package_name(spec).len();
        let mut prefix = spec.to_string();
        let mut hits = Vec::new();
        loop {
            if let Some(list) = self.by_spec.get(&prefix) {
                hits.extend(list.iter().copied());
            }
            match prefix.rfind('/') {
                Some(p) if p >= min_len => prefix.truncate(p),
                _ => break,
            }
        }
        for i in hits {
            self.edge(Dest::Sym(i), EdgeKind::Dynamic, line);
        }
    }

    /// Constructing a class: its initializers and its constructor, and up the chain until a constructor takes over (`super(...)`).
    fn class_edges(&mut self, class: usize, kind: EdgeKind, line: usize) {
        let mut c = class;
        for _ in 0..64 {
            let (init, ctor) = (self.js.classes[c].init, self.js.classes[c].ctor);
            self.edge(Dest::Method(init), kind, line);
            if let Some(ct) = ctor {
                self.edge(Dest::Method(ct), kind, line);
                return;
            }
            match self.js.classes[c].base.clone() {
                Base::Project(b) => c = b,
                Base::Ext(s, p) => {
                    self.reference(&s, &p, true, true, false, kind, line);
                    return;
                }
                _ => return,
            }
        }
    }

    fn call_value(&mut self, b: &Binding, kind: EdgeKind, line: usize) {
        match self.js.resolve(b, 0) {
            Binding::Func(i) => self.edge(Dest::Method(i), kind, line),
            Binding::Ext(s, p) => self.reference(&s, &p, false, true, false, kind, line),
            Binding::Module(f) => {
                let d = self.js.export_binding(f, "default", 0);
                if d != Binding::Opaque {
                    self.call_value(&d, kind, line);
                }
            }
            _ => {}
        }
    }

    fn method_call(&mut self, class: usize, name: &str, line: usize) {
        let found = self.js.find_method(class, name, false);
        if !found.is_empty() {
            for f in found {
                self.edge(Dest::Method(f), EdgeKind::Static, line);
            }
            let overrides: Vec<usize> =
                self.js.descendants(class).into_iter().filter_map(|d| self.js.classes[d].methods.get(name)).flatten().copied().collect();
            for m in overrides {
                self.edge(Dest::Method(m), EdgeKind::Dynamic, line);
            }
        } else if let Some((s, mut p)) = self.js.external_base(class) {
            p.push(name.to_string());
            self.reference(&s, &p, false, true, false, EdgeKind::Static, line);
        } else {
            self.unknown_receiver(name, line, true);
        }
    }

    fn call_on(&mut self, receiver: &Binding, name: &str, line: usize) {
        match self.js.resolve(receiver, 0) {
            Binding::Ext(s, mut p) => {
                p.push(name.to_string());
                self.reference(&s, &p, false, true, false, EdgeKind::Static, line);
            }
            Binding::Instance(Ty::Ext(s, mut p)) => {
                p.push(name.to_string());
                self.reference(&s, &p, false, true, false, EdgeKind::Static, line);
            }
            Binding::Builtin(b) => {
                let risky = (b == "vm" && (name.starts_with("run") || name == "Script" || name == "compileFunction"))
                    || (b == "module" && matches!(name, "createRequire" | "_load" | "require"));
                if risky {
                    self.reflection();
                }
            }
            Binding::Module(f) => match self.js.export_binding(f, name, 0) {
                Binding::Opaque => self.unknown_receiver(name, line, true),
                b => self.call_value(&b, EdgeKind::Static, line),
            },
            Binding::Instance(Ty::Class(c)) => self.method_call(c, name, line),
            Binding::Class(c) => {
                let found = self.js.find_method(c, name, true);
                if !found.is_empty() {
                    for f in found {
                        self.edge(Dest::Method(f), EdgeKind::Static, line);
                    }
                } else if let Some((s, mut p)) = self.js.external_base(c) {
                    p.push(name.to_string());
                    self.reference(&s, &p, false, true, false, EdgeKind::Static, line);
                } else {
                    self.unknown_receiver(name, line, true);
                }
            }
            _ => self.unknown_receiver(name, line, true),
        }
    }

    // ---- functions -----------------------------------------------------------------------------------------------------------

    fn func_value(&mut self, node: Node<'a>) -> Binding {
        match self.js.by_pos.get(&(self.file, node.start_byte(), node.end_byte())) {
            Some(&i) => {
                if !self.analyzed[i] {
                    self.pending.push(Pending::Func(node, i));
                }
                Binding::Func(i)
            }
            None => Binding::Opaque,
        }
    }

    fn drain_pending(&mut self) {
        let items = std::mem::take(&mut self.pending);
        if items.is_empty() {
            return;
        }
        let snapshot = self.scopes.clone();
        for item in items {
            match item {
                Pending::Func(node, i) => self.analyze_function(node, i, snapshot.clone()),
                Pending::Class(node, c) => self.analyze_class_init(node, c, snapshot.clone()),
            }
        }
    }

    fn analyze_function(&mut self, node: Node<'a>, idx: usize, parent: Vec<HashMap<String, Binding>>) {
        if self.analyzed[idx] {
            return;
        }
        self.analyzed[idx] = true;
        let saved = (
            self.cur,
            self.class,
            self.in_static,
            std::mem::take(&mut self.scopes),
            std::mem::take(&mut self.pending),
            std::mem::take(&mut self.local_assigned),
            self.depth,
        );
        let f = &self.js.funcs[idx];
        let arrow = node.kind() == "arrow_function";
        let (class, in_static) = if f.class.is_some() {
            (f.class, f.is_static)
        } else if arrow {
            (saved.1, saved.2)
        } else {
            (None, false)
        };
        self.cur = idx;
        self.class = class;
        self.in_static = in_static;
        self.depth = 0;
        self.scopes = parent;
        self.scopes.push(HashMap::new());
        self.local_assigned = assigned_names(node, self.src());

        self.bind_parameters(node);
        match node.child_by_field_name("body") {
            Some(body) if body.kind() == "statement_block" => {
                let scope = self.js.prebind(self.file, self.rel(), body, self.src(), &self.local_assigned);
                if let Some(s) = self.scopes.last_mut() {
                    s.extend(scope);
                }
                self.visit_children(body);
            }
            Some(body) => {
                self.visit_escape(body);
            }
            None => {}
        }
        self.drain_pending();

        self.cur = saved.0;
        self.class = saved.1;
        self.in_static = saved.2;
        self.scopes = saved.3;
        self.pending = saved.4;
        self.local_assigned = saved.5;
        self.depth = saved.6;
    }

    fn bind_parameters(&mut self, func: Node<'a>) {
        let src = self.src();
        if let Some(single) = func.child_by_field_name("parameter") {
            self.declare(text(single, src), Binding::Opaque);
        }
        let Some(params) = func.child_by_field_name("parameters") else { return };
        let mut c = params.walk();
        for p in params.named_children(&mut c) {
            match p.kind() {
                "identifier" => self.declare(text(p, src), Binding::Opaque),
                "required_parameter" | "optional_parameter" => {
                    let pattern = p.child_by_field_name("pattern");
                    let typed = p.child_by_field_name("type").and_then(|t| self.type_binding(t));
                    if let Some(default) = p.child_by_field_name("value") {
                        self.visit_escape(default);
                    }
                    match pattern {
                        Some(n) if n.kind() == "identifier" => self.declare(text(n, src), typed.unwrap_or(Binding::Opaque)),
                        Some(n) => self.declare_opaque(n),
                        None => {}
                    }
                }
                "assignment_pattern" => {
                    if let Some(l) = p.child_by_field_name("left") {
                        self.declare_opaque(l);
                    }
                    if let Some(r) = p.child_by_field_name("right") {
                        self.visit_escape(r);
                    }
                }
                _ => self.declare_opaque(p),
            }
        }
    }

    fn declare_opaque(&mut self, pattern: Node<'a>) {
        let mut names = HashSet::new();
        collect_pattern_names(pattern, self.src(), &mut names);
        for n in names {
            self.declare(&n, Binding::Opaque);
        }
    }

    fn analyze_class_init(&mut self, node: Node<'a>, class: usize, parent: Vec<HashMap<String, Binding>>) {
        let init = self.js.classes[class].init;
        if self.analyzed[init] {
            return;
        }
        self.analyzed[init] = true;
        let saved = (self.cur, self.class, self.in_static, std::mem::take(&mut self.scopes), std::mem::take(&mut self.pending), self.depth);
        self.cur = init;
        self.class = Some(class);
        self.scopes = parent;
        self.scopes.push(HashMap::new());
        self.depth = 0;
        let mut c = node.walk();
        let body = node.named_children(&mut c).find(|n| n.kind() == "class_body");
        if let Some(body) = body {
            let mut mc = body.walk();
            for member in body.named_children(&mut mc) {
                let mut k = member.walk();
                let is_static = member.children(&mut k).any(|t| !t.is_named() && t.kind() == "static");
                self.in_static = is_static;
                match member.kind() {
                    "field_definition" | "public_field_definition" => {
                        if let Some(v) = member.child_by_field_name("value") {
                            self.visit_escape(v);
                        }
                    }
                    "class_static_block" => {
                        self.in_static = true;
                        self.visit_children(member);
                    }
                    _ => {}
                }
            }
        }
        self.drain_pending();
        self.cur = saved.0;
        self.class = saved.1;
        self.in_static = saved.2;
        self.scopes = saved.3;
        self.pending = saved.4;
        self.depth = saved.5;
    }

    fn visit_class(&mut self, node: Node<'a>) -> Binding {
        let Some(&c) = self.js.class_by_pos.get(&(self.file, node.start_byte(), node.end_byte())) else { return Binding::Opaque };
        let line = line(node);
        if let Some((s, e)) = self.js.classes[c].extends {
            if let Some(ext) = self.files[self.file].tree.root_node().descendant_for_byte_range(s, e) {
                let b = self.visit(ext);
                if let Binding::Ext(spec, path) = self.js.resolve(&b, 0) {
                    self.reference(&spec, &path, true, true, false, EdgeKind::Static, line);
                }
            }
        }
        self.edge(Dest::Method(self.js.classes[c].init), EdgeKind::Static, line);
        self.pending.push(Pending::Class(node, c));
        let mut cc = node.walk();
        let mut members: Vec<Node<'a>> = Vec::new();
        for ch in node.named_children(&mut cc) {
            match ch.kind() {
                "decorator" => {
                    self.visit(ch);
                }
                "class_body" => {
                    let mut mc = ch.walk();
                    members.extend(ch.named_children(&mut mc));
                }
                _ => {}
            }
        }
        for member in members {
            if member.kind() == "decorator" {
                self.visit(member);
                continue;
            }
            let mut dc = member.walk();
            let decorators: Vec<Node<'a>> = member.named_children(&mut dc).filter(|n| n.kind() == "decorator").collect();
            for d in decorators {
                self.visit(d);
            }
            if member.kind() == "method_definition" {
                if let Some(&i) = self.js.by_pos.get(&(self.file, member.start_byte(), member.end_byte())) {
                    self.pending.push(Pending::Func(member, i));
                }
            } else if matches!(member.kind(), "field_definition" | "public_field_definition") {
                // Arrow functions that are fields are methods of the class; they are analyzed with the class initializer.
            }
        }
        Binding::Class(c)
    }

    // ---- expressions ---------------------------------------------------------------------------------------------------------

    fn visit_children(&mut self, node: Node<'a>) {
        let mut c = node.walk();
        let children: Vec<Node<'a>> = node.named_children(&mut c).collect();
        for ch in children {
            self.visit_escape(ch);
        }
    }

    fn visit_escape(&mut self, node: Node<'a>) -> Binding {
        let b = self.visit(node);
        self.escape(&b, line(node));
        b
    }

    fn visit(&mut self, node: Node<'a>) -> Binding {
        if self.depth > MAX_DEPTH {
            self.uncertainty(Uncertainty::Incomplete);
            return Binding::Opaque;
        }
        self.depth += 1;
        let b = self.visit_inner(node);
        self.depth -= 1;
        b
    }

    fn visit_inner(&mut self, node: Node<'a>) -> Binding {
        let kind = node.kind();
        if skip_kind(kind) {
            return Binding::Opaque;
        }
        let src = self.src();
        match kind {
            "identifier" => self.lookup(text(node, src)).unwrap_or(Binding::Opaque),
            "this" => self.this_binding(),
            "function_declaration"
            | "generator_function_declaration"
            | "function_expression"
            | "generator_function"
            | "function"
            | "arrow_function"
            | "method_definition" => self.func_value(node),
            "class_declaration" | "class" | "abstract_class_declaration" => self.visit_class(node),
            "call_expression" => self.visit_call(node),
            "new_expression" => self.visit_new(node),
            "member_expression" => self.visit_member(node),
            "subscript_expression" => {
                let obj = node.child_by_field_name("object").map(|o| self.visit(o)).unwrap_or(Binding::Opaque);
                match node.child_by_field_name("index") {
                    Some(i) => match literal_text(i, src) {
                        Some(name) => self.member_value(&obj, &name, line(node)),
                        None => {
                            self.visit_escape(i);
                            Binding::Opaque
                        }
                    },
                    None => Binding::Opaque,
                }
            }
            "parenthesized_expression" | "non_null_expression" | "await_expression" | "satisfies_expression" => match node.named_child(0) {
                Some(inner) => self.visit(inner),
                None => Binding::Opaque,
            },
            "as_expression" => {
                let inner = node.named_child(0).map(|n| self.visit(n)).unwrap_or(Binding::Opaque);
                match node.named_child(1).and_then(|t| self.type_binding(t)) {
                    Some(t) => t,
                    None => inner,
                }
            }
            "type_assertion" => match node.named_child(node.named_child_count().saturating_sub(1) as u32) {
                Some(inner) => self.visit(inner),
                None => Binding::Opaque,
            },
            "assignment_expression" => {
                let (l, r) = (node.child_by_field_name("left"), node.child_by_field_name("right"));
                let exports_target = l
                    .map(|l| {
                        matches!(text(l, src), "module.exports")
                            || text(l, src).starts_with("module.exports.")
                            || text(l, src).starts_with("exports.")
                    })
                    .unwrap_or(false);
                if let Some(l) = l {
                    match l.kind() {
                        "identifier" => {}
                        "member_expression" | "subscript_expression" => {
                            if let Some(o) = l.child_by_field_name("object") {
                                self.visit(o);
                            }
                        }
                        _ => {}
                    }
                }
                match (r, l) {
                    (Some(r), Some(l)) if l.kind() == "identifier" => self.visit(r),
                    (Some(r), _) if exports_target => {
                        if r.kind() == "object" {
                            self.visit_object(r, false);
                            Binding::Opaque
                        } else {
                            let b = self.visit(r);
                            self.escape_external(&b, line(r));
                            b
                        }
                    }
                    (Some(r), _) => {
                        self.visit_escape(r);
                        Binding::Opaque
                    }
                    _ => Binding::Opaque,
                }
            }
            "object" => {
                self.visit_object(node, true);
                Binding::Opaque
            }
            "shorthand_property_identifier" => self.lookup(text(node, src)).unwrap_or(Binding::Opaque),
            "variable_declaration" | "lexical_declaration" => {
                let is_const = node.child(0).map(|k| k.kind() == "const").unwrap_or(false);
                let mut c = node.walk();
                let declarators: Vec<Node<'a>> = node.named_children(&mut c).filter(|d| d.kind() == "variable_declarator").collect();
                for d in declarators {
                    self.visit_declarator(d, is_const);
                }
                Binding::Opaque
            }
            "export_statement" => {
                if is_type_only(node) {
                    return Binding::Opaque;
                }
                let ln = line(node);
                if let Some(s) = node.child_by_field_name("source") {
                    let spec = string_value(s, src);
                    self.import_edge(&spec, ln);
                    // `export { a } from 'pkg'` and `export * from 'pkg'` expose the package's members to importers.
                    if let Spec::Ext(pkg) = self.js.resolve_spec(self.rel(), &spec) {
                        let mut c = node.walk();
                        let clause = node.named_children(&mut c).find(|n| n.kind() == "export_clause");
                        match clause {
                            Some(clause) => {
                                let mut cc = clause.walk();
                                let names: Vec<String> = clause
                                    .named_children(&mut cc)
                                    .filter(|sp| sp.kind() == "export_specifier")
                                    .filter_map(|sp| sp.child_by_field_name("name"))
                                    .map(|n| text(n, src).to_string())
                                    .collect();
                                for name in names {
                                    self.reference(&pkg, &[name], false, false, false, EdgeKind::Dynamic, ln);
                                }
                            }
                            None => self.reference_all(&pkg, ln),
                        }
                    }
                }
                let mut c = node.walk();
                let parts: Vec<Node<'a>> = node.named_children(&mut c).filter(|n| matches!(n.kind(), "decorator")).collect();
                for p in parts {
                    self.visit(p);
                }
                if let Some(d) = node.child_by_field_name("declaration") {
                    self.visit(d);
                    if matches!(d.kind(), "lexical_declaration" | "variable_declaration") {
                        let mut dc = d.walk();
                        let names: Vec<String> = d
                            .named_children(&mut dc)
                            .filter_map(|v| v.child_by_field_name("name"))
                            .filter(|n| n.kind() == "identifier")
                            .map(|n| text(n, src).to_string())
                            .collect();
                        for n in names {
                            if let Some(b) = self.lookup(&n) {
                                self.escape_external(&b, ln);
                            }
                        }
                    }
                } else if let Some(v) = node.child_by_field_name("value") {
                    let b = self.visit(v);
                    self.escape_external(&b, ln);
                }
                Binding::Opaque
            }
            "import_statement" => {
                if is_type_only(node) {
                    return Binding::Opaque;
                }
                let ln = line(node);
                if let Some(s) = node.child_by_field_name("source") {
                    self.import_edge(&string_value(s, src), ln);
                } else {
                    let mut c = node.walk();
                    let clause = node.named_children(&mut c).find(|n| n.kind() == "import_require_clause");
                    if let Some(s) = clause.and_then(|cl| cl.child_by_field_name("source")) {
                        self.import_edge(&string_value(s, src), ln);
                    }
                }
                Binding::Opaque
            }
            "for_in_statement" => {
                if let Some(l) = node.child_by_field_name("left") {
                    self.declare_opaque(l);
                }
                if let Some(r) = node.child_by_field_name("right") {
                    self.visit_escape(r);
                }
                if let Some(b) = node.child_by_field_name("body") {
                    self.visit(b);
                }
                Binding::Opaque
            }
            "catch_clause" => {
                if let Some(p) = node.child_by_field_name("parameter") {
                    self.declare_opaque(p);
                }
                if let Some(b) = node.child_by_field_name("body") {
                    self.visit(b);
                }
                Binding::Opaque
            }
            "expression_statement" => {
                if let Some(e) = node.named_child(0) {
                    self.visit(e);
                }
                Binding::Opaque
            }
            "jsx_self_closing_element" | "jsx_opening_element" => {
                self.visit_jsx(node);
                Binding::Opaque
            }
            _ => {
                self.visit_children(node);
                Binding::Opaque
            }
        }
    }

    fn visit_jsx(&mut self, node: Node<'a>) {
        let src = self.src();
        let ln = line(node);
        if let Some(name) = node.child_by_field_name("name") {
            let first = text(name, src).chars().next().unwrap_or('a');
            if first.is_uppercase() || name.kind() == "member_expression" {
                let b = if name.kind() == "identifier" || name.kind() == "member_expression" { self.visit(name) } else { Binding::Opaque };
                match self.js.resolve(&b, 0) {
                    Binding::Class(c) => self.class_edges(c, EdgeKind::Static, ln),
                    Binding::Ext(s, p) => self.reference(&s, &p, true, true, false, EdgeKind::Static, ln),
                    other => self.call_value(&other, EdgeKind::Static, ln),
                }
            }
        }
        let mut c = node.walk();
        let attrs: Vec<Node<'a>> = node.named_children(&mut c).filter(|n| n.kind() == "jsx_attribute").collect();
        for a in attrs {
            self.visit_children(a);
        }
    }

    fn visit_declarator(&mut self, d: Node<'a>, is_const: bool) {
        let src = self.src();
        let Some(name) = d.child_by_field_name("name") else { return };
        let mut b = d.child_by_field_name("value").map(|v| self.visit(v)).unwrap_or(Binding::Opaque);
        if b == Binding::Opaque {
            if let Some(t) = d.child_by_field_name("type").and_then(|t| self.type_binding(t)) {
                b = t;
            }
        }
        let assigned =
            |this: &Self, n: &str| !is_const && (this.local_assigned.contains(n) || this.js.files[this.file].reassigned.contains(n));
        match name.kind() {
            "identifier" => {
                let n = text(name, src);
                let b = if assigned(self, n) { Binding::Opaque } else { b };
                self.declare(n, b);
            }
            "object_pattern" => {
                let mut c = name.walk();
                let props: Vec<Node<'a>> = name.named_children(&mut c).collect();
                for p in props {
                    match p.kind() {
                        "shorthand_property_identifier_pattern" => {
                            let n = text(p, src);
                            let v = if assigned(self, n) { Binding::Opaque } else { self.js.member_of(&b, n) };
                            self.declare(n, v);
                        }
                        "pair_pattern" => {
                            if let (Some(k), Some(v)) = (p.child_by_field_name("key"), p.child_by_field_name("value")) {
                                if v.kind() == "identifier" {
                                    let n = text(v, src);
                                    let value = if assigned(self, n) { Binding::Opaque } else { self.js.member_of(&b, text(k, src)) };
                                    self.declare(n, value);
                                } else {
                                    self.declare_opaque(v);
                                }
                            }
                        }
                        _ => self.declare_opaque(p),
                    }
                }
            }
            _ => self.declare_opaque(name),
        }
    }

    fn visit_object(&mut self, node: Node<'a>, escape: bool) {
        let src = self.src();
        let mut c = node.walk();
        let children: Vec<Node<'a>> = node.named_children(&mut c).collect();
        for ch in children {
            match ch.kind() {
                "pair" => {
                    if let Some(k) = ch.child_by_field_name("key") {
                        if k.kind() == "computed_property_name" {
                            self.visit_children(k);
                        }
                    }
                    if let Some(v) = ch.child_by_field_name("value") {
                        if escape {
                            self.visit_escape(v);
                        } else {
                            let b = self.visit(v);
                            self.escape_external(&b, line(v));
                        }
                    }
                }
                "shorthand_property_identifier" => {
                    if let Some(b) = self.lookup(text(ch, src)) {
                        if escape {
                            self.escape(&b, line(ch));
                        } else {
                            self.escape_external(&b, line(ch));
                        }
                    }
                }
                "method_definition" => {
                    let b = self.func_value(ch);
                    if escape {
                        self.escape(&b, line(ch));
                    }
                }
                _ => {
                    self.visit_escape(ch);
                }
            }
        }
    }

    fn member_value(&mut self, object: &Binding, name: &str, line: usize) -> Binding {
        match self.js.resolve(object, 0) {
            Binding::Ext(s, mut p) => {
                p.push(name.to_string());
                Binding::Ext(s, p)
            }
            Binding::Module(f) => self.js.export_binding(f, name, 0),
            Binding::Instance(Ty::Class(c)) => {
                if let Some(t) = self.js.classes[c].fields.get(name) {
                    return Binding::Instance(t.clone());
                }
                for m in self.js.find_method(c, name, false) {
                    self.edge(Dest::Method(m), EdgeKind::Dynamic, line);
                }
                Binding::Opaque
            }
            Binding::Class(c) => {
                for m in self.js.find_method(c, name, true) {
                    self.edge(Dest::Method(m), EdgeKind::Dynamic, line);
                }
                Binding::Opaque
            }
            Binding::Builtin(_) | Binding::Instance(Ty::Ext(..)) => Binding::Opaque,
            _ => {
                self.unknown_receiver(name, line, false);
                Binding::Opaque
            }
        }
    }

    fn visit_member(&mut self, node: Node<'a>) -> Binding {
        let (Some(o), Some(p)) = (node.child_by_field_name("object"), node.child_by_field_name("property")) else { return Binding::Opaque };
        if o.kind() == "super" {
            return Binding::Opaque;
        }
        let ob = self.visit(o);
        let name = text(p, self.src());
        self.member_value(&ob, name, line(node))
    }

    fn visit_new(&mut self, node: Node<'a>) -> Binding {
        let ln = line(node);
        let b = node.child_by_field_name("constructor").map(|c| self.visit(c)).unwrap_or(Binding::Opaque);
        if let Some(args) = node.child_by_field_name("arguments") {
            self.visit_children(args);
        }
        if node
            .child_by_field_name("constructor")
            .map(|c| c.kind() == "identifier" && text(c, self.src()) == "Function" && self.lookup("Function").is_none())
            .unwrap_or(false)
        {
            self.reflection();
        }
        match self.js.resolve(&b, 0) {
            Binding::Class(c) => {
                self.class_edges(c, EdgeKind::Static, ln);
                Binding::Instance(Ty::Class(c))
            }
            Binding::Ext(s, p) => {
                self.reference(&s, &p, true, true, false, EdgeKind::Static, ln);
                Binding::Instance(Ty::Ext(s, p))
            }
            _ => Binding::Opaque,
        }
    }

    fn visit_call(&mut self, node: Node<'a>) -> Binding {
        let src = self.src();
        let ln = line(node);
        let Some(mut f) = node.child_by_field_name("function") else { return Binding::Opaque };
        while f.kind() == "parenthesized_expression" || f.kind() == "non_null_expression" {
            match f.named_child(0) {
                Some(inner) => f = inner,
                None => break,
            }
        }
        let mut result = Binding::Opaque;
        match f.kind() {
            "import" => match literal_argument(node, src) {
                Some(spec) => {
                    self.import_edge(&spec, ln);
                    result = self.js.module_binding(self.rel(), &spec);
                }
                None => self.reflection(),
            },
            "identifier" => {
                let name = text(f, src);
                let shadowed = self.lookup(name).is_some();
                if name == "require" && !shadowed {
                    match literal_argument(node, src) {
                        Some(spec) => {
                            self.import_edge(&spec, ln);
                            result = self.js.module_binding(self.rel(), &spec);
                        }
                        None => self.reflection(),
                    }
                } else if matches!(name, "eval" | "Function") && !shadowed {
                    self.reflection();
                } else {
                    let b = self.visit(f);
                    self.call_value(&b, EdgeKind::Static, ln);
                }
            }
            "super" => {
                if let Some(c) = self.class {
                    match self.js.classes[c].base.clone() {
                        Base::Project(b) => self.class_edges(b, EdgeKind::Static, ln),
                        Base::Ext(s, p) => self.reference(&s, &p, true, true, false, EdgeKind::Static, ln),
                        _ => {}
                    }
                }
            }
            "member_expression" => {
                result = self.call_member(f, ln);
            }
            "subscript_expression" => {
                let obj = f.child_by_field_name("object").map(|o| self.visit(o)).unwrap_or(Binding::Opaque);
                if let Some(i) = f.child_by_field_name("index") {
                    match literal_text(i, src) {
                        Some(name) => self.call_on(&obj, &name, ln),
                        None => {
                            self.visit_escape(i);
                            self.reflection();
                        }
                    }
                }
            }
            "function_expression" | "arrow_function" | "function" | "generator_function" => {
                if let Binding::Func(i) = self.func_value(f) {
                    self.edge(Dest::Method(i), EdgeKind::Static, ln);
                }
            }
            _ => {
                let b = self.visit(f);
                self.call_value(&b, EdgeKind::Static, ln);
            }
        }
        if let Some(args) = node.child_by_field_name("arguments") {
            if args.kind() == "arguments" {
                self.visit_children(args);
            } else {
                self.visit_children(node);
            }
        }
        result
    }

    fn call_member(&mut self, f: Node<'a>, ln: usize) -> Binding {
        let src = self.src();
        let (Some(o), Some(p)) = (f.child_by_field_name("object"), f.child_by_field_name("property")) else { return Binding::Opaque };
        let name = text(p, src);
        if o.kind() == "super" {
            if let Some(c) = self.class {
                match self.js.classes[c].base.clone() {
                    Base::Project(b) => {
                        let found = self.js.find_method(b, name, false);
                        if found.is_empty() {
                            self.method_call(b, name, ln);
                        }
                        for m in found {
                            self.edge(Dest::Method(m), EdgeKind::Static, ln);
                        }
                    }
                    Base::Ext(s, mut path) => {
                        path.push(name.to_string());
                        self.reference(&s, &path, false, true, false, EdgeKind::Static, ln);
                    }
                    _ => self.unknown_receiver(name, ln, true),
                }
            }
            return Binding::Opaque;
        }
        let ob = self.visit(o);
        if matches!(name, "call" | "apply" | "bind") {
            let resolved = self.js.resolve(&ob, 0);
            if matches!(resolved, Binding::Func(_) | Binding::Ext(..) | Binding::Module(_)) {
                let kind = if name == "bind" { EdgeKind::Dynamic } else { EdgeKind::Static };
                self.call_value(&resolved, kind, ln);
                if let Binding::Ext(..) = resolved {
                    self.call_on(&resolved, name, ln);
                }
                return Binding::Opaque;
            }
        }
        if let Binding::Builtin(b) = self.js.resolve(&ob, 0) {
            if b == "vm" || b == "module" {
                self.call_on(&ob, name, ln);
                return Binding::Opaque;
            }
        }
        if o.kind() == "identifier" && text(o, src) == "Reflect" && self.lookup("Reflect").is_none() {
            self.reflection();
            return Binding::Opaque;
        }
        self.call_on(&ob, name, ln);
        Binding::Opaque
    }
}

// ---- entry points ----------------------------------------------------------------------------------------------------------------

struct JsNames<'a> {
    js: &'a Js,
    files: &'a [JsFile],
}

impl Names for JsNames<'_> {
    fn method_id(&self, m: usize) -> String {
        self.js.funcs[m].id.clone()
    }

    fn method_file(&self, m: usize) -> Option<String> {
        self.files.get(self.js.funcs[m].file).map(|f| f.rel.clone())
    }
}

fn class_entries(js: &Js, c: usize, kind: &'static str, out: &mut Vec<Entry>) {
    let cls = &js.classes[c];
    out.push(Entry { method: cls.init, kind, dynamic_only: false });
    if let Some(ct) = cls.ctor {
        out.push(Entry { method: ct, kind, dynamic_only: false });
    }
    for list in cls.methods.values().chain(cls.statics.values()) {
        for &m in list {
            out.push(Entry { method: m, kind, dynamic_only: false });
        }
    }
}

fn export_entries(js: &Js, file: usize, kind: &'static str, out: &mut Vec<Entry>) {
    let mut names: Vec<&String> = js.files[file].exports.keys().collect();
    names.sort();
    for n in names {
        match js.export_binding(file, n, 0) {
            Binding::Func(i) => out.push(Entry { method: i, kind, dynamic_only: false }),
            Binding::Class(c) => class_entries(js, c, kind, out),
            _ => {}
        }
    }
}

fn entrypoints(js: &Js, files: &[JsFile], spec: &EntrypointSpec, diagnostics: &mut Vec<Diagnostic>) -> Vec<Entry> {
    let mut entries: Vec<Entry> = Vec::new();
    let roots: Vec<usize> = {
        let r: Vec<usize> = (0..js.files.len()).filter(|&i| js.files[i].imported_by == 0).collect();
        if r.is_empty() {
            (0..js.files.len()).collect()
        } else {
            r
        }
    };
    match spec.mode.as_str() {
        "auto" => {
            for &f in &roots {
                entries.push(Entry { method: js.files[f].init, kind: "module", dynamic_only: false });
                export_entries(js, f, "export", &mut entries);
            }
            for (c, cls) in js.classes.iter().enumerate() {
                if cls.decorated {
                    class_entries(js, c, "framework", &mut entries);
                }
            }
            for (m, f) in js.funcs.iter().enumerate() {
                if f.decorated && f.kind != FuncKind::ClassInit {
                    entries.push(Entry { method: m, kind: "framework", dynamic_only: false });
                }
            }
        }
        "public-api" => {
            for f in 0..js.files.len() {
                entries.push(Entry { method: js.files[f].init, kind: "module", dynamic_only: false });
                export_entries(js, f, "public-api", &mut entries);
            }
        }
        _ => {}
    }
    for name in &spec.explicit {
        let mut found = false;
        for (m, f) in js.funcs.iter().enumerate() {
            let wildcard = name.strip_suffix("::*").map(|file| files.get(f.file).map(|x| x.rel == file).unwrap_or(false)).unwrap_or(false);
            if f.id == *name || wildcard {
                entries.push(Entry { method: m, kind: "explicit", dynamic_only: false });
                found = true;
            }
        }
        if !found {
            diagnostics.push(Diagnostic { file: None, message: format!("explicit entrypoint '{}' not found", crate::safe(name)) });
        }
    }
    let mut seen = HashSet::new();
    entries.retain(|e| seen.insert(e.method));
    entries
}

// ---- the driver ------------------------------------------------------------------------------------------------------------------

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

pub fn execute(request: &Request) -> Result<Output, String> {
    let mut symbol_infos: Vec<JsSym> = Vec::new();
    let index = TargetIndex::build_with(&request.targets, split_symbol)?;
    for sym in &index.syms {
        symbol_infos.push(parse_symbol(&sym.text)?);
    }
    let root = std::path::Path::new(&request.root);
    let discovery = discover::discover_with(root, request.limits.max_files, classify)?;

    let mut diagnostics: Vec<Diagnostic> = Vec::new();
    let mut stats = Stats::default();
    let mut incomplete = false;
    for (path, reason) in &discovery.skipped {
        stats.files_skipped += 1;
        push(&mut diagnostics, Some(path.clone()), reason.clone());
    }
    for rel in discovery.foreign.iter().take(MAX_DIAGNOSTICS) {
        push(&mut diagnostics, Some(rel.clone()), "single-file component: its script is not analyzed".to_string());
    }
    if !discovery.foreign.is_empty() {
        incomplete = true;
    }

    let mut parsers: HashMap<u8, tree_sitter::Parser> = HashMap::new();
    for (key, lang) in [
        (0u8, tree_sitter_javascript::LANGUAGE.into()),
        (1, tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
        (2, tree_sitter_typescript::LANGUAGE_TSX.into()),
    ] {
        let mut p = tree_sitter::Parser::new();
        p.set_language(&lang).map_err(|e| format!("grammar error: {e}"))?;
        parsers.insert(key, p);
    }
    let file_timeout = std::time::Duration::from_millis(request.limits.file_timeout_ms);

    let mut files: Vec<JsFile> = Vec::new();
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
        let key = match lang_of(&file.rel) {
            Lang::Js => 0u8,
            Lang::Ts => 1,
            Lang::Tsx => 2,
        };
        let parser = parsers.get_mut(&key).expect("parsers exist");
        parser.reset();
        match crate::parse_with_deadline(parser, &src, file_timeout) {
            Some(tree) => {
                if tree.root_node().has_error() {
                    stats.files_with_errors += 1;
                    incomplete = true;
                    push(&mut diagnostics, Some(file.rel.clone()), "syntax the parser could not read completely".to_string());
                }
                stats.files += 1;
                files.push(JsFile { rel: file.rel.clone(), src, tree });
            }
            None => {
                stats.files_skipped += 1;
                incomplete = true;
                push(&mut diagnostics, Some(file.rel.clone()), "parse timed out; not analyzed".to_string());
            }
        }
    }

    let mut manifests: Vec<(String, String)> = Vec::new();
    for m in &discovery.manifests {
        match std::fs::metadata(&m.path) {
            Ok(meta) if meta.len() <= MAX_MANIFEST_BYTES => {
                if let Ok(content) = std::fs::read_to_string(&m.path) {
                    manifests.push((m.rel.clone(), content));
                }
            }
            _ => {}
        }
    }

    let listing: Vec<(String, usize)> = files.iter().map(|f| (f.rel.clone(), 0)).collect();
    let (mut js, notes, config_incomplete) = Js::new(&listing, &manifests);
    for n in notes {
        push(&mut diagnostics, None, n);
    }
    incomplete |= config_incomplete;

    let mut used = HashSet::new();
    for (i, f) in files.iter().enumerate() {
        js.collect_file(i, &f.rel, &f.src, f.tree.root_node(), &mut used);
    }
    js.link(&files);

    let mut by_spec: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, s) in symbol_infos.iter().enumerate() {
        by_spec.entry(s.spec.clone()).or_default().push(i);
    }

    let n = js.funcs.len();
    let mut flow = Flow {
        js: &js,
        files: &files,
        targets: &index,
        syms: &symbol_infos,
        by_spec,
        edges: vec![Vec::new(); n],
        uncertain: vec![Vec::new(); n],
        reflection_sites: 0,
        seen: HashSet::new(),
        analyzed: vec![false; n],
        file: 0,
        cur: 0,
        class: None,
        in_static: false,
        scopes: Vec::new(),
        local_assigned: HashSet::new(),
        pending: Vec::new(),
        depth: 0,
        diagnostics: Vec::new(),
        diag_seen: HashSet::new(),
    };

    for (i, f) in files.iter().enumerate() {
        flow.file = i;
        flow.cur = js.files[i].init;
        flow.class = None;
        flow.in_static = false;
        flow.analyzed[flow.cur] = true;
        flow.scopes = vec![js.files[i].scope.clone()];
        flow.local_assigned = HashSet::new();
        flow.depth = 0;
        let root = f.tree.root_node();
        flow.visit_children_statements(root);
        flow.drain_pending();
    }
    let Flow { edges, uncertain, reflection_sites, diagnostics: flow_diagnostics, .. } = flow;
    for d in flow_diagnostics {
        if diagnostics.len() < MAX_DIAGNOSTICS {
            diagnostics.push(d);
        }
    }
    let graph = Graph { edges, uncertain, reflection_sites };

    let entries = entrypoints(&js, &files, &request.entrypoints, &mut diagnostics);
    let names = JsNames { js: &js, files: &files };
    let results = reach::label_targets(&names, &graph, &index, &request.targets, &entries, &reach::Completeness { incomplete });

    stats.types = js.classes.len();
    stats.methods = js.funcs.len();
    stats.edges = graph.edges.iter().map(|e| e.len()).sum();
    stats.entrypoints = entries.iter().filter(|e| js.funcs[e.method].kind != FuncKind::ClassInit).count();
    stats.reflection_sites = graph.reflection_sites;

    let mut shown: Vec<EntrypointOut> = entries
        .iter()
        .filter(|e| js.funcs[e.method].kind != FuncKind::ClassInit)
        .map(|e| EntrypointOut { method: js.funcs[e.method].id.clone(), kind: e.kind.to_string() })
        .collect();
    shown.sort_by(|a, b| a.method.cmp(&b.method));
    shown.truncate(200);

    Ok(Output {
        schema_version: SCHEMA_VERSION,
        analyzer: AnalyzerInfo { name: "deprisk-reach", version: env!("CARGO_PKG_VERSION") },
        language: "javascript",
        source_digest: hex(&Sha256::digest(digest_lines.as_bytes())),
        stats,
        entrypoints: shown,
        results,
        diagnostics,
    })
}

impl<'a> Flow<'a> {
    /// The statements of a module: imports and exports run when the module does.
    fn visit_children_statements(&mut self, root: Node<'a>) {
        let mut c = root.walk();
        let children: Vec<Node<'a>> = root.named_children(&mut c).collect();
        for ch in children {
            self.visit(ch);
        }
    }
}
