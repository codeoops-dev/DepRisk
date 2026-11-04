//! Phase 1: what the sources declare. Types, members, usings. No bodies are analyzed here (see analyze.rs).

use std::collections::{HashMap, HashSet, VecDeque};
use tree_sitter::{Node, Tree};

pub struct Parsed {
    pub rel: String,
    pub src: String,
    pub tree: Tree,
}

#[derive(Default, Clone)]
pub struct FileFacts {
    pub usings: Vec<String>,
    pub aliases: HashMap<String, String>,
    pub static_usings: Vec<String>,
    pub has_top_level: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TypeKind {
    Class,
    Struct,
    Interface,
    Record,
    Enum,
    Other,
}

pub struct TypeInfo {
    pub fq: String,
    pub simple: String,
    pub ns: String,
    pub kind: TypeKind,
    /// Base types and interfaces as written (generic arguments removed).
    pub bases: Vec<String>,
    /// Field and property names to the type they were declared with ("" when it cannot be named).
    pub fields: HashMap<String, String>,
    pub is_public: bool,
    pub is_abstract: bool,
    pub file: usize,
    /// The synthetic method that stands for field initializers and static initializers.
    pub init: usize,
    pub methods: Vec<usize>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MethodKind {
    Normal,
    Ctor,
    Init,
    Property,
    TopLevel,
    /// Indexers, operators, finalizers, event accessors: invoked by the runtime or by syntax this analyzer does not model.
    Unmodeled,
}

pub struct Method {
    pub id: String,
    pub name: String,
    pub ty: Option<usize>,
    pub file: usize,
    pub min_args: usize,
    pub max_args: usize,
    pub variadic: bool,
    pub is_static: bool,
    pub is_public: bool,
    pub is_virtual: bool,
    pub is_extension: bool,
    pub kind: MethodKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Resolved {
    Project(usize),
    External(String),
}

#[derive(Default)]
pub struct Program {
    pub facts: Vec<FileFacts>,
    pub global_usings: Vec<String>,
    pub global_aliases: HashMap<String, String>,
    pub global_static: Vec<String>,
    pub types: Vec<TypeInfo>,
    pub types_by_fq: HashMap<String, usize>,
    pub types_by_simple: HashMap<String, Vec<usize>>,
    pub methods: Vec<Method>,
    /// (file, start byte of the declaration) to method index.
    pub by_pos: HashMap<(usize, usize), usize>,
    pub top_level: Vec<(usize, usize)>,
    /// For every type, its bases that are project types or external types.
    pub base_links: Vec<Vec<Resolved>>,
    pub derived: Vec<Vec<usize>>,
}

pub fn text<'a>(node: Node, src: &'a str) -> &'a str {
    &src[node.byte_range()]
}

/// The dotted name of a type or namespace expression: identifier, qualified, generic (arguments dropped), alias-qualified,
/// nullable, or a member access chain of those. None for everything else.
pub fn dotted(node: Node, src: &str) -> Option<String> {
    match node.kind() {
        "identifier" => Some(text(node, src).to_string()),
        "qualified_name" => {
            let q = dotted(node.child_by_field_name("qualifier")?, src)?;
            let n = dotted(node.child_by_field_name("name")?, src)?;
            Some(format!("{q}.{n}"))
        }
        "member_access_expression" => {
            let q = dotted(node.child_by_field_name("expression")?, src)?;
            let n = dotted(node.child_by_field_name("name")?, src)?;
            Some(format!("{q}.{n}"))
        }
        "generic_name" => {
            let mut c = node.walk();
            let first = node.named_children(&mut c).find(|n| n.kind() == "identifier");
            first.map(|n| text(n, src).to_string())
        }
        "alias_qualified_name" => dotted(node.child_by_field_name("name")?, src),
        "nullable_type" => {
            let mut c = node.walk();
            let inner = node.named_children(&mut c).next();
            inner.and_then(|n| dotted(n, src))
        }
        _ => None,
    }
}

/// The type a declaration names, or None for `var`, predefined types, arrays, tuples, and the like.
pub fn type_text(node: Node, src: &str) -> Option<String> {
    dotted(node, src)
}

fn modifiers(node: Node, src: &str) -> Vec<String> {
    let mut c = node.walk();
    node.children(&mut c).filter(|n| n.kind() == "modifier").map(|n| text(n, src).to_string()).collect()
}

fn join(ns: &str, name: &str) -> String {
    if ns.is_empty() {
        name.to_string()
    } else {
        format!("{ns}.{name}")
    }
}

impl Program {
    pub fn collect(parsed: &[Parsed]) -> Program {
        let mut prog = Program::default();
        for (idx, p) in parsed.iter().enumerate() {
            let mut facts = FileFacts::default();
            let root = p.tree.root_node();
            let mut ns = String::new();
            prog.collect_container(idx, p, root, &mut ns, None, &mut facts, 0);

            if facts.has_top_level {
                let id = format!("<top-level>:{}", p.rel);
                let m = prog.add_method(Method {
                    id,
                    name: "<top-level>".to_string(),
                    ty: None,
                    file: idx,
                    min_args: 0,
                    max_args: 0,
                    variadic: false,
                    is_static: true,
                    is_public: false,
                    is_virtual: false,
                    is_extension: false,
                    kind: MethodKind::TopLevel,
                });
                prog.by_pos.insert((idx, usize::MAX), m);
                prog.top_level.push((idx, m));
            }
            prog.facts.push(facts);
        }
        prog.finish();
        prog
    }

    fn add_method(&mut self, m: Method) -> usize {
        self.methods.push(m);
        self.methods.len() - 1
    }

    #[allow(clippy::too_many_arguments)]
    fn collect_container(
        &mut self,
        file: usize,
        p: &Parsed,
        node: Node,
        ns: &mut String,
        outer: Option<usize>,
        facts: &mut FileFacts,
        depth: usize,
    ) {
        if depth > 200 {
            return;
        }
        let mut c = node.walk();
        for child in node.children(&mut c) {
            match child.kind() {
                "using_directive" => self.collect_using(&child, &p.src, facts),
                "file_scoped_namespace_declaration" => {
                    if let Some(n) = child.child_by_field_name("name").and_then(|n| dotted(n, &p.src)) {
                        *ns = n;
                    }
                }
                "namespace_declaration" => {
                    let inner = child.child_by_field_name("name").and_then(|n| dotted(n, &p.src)).unwrap_or_default();
                    let mut nested = join(ns, &inner);
                    if let Some(body) = child.child_by_field_name("body") {
                        self.collect_container(file, p, body, &mut nested, outer, facts, depth + 1);
                    }
                }
                "class_declaration"
                | "struct_declaration"
                | "interface_declaration"
                | "record_declaration"
                | "record_struct_declaration"
                | "enum_declaration" => {
                    self.collect_type(file, p, child, ns, outer, depth + 1);
                }
                "global_statement" => facts.has_top_level = true,
                _ => {}
            }
        }
    }

    fn collect_using(&mut self, node: &Node, src: &str, facts: &mut FileFacts) {
        let mut is_global = false;
        let mut is_static = false;
        let mut c = node.walk();
        for ch in node.children(&mut c) {
            match ch.kind() {
                "global" => is_global = true,
                "static" => is_static = true,
                _ => {}
            }
        }

        let name_node = node.child_by_field_name("name");
        let mut c2 = node.walk();
        let target =
            node.named_children(&mut c2).filter(|n| name_node.map(|a| a.id() != n.id()).unwrap_or(true)).find_map(|n| dotted(n, src));
        let Some(target) = target else { return };

        if let Some(alias) = name_node {
            let alias = text(alias, src).to_string();
            if is_global {
                self.global_aliases.insert(alias, target);
            } else {
                facts.aliases.insert(alias, target);
            }
        } else if is_static {
            if is_global {
                self.global_static.push(target);
            } else {
                facts.static_usings.push(target);
            }
        } else if is_global {
            self.global_usings.push(target);
        } else {
            facts.usings.push(target);
        }
    }

    fn collect_type(&mut self, file: usize, p: &Parsed, node: Node, ns: &str, outer: Option<usize>, depth: usize) {
        if depth > 200 {
            return;
        }
        let src = &p.src;
        let Some(name_node) = node.child_by_field_name("name") else { return };
        let name = text(name_node, src).to_string();
        let kind = match node.kind() {
            "class_declaration" => TypeKind::Class,
            "struct_declaration" => TypeKind::Struct,
            "interface_declaration" => TypeKind::Interface,
            "record_declaration" | "record_struct_declaration" => TypeKind::Record,
            "enum_declaration" => TypeKind::Enum,
            _ => TypeKind::Other,
        };
        let fq = match outer {
            Some(o) => format!("{}.{}", self.types[o].fq, name),
            None => join(ns, &name),
        };
        let mods = modifiers(node, src);
        let idx = self.get_or_create_type(&fq, &name, ns, kind, file);

        let public_here = mods.iter().any(|m| m == "public");
        let outer_public = outer.map(|o| self.types[o].is_public).unwrap_or(true);
        if public_here && outer_public {
            self.types[idx].is_public = true;
        }
        if mods.iter().any(|m| m == "abstract") {
            self.types[idx].is_abstract = true;
        }

        let mut c = node.walk();
        for ch in node.children(&mut c) {
            if ch.kind() == "base_list" {
                let mut bc = ch.walk();
                for b in ch.named_children(&mut bc) {
                    if let Some(n) = dotted(b, src) {
                        if !self.types[idx].bases.contains(&n) {
                            self.types[idx].bases.push(n);
                        }
                    }
                }
            }
        }

        // Records: the primary constructor's parameters are properties and a constructor.
        let mut c = node.walk();
        for ch in node.children(&mut c) {
            if ch.kind() == "parameter_list" {
                let (params, min_args, max_args, variadic, _) = parse_parameters(ch, src);
                for (pname, ptype) in &params {
                    self.types[idx].fields.insert(pname.clone(), ptype.clone());
                }
                let m = self.new_member(idx, "#ctor", MethodKind::Ctor, ch, file, &mods, src, min_args, max_args, variadic, false);
                self.by_pos.insert((file, ch.start_byte()), m);
            }
        }

        if let Some(body) = node.child_by_field_name("body") {
            let in_interface = kind == TypeKind::Interface;
            let mut bc = body.walk();
            for member in body.children(&mut bc) {
                self.collect_member(file, p, member, idx, in_interface, depth + 1);
            }
        }
    }

    fn get_or_create_type(&mut self, fq: &str, simple: &str, ns: &str, kind: TypeKind, file: usize) -> usize {
        if let Some(&i) = self.types_by_fq.get(fq) {
            return i;
        }
        let idx = self.types.len();
        let init = self.add_method(Method {
            id: format!("{fq}.<init>"),
            name: "<init>".to_string(),
            ty: Some(idx),
            file,
            min_args: 0,
            max_args: 0,
            variadic: false,
            is_static: false,
            is_public: false,
            is_virtual: false,
            is_extension: false,
            kind: MethodKind::Init,
        });
        self.types.push(TypeInfo {
            fq: fq.to_string(),
            simple: simple.to_string(),
            ns: ns.to_string(),
            kind,
            bases: Vec::new(),
            fields: HashMap::new(),
            is_public: false,
            is_abstract: false,
            file,
            init,
            methods: Vec::new(),
        });
        self.types_by_fq.insert(fq.to_string(), idx);
        self.types_by_simple.entry(simple.to_string()).or_default().push(idx);
        idx
    }

    #[allow(clippy::too_many_arguments)]
    fn new_member(
        &mut self,
        ty: usize,
        name: &str,
        kind: MethodKind,
        _node: Node,
        file: usize,
        mods: &[String],
        _src: &str,
        min_args: usize,
        max_args: usize,
        variadic: bool,
        is_extension: bool,
    ) -> usize {
        let in_interface = self.types[ty].kind == TypeKind::Interface;
        let virtual_like = in_interface || mods.iter().any(|m| m == "virtual" || m == "abstract" || m == "override");
        let public = in_interface || mods.iter().any(|m| m == "public");
        let id = format!("{}.{}", self.types[ty].fq, name);
        let m = self.add_method(Method {
            id,
            name: name.to_string(),
            ty: Some(ty),
            file,
            min_args,
            max_args,
            variadic,
            is_static: mods.iter().any(|m| m == "static"),
            is_public: public,
            is_virtual: virtual_like,
            is_extension,
            kind,
        });
        self.types[ty].methods.push(m);
        m
    }

    fn collect_member(&mut self, file: usize, p: &Parsed, node: Node, ty: usize, _in_interface: bool, depth: usize) {
        let src = &p.src;
        let mods = modifiers(node, src);
        match node.kind() {
            "class_declaration"
            | "struct_declaration"
            | "interface_declaration"
            | "record_declaration"
            | "record_struct_declaration"
            | "enum_declaration" => {
                let ns = self.types[ty].ns.clone();
                self.collect_type(file, p, node, &ns, Some(ty), depth + 1);
            }
            "field_declaration" => {
                let mut c = node.walk();
                for vd in node.children(&mut c).filter(|n| n.kind() == "variable_declaration") {
                    let ty_name = vd.child_by_field_name("type").and_then(|t| type_text(t, src)).unwrap_or_default();
                    let mut vc = vd.walk();
                    for decl in vd.named_children(&mut vc).filter(|n| n.kind() == "variable_declarator") {
                        if let Some(n) = decl.child_by_field_name("name") {
                            self.types[ty].fields.insert(text(n, src).to_string(), ty_name.clone());
                        }
                    }
                }
            }
            "property_declaration" => {
                let Some(name_node) = node.child_by_field_name("name") else { return };
                let name = text(name_node, src).to_string();
                let ty_name = node.child_by_field_name("type").and_then(|t| type_text(t, src)).unwrap_or_default();
                self.types[ty].fields.insert(name.clone(), ty_name);
                let m = self.new_member(ty, &name, MethodKind::Property, node, file, &mods, src, 0, 0, false, false);
                self.by_pos.insert((file, node.start_byte()), m);
            }
            "method_declaration" => {
                let Some(name_node) = node.child_by_field_name("name") else { return };
                let name = text(name_node, src).to_string();
                let (min_args, max_args, variadic, ext) = match node.child_by_field_name("parameters") {
                    Some(pl) => {
                        let (_, a, b, v, e) = parse_parameters(pl, src);
                        (a, b, v, e)
                    }
                    None => (0, 0, false, false),
                };
                let m = self.new_member(ty, &name, MethodKind::Normal, node, file, &mods, src, min_args, max_args, variadic, ext);
                self.by_pos.insert((file, node.start_byte()), m);
            }
            "constructor_declaration" => {
                let (min_args, max_args, variadic) = match node.child_by_field_name("parameters") {
                    Some(pl) => {
                        let (_, a, b, v, _) = parse_parameters(pl, src);
                        (a, b, v)
                    }
                    None => (0, 0, false),
                };
                let m = self.new_member(ty, "#ctor", MethodKind::Ctor, node, file, &mods, src, min_args, max_args, variadic, false);
                self.by_pos.insert((file, node.start_byte()), m);
            }
            "operator_declaration"
            | "conversion_operator_declaration"
            | "destructor_declaration"
            | "indexer_declaration"
            | "event_declaration" => {
                let label = format!("<{}@{}>", node.kind().trim_end_matches("_declaration"), node.start_position().row + 1);
                let m = self.new_member(ty, &label, MethodKind::Unmodeled, node, file, &mods, src, 0, usize::MAX, true, false);
                self.by_pos.insert((file, node.start_byte()), m);
            }
            _ => {}
        }
    }

    /// Resolves the bases of every type and the reverse relation.
    fn finish(&mut self) {
        let mut links = Vec::with_capacity(self.types.len());
        for t in 0..self.types.len() {
            let mut resolved = Vec::new();
            let bases = self.types[t].bases.clone();
            for b in &bases {
                let own_ns = self.types[t].ns.clone();
                let ctx = ResolveCtx { file: self.types[t].file, ns: &own_ns, ty: None };
                for r in self.resolve_type_name(b, &ctx) {
                    if r != Resolved::Project(t) && !resolved.contains(&r) {
                        resolved.push(r);
                    }
                }
            }
            links.push(resolved);
        }
        let mut derived = vec![Vec::new(); self.types.len()];
        for (t, rs) in links.iter().enumerate() {
            for r in rs {
                if let Resolved::Project(b) = r {
                    derived[*b].push(t);
                }
            }
        }
        self.base_links = links;
        self.derived = derived;
    }

    /// All project types below `t` (transitively), nearest first.
    pub fn descendants(&self, t: usize) -> Vec<usize> {
        let mut seen: HashSet<usize> = HashSet::new();
        let mut out = Vec::new();
        let mut queue: VecDeque<usize> = self.derived[t].iter().copied().collect();
        while let Some(d) = queue.pop_front() {
            if d != t && seen.insert(d) {
                out.push(d);
                queue.extend(self.derived[d].iter().copied());
            }
        }
        out
    }

    fn usings_of(&self, file: usize) -> impl Iterator<Item = &String> {
        self.facts.get(file).map(|f| f.usings.iter()).into_iter().flatten().chain(self.global_usings.iter())
    }

    fn alias_of(&self, file: usize, head: &str) -> Option<&String> {
        self.facts.get(file).and_then(|f| f.aliases.get(head)).or_else(|| self.global_aliases.get(head))
    }

    pub fn static_usings_of(&self, file: usize) -> Vec<String> {
        let mut v: Vec<String> = self.facts.get(file).map(|f| f.static_usings.clone()).unwrap_or_default();
        v.extend(self.global_static.iter().cloned());
        v
    }

    /// Does `file` import the namespace `ns` (or sit inside it)?
    pub fn imports_namespace(&self, file: usize, ns: &str, own_ns: &str) -> bool {
        if ns.is_empty() {
            return true;
        }
        own_ns == ns || own_ns.starts_with(&format!("{ns}.")) || self.usings_of(file).any(|u| u == ns)
    }

    fn fq_to_resolved(&self, fq: &str) -> Resolved {
        match self.types_by_fq.get(fq) {
            Some(&i) => Resolved::Project(i),
            None => Resolved::External(fq.to_string()),
        }
    }

    /// Candidate meanings of a (possibly dotted) type name as seen from a place in the code. Project types shadow external
    /// ones. For external names there is no way to know which namespace a name comes from, so every import is a candidate.
    pub fn resolve_type_name(&self, name: &str, ctx: &ResolveCtx) -> Vec<Resolved> {
        let (head, rest) = match name.split_once('.') {
            Some((h, r)) => (h, Some(r)),
            None => (name, None),
        };

        if let Some(target) = self.alias_of(ctx.file, head) {
            let fq = match rest {
                Some(r) => format!("{target}.{r}"),
                None => target.clone(),
            };
            return vec![self.fq_to_resolved(&fq)];
        }

        // Enclosing types and namespaces, innermost first.
        let mut prefixes: Vec<String> = Vec::new();
        let mut cur = ctx.ty;
        while let Some(t) = cur {
            prefixes.push(self.types[t].fq.clone());
            cur = self.types[t].fq.rsplit_once('.').and_then(|(outer, _)| self.types_by_fq.get(outer).copied());
        }
        let mut ns = ctx.ns.to_string();
        loop {
            prefixes.push(ns.clone());
            match ns.rsplit_once('.') {
                Some((parent, _)) => ns = parent.to_string(),
                None => {
                    if !ns.is_empty() {
                        ns = String::new();
                    } else {
                        break;
                    }
                }
            }
        }

        for prefix in &prefixes {
            if let Some(&i) = self.types_by_fq.get(&join(prefix, name)) {
                return vec![Resolved::Project(i)];
            }
        }

        let mut found: Vec<Resolved> = Vec::new();
        for u in self.usings_of(ctx.file) {
            if let Some(&i) = self.types_by_fq.get(&join(u, name)) {
                let r = Resolved::Project(i);
                if !found.contains(&r) {
                    found.push(r);
                }
            }
        }
        if !found.is_empty() {
            return found;
        }

        let mut external: Vec<Resolved> = Vec::new();
        let mut push = |fq: String| {
            let r = Resolved::External(fq);
            if !external.contains(&r) {
                external.push(r);
            }
        };
        push(name.to_string());
        for prefix in prefixes.iter().filter(|p| !p.is_empty() && !self.types_by_fq.contains_key(p.as_str())) {
            push(join(prefix, name));
        }
        for u in self.usings_of(ctx.file) {
            push(join(u, name));
        }
        external
    }
}

pub struct ResolveCtx<'a> {
    pub file: usize,
    pub ns: &'a str,
    pub ty: Option<usize>,
}

/// (name, declared type or "" per parameter, min args, max args, variadic, is extension method)
pub fn parse_parameters(list: Node, src: &str) -> (Vec<(String, String)>, usize, usize, bool, bool) {
    let mut params = Vec::new();
    let mut min = 0;
    let mut max = 0;
    let mut variadic = false;
    let mut extension = false;
    let mut c = list.walk();
    for (i, p) in list.named_children(&mut c).filter(|n| n.kind() == "parameter").enumerate() {
        let name = p.child_by_field_name("name").map(|n| text(n, src).to_string()).unwrap_or_default();
        let ty = p.child_by_field_name("type").and_then(|t| type_text(t, src)).unwrap_or_default();
        let mut has_default = false;
        let mut is_params = false;
        let mut pc = p.walk();
        for ch in p.children(&mut pc) {
            match (ch.kind(), text(ch, src)) {
                ("equals_value_clause", _) => has_default = true,
                (_, "params") => is_params = true,
                (_, "this") if i == 0 => extension = true,
                _ => {}
            }
        }
        max += 1;
        if is_params {
            variadic = true;
        } else if !has_default {
            min += 1;
        }
        params.push((name, ty));
    }
    (params, min, max, variadic, extension)
}
