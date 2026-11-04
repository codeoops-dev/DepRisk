//! Phase 2: the call graph. Every method body is read once; each call, construction, and member reference becomes an edge
//! to a project method or to one of the symbols asked about. There is no type checker here, so the front end resolves what
//! it can by names, usings, and declared types (static edges) and over-approximates the rest (dynamic edges, or an
//! uncertainty that keeps the result from ever being `unreachable`). See ADR 0012.

use crate::program::*;
use crate::targets::TargetIndex;
use std::collections::{HashMap, HashSet, VecDeque};
use tree_sitter::Node;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Dest {
    Method(usize),
    Sym(usize),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EdgeKind {
    Static,
    Dynamic,
}

#[derive(Clone, Copy, Debug)]
pub struct Edge {
    pub to: Dest,
    pub kind: EdgeKind,
    pub line: usize,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum Uncertainty {
    /// Reflection or dynamic code whose target cannot be read from the source.
    Reflection,
    /// A call whose receiver type is unknown and whose member name is the one of a symbol that is not imported here.
    NameMatch(usize),
    /// Code the analyzer could not read completely (nesting too deep).
    Incomplete,
}

pub struct Graph {
    pub edges: Vec<Vec<Edge>>,
    pub uncertain: Vec<Vec<Uncertainty>>,
    pub reflection_sites: usize,
}

const MAX_DEPTH: usize = 300;

const REFLECTION_NAMES: [&str; 22] = [
    "GetType",
    "CreateInstance",
    "CreateInstanceFrom",
    "Load",
    "LoadFrom",
    "LoadFile",
    "LoadWithPartialName",
    "GetMethod",
    "GetMethods",
    "GetProperty",
    "GetProperties",
    "GetField",
    "GetFields",
    "GetConstructor",
    "GetConstructors",
    "InvokeMember",
    "DynamicInvoke",
    "MakeGenericMethod",
    "MakeGenericType",
    "GetTypes",
    "GetExportedTypes",
    "GetMember",
];

#[derive(Clone)]
enum Receiver {
    This,
    Base,
    Types(Vec<Resolved>),
    Unknown,
}

#[derive(Clone, Copy)]
enum Use {
    /// A call with this many arguments.
    Call(usize),
    /// A property or field access.
    Access,
}

pub fn analyze(prog: &Program, parsed: &[Parsed], targets: &TargetIndex) -> Graph {
    let mut graph =
        Graph { edges: vec![Vec::new(); prog.methods.len()], uncertain: vec![Vec::new(); prog.methods.len()], reflection_sites: 0 };
    let mut name_index: HashMap<&str, Vec<usize>> = HashMap::new();
    for (i, m) in prog.methods.iter().enumerate() {
        if m.kind == MethodKind::Normal {
            name_index.entry(m.name.as_str()).or_default().push(i);
        }
    }

    for (file, p) in parsed.iter().enumerate() {
        let mut walker = FileWalker { prog, parsed: p, file, targets, name_index: &name_index, graph: &mut graph };
        let mut ns = String::new();
        walker.container(p.tree.root_node(), &mut ns, None, 0);

        if let Some(&m) = prog.by_pos.get(&(file, usize::MAX)) {
            let mut ctx = walker.ctx(m, String::new(), None);
            let mut c = p.tree.root_node().walk();
            for child in p.tree.root_node().children(&mut c) {
                if child.kind() == "global_statement" {
                    ctx.visit(child);
                }
            }
            walker.finish(ctx, m);
        }
    }
    graph
}

struct FileWalker<'a, 'g> {
    prog: &'a Program,
    parsed: &'a Parsed,
    file: usize,
    targets: &'a TargetIndex,
    name_index: &'a HashMap<&'a str, Vec<usize>>,
    graph: &'g mut Graph,
}

impl<'a, 'g> FileWalker<'a, 'g> {
    fn ctx(&self, _method: usize, ns: String, ty: Option<usize>) -> Ctx<'a> {
        let parsed: &'a Parsed = self.parsed;
        Ctx {
            prog: self.prog,
            targets: self.targets,
            name_index: self.name_index,
            file: self.file,
            src: &parsed.src,
            ns,
            ty,
            vars: HashMap::new(),
            edges: Vec::new(),
            edge_pos: HashMap::new(),
            unc: Vec::new(),
            depth: 0,
            reflection_sites: 0,
        }
    }

    fn finish(&mut self, ctx: Ctx<'a>, method: usize) {
        self.graph.reflection_sites += ctx.reflection_sites;
        let edges = &mut self.graph.edges[method];
        for e in ctx.edges {
            if let Some(existing) = edges.iter_mut().find(|x| x.to == e.to) {
                if e.kind == EdgeKind::Static {
                    existing.kind = EdgeKind::Static;
                }
            } else {
                edges.push(e);
            }
        }
        let unc = &mut self.graph.uncertain[method];
        for u in ctx.unc {
            if !unc.contains(&u) {
                unc.push(u);
            }
        }
    }

    fn container(&mut self, node: Node<'a>, ns: &mut String, outer: Option<usize>, depth: usize) {
        if depth > 200 {
            return;
        }
        let src = &self.parsed.src;
        let mut c = node.walk();
        for child in node.children(&mut c) {
            match child.kind() {
                "file_scoped_namespace_declaration" => {
                    if let Some(n) = child.child_by_field_name("name").and_then(|n| dotted(n, src)) {
                        *ns = n;
                    }
                }
                "namespace_declaration" => {
                    let inner = child.child_by_field_name("name").and_then(|n| dotted(n, src)).unwrap_or_default();
                    let mut nested = if ns.is_empty() { inner } else { format!("{ns}.{inner}") };
                    if let Some(body) = child.child_by_field_name("body") {
                        self.container(body, &mut nested, outer, depth + 1);
                    }
                }
                "class_declaration"
                | "struct_declaration"
                | "interface_declaration"
                | "record_declaration"
                | "record_struct_declaration"
                | "enum_declaration" => self.type_decl(child, ns, outer, depth + 1),
                _ => {}
            }
        }
    }

    fn type_decl(&mut self, node: Node<'a>, ns: &str, outer: Option<usize>, depth: usize) {
        if depth > 200 {
            return;
        }
        let src = &self.parsed.src;
        let Some(name) = node.child_by_field_name("name").map(|n| text(n, src).to_string()) else { return };
        let fq = match outer {
            Some(o) => format!("{}.{}", self.prog.types[o].fq, name),
            None => {
                if ns.is_empty() {
                    name
                } else {
                    format!("{ns}.{name}")
                }
            }
        };
        let Some(&t) = self.prog.types_by_fq.get(&fq) else { return };

        // A type that derives from a type the request asks about is, from the moment it is used, in that type's hands.
        let init = self.prog.types[t].init;
        {
            let mut ctx = self.ctx(init, ns.to_string(), Some(t));
            for base in &self.prog.base_links[t] {
                if let Resolved::External(base_fq) = base {
                    for &s in self.targets.type_syms(base_fq) {
                        if self.targets.syms[s].member.is_none() {
                            ctx.add(Dest::Sym(s), EdgeKind::Static, node.start_position().row + 1);
                        }
                    }
                }
            }
            self.finish(ctx, init);
        }

        let mut c = node.walk();
        for child in node.children(&mut c) {
            if child.kind() == "parameter_list" {
                // A record's primary constructor.
                if let Some(&m) = self.prog.by_pos.get(&(self.file, child.start_byte())) {
                    let mut ctx = self.ctx(m, ns.to_string(), Some(t));
                    ctx.add(Dest::Method(init), EdgeKind::Static, child.start_position().row + 1);
                    self.finish(ctx, m);
                }
            }
        }

        let Some(body) = node.child_by_field_name("body") else { return };
        let mut bc = body.walk();
        for member in body.children(&mut bc) {
            match member.kind() {
                "class_declaration"
                | "struct_declaration"
                | "interface_declaration"
                | "record_declaration"
                | "record_struct_declaration"
                | "enum_declaration" => self.type_decl(member, ns, Some(t), depth + 1),
                "field_declaration" => {
                    let mut ctx = self.ctx(init, ns.to_string(), Some(t));
                    ctx.visit(member);
                    self.finish(ctx, init);
                }
                "property_declaration"
                | "method_declaration"
                | "constructor_declaration"
                | "operator_declaration"
                | "conversion_operator_declaration"
                | "destructor_declaration"
                | "indexer_declaration"
                | "event_declaration" => {
                    let Some(&m) = self.prog.by_pos.get(&(self.file, member.start_byte())) else { continue };
                    let mut ctx = self.ctx(m, ns.to_string(), Some(t));
                    if self.prog.methods[m].kind == MethodKind::Ctor {
                        // Constructing a type runs its initializers.
                        ctx.add(Dest::Method(init), EdgeKind::Static, member.start_position().row + 1);
                    }
                    if let Some(pl) = member.child_by_field_name("parameters") {
                        ctx.declare_parameters(pl);
                    }
                    let mut mc = member.walk();
                    for ch in member.named_children(&mut mc) {
                        ctx.visit(ch);
                    }
                    self.finish(ctx, m);
                }
                _ => {}
            }
        }
    }
}

struct Ctx<'a> {
    prog: &'a Program,
    targets: &'a TargetIndex,
    name_index: &'a HashMap<&'a str, Vec<usize>>,
    file: usize,
    src: &'a str,
    ns: String,
    ty: Option<usize>,
    vars: HashMap<String, String>,
    edges: Vec<Edge>,
    edge_pos: HashMap<Dest, usize>,
    unc: Vec<Uncertainty>,
    depth: usize,
    reflection_sites: usize,
}

impl<'a> Ctx<'a> {
    fn add(&mut self, to: Dest, kind: EdgeKind, line: usize) {
        match self.edge_pos.get(&to) {
            Some(&i) => {
                if kind == EdgeKind::Static {
                    self.edges[i].kind = EdgeKind::Static;
                }
            }
            None => {
                self.edge_pos.insert(to, self.edges.len());
                self.edges.push(Edge { to, kind, line });
            }
        }
    }

    fn uncertain(&mut self, u: Uncertainty) {
        if !self.unc.contains(&u) {
            self.unc.push(u);
        }
    }

    fn resolve(&self, name: &str) -> Vec<Resolved> {
        self.prog.resolve_type_name(name, &ResolveCtx { file: self.file, ns: &self.ns, ty: self.ty })
    }

    fn declare_parameters(&mut self, list: Node<'a>) {
        let mut c = list.walk();
        for p in list.named_children(&mut c).filter(|n| n.kind() == "parameter") {
            if let Some(name) = p.child_by_field_name("name") {
                let ty = p.child_by_field_name("type").and_then(|t| type_text(t, self.src)).unwrap_or_default();
                self.vars.insert(text(name, self.src).to_string(), ty);
            }
        }
    }

    // --- walking ---

    fn visit(&mut self, node: Node<'a>) {
        if self.depth >= MAX_DEPTH {
            self.uncertain(Uncertainty::Incomplete);
            return;
        }
        self.depth += 1;
        match node.kind() {
            "invocation_expression" => self.invocation(node),
            "object_creation_expression" => self.creation(node),
            "member_access_expression" => self.member_reference(node),
            "conditional_access_expression" => self.conditional_access(node),
            "variable_declaration" => self.variable_declaration(node),
            "foreach_statement" => {
                if let Some(left) = node.child_by_field_name("left") {
                    let ty = node.child_by_field_name("type").and_then(|t| type_text(t, self.src)).unwrap_or_default();
                    self.vars.insert(text(left, self.src).to_string(), ty);
                }
                self.visit_children(node);
            }
            "catch_declaration" | "declaration_pattern" | "declaration_expression" => {
                if let Some(name) = node.child_by_field_name("name") {
                    let ty = node.child_by_field_name("type").and_then(|t| type_text(t, self.src)).unwrap_or_default();
                    self.vars.insert(text(name, self.src).to_string(), ty);
                }
                self.visit_children(node);
            }
            "lambda_expression" | "anonymous_method_expression" | "local_function_statement" => {
                if let Some(params) = node.child_by_field_name("parameters") {
                    if params.kind() == "parameter_list" {
                        self.declare_parameters(params);
                    } else if params.kind() == "identifier" {
                        self.vars.insert(text(params, self.src).to_string(), String::new());
                    } else if params.kind() == "parameter" {
                        if let Some(n) = params.child_by_field_name("name") {
                            self.vars.insert(text(n, self.src).to_string(), String::new());
                        }
                    }
                }
                self.visit_children(node);
            }
            "identifier" => self.method_group(node),
            _ => self.visit_children(node),
        }
        self.depth -= 1;
    }

    fn visit_children(&mut self, node: Node<'a>) {
        let mut c = node.walk();
        for ch in node.named_children(&mut c) {
            self.visit(ch);
        }
    }

    fn variable_declaration(&mut self, node: Node<'a>) {
        let declared = node.child_by_field_name("type").filter(|t| t.kind() != "implicit_type").and_then(|t| type_text(t, self.src));
        let mut c = node.walk();
        for decl in node.named_children(&mut c).filter(|n| n.kind() == "variable_declarator") {
            let Some(name) = decl.child_by_field_name("name") else { continue };
            let ty = match &declared {
                Some(t) => t.clone(),
                None => self.infer(decl, name).unwrap_or_default(),
            };
            self.vars.insert(text(name, self.src).to_string(), ty);
        }
        self.visit_children(node);
    }

    /// The type of `var x = <initializer>` when the initializer says it (`new T(...)`, `(T)expr`).
    fn infer(&self, declarator: Node<'a>, name: Node<'a>) -> Option<String> {
        let mut c = declarator.walk();
        let init = declarator.named_children(&mut c).find(|n| n.id() != name.id())?;
        let init = if init.kind() == "equals_value_clause" {
            let mut ic = init.walk();
            let inner = init.named_children(&mut ic).next();
            inner?
        } else {
            init
        };
        match init.kind() {
            "object_creation_expression" | "cast_expression" => init.child_by_field_name("type").and_then(|t| type_text(t, self.src)),
            _ => None,
        }
    }

    // --- calls ---

    fn argument_count(&self, args: Option<Node<'a>>) -> usize {
        match args {
            Some(a) => {
                let mut c = a.walk();
                let n = a.named_children(&mut c).filter(|n| n.kind() == "argument").count();
                n
            }
            None => 0,
        }
    }

    fn invocation(&mut self, node: Node<'a>) {
        let line = node.start_position().row + 1;
        let args = node.child_by_field_name("arguments");
        let argc = self.argument_count(args);
        let Some(func) = node.child_by_field_name("function") else {
            self.visit_children(node);
            return;
        };

        let mut member_name: Option<String> = None;
        let mut receiver_text: Option<String> = None;

        match func.kind() {
            "identifier" | "generic_name" => {
                if let Some(name) = dotted(func, self.src) {
                    member_name = Some(name.clone());
                    self.call_this(&name, Some(argc), line);
                }
            }
            "member_access_expression" => {
                let name = func.child_by_field_name("name").and_then(|n| dotted(n, self.src));
                let expr = func.child_by_field_name("expression");
                let recv = self.receiver_of_access(func);
                if let Some(name) = name {
                    receiver_text = expr.map(|e| text(e, self.src).to_string());
                    member_name = Some(name.clone());
                    self.call_member(recv, &name, Use::Call(argc), line);
                }
                if let Some(e) = expr {
                    self.visit(e);
                }
            }
            "conditional_access_expression" => {
                let cond = func.child_by_field_name("condition");
                let binding_name = {
                    let mut c = func.walk();
                    let binding = func.named_children(&mut c).find(|n| n.kind() == "member_binding_expression");
                    binding.and_then(|b| b.child_by_field_name("name")).and_then(|n| dotted(n, self.src))
                };
                if let (Some(cond), Some(name)) = (cond, binding_name) {
                    let recv = self.receiver_of(cond);
                    receiver_text = Some(text(cond, self.src).to_string());
                    member_name = Some(name.clone());
                    self.call_member(recv, &name, Use::Call(argc), line);
                    self.visit(cond);
                } else {
                    self.visit(func);
                }
            }
            _ => self.visit(func),
        }

        if let Some(name) = member_name {
            if REFLECTION_NAMES.contains(&name.as_str()) {
                self.reflection(&name, receiver_text.as_deref(), args, line);
            }
        }
        if let Some(a) = args {
            self.visit(a);
        }
    }

    fn conditional_access(&mut self, node: Node<'a>) {
        // `a?.B` outside of a call: a property access on the condition.
        let line = node.start_position().row + 1;
        if let Some(cond) = node.child_by_field_name("condition") {
            let binding_name = {
                let mut c = node.walk();
                let binding = node.named_children(&mut c).find(|n| n.kind() == "member_binding_expression");
                binding.and_then(|b| b.child_by_field_name("name")).and_then(|n| dotted(n, self.src))
            };
            if let Some(name) = binding_name {
                let recv = self.receiver_of(cond);
                self.call_member(recv, &name, Use::Access, line);
            }
        }
        self.visit_children(node);
    }

    fn member_reference(&mut self, node: Node<'a>) {
        let line = node.start_position().row + 1;
        let name = node.child_by_field_name("name").and_then(|n| dotted(n, self.src));
        let expr = node.child_by_field_name("expression");
        if let Some(name) = name {
            let recv = self.receiver_of_access(node);
            self.call_member(recv, &name, Use::Access, line);
        }
        if let Some(e) = expr {
            self.visit(e);
        }
    }

    fn creation(&mut self, node: Node<'a>) {
        let line = node.start_position().row + 1;
        let argc = self.argument_count(node.child_by_field_name("arguments"));
        let resolved = node.child_by_field_name("type").and_then(|t| type_text(t, self.src)).map(|n| self.resolve(&n)).unwrap_or_default();

        for r in &resolved {
            match r {
                Resolved::Project(t) => {
                    let init = self.prog.types[*t].init;
                    self.add(Dest::Method(init), EdgeKind::Static, line);
                    for m in self.members_named(*t, "#ctor", Use::Call(argc)) {
                        self.add(Dest::Method(m), EdgeKind::Static, line);
                    }
                }
                Resolved::External(fq) => {
                    for s in self.targets.match_external(fq, "#ctor") {
                        self.add(Dest::Sym(s), EdgeKind::Static, line);
                    }
                }
            }
        }

        // Properties set by an object initializer: `new T { Prop = value }`.
        let mut c = node.walk();
        let initializer = node.named_children(&mut c).find(|n| n.kind() == "initializer_expression");
        if let Some(init) = initializer {
            let mut ic = init.walk();
            for assign in init.named_children(&mut ic).filter(|n| n.kind() == "assignment_expression") {
                let Some(left) = assign.child_by_field_name("left") else { continue };
                if left.kind() != "identifier" {
                    continue;
                }
                let prop = text(left, self.src).to_string();
                for r in &resolved {
                    match r {
                        Resolved::Project(t) => {
                            for m in self.members_named(*t, &prop, Use::Access) {
                                self.add(Dest::Method(m), EdgeKind::Static, line);
                            }
                        }
                        Resolved::External(fq) => {
                            for s in self.targets.match_external(fq, &prop) {
                                self.add(Dest::Sym(s), EdgeKind::Static, line);
                            }
                        }
                    }
                }
            }
        }
        self.visit_children(node);
    }

    /// A method name used as a value (`Subscribe(Handler)`, `x.Event += Handler`): the callee is invoked by someone else.
    fn method_group(&mut self, node: Node<'a>) {
        let Some(parent) = node.parent() else { return };
        if !matches!(parent.kind(), "argument" | "assignment_expression" | "equals_value_clause") {
            return;
        }
        let name = text(node, self.src);
        if self.vars.contains_key(name) {
            return;
        }
        let line = node.start_position().row + 1;
        let mut cur = self.ty;
        while let Some(t) = cur {
            for m in self.members_named(t, name, Use::Call(usize::MAX)) {
                self.add(Dest::Method(m), EdgeKind::Dynamic, line);
            }
            cur = self.outer_of(t);
        }
    }

    // --- receivers ---

    fn receiver_of_access(&mut self, access: Node<'a>) -> Receiver {
        match access.child_by_field_name("expression") {
            Some(e) => self.receiver_of(e),
            None => match access.child(0).map(|c| c.kind()) {
                Some("this") => Receiver::This,
                Some("base") => Receiver::Base,
                _ => Receiver::Unknown,
            },
        }
    }

    fn typed(&self, ty: &str) -> Receiver {
        if ty.is_empty() || ty == "dynamic" {
            Receiver::Unknown
        } else {
            Receiver::Types(self.resolve(ty))
        }
    }

    fn receiver_of(&mut self, node: Node<'a>) -> Receiver {
        match node.kind() {
            "this_expression" | "this" => Receiver::This,
            "base_expression" | "base" => Receiver::Base,
            "identifier" => {
                let name = text(node, self.src);
                if let Some(t) = self.vars.get(name) {
                    return self.typed(&t.clone());
                }
                if let Some(t) = self.field_type(name) {
                    return self.typed(&t);
                }
                self.receiver_dotted(name)
            }
            "qualified_name" | "member_access_expression" | "generic_name" | "alias_qualified_name" => match dotted(node, self.src) {
                Some(d) => self.receiver_dotted(&d),
                None => Receiver::Unknown,
            },
            "parenthesized_expression" => {
                let mut c = node.walk();
                let inner = node.named_children(&mut c).next();
                match inner {
                    Some(i) => self.receiver_of(i),
                    None => Receiver::Unknown,
                }
            }
            "object_creation_expression" | "cast_expression" => {
                match node.child_by_field_name("type").and_then(|t| type_text(t, self.src)) {
                    Some(t) => self.typed(&t),
                    None => Receiver::Unknown,
                }
            }
            _ => Receiver::Unknown,
        }
    }

    /// A dotted name as a receiver: a type (project, or one the request asks about), or an expression whose type is unknown.
    fn receiver_dotted(&self, dotted_name: &str) -> Receiver {
        let head = dotted_name.split('.').next().unwrap_or(dotted_name);
        if dotted_name.contains('.') && (self.vars.contains_key(head) || self.field_type(head).is_some()) {
            return Receiver::Unknown;
        }
        let resolved = self.resolve(dotted_name);
        let projects: Vec<Resolved> = resolved.iter().filter(|r| matches!(r, Resolved::Project(_))).cloned().collect();
        if !projects.is_empty() {
            return Receiver::Types(projects);
        }
        let known: Vec<Resolved> =
            resolved.iter().filter(|r| matches!(r, Resolved::External(fq) if self.targets.has_type(fq))).cloned().collect();
        if !known.is_empty() {
            return Receiver::Types(known);
        }
        if head.chars().next().map(|c| c.is_uppercase()).unwrap_or(false) {
            Receiver::Types(resolved)
        } else {
            Receiver::Unknown
        }
    }

    fn outer_of(&self, t: usize) -> Option<usize> {
        self.prog.types[t].fq.rsplit_once('.').and_then(|(outer, _)| self.prog.types_by_fq.get(outer).copied())
    }

    /// The declared type of a field or property visible in the current type (own, inherited from project bases, or of an
    /// enclosing type). `Some("")` if it is declared with a type that cannot be named.
    fn field_type(&self, name: &str) -> Option<String> {
        let mut cur = self.ty;
        while let Some(t) = cur {
            let mut seen = HashSet::new();
            let mut queue = VecDeque::from([t]);
            while let Some(c) = queue.pop_front() {
                if !seen.insert(c) {
                    continue;
                }
                if let Some(ty) = self.prog.types[c].fields.get(name) {
                    return Some(ty.clone());
                }
                for b in &self.prog.base_links[c] {
                    if let Resolved::Project(bi) = b {
                        queue.push_back(*bi);
                    }
                }
            }
            cur = self.outer_of(t);
        }
        None
    }

    // --- resolving a call ---

    fn call_member(&mut self, recv: Receiver, member: &str, usage: Use, line: usize) {
        match recv {
            Receiver::This => self.call_this(member, if let Use::Call(n) = usage { Some(n) } else { None }, line),
            Receiver::Base => {
                let Some(t) = self.ty else {
                    self.name_only(member, usage, line);
                    return;
                };
                let bases = self.prog.base_links[t].clone();
                let mut found = false;
                for b in bases {
                    found |= match b {
                        Resolved::Project(bi) => self.call_in_type(bi, member, usage, line),
                        Resolved::External(fq) => self.external_member(&fq, member, line),
                    };
                }
                if !found {
                    self.name_only_external(member, line);
                }
            }
            Receiver::Types(list) => {
                for r in list {
                    match r {
                        Resolved::Project(t) => {
                            if !self.call_in_type(t, member, usage, line) {
                                self.extension_calls(member, usage, line);
                            }
                        }
                        Resolved::External(fq) => {
                            self.external_member(&fq, member, line);
                        }
                    }
                }
            }
            Receiver::Unknown => self.name_only(member, usage, line),
        }
    }

    /// An unqualified call, or `this.Member`: the current type and its bases, enclosing types, `using static`.
    fn call_this(&mut self, member: &str, argc: Option<usize>, line: usize) {
        let usage = match argc {
            Some(n) => Use::Call(n),
            None => Use::Access,
        };
        let mut cur = self.ty;
        while let Some(t) = cur {
            if self.call_in_type(t, member, usage, line) {
                return;
            }
            cur = self.outer_of(t);
        }
        for su in self.prog.static_usings_of(self.file) {
            for r in self.resolve(&su) {
                let hit = match r {
                    Resolved::Project(t) => self.call_in_type(t, member, usage, line),
                    Resolved::External(fq) => {
                        let hits = self.targets.match_external(&fq, member);
                        for s in &hits {
                            self.add(Dest::Sym(*s), EdgeKind::Static, line);
                        }
                        !hits.is_empty()
                    }
                };
                if hit {
                    return;
                }
            }
        }
        // Inherited from an external base type, or a local function.
        self.name_only(member, usage, line);
    }

    /// Calls `member` on a project type: the nearest declaration in the type's chain of bases (static edges), the overriding
    /// and implementing members below the type (dynamic edges), and symbols of external bases. False if nothing was found.
    fn call_in_type(&mut self, t: usize, member: &str, usage: Use, line: usize) -> bool {
        let mut seen = HashSet::new();
        let mut queue = VecDeque::from([t]);
        let mut found = false;
        while let Some(c) = queue.pop_front() {
            if !seen.insert(c) {
                continue;
            }
            let ms = self.members_named(c, member, usage);
            if !ms.is_empty() {
                found = true;
                let virtual_like = self.prog.types[c].kind == TypeKind::Interface || ms.iter().any(|&m| self.prog.methods[m].is_virtual);
                for &m in &ms {
                    self.add(Dest::Method(m), EdgeKind::Static, line);
                }
                let init = self.prog.types[c].init;
                self.add(Dest::Method(init), EdgeKind::Static, line);
                if virtual_like {
                    let mut below = vec![t];
                    below.extend(self.prog.descendants(t));
                    for d in below {
                        for m in self.members_named(d, member, usage) {
                            self.add(Dest::Method(m), EdgeKind::Dynamic, line);
                        }
                    }
                }
                break;
            }
            let bases = self.prog.base_links[c].clone();
            for b in bases {
                match b {
                    Resolved::Project(bi) => queue.push_back(bi),
                    Resolved::External(fq) => {
                        let hits = self.targets.match_external(&fq, member);
                        for s in &hits {
                            self.add(Dest::Sym(*s), EdgeKind::Static, line);
                        }
                        found |= !hits.is_empty();
                    }
                }
            }
        }
        found
    }

    fn members_named(&self, t: usize, name: &str, usage: Use) -> Vec<usize> {
        let all: Vec<usize> = self.prog.types[t]
            .methods
            .iter()
            .copied()
            .filter(|&m| {
                let method = &self.prog.methods[m];
                method.name == name
                    && match usage {
                        Use::Call(_) => matches!(method.kind, MethodKind::Normal | MethodKind::Ctor),
                        Use::Access => method.kind == MethodKind::Property,
                    }
            })
            .collect();
        match usage {
            Use::Call(n) if n != usize::MAX => {
                let fitting: Vec<usize> = all
                    .iter()
                    .copied()
                    .filter(|&m| {
                        let method = &self.prog.methods[m];
                        n >= method.min_args && (n <= method.max_args || method.variadic)
                    })
                    .collect();
                // No overload resolution here: when no arity fits, every overload stays a candidate.
                if fitting.is_empty() {
                    all
                } else {
                    fitting
                }
            }
            _ => all,
        }
    }

    fn external_member(&mut self, fq: &str, member: &str, line: usize) -> bool {
        let hits = self.targets.match_external(fq, member);
        if hits.is_empty() {
            self.name_only_external(member, line);
            return false;
        }
        for s in hits {
            self.add(Dest::Sym(s), EdgeKind::Static, line);
        }
        true
    }

    fn extension_calls(&mut self, member: &str, usage: Use, line: usize) {
        if !matches!(usage, Use::Call(_)) {
            return;
        }
        if let Some(ms) = self.name_index.get(member) {
            for &m in ms {
                if self.prog.methods[m].is_extension {
                    self.add(Dest::Method(m), EdgeKind::Dynamic, line);
                }
            }
        }
    }

    /// The receiver's type is unknown: any project method of that name could be meant, and any symbol with that member name.
    fn name_only(&mut self, member: &str, usage: Use, line: usize) {
        if matches!(usage, Use::Call(_)) {
            if let Some(ms) = self.name_index.get(member) {
                for &m in ms {
                    self.add(Dest::Method(m), EdgeKind::Dynamic, line);
                }
            }
        }
        self.name_only_external(member, line);
    }

    fn file_mentions(&self, type_fq: &str) -> bool {
        let (ns, simple) = match type_fq.rsplit_once('.') {
            Some((n, s)) => (n, s),
            None => ("", type_fq),
        };
        self.prog.imports_namespace(self.file, ns, &self.ns) || self.src.contains(simple)
    }

    /// Symbols matched by member name only. If the file names or imports the symbol's type, the match is a dynamic edge.
    /// If not, the call may still be on that type (a value that flowed in from elsewhere): the method is marked uncertain.
    fn name_only_external(&mut self, member: &str, line: usize) {
        let targets = self.targets;
        for &s in targets.with_member(member) {
            if self.file_mentions(&targets.syms[s].type_fq) {
                self.add(Dest::Sym(s), EdgeKind::Dynamic, line);
            } else {
                self.uncertain(Uncertainty::NameMatch(s));
            }
        }
        for &s in &targets.wildcards {
            if self.file_mentions(&targets.syms[s].type_fq) && self.file_names_member(member, &targets.syms[s].type_fq) {
                self.add(Dest::Sym(s), EdgeKind::Dynamic, line);
            }
        }
    }

    /// For a wildcard symbol, a member name alone says nothing; require that the file imports the type's namespace.
    fn file_names_member(&self, _member: &str, type_fq: &str) -> bool {
        let ns = type_fq.rsplit_once('.').map(|(n, _)| n).unwrap_or("");
        self.prog.imports_namespace(self.file, ns, &self.ns)
    }

    // --- reflection ---

    fn reflection(&mut self, name: &str, receiver: Option<&str>, args: Option<Node<'a>>, line: usize) {
        let argc = self.argument_count(args);
        if name == "GetType" && argc == 0 {
            return; // obj.GetType() reads the runtime type; it does not look anything up by name
        }
        if matches!(name, "Load" | "LoadFrom" | "LoadFile" | "LoadWithPartialName")
            && !receiver.map(|r| r.contains("Assembly") || r.contains("LoadContext")).unwrap_or(false)
        {
            return;
        }
        self.reflection_sites += 1;

        let mut literals: Vec<String> = Vec::new();
        let mut resolvable = true;
        if let Some(a) = args {
            let mut c = a.walk();
            for arg in a.named_children(&mut c).filter(|n| n.kind() == "argument") {
                let mut ac = arg.walk();
                let Some(expr) = arg.named_children(&mut ac).next() else { continue };
                match expr.kind() {
                    "string_literal" => literals.push(text(expr, self.src).trim_matches('"').to_string()),
                    "typeof_expression" => {
                        let mut tc = expr.walk();
                        let named = expr.named_children(&mut tc).next().and_then(|t| type_text(t, self.src));
                        if let Some(n) = named {
                            for r in self.resolve(&n) {
                                if let Resolved::External(fq) = r {
                                    for &s in self.targets.type_syms(&fq) {
                                        self.add(Dest::Sym(s), EdgeKind::Dynamic, line);
                                    }
                                }
                            }
                        }
                    }
                    _ => resolvable = false,
                }
            }
        }

        let syms: Vec<usize> = (0..self.targets.syms.len()).collect();
        for lit in &literals {
            for &s in &syms {
                let sym = &self.targets.syms[s];
                if lit.contains(&sym.type_fq) || sym.member.as_deref() == Some(lit.as_str()) {
                    self.add(Dest::Sym(s), EdgeKind::Dynamic, line);
                }
            }
        }
        if !resolvable {
            self.uncertain(Uncertainty::Reflection);
        }
    }
}
