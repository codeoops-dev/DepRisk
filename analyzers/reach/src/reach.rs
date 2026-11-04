//! Phase 3: entrypoints, reachability over the graph, and the label of every target.

use crate::analyze::{Dest, EdgeKind, Graph, Uncertainty};
use crate::program::*;
use crate::protocol::*;
use crate::targets::TargetIndex;
use std::collections::VecDeque;

pub struct Entry {
    pub method: usize,
    pub kind: &'static str,
    /// Only used for the over-approximating search: members that something else invokes (indexers, operators, finalizers).
    pub dynamic_only: bool,
}

pub fn entrypoints(prog: &Program, spec: &EntrypointSpec, diagnostics: &mut Vec<Diagnostic>) -> Vec<Entry> {
    let mut entries: Vec<Entry> = Vec::new();
    let mut seen = vec![false; prog.methods.len()];
    let mut add = |entries: &mut Vec<Entry>, m: usize, kind: &'static str, dynamic_only: bool| {
        if !seen[m] {
            seen[m] = true;
            entries.push(Entry { method: m, kind, dynamic_only });
        }
        // Using a type runs its initializers.
        if let Some(t) = prog.methods[m].ty {
            let init = prog.types[t].init;
            if !seen[init] {
                seen[init] = true;
                entries.push(Entry { method: init, kind, dynamic_only });
            }
        }
    };

    for (i, m) in prog.methods.iter().enumerate() {
        let ty = m.ty.map(|t| &prog.types[t]);
        match m.kind {
            MethodKind::TopLevel => add(&mut entries, i, "top-level", false),
            MethodKind::Unmodeled => add(&mut entries, i, "unmodeled", true),
            MethodKind::Normal => {
                if spec.mode == "auto" {
                    if m.name == "Main" && m.is_static && m.max_args <= 1 {
                        add(&mut entries, i, "main", false);
                        continue;
                    }
                    if let Some(t) = ty {
                        let web_base = t.bases.iter().any(|b| {
                            let last = b.rsplit('.').next().unwrap_or(b);
                            matches!(last, "Controller" | "ControllerBase" | "ApiController" | "Hub" | "PageModel")
                        });
                        if m.is_public && !m.is_static && (t.simple.ends_with("Controller") || web_base) {
                            add(&mut entries, i, "controller", false);
                            continue;
                        }
                        let hosted = t.bases.iter().any(|b| {
                            let last = b.rsplit('.').next().unwrap_or(b);
                            matches!(last, "BackgroundService" | "IHostedService" | "IHostedLifecycleService")
                        });
                        if hosted && matches!(m.name.as_str(), "ExecuteAsync" | "StartAsync" | "StopAsync") {
                            add(&mut entries, i, "hosted-service", false);
                            continue;
                        }
                    }
                }
                if spec.mode == "public-api" && m.is_public && ty.map(|t| t.is_public).unwrap_or(false) {
                    add(&mut entries, i, "public-api", false);
                }
            }
            MethodKind::Ctor | MethodKind::Property => {
                if spec.mode == "public-api" && m.is_public && ty.map(|t| t.is_public).unwrap_or(false) {
                    add(&mut entries, i, "public-api", false);
                }
            }
            MethodKind::Init => {}
        }
    }

    for name in &spec.explicit {
        let before = entries.len();
        let wildcard = name.strip_suffix(".*");
        for (i, m) in prog.methods.iter().enumerate() {
            let matches = match wildcard {
                Some(ty) => m.ty.map(|t| prog.types[t].fq == ty).unwrap_or(false) && m.kind != MethodKind::Init,
                None => m.id == *name && m.kind != MethodKind::Init,
            };
            if matches {
                add(&mut entries, i, "explicit", false);
            }
        }
        if entries.len() == before && !prog.methods.iter().any(|m| m.id == *name) {
            diagnostics.push(Diagnostic { file: None, message: format!("explicit entrypoint '{}' matches no method", crate::safe(name)) });
        }
    }

    entries
}

struct Search {
    method_parent: Vec<Option<(usize, usize)>>, // method -> (from method, edge index in from)
    sym_parent: Vec<Option<(usize, usize)>>,
    method_seen: Vec<bool>,
    sym_dist: Vec<u32>,
}

fn search(graph: &Graph, entries: &[&Entry], sym_count: usize, static_only: bool) -> Search {
    let n = graph.edges.len();
    let mut s = Search {
        method_parent: vec![None; n],
        sym_parent: vec![None; sym_count],
        method_seen: vec![false; n],
        sym_dist: vec![u32::MAX; sym_count],
    };
    let mut dist = vec![0u32; n];
    let mut queue = VecDeque::new();
    for e in entries {
        if !s.method_seen[e.method] {
            s.method_seen[e.method] = true;
            queue.push_back(e.method);
        }
    }
    while let Some(m) = queue.pop_front() {
        for (ei, edge) in graph.edges[m].iter().enumerate() {
            if static_only && edge.kind != EdgeKind::Static {
                continue;
            }
            match edge.to {
                Dest::Method(t) => {
                    if !s.method_seen[t] {
                        s.method_seen[t] = true;
                        s.method_parent[t] = Some((m, ei));
                        dist[t] = dist[m] + 1;
                        queue.push_back(t);
                    }
                }
                Dest::Sym(y) => {
                    let d = dist[m] + 1;
                    if d < s.sym_dist[y] {
                        s.sym_dist[y] = d;
                        s.sym_parent[y] = Some((m, ei));
                    }
                }
            }
        }
    }
    s
}

fn kind_name(k: EdgeKind) -> &'static str {
    match k {
        EdgeKind::Static => "static",
        EdgeKind::Dynamic => "dynamic",
    }
}

fn path_to(prog: &Program, parsed: &[Parsed], graph: &Graph, targets: &TargetIndex, s: &Search, sym: usize) -> Vec<PathEdge> {
    let mut edges: Vec<PathEdge> = Vec::new();
    let mut cur = s.sym_parent[sym];
    let mut last_to = targets.syms[sym].text.clone();
    while let Some((from, ei)) = cur {
        let edge = &graph.edges[from][ei];
        let file = parsed.get(prog.methods[from].file).map(|p| p.rel.clone());
        edges.push(PathEdge {
            from: prog.methods[from].id.clone(),
            to: last_to.clone(),
            kind: kind_name(edge.kind),
            file,
            line: Some(edge.line),
        });
        last_to = prog.methods[from].id.clone();
        cur = s.method_parent[from];
    }
    edges.reverse();
    if edges.len() > 100 {
        edges.truncate(100);
    }
    edges
}

pub struct Completeness {
    /// Files that were skipped or could not be read completely.
    pub incomplete: bool,
}

pub fn label_targets(
    prog: &Program,
    parsed: &[Parsed],
    graph: &Graph,
    targets: &TargetIndex,
    request: &[Target],
    entries: &[Entry],
    completeness: &Completeness,
) -> Vec<TargetResult> {
    let all: Vec<&Entry> = entries.iter().collect();
    let static_entries: Vec<&Entry> = entries.iter().filter(|e| !e.dynamic_only).collect();
    let by_static = search(graph, &static_entries, targets.syms.len(), true);
    let by_all = search(graph, &all, targets.syms.len(), false);

    let mut out = Vec::new();
    for (ti, target) in request.iter().enumerate() {
        let syms: Vec<usize> = (0..targets.syms.len()).filter(|&s| targets.syms[s].targets.contains(&ti)).collect();
        let result = |label: &'static str, reason: &'static str, path: Vec<PathEdge>, symbol: Option<String>| TargetResult {
            key: target.key.clone(),
            label,
            reason,
            path,
            symbol,
        };

        if syms.is_empty() {
            out.push(result("unknown", "no-symbols", Vec::new(), None));
            continue;
        }
        if entries.is_empty() {
            // If something could not be read, that is the more useful reason: the entrypoints may have been in it.
            let reason = if completeness.incomplete { "incomplete-analysis" } else { "no-entrypoints" };
            out.push(result("unknown", reason, Vec::new(), None));
            continue;
        }

        let nearest = |s: &Search| {
            syms.iter()
                .copied()
                .filter(|&y| s.sym_dist[y] != u32::MAX)
                .min_by(|&a, &b| s.sym_dist[a].cmp(&s.sym_dist[b]).then_with(|| targets.syms[a].text.cmp(&targets.syms[b].text)))
        };

        if let Some(y) = nearest(&by_static) {
            let p = path_to(prog, parsed, graph, targets, &by_static, y);
            out.push(result("reachable", "static-path", p, Some(targets.syms[y].text.clone())));
            continue;
        }
        if let Some(y) = nearest(&by_all) {
            let p = path_to(prog, parsed, graph, targets, &by_all, y);
            out.push(result("possibly-reachable", "dynamic-path", p, Some(targets.syms[y].text.clone())));
            continue;
        }

        // No path. That only means "unreachable" if nothing could hide one.
        let mut incomplete = completeness.incomplete;
        let mut reflection = false;
        let mut receiver = false;
        for (m, seen) in by_all.method_seen.iter().enumerate() {
            if !*seen {
                continue;
            }
            for u in &graph.uncertain[m] {
                match u {
                    Uncertainty::Incomplete => incomplete = true,
                    Uncertainty::Reflection => reflection = true,
                    Uncertainty::NameMatch(s) => {
                        if syms.contains(s) {
                            receiver = true;
                        }
                    }
                }
            }
        }
        if incomplete {
            out.push(result("unknown", "incomplete-analysis", Vec::new(), None));
        } else if reflection {
            out.push(result("unknown", "unresolved-reflection", Vec::new(), None));
        } else if receiver {
            out.push(result("unknown", "unresolved-receiver", Vec::new(), None));
        } else if !target.complete {
            out.push(result("unknown", "symbol-list-incomplete", Vec::new(), None));
        } else {
            out.push(result("unreachable", "no-path", Vec::new(), None));
        }
    }
    out
}
