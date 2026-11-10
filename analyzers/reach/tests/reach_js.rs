//! End-to-end tests for JavaScript and TypeScript (ADR 0019): real sources in a temporary directory, a request with
//! `"language": "javascript"` on stdin, the labels on stdout. Each test states what is claimed about reachability and why.

use serde_json::{json, Value};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

struct Project {
    dir: PathBuf,
}

impl Project {
    fn new(files: &[(&str, &str)]) -> Project {
        let dir = std::env::temp_dir().join(format!("deprisk-reach-js-{}-{}", std::process::id(), COUNTER.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir_all(&dir).unwrap();
        for (name, content) in files {
            let path = dir.join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, content).unwrap();
        }
        Project { dir }
    }
}

impl Drop for Project {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn run_raw(request: &Value) -> (i32, Value, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_deprisk-reach"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(request.to_string().as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    let json = serde_json::from_slice(&out.stdout).unwrap_or(Value::Null);
    (out.status.code().unwrap_or(-1), json, String::from_utf8_lossy(&out.stderr).to_string())
}

fn analyze(files: &[(&str, &str)], symbols: &[&str]) -> Value {
    analyze_with(files, symbols, json!({ "mode": "auto" }))
}

fn analyze_with(files: &[(&str, &str)], symbols: &[&str], entrypoints: Value) -> Value {
    let project = Project::new(files);
    let request = json!({
        "schemaVersion": 1, "language": "javascript", "root": project.dir.to_string_lossy(), "entrypoints": entrypoints,
        "targets": [{ "key": "t", "symbols": symbols, "complete": true }]
    });
    let (code, out, err) = run_raw(&request);
    assert_eq!(code, 0, "analyzer failed: {err}");
    out
}

fn label(out: &Value) -> (&str, &str) {
    let r = &out["results"][0];
    (r["label"].as_str().unwrap(), r["reason"].as_str().unwrap())
}

fn expect(out: &Value, label_: &str, reason: &str) {
    assert_eq!(label(out), (label_, reason), "diagnostics: {}", out["diagnostics"]);
}

#[test]
fn a_call_on_a_required_package_is_reachable_with_a_static_path() {
    let out = analyze(&[("app.js", "const _ = require('lodash');\nfunction main() { _.template('x'); }\nmain();")], &["lodash::template"]);
    expect(&out, "reachable", "static-path");
    assert_eq!(out["language"], "javascript");
    let path = out["results"][0]["path"].as_array().unwrap();
    assert_eq!(path.last().unwrap()["to"], "lodash::template");
}

#[test]
fn a_package_that_is_imported_but_whose_member_is_never_used_is_unreachable() {
    let out = analyze(&[("app.js", "const _ = require('lodash');\n_.map([1], x => x);")], &["lodash::template"]);
    expect(&out, "unreachable", "no-path");
}

#[test]
fn es_default_named_and_namespace_imports_resolve_to_package_members() {
    let src = "import def, { parse as p } from 'pkg';\nimport * as ns from 'other';\ndef.one(); p(); ns.two.three();";
    for (symbol, label_) in
        [("pkg::default.one", "reachable"), ("pkg::parse", "reachable"), ("other::two.three", "reachable"), ("pkg::two", "unreachable")]
    {
        expect(&analyze(&[("a.mjs", src)], &[symbol]), label_, if label_ == "reachable" { "static-path" } else { "no-path" });
    }
}

#[test]
fn a_default_import_of_a_commonjs_package_also_matches_the_module_member() {
    // `import d from 'cjs'` is `module.exports` for a CommonJS package, so `d.fn()` is `cjs::fn`.
    expect(&analyze(&[("a.js", "import d from 'cjs';\nd.fn();")], &["cjs::fn"]), "reachable", "static-path");
}

#[test]
fn calling_the_module_value_itself_matches_default() {
    expect(&analyze(&[("a.js", "const run = require('runner');\nrun(1);")], &["runner::default"]), "reachable", "static-path");
}

#[test]
fn destructured_requires_bind_the_named_members() {
    let src = "const { template, merge: m } = require('lodash');\ntemplate(); ";
    expect(&analyze(&[("a.js", src)], &["lodash::template"]), "reachable", "static-path");
    expect(&analyze(&[("a.js", src)], &["lodash::merge"]), "unreachable", "no-path");
}

#[test]
fn a_wildcard_matches_any_use_of_the_package_even_a_bare_import() {
    expect(&analyze(&[("a.js", "import 'polyfill';")], &["polyfill::*"]), "reachable", "static-path");
    expect(&analyze(&[("a.js", "console.log(1);")], &["polyfill::*"]), "unreachable", "no-path");
}

#[test]
fn a_call_through_a_project_module_is_followed_and_an_unused_export_is_not() {
    let files = [
        ("app.js", "import { helper } from './util';\nhelper();"),
        (
            "util.js",
            "const lib = require('legacy-lib');\nexport function helper() { return 1; }\nexport function unused() { lib.danger(); }",
        ),
    ];
    expect(&analyze(&files, &["legacy-lib::danger"]), "unreachable", "no-path");

    let used = [
        ("app.js", "import { helper } from './util';\nhelper();"),
        ("util.js", "const lib = require('legacy-lib');\nexport function helper() { lib.danger(); }"),
    ];
    expect(&analyze(&used, &["legacy-lib::danger"]), "reachable", "static-path");
}

#[test]
fn commonjs_exports_of_every_shape_are_followed() {
    for exports in ["module.exports = { run };", "exports.run = run;", "module.exports.run = run;", "module.exports = { run: run };"] {
        let util = format!("const lib = require('lib');\nfunction run() {{ lib.go(); }}\n{exports}");
        let files = [("app.js", "const u = require('./util');\nu.run();"), ("util.js", util.as_str())];
        expect(&analyze(&files, &["lib::go"]), "reachable", "static-path");
    }
}

#[test]
fn a_default_export_function_is_called_through_a_default_import_and_through_require() {
    let util = "const lib = require('lib');\nexport default function () { lib.go(); }";
    expect(&analyze(&[("app.js", "import f from './util';\nf();"), ("util.js", util)], &["lib::go"]), "reachable", "static-path");
    let cjs = "const lib = require('lib');\nmodule.exports = function () { lib.go(); };";
    expect(&analyze(&[("app.js", "require('./util')();"), ("util.js", cjs)], &["lib::go"]), "reachable", "static-path");
}

#[test]
fn reexports_and_namespace_imports_resolve_through_the_chain() {
    let files = [
        ("app.js", "import * as u from './index';\nu.run();"),
        ("index.js", "export * from './impl';"),
        ("impl.js", "import lib from 'lib';\nexport function run() { lib.go(); }"),
    ];
    expect(&analyze(&files, &["lib::go"]), "reachable", "static-path");
}

#[test]
fn importing_a_module_runs_its_top_level_code() {
    let files = [("app.js", "import './setup';"), ("setup.js", "const lib = require('lib');\nlib.init();")];
    expect(&analyze(&files, &["lib::init"]), "reachable", "static-path");
}

#[test]
fn a_function_passed_as_a_callback_is_possibly_reached_and_a_function_never_used_is_not() {
    let src = "const express = require('express');\nconst yaml = require('js-yaml');\nconst app = express();\napp.get('/', (req, res) => yaml.load(req.body));\nfunction never() { yaml.dump({}); }";
    expect(&analyze(&[("app.js", src)], &["js-yaml::load"]), "possibly-reachable", "dynamic-path");
    expect(&analyze(&[("app.js", src)], &["js-yaml::dump"]), "unreachable", "no-path");
}

#[test]
fn an_immediately_invoked_function_is_a_static_call() {
    expect(
        &analyze(&[("a.js", "const lib = require('lib');\n(function () { lib.go(); })();\n(() => lib.stop())();")], &["lib::go"]),
        "reachable",
        "static-path",
    );
}

#[test]
fn a_method_of_an_external_class_is_reached_through_the_instance_that_was_constructed() {
    let src = "const { Parser } = require('xml');\nconst p = new Parser();\np.parse('x');";
    expect(&analyze(&[("a.js", src)], &["xml::Parser.parse"]), "reachable", "static-path");
    expect(&analyze(&[("a.js", src)], &["xml::Parser.*"]), "reachable", "static-path");
    expect(&analyze(&[("a.js", src)], &["xml::Parser.validate"]), "unreachable", "no-path");
}

#[test]
fn constructing_alone_reaches_the_constructor_wildcard_but_not_a_method() {
    let src = "import { Parser } from 'xml';\nconst p = new Parser();";
    expect(&analyze(&[("a.js", src)], &["xml::Parser.*"]), "reachable", "static-path");
    expect(&analyze(&[("a.js", src)], &["xml::Parser.parse"]), "unreachable", "no-path");
}

#[test]
fn a_variable_that_is_assigned_again_loses_its_type_and_the_call_is_matched_by_name() {
    // `p` may hold something else by the time it is used: the call is a call on an unknown receiver, and the package's member of
    // that name is reached dynamically because this file imports the package.
    let src = "import { Parser } from 'xml';\nlet p = new Parser();\nif (process.env.X) { p = other(); }\np.parse('x');";
    expect(&analyze(&[("a.js", src)], &["xml::Parser.parse"]), "possibly-reachable", "dynamic-path");
}

#[test]
fn a_call_on_an_unknown_receiver_of_a_member_the_file_does_not_import_is_unresolved() {
    let files = [
        ("a.js", "function use(client) { client.parse('x'); }\nuse(make());"),
        ("b.js", "import { Parser } from 'xml';\nexport const p = new Parser();"),
    ];
    expect(&analyze(&files, &["xml::Parser.parse"]), "unknown", "unresolved-receiver");
}

#[test]
fn project_classes_dispatch_on_constructed_instances_and_this() {
    let src = "import lib from 'lib';\nclass A { run() { this.step(); } step() { lib.go(); } other() { lib.stop(); } }\nnew A().run();";
    expect(&analyze(&[("a.js", src)], &["lib::go"]), "reachable", "static-path");
    expect(&analyze(&[("a.js", src)], &["lib::stop"]), "unreachable", "no-path");
}

#[test]
fn an_override_in_a_subclass_is_possibly_reached_through_the_base_type() {
    let src =
        "import lib from 'lib';\nclass A { run() { return 1; } }\nclass B extends A { run() { lib.go(); } }\nconst a = new A();\na.run();";
    expect(&analyze(&[("a.js", src)], &["lib::go"]), "possibly-reachable", "dynamic-path");
}

#[test]
fn a_subclass_of_an_external_class_uses_the_package_when_constructed_and_when_inherited_methods_are_called() {
    let src = "import { Base } from 'framework';\nclass Mine extends Base { go() { this.save(); } }\nnew Mine().go();";
    expect(&analyze(&[("a.js", src)], &["framework::Base.save"]), "reachable", "static-path");
    expect(&analyze(&[("a.js", src)], &["framework::Base.*"]), "reachable", "static-path");
    expect(&analyze(&[("a.js", src)], &["framework::Base.delete"]), "unreachable", "no-path");
}

#[test]
fn super_calls_reach_the_base_class() {
    let src = "import { Base } from 'framework';\nclass Mine extends Base { constructor() { super(); } run() { super.save(); } }\nnew Mine().run();";
    expect(&analyze(&[("a.js", src)], &["framework::Base.save"]), "reachable", "static-path");
}

#[test]
fn static_methods_of_project_classes_are_called_on_the_class() {
    let src = "import lib from 'lib';\nclass U { static load() { lib.read(); } }\nU.load();";
    expect(&analyze(&[("a.js", src)], &["lib::read"]), "reachable", "static-path");
}

#[test]
fn class_fields_and_static_blocks_run_with_the_class() {
    let src = "import lib from 'lib';\nclass A { x = lib.field(); static y = lib.statics(); }\nnew A();";
    expect(&analyze(&[("a.js", src)], &["lib::field"]), "reachable", "static-path");
    expect(&analyze(&[("a.js", src)], &["lib::statics"]), "reachable", "static-path");
}

#[test]
fn eval_and_function_constructors_make_the_answer_unknown() {
    expect(&analyze(&[("a.js", "eval(process.argv[2]);")], &["lib::go"]), "unknown", "unresolved-reflection");
    expect(&analyze(&[("a.js", "const f = new Function('return 1');\nf();")], &["lib::go"]), "unknown", "unresolved-reflection");
}

#[test]
fn a_require_or_import_of_a_computed_name_makes_the_answer_unknown() {
    expect(&analyze(&[("a.js", "const n = process.env.PLUGIN;\nrequire(n);")], &["lib::go"]), "unknown", "unresolved-reflection");
    expect(
        &analyze(&[("a.js", "async function f(n) { await import(n); }\nf(process.env.P);")], &["lib::go"]),
        "unknown",
        "unresolved-reflection",
    );
}

#[test]
fn a_computed_member_call_makes_the_answer_unknown_and_a_literal_one_does_not() {
    expect(&analyze(&[("a.js", "const lib = require('lib');\nlib[process.env.M]();")], &["lib::go"]), "unknown", "unresolved-reflection");
    expect(&analyze(&[("a.js", "const lib = require('lib');\nlib['go']();")], &["lib::go"]), "reachable", "static-path");
}

#[test]
fn a_literal_dynamic_import_is_followed() {
    expect(
        &analyze(&[("a.js", "async function f() { const m = await import('lib'); m.go(); }\nf();")], &["lib::go"]),
        "reachable",
        "static-path",
    );
}

#[test]
fn reflect_and_vm_are_reflection() {
    expect(&analyze(&[("a.js", "Reflect.apply(fn, null, []);")], &["lib::go"]), "unknown", "unresolved-reflection");
    expect(&analyze(&[("a.js", "const vm = require('vm');\nvm.runInThisContext('1');")], &["lib::go"]), "unknown", "unresolved-reflection");
}

#[test]
fn call_apply_and_bind_on_a_function_are_calls() {
    let src = "const lib = require('lib');\nfunction f() { lib.go(); }\nf.call(null);";
    expect(&analyze(&[("a.js", src)], &["lib::go"]), "reachable", "static-path");
    let bound = "const lib = require('lib');\nfunction f() { lib.go(); }\nsetTimeout(f.bind(null), 1);";
    expect(&analyze(&[("a.js", bound)], &["lib::go"]), "possibly-reachable", "dynamic-path");
}

#[test]
fn a_local_variable_that_shadows_an_import_is_not_the_import() {
    let src = "const _ = require('lodash');\nfunction f(_) { _.template(); }\nf({ template() {} });";
    // `_` inside f is the parameter, an object of unknown type: its `template` is matched by name, and this file imports lodash.
    expect(&analyze(&[("a.js", src)], &["lodash::template"]), "possibly-reachable", "dynamic-path");
    let strict = "const _ = require('lodash');\nfunction f(_) { return _; }\n_.map([1], x => x);\nf(1);";
    expect(&analyze(&[("a.js", strict)], &["lodash::template"]), "unreachable", "no-path");
}

#[test]
fn a_subpath_import_conservatively_matches_every_symbol_of_the_package() {
    expect(&analyze(&[("a.js", "const map = require('lodash/fp/map');\nmap(1);")], &["lodash::template"]), "reachable", "static-path");
}

#[test]
fn scoped_packages_and_their_subpaths_are_packages() {
    expect(&analyze(&[("a.js", "import { x } from '@scope/pkg';\nx();")], &["@scope/pkg::x"]), "reachable", "static-path");
    expect(&analyze(&[("a.js", "import { x } from '@scope/pkg/sub';\nx();")], &["@scope/pkg::x"]), "reachable", "static-path");
}

#[test]
fn modules_nobody_imports_are_entry_points_with_their_exports() {
    // A handler file that a platform calls: nothing in the project imports it, so its exports are entry points.
    let src = "const lib = require('lib');\nexports.handler = async () => { lib.go(); };";
    let out = analyze(&[("handler.js", src)], &["lib::go"]);
    expect(&out, "reachable", "static-path");
    assert!(out["entrypoints"].as_array().unwrap().iter().any(|e| e["kind"] == "export"));
}

#[test]
fn an_imported_module_is_not_an_entry_point_in_auto_mode_but_its_exports_are_in_public_api_mode() {
    let files = [
        ("test.js", "const { used } = require('./lib');\nused();"),
        ("lib.js", "const x = require('x');\nexports.used = () => 1;\nexports.other = () => x.go();"),
    ];
    expect(&analyze(&files, &["x::go"]), "unreachable", "no-path");
    expect(&analyze_with(&files, &["x::go"], json!({ "mode": "public-api" })), "reachable", "static-path");
}

#[test]
fn explicit_entry_points_by_id_and_by_file_wildcard() {
    let files = [
        ("a.js", "import lib from 'lib';\nexport function handler() { lib.go(); }\nconst keep = 1;"),
        ("b.js", "import { handler } from './a';\nconsole.log(1);"),
    ];
    expect(&analyze_with(&files, &["lib::go"], json!({ "mode": "none", "explicit": ["a.js::handler"] })), "reachable", "static-path");
    expect(&analyze_with(&files, &["lib::go"], json!({ "mode": "none", "explicit": ["a.js::*"] })), "reachable", "static-path");
    let missing = analyze_with(&files, &["lib::go"], json!({ "mode": "none", "explicit": ["a.js::nope"] }));
    expect(&missing, "unknown", "no-entrypoints");
    assert!(missing["diagnostics"].as_array().unwrap().iter().any(|d| d["message"].as_str().unwrap().contains("not found")));
}

#[test]
fn typescript_declared_types_resolve_receivers_including_parameter_properties_and_casts() {
    let src = "import { Api } from 'sdk';\nimport { Svc } from './svc';\nnew Svc(new Api()).run();";
    let svc = "import { Api } from 'sdk';\nexport class Svc {\n  constructor(private readonly api: Api) {}\n  run(): void { this.api.send(); (this.api as Api).flush(); }\n}";
    let files = [("main.ts", src), ("svc.ts", svc)];
    expect(&analyze(&files, &["sdk::Api.send"]), "reachable", "static-path");
    expect(&analyze(&files, &["sdk::Api.flush"]), "reachable", "static-path");
    expect(&analyze(&files, &["sdk::Api.close"]), "unreachable", "no-path");
}

#[test]
fn a_type_only_import_is_no_reference() {
    let src = "import type { Parser } from 'xml';\nimport { type Doc, build } from 'xml';\nexport function f(p: Parser, d: Doc) { return 1; }\nf(null as any, null as any);";
    expect(&analyze(&[("a.ts", src)], &["xml::Parser.*"]), "unreachable", "no-path");
    expect(&analyze(&[("a.ts", src)], &["xml::Doc.*"]), "unreachable", "no-path");
}

#[test]
fn decorated_classes_and_methods_are_entry_points_because_a_framework_calls_them() {
    let src = "import { Component } from 'ng';\nimport lib from 'lib';\n@Component({})\nclass C { ngOnInit() { lib.go(); } }\nclass D { @Listen('x') on() { lib.stop(); } plain() { lib.skip(); } }\nnew D().plain;";
    let out = analyze(&[("c.ts", src)], &["lib::go"]);
    expect(&out, "reachable", "static-path");
    expect(&analyze(&[("c.ts", src)], &["lib::stop"]), "reachable", "static-path");
    assert!(out["entrypoints"].as_array().unwrap().iter().any(|e| e["kind"] == "framework"));
}

#[test]
fn tsx_components_are_calls() {
    let files = [
        ("app.tsx", "import { Widget } from './widget';\nexport const App = () => <div><Widget /></div>;\nApp();"),
        ("widget.tsx", "import lib from 'lib';\nexport function Widget() { lib.render(); return <span/>; }"),
    ];
    expect(&analyze(&files, &["lib::render"]), "reachable", "static-path");
}

#[test]
fn a_getter_is_reached_by_reading_the_property() {
    let src = "import lib from 'lib';\nclass A { get value() { return lib.read(); } }\nconst a = new A();\nconsole.log(a.value);";
    expect(&analyze(&[("a.js", src)], &["lib::read"]), "possibly-reachable", "dynamic-path");
}

#[test]
fn imports_that_may_be_project_code_that_was_not_found_make_the_answer_unknown() {
    // A path alias: `@/lib/x` is probably a file of the project that this analysis cannot resolve.
    let out = analyze(&[("a.ts", "import { x } from '@/lib/x';\nimport lib from 'lib';\nx();\nlib.go();")], &["lib::stop"]);
    expect(&out, "unknown", "incomplete-analysis");
    assert!(out["diagnostics"].as_array().unwrap().iter().any(|d| d["message"].as_str().unwrap().contains("not followed")));

    // A relative import of a missing file.
    expect(&analyze(&[("a.js", "const x = require('./missing');\nx();")], &["lib::go"]), "unknown", "incomplete-analysis");

    // A tsconfig path alias.
    let files = [
        ("tsconfig.json", "{ \"compilerOptions\": { \"paths\": { \"@app/*\": [\"src/*\"] } } /* comment */, }"),
        ("a.ts", "import { x } from '@app/x';\nx();"),
    ];
    expect(&analyze(&files, &["lib::go"]), "unknown", "incomplete-analysis");
}

#[test]
fn a_sibling_workspace_package_is_project_code_and_not_a_dependency() {
    let files = [
        ("package.json", "{ \"name\": \"root\" }"),
        ("packages/shared/package.json", "{ \"name\": \"@org/shared\" }"),
        ("app/main.js", "const s = require('@org/shared');\ns.go();"),
    ];
    expect(&analyze(&files, &["lib::go"]), "unknown", "incomplete-analysis");
}

#[test]
fn json_and_style_imports_are_not_code() {
    let files = [
        ("a.js", "const data = require('./data.json');\nimport './style.css';\nconst lib = require('lib');\nlib.go(data);"),
        ("data.json", "{}"),
        ("style.css", "a{}"),
    ];
    expect(&analyze(&files, &["lib::go"]), "reachable", "static-path");
}

#[test]
fn a_file_the_parser_cannot_read_and_a_framework_component_make_the_answer_unknown() {
    let broken = analyze(&[("a.js", "const lib = require('lib');\nfunction ( {"), ("b.js", "console.log(1);")], &["lib::go"]);
    expect(&broken, "unknown", "incomplete-analysis");
    assert_eq!(broken["stats"]["filesWithErrors"], 1);

    let vue = analyze(&[("a.js", "console.log(1);"), ("Comp.vue", "<script>import lib from 'lib'; lib.go();</script>")], &["lib::go"]);
    expect(&vue, "unknown", "incomplete-analysis");
    assert!(vue["diagnostics"].as_array().unwrap().iter().any(|d| d["message"].as_str().unwrap().contains("single-file component")));
}

#[test]
fn node_modules_and_declaration_files_are_not_analyzed() {
    let files =
        [("a.js", "console.log(1);"), ("node_modules/pkg/index.js", "require('lib').go();"), ("types.d.ts", "declare const x: number;")];
    let out = analyze(&files, &["lib::go"]);
    expect(&out, "unreachable", "no-path");
    assert_eq!(out["stats"]["files"], 1);
}

#[test]
fn the_output_is_deterministic_and_identifies_what_was_read() {
    let files = [("a.js", "const lib = require('lib');\nlib.go();"), ("b.ts", "export const x: number = 1;")];
    let a = analyze(&files, &["lib::go"]);
    let b = analyze(&files, &["lib::go"]);
    assert_eq!(a, b);
    assert_eq!(a["sourceDigest"].as_str().unwrap().len(), 64);
    assert_eq!(a["stats"]["files"], 2);
}

#[test]
fn invalid_symbols_and_unknown_languages_are_refused() {
    for symbol in ["lodash", "../x::y", "pkg::", "pkg::1a", "pkg::a..b", "pkg::*.a", "::x", "pkg::a b"] {
        let project = Project::new(&[("a.js", "1;")]);
        let request = json!({ "schemaVersion": 1, "language": "javascript", "root": project.dir.to_string_lossy(), "targets": [{ "key": "t", "symbols": [symbol], "complete": true }] });
        let (code, _, err) = run_raw(&request);
        assert_eq!(code, 2, "'{symbol}' should be refused: {err}");
        assert!(err.contains("invalid JavaScript symbol"), "{err}");
    }
    let project = Project::new(&[("a.js", "1;")]);
    let request = json!({ "schemaVersion": 1, "language": "cobol", "root": project.dir.to_string_lossy(), "targets": [] });
    let (code, _, err) = run_raw(&request);
    assert_eq!(code, 2);
    assert!(err.contains("unknown language"), "{err}");
}

#[test]
fn deep_nesting_is_reported_not_a_crash() {
    let deep = format!("const lib = require('lib');\nlib.go({}{}{});", "[".repeat(2000), "1", "]".repeat(2000));
    let out = analyze(&[("a.js", deep.as_str())], &["lib::stop"]);
    let (l, _) = label(&out);
    assert!(l == "unknown" || l == "unreachable", "{l}");
}

#[test]
fn a_workspace_package_is_followed_into_its_sources_through_main_a_source_folder_and_subpaths() {
    let files = [
        ("package.json", "{ \"name\": \"root\" }"),
        ("packages/shared/package.json", "{ \"name\": \"@org/shared\", \"main\": \"dist/index.js\" }"),
        ("packages/shared/src/index.ts", "import lib from 'lib';\nexport function go() { lib.go(); }"),
        ("packages/shared/src/extra.ts", "import lib from 'lib';\nexport function extra() { lib.extra(); }"),
        ("app/main.ts", "import { go } from '@org/shared';\nimport { extra } from '@org/shared/src/extra';\ngo();\nextra();"),
    ];
    // `main` points at a build folder that is not in the repository: the sources it stands for are used.
    expect(&analyze(&files, &["lib::go"]), "reachable", "static-path");
    expect(&analyze(&files, &["lib::extra"]), "reachable", "static-path");
}

#[test]
fn requiring_the_project_directory_resolves_to_its_main_or_index() {
    let files = [
        ("package.json", "{ \"name\": \"p\", \"main\": \"./lib/p.js\" }"),
        ("lib/p.js", "const x = require('x');\nmodule.exports = { go() { x.go(); } };"),
        ("test/t.js", "const p = require('..');\np.go();"),
    ];
    expect(&analyze(&files, &["x::go"]), "reachable", "static-path");
    let index = [("index.js", "const x = require('x');\nexports.go = () => x.go();"), ("test/t.js", "require('../').go();")];
    expect(&analyze(&index, &["x::go"]), "reachable", "static-path");
}

#[test]
fn a_value_of_a_package_that_a_module_exposes_counts_as_used_by_whoever_imports_it() {
    let cases = [
        "const bp = require('body-parser');\nexports.json = bp.json;",
        "const bp = require('body-parser');\nmodule.exports = { json: bp.json };",
        "const bp = require('body-parser');\nconst { json } = bp;\nmodule.exports = { json };",
        "import bp from 'body-parser';\nexport const json = bp.json;",
        "import bp from 'body-parser';\nexport default bp.json;",
        "export { json } from 'body-parser';",
    ];
    for src in cases {
        expect(&analyze(&[("lib.js", src)], &["body-parser::json"]), "possibly-reachable", "dynamic-path");
    }
    // Only what is exposed: another member of the package stays unused.
    expect(&analyze(&[("lib.js", cases[0])], &["body-parser::urlencoded"]), "unreachable", "no-path");
}

#[test]
fn exposing_a_whole_package_or_passing_the_module_on_reaches_all_of_its_symbols() {
    for src in [
        "module.exports = require('lodash');",
        "export * from 'lodash';",
        "const _ = require('lodash');\nregister(_);",
        "import _ from 'lodash';\nexport default _;",
    ] {
        expect(&analyze(&[("lib.js", src)], &["lodash::template"]), "possibly-reachable", "dynamic-path");
    }
}

#[test]
fn an_alias_of_a_package_member_that_is_never_called_or_exposed_is_not_a_use() {
    expect(
        &analyze(&[("a.js", "const bp = require('body-parser');\nconst json = bp.json;\nconsole.log(1);")], &["body-parser::json"]),
        "unreachable",
        "no-path",
    );
}
