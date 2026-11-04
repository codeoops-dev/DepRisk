//! End-to-end tests: real C# sources in a temporary directory, a request on stdin, the labels on stdout.
//! Each test states what is being claimed about reachability and why.

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
        let dir = std::env::temp_dir().join(format!("deprisk-reach-{}-{}", std::process::id(), COUNTER.fetch_add(1, Ordering::SeqCst)));
        std::fs::create_dir_all(&dir).unwrap();
        for (name, content) in files {
            let path = dir.join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, content).unwrap();
        }
        Project { dir }
    }

    fn request(&self, targets: Value, entrypoints: Value) -> Value {
        json!({ "schemaVersion": 1, "root": self.dir.to_string_lossy(), "entrypoints": entrypoints, "targets": targets })
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

fn analyze(files: &[(&str, &str)], symbols: &[&str], complete: bool) -> Value {
    analyze_with(files, symbols, complete, json!({ "mode": "auto" }))
}

fn analyze_with(files: &[(&str, &str)], symbols: &[&str], complete: bool, entrypoints: Value) -> Value {
    let project = Project::new(files);
    let request = project.request(json!([{ "key": "t", "symbols": symbols, "complete": complete }]), entrypoints);
    let (code, out, err) = run_raw(&request);
    assert_eq!(code, 0, "analyzer failed: {err}");
    out
}

fn label(out: &Value) -> (&str, &str) {
    let r = &out["results"][0];
    (r["label"].as_str().unwrap(), r["reason"].as_str().unwrap())
}

const JSON_SYM: &str = "Newtonsoft.Json.JsonConvert.DeserializeObject";

#[test]
fn a_call_through_a_using_is_reachable_with_a_static_path() {
    let out = analyze(
        &[("Program.cs", "using Newtonsoft.Json;\nclass P { static void Main() {\n var x = JsonConvert.DeserializeObject(\"{}\");\n } }")],
        &[JSON_SYM],
        true,
    );
    assert_eq!(label(&out), ("reachable", "static-path"));
    let path = out["results"][0]["path"].as_array().unwrap();
    assert_eq!(path.len(), 1);
    assert_eq!(path[0]["from"], "P.Main");
    assert_eq!(path[0]["to"], JSON_SYM);
    assert_eq!(path[0]["kind"], "static");
    assert_eq!(path[0]["file"], "Program.cs");
    assert_eq!(path[0]["line"], 3);
    assert_eq!(out["results"][0]["symbol"], JSON_SYM);
}

#[test]
fn a_fully_qualified_call_needs_no_using() {
    let out =
        analyze(&[("P.cs", "class P { static void Main() { Newtonsoft.Json.JsonConvert.DeserializeObject(\"x\"); } }")], &[JSON_SYM], true);
    assert_eq!(label(&out), ("reachable", "static-path"));
}

#[test]
fn aliases_for_a_type_and_for_a_namespace_are_followed() {
    let by_type = analyze(
        &[("P.cs", "using J = Newtonsoft.Json.JsonConvert;\nclass P { static void Main() { J.DeserializeObject(\"x\"); } }")],
        &[JSON_SYM],
        true,
    );
    let by_namespace = analyze(
        &[("P.cs", "using J = Newtonsoft.Json;\nclass P { static void Main() { J.JsonConvert.DeserializeObject(\"x\"); } }")],
        &[JSON_SYM],
        true,
    );
    assert_eq!(label(&by_type), ("reachable", "static-path"));
    assert_eq!(label(&by_namespace), ("reachable", "static-path"));
}

#[test]
fn global_usings_and_using_static_apply_to_every_file() {
    let global = analyze(
        &[("G.cs", "global using Newtonsoft.Json;"), ("P.cs", "class P { static void Main() { JsonConvert.DeserializeObject(\"x\"); } }")],
        &[JSON_SYM],
        true,
    );
    let static_using = analyze(
        &[("P.cs", "using static Newtonsoft.Json.JsonConvert;\nclass P { static void Main() { DeserializeObject(\"x\"); } }")],
        &[JSON_SYM],
        true,
    );
    assert_eq!(label(&global), ("reachable", "static-path"));
    assert_eq!(label(&static_using), ("reachable", "static-path"));
}

#[test]
fn instance_calls_are_resolved_by_declared_and_inferred_types() {
    let sym = "Lib.Parser.Parse";
    let var_new = analyze(&[("P.cs", "using Lib;\nclass P { static void Main() { var p = new Parser(); p.Parse(1); } }")], &[sym], true);
    let declared = analyze(&[("P.cs", "using Lib;\nclass P { static void Main() { Parser p = Make(); p.Parse(1); } }")], &[sym], true);
    let parameter = analyze(
        &[("P.cs", "using Lib;\nclass P { static void Main() { Do(null); } static void Do(Parser p) { p.Parse(1); } }")],
        &[sym],
        true,
    );
    let cast = analyze(&[("P.cs", "using Lib;\nclass P { static void Main() { ((Parser)o).Parse(1); } }")], &[sym], true);
    let field = analyze(
        &[("P.cs", "using Lib;\nclass P { private readonly Parser _p = new Parser(); void Run() { _p.Parse(1); } static void Main() { new P().Run(); } }")],
        &[sym],
        true,
    );
    for (name, out) in [("var new", var_new), ("declared", declared), ("parameter", parameter), ("cast", cast), ("field", field)] {
        assert_eq!(label(&out), ("reachable", "static-path"), "{name}");
    }
}

#[test]
fn a_constructor_a_property_and_a_wildcard_are_symbols_too() {
    let ctor = analyze(&[("P.cs", "using Lib;\nclass P { static void Main() { new Parser(); } }")], &["Lib.Parser.#ctor"], true);
    let property = analyze(
        &[("P.cs", "using Lib;\nclass P { static void Main() { Config c = null; var v = c.Value; } }")],
        &["Lib.Config.Value"],
        true,
    );
    let initializer = analyze(
        &[("P.cs", "using Lib;\nclass P { static void Main() { var c = new Config { Value = 1 }; } }")],
        &["Lib.Config.Value"],
        true,
    );
    let wildcard =
        analyze(&[("P.cs", "using Lib;\nclass P { static void Main() { Parser p = null; p.Anything(); } }")], &["Lib.Parser.*"], true);
    for (name, out) in [("ctor", ctor), ("property", property), ("initializer", initializer), ("wildcard", wildcard)] {
        assert_eq!(label(&out), ("reachable", "static-path"), "{name}");
    }
}

#[test]
fn a_chain_of_project_methods_is_followed_and_the_path_is_the_shortest() {
    let out = analyze(
        &[(
            "P.cs",
            "using Newtonsoft.Json;\nnamespace App {\n class P { static void Main() { new A().Go(); } }\n class A { public void Go() { B.Step(); } }\n static class B { public static void Step() { JsonConvert.DeserializeObject(\"x\"); } }\n}",
        )],
        &[JSON_SYM],
        true,
    );
    assert_eq!(label(&out), ("reachable", "static-path"));
    let path: Vec<(String, String)> = out["results"][0]["path"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| (e["from"].as_str().unwrap().to_string(), e["to"].as_str().unwrap().to_string()))
        .collect();
    assert_eq!(
        path,
        vec![
            ("App.P.Main".to_string(), "App.A.Go".to_string()),
            ("App.A.Go".to_string(), "App.B.Step".to_string()),
            ("App.B.Step".to_string(), JSON_SYM.to_string()),
        ]
    );
}

#[test]
fn code_nothing_calls_is_unreachable_only_if_the_symbol_list_is_complete() {
    let files = [(
        "P.cs",
        "using Newtonsoft.Json;\nclass P { static void Main() { } static void Dead() { JsonConvert.DeserializeObject(\"x\"); } }",
    )];
    assert_eq!(label(&analyze(&files, &[JSON_SYM], true)), ("unreachable", "no-path"));
    assert_eq!(label(&analyze(&files, &[JSON_SYM], false)), ("unknown", "symbol-list-incomplete"));
}

#[test]
fn a_call_on_an_unknown_receiver_is_a_dynamic_edge_when_the_type_is_imported() {
    let out = analyze(
        &[("P.cs", "using Lib;\nclass P { static void Main() { var p = Factory.Create(); p.Parse(1); } }")],
        &["Lib.Parser.Parse"],
        true,
    );
    assert_eq!(label(&out), ("possibly-reachable", "dynamic-path"));
    assert_eq!(out["results"][0]["path"][0]["kind"], "dynamic");
}

#[test]
fn a_call_on_an_unknown_receiver_in_a_file_that_never_names_the_type_is_unknown_not_unreachable() {
    // The value may have flowed in from another library without the type ever being named here. Saying "unreachable" would be a guess.
    let out = analyze(&[("P.cs", "class P { static void Main() { var p = Make(); p.Parse(1); } }")], &["Lib.Parser.Parse"], true);
    assert_eq!(label(&out), ("unknown", "unresolved-receiver"));
}

#[test]
fn an_unrelated_member_with_a_different_name_does_not_make_anything_unknown() {
    let out = analyze(&[("P.cs", "class P { static void Main() { var p = Make(); p.Other(1); } }")], &["Lib.Parser.Parse"], true);
    assert_eq!(label(&out), ("unreachable", "no-path"));
}

#[test]
fn interface_and_virtual_dispatch_add_dynamic_edges_to_every_implementation() {
    let interface = analyze(
        &[(
            "P.cs",
            "using Newtonsoft.Json;\ninterface IRunner { void Run(); }\nclass R : IRunner { public void Run() { JsonConvert.DeserializeObject(\"x\"); } }\nclass P { static void Main() { IRunner r = new R(); r.Run(); } }",
        )],
        &[JSON_SYM],
        true,
    );
    let virtual_call = analyze(
        &[(
            "P.cs",
            "using Newtonsoft.Json;\nclass B { public virtual void Run() { } }\nclass D : B { public override void Run() { JsonConvert.DeserializeObject(\"x\"); } }\nclass P { static void Main() { B b = new D(); b.Run(); } }",
        )],
        &[JSON_SYM],
        true,
    );
    assert_eq!(label(&interface), ("possibly-reachable", "dynamic-path"));
    assert_eq!(label(&virtual_call), ("possibly-reachable", "dynamic-path"));
}

#[test]
fn a_concrete_receiver_is_a_static_edge_even_if_the_method_is_not_virtual() {
    let out = analyze(
        &[(
            "P.cs",
            "using Newtonsoft.Json;\nclass R { public void Run() { JsonConvert.DeserializeObject(\"x\"); } }\nclass P { static void Main() { R r = new R(); r.Run(); } }",
        )],
        &[JSON_SYM],
        true,
    );
    assert_eq!(label(&out), ("reachable", "static-path"));
}

#[test]
fn entrypoints_top_level_statements_controllers_and_hosted_services() {
    let top = analyze(&[("P.cs", "using Newtonsoft.Json;\nJsonConvert.DeserializeObject(\"x\");")], &[JSON_SYM], true);
    assert_eq!(label(&top), ("reachable", "static-path"));
    assert_eq!(top["entrypoints"][0]["kind"], "top-level");

    let controller = analyze(
        &[("C.cs", "using Newtonsoft.Json;\nclass OrdersController : ControllerBase { public object Get() { return JsonConvert.DeserializeObject(\"x\"); } private void Hidden() { } }")],
        &[JSON_SYM],
        true,
    );
    assert_eq!(label(&controller), ("reachable", "static-path"));
    assert_eq!(controller["entrypoints"][0]["kind"], "controller");

    let hosted = analyze(
        &[("W.cs", "using Newtonsoft.Json;\nclass Worker : BackgroundService { protected override Task ExecuteAsync(CancellationToken t) { JsonConvert.DeserializeObject(\"x\"); return null; } }")],
        &[JSON_SYM],
        true,
    );
    assert_eq!(label(&hosted), ("reachable", "static-path"));
}

#[test]
fn a_private_controller_method_is_not_an_entrypoint() {
    let out = analyze(
        &[("C.cs", "using Newtonsoft.Json;\nclass OrdersController : ControllerBase { private void Hidden() { JsonConvert.DeserializeObject(\"x\"); } public void Get() { } }")],
        &[JSON_SYM],
        true,
    );
    assert_eq!(label(&out), ("unreachable", "no-path"));
}

#[test]
fn no_entrypoints_is_unknown_and_a_library_can_name_its_public_api() {
    let files = [("L.cs", "using Newtonsoft.Json;\npublic class Lib { public void Api() { JsonConvert.DeserializeObject(\"x\"); } }")];
    assert_eq!(label(&analyze(&files, &[JSON_SYM], true)), ("unknown", "no-entrypoints"));

    let public_api = analyze_with(&files, &[JSON_SYM], true, json!({ "mode": "public-api" }));
    assert_eq!(label(&public_api), ("reachable", "static-path"));
    assert_eq!(public_api["entrypoints"][0]["kind"], "public-api");

    let internal = analyze_with(
        &[("L.cs", "using Newtonsoft.Json;\ninternal class Lib { public void Api() { JsonConvert.DeserializeObject(\"x\"); } }")],
        &[JSON_SYM],
        true,
        json!({ "mode": "public-api" }),
    );
    assert_eq!(label(&internal), ("unknown", "no-entrypoints"));
}

#[test]
fn explicit_entrypoints_by_name_and_by_type() {
    let files = [(
        "W.cs",
        "using Newtonsoft.Json;\nnamespace App { class Worker { public void Run() { JsonConvert.DeserializeObject(\"x\"); } } }",
    )];
    let by_method = analyze_with(&files, &[JSON_SYM], true, json!({ "mode": "none", "explicit": ["App.Worker.Run"] }));
    let by_type = analyze_with(&files, &[JSON_SYM], true, json!({ "mode": "none", "explicit": ["App.Worker.*"] }));
    let missing = analyze_with(&files, &[JSON_SYM], true, json!({ "mode": "none", "explicit": ["App.Nope.Run"] }));
    assert_eq!(label(&by_method), ("reachable", "static-path"));
    assert_eq!(label(&by_type), ("reachable", "static-path"));
    assert_eq!(label(&missing), ("unknown", "no-entrypoints"));
    assert!(missing["diagnostics"][0]["message"].as_str().unwrap().contains("matches no method"));
}

#[test]
fn reflection_that_cannot_be_read_makes_a_missing_path_unknown() {
    let unresolved = analyze(
        &[("P.cs", "class P { static void Main(string[] a) { var t = System.Type.GetType(a[0]); System.Activator.CreateInstance(t); } }")],
        &[JSON_SYM],
        true,
    );
    assert_eq!(label(&unresolved), ("unknown", "unresolved-reflection"));
    assert_eq!(unresolved["stats"]["reflectionSites"], 2);
}

#[test]
fn reflection_by_a_string_that_names_the_type_is_a_dynamic_edge() {
    let out =
        analyze(&[("P.cs", "class P { static void Main() { System.Type.GetType(\"Newtonsoft.Json.JsonConvert\"); } }")], &[JSON_SYM], true);
    assert_eq!(label(&out), ("possibly-reachable", "dynamic-path"));
}

#[test]
fn reflection_by_typeof_names_the_type_and_harmless_reflection_changes_nothing() {
    let named = analyze(
        &[("P.cs", "using Newtonsoft.Json;\nclass P { static void Main() { typeof(JsonConvert).GetMethod(\"DeserializeObject\"); } }")],
        &[JSON_SYM],
        true,
    );
    assert_eq!(label(&named), ("possibly-reachable", "dynamic-path"));

    // obj.GetType() reads the runtime type; a literal that names something else is no reason to doubt.
    let harmless = analyze(
        &[("P.cs", "class P { static void Main() { var t = new object().GetType(); System.Type.GetType(\"System.String\"); } }")],
        &[JSON_SYM],
        true,
    );
    assert_eq!(label(&harmless), ("unreachable", "no-path"));
}

#[test]
fn reflection_in_code_nothing_calls_does_not_matter() {
    let out = analyze(
        &[(
            "P.cs",
            "class P { static void Main() { } static void Dead(string n) { System.Activator.CreateInstance(System.Type.GetType(n)); } }",
        )],
        &[JSON_SYM],
        true,
    );
    assert_eq!(label(&out), ("unreachable", "no-path"));
}

#[test]
fn a_file_the_parser_cannot_read_makes_a_missing_path_unknown() {
    let out = analyze(&[("P.cs", "class P { static void Main() { } }"), ("Broken.cs", "class { { { namespace ((( ; ;")], &[JSON_SYM], true);
    assert_eq!(label(&out), ("unknown", "incomplete-analysis"));
    assert_eq!(out["stats"]["filesWithErrors"], 1);
    assert_eq!(out["diagnostics"][0]["file"], "Broken.cs");
}

#[test]
fn a_project_type_shadows_an_external_type_of_the_same_name() {
    let out = analyze(
        &[("P.cs", "namespace My {\n class JsonConvert { public static void DeserializeObject(string s) { } }\n class P { static void Main() { JsonConvert.DeserializeObject(\"x\"); } }\n}")],
        &[JSON_SYM],
        true,
    );
    assert_eq!(label(&out), ("unreachable", "no-path"));
}

#[test]
fn extension_methods_are_dynamic_edges() {
    let out = analyze(
        &[(
            "P.cs",
            "using Newtonsoft.Json;\nclass Svc { }\nstatic class Ext { public static void Go(this Svc s) { JsonConvert.DeserializeObject(\"x\"); } }\nclass P { static void Main() { var s = new Svc(); s.Go(); } }",
        )],
        &[JSON_SYM],
        true,
    );
    assert_eq!(label(&out), ("possibly-reachable", "dynamic-path"));
}

#[test]
fn lambdas_and_local_functions_belong_to_their_enclosing_method() {
    let lambda = analyze(
        &[("P.cs", "using Newtonsoft.Json;\nclass P { static void Main() { Run(() => JsonConvert.DeserializeObject(\"x\")); } static void Run(System.Action a) { } }")],
        &[JSON_SYM],
        true,
    );
    let local = analyze(
        &[(
            "P.cs",
            "using Newtonsoft.Json;\nclass P { static void Main() { void Inner() { JsonConvert.DeserializeObject(\"x\"); } Inner(); } }",
        )],
        &[JSON_SYM],
        true,
    );
    assert_eq!(label(&lambda), ("reachable", "static-path"));
    assert_eq!(label(&local), ("reachable", "static-path"));
}

#[test]
fn a_method_passed_as_a_value_is_a_dynamic_edge() {
    let out = analyze(
        &[(
            "P.cs",
            "using Newtonsoft.Json;\nclass P { static void Main() { Subscribe(Handler); } static void Handler() { JsonConvert.DeserializeObject(\"x\"); } static void Subscribe(System.Action a) { } }",
        )],
        &[JSON_SYM],
        true,
    );
    assert_eq!(label(&out), ("possibly-reachable", "dynamic-path"));
}

#[test]
fn conditional_access_and_await_do_not_hide_calls() {
    let out = analyze(
        &[("P.cs", "using Lib;\nclass P { static async void Main() { Parser p = null; p?.Parse(1); await Task.Delay(1); } }")],
        &["Lib.Parser.Parse"],
        true,
    );
    assert_eq!(label(&out), ("reachable", "static-path"));
}

#[test]
fn deriving_from_a_type_the_request_names_counts_once_the_derived_type_is_used() {
    let out = analyze(
        &[("P.cs", "using Newtonsoft.Json;\nclass MyConverter : JsonConverter { }\nclass P { static void Main() { new MyConverter(); } }")],
        &["Newtonsoft.Json.JsonConverter.*"],
        true,
    );
    assert_eq!(label(&out), ("reachable", "static-path"));
}

#[test]
fn static_initializers_run_with_their_type() {
    let out = analyze(
        &[(
            "P.cs",
            "using Newtonsoft.Json;\nclass P { static readonly object O = JsonConvert.DeserializeObject(\"x\"); static void Main() { } }",
        )],
        &[JSON_SYM],
        true,
    );
    assert_eq!(label(&out), ("reachable", "static-path"));
}

#[test]
fn indexers_and_operators_are_reachable_only_in_the_over_approximation() {
    let out = analyze(
        &[(
            "P.cs",
            "using Newtonsoft.Json;\nclass Bag { public object this[int i] { get { return JsonConvert.DeserializeObject(\"x\"); } } }\nclass P { static void Main() { } }",
        )],
        &[JSON_SYM],
        true,
    );
    assert_eq!(label(&out), ("possibly-reachable", "dynamic-path"));
}

#[test]
fn file_scoped_and_nested_namespaces_give_the_methods_their_full_names() {
    let out = analyze(
        &[("P.cs", "using Newtonsoft.Json;\nnamespace My.App;\nclass P { static void Main() { JsonConvert.DeserializeObject(\"x\"); } }")],
        &[JSON_SYM],
        true,
    );
    assert_eq!(out["entrypoints"][0]["method"], "My.App.P.Main");
}

#[test]
fn build_output_and_hidden_tool_directories_are_not_analyzed() {
    let out = analyze(
        &[
            ("P.cs", "class P { static void Main() { } }"),
            ("obj/Debug/Gen.cs", "using Newtonsoft.Json;\nclass G { static void Main() { JsonConvert.DeserializeObject(\"x\"); } }"),
            ("bin/X.cs", "class X { static void Main() { } }"),
        ],
        &[JSON_SYM],
        true,
    );
    assert_eq!(label(&out), ("unreachable", "no-path"));
    assert_eq!(out["stats"]["files"], 1);
}

#[cfg(unix)]
#[test]
fn symbolic_links_are_never_followed() {
    let project = Project::new(&[("P.cs", "class P { static void Main() { } }")]);
    let outside =
        Project::new(&[("Evil.cs", "using Newtonsoft.Json;\nclass E { static void Main() { JsonConvert.DeserializeObject(\"x\"); } }")]);
    std::os::unix::fs::symlink(outside.dir.join("Evil.cs"), project.dir.join("Link.cs")).unwrap();
    std::os::unix::fs::symlink(&outside.dir, project.dir.join("linked-dir")).unwrap();

    let (code, out, _) =
        run_raw(&project.request(json!([{ "key": "t", "symbols": [JSON_SYM], "complete": true }]), json!({ "mode": "auto" })));

    assert_eq!(code, 0);
    assert_eq!(label(&out), ("unreachable", "no-path"));
    assert_eq!(out["stats"]["files"], 1);
    assert!(out["stats"]["filesSkipped"].as_u64().unwrap() >= 2);
}

#[test]
fn hostile_depth_does_not_crash_and_is_never_claimed_unreachable() {
    let nested = format!("class P {{ static void Main() {{ var x = {}1{}; }} }}", "(".repeat(3000), ")".repeat(3000));
    let out = analyze(&[("P.cs", &nested)], &[JSON_SYM], true);
    let (l, reason) = label(&out);
    assert_eq!(l, "unknown", "reason: {reason}");
}

#[test]
fn oversized_files_are_skipped_and_reported_so_the_result_is_unknown() {
    let project = Project::new(&[("P.cs", "class P { static void Main() { } }"), ("Big.cs", &"// padding\n".repeat(1000))]);
    let mut request = project.request(json!([{ "key": "t", "symbols": [JSON_SYM], "complete": true }]), json!({ "mode": "auto" }));
    request["limits"] = json!({ "maxFileBytes": 100 });
    let (code, out, _) = run_raw(&request);
    assert_eq!(code, 0);
    assert_eq!(label(&out), ("unknown", "incomplete-analysis"));
    assert_eq!(out["stats"]["filesSkipped"], 1);
}

#[test]
fn several_targets_share_symbols_and_keep_their_own_keys() {
    let project = Project::new(&[("P.cs", "using Lib;\nclass P { static void Main() { Parser p = null; p.Parse(1); } }")]);
    let request = project.request(
        json!([
            { "key": "a", "symbols": ["Lib.Parser.Parse"], "complete": true },
            { "key": "b", "symbols": ["Lib.Parser.Parse", "Lib.Other.Do"], "complete": true },
            { "key": "c", "symbols": ["Lib.Other.Do"], "complete": true },
            { "key": "d", "symbols": [], "complete": true }
        ]),
        json!({ "mode": "auto" }),
    );
    let (code, out, _) = run_raw(&request);
    assert_eq!(code, 0);
    let results = out["results"].as_array().unwrap();
    let get = |key: &str| {
        results
            .iter()
            .find(|r| r["key"] == key)
            .map(|r| (r["label"].as_str().unwrap().to_string(), r["reason"].as_str().unwrap().to_string()))
            .unwrap()
    };
    assert_eq!(get("a"), ("reachable".to_string(), "static-path".to_string()));
    assert_eq!(get("b"), ("reachable".to_string(), "static-path".to_string()));
    assert_eq!(get("c"), ("unreachable".to_string(), "no-path".to_string()));
    assert_eq!(get("d"), ("unknown".to_string(), "no-symbols".to_string()));
}

#[test]
fn the_output_is_deterministic() {
    let project = Project::new(&[
        ("B.cs", "using Lib;\nclass B { public void Go() { new Parser().Parse(1); } }"),
        ("A.cs", "class A { static void Main() { new B().Go(); } }"),
    ]);
    let request = project.request(json!([{ "key": "t", "symbols": ["Lib.Parser.Parse"], "complete": true }]), json!({ "mode": "auto" }));
    let first = run_raw(&request).1;
    let second = run_raw(&request).1;
    assert_eq!(first, second);
    assert_eq!(first["analyzer"]["name"], "deprisk-reach");
}

#[test]
fn invalid_requests_are_rejected_with_exit_code_2() {
    let project = Project::new(&[("P.cs", "class P { }")]);
    let good = project.request(json!([{ "key": "t", "symbols": [JSON_SYM], "complete": true }]), json!({ "mode": "auto" }));

    let mut wrong_version = good.clone();
    wrong_version["schemaVersion"] = json!(2);
    let mut bad_mode = good.clone();
    bad_mode["entrypoints"] = json!({ "mode": "everything" });
    let bad_symbol = project.request(json!([{ "key": "t", "symbols": ["NoMember"], "complete": true }]), json!({ "mode": "auto" }));
    let bad_chars = project.request(json!([{ "key": "t", "symbols": ["A.B C"], "complete": true }]), json!({ "mode": "auto" }));
    let mut missing_root = good.clone();
    missing_root["root"] = json!("/definitely/not/here");
    let mut file_root = good.clone();
    file_root["root"] = json!(project.dir.join("P.cs").to_string_lossy());

    for (name, request) in [
        ("version", wrong_version),
        ("mode", bad_mode),
        ("symbol", bad_symbol),
        ("chars", bad_chars),
        ("root", missing_root),
        ("file root", file_root),
    ] {
        let (code, _, err) = run_raw(&request);
        assert_eq!(code, 2, "{name}: {err}");
        assert!(err.starts_with("deprisk-reach:"), "{name}: {err}");
    }
}

#[test]
fn garbage_on_stdin_is_rejected_with_exit_code_2() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_deprisk-reach"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"not json").unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(2));
}
