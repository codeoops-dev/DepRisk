# deprisk-reach

The DepRisk reachability analyzer for C#. It reads C# sources, builds a conservative call graph, and says for each requested set of symbols whether it can be reached from the application's entrypoints. See [ADR 0012](../../docs/adr/0012-reachability-analyzer.md) for the design and its limits.

It is a separate process with a JSON protocol: one request on stdin ([schema](../../schemas/reach-request.v1.schema.json)), one result on stdout ([schema](../../schemas/reach-result.v1.schema.json)). The DepRisk CLI is the intended caller; you can also run it by hand.

```bash
cargo build --release --locked
cat > request.json <<'JSON'
{
  "schemaVersion": 1,
  "root": "path/to/your/sources",
  "entrypoints": { "mode": "auto" },
  "targets": [
    {
      "key": "example",
      "symbols": ["Newtonsoft.Json.JsonConvert.DeserializeObject"],
      "complete": true
    }
  ]
}
JSON
./target/release/deprisk-reach < request.json
```

Each target gets `reachable` (with a path of static edges), `possibly-reachable`, `unreachable`, or `unknown` with the reason. `unreachable` is only ever said when nothing could hide a path; read the ADR before relying on it.

Develop: `cargo fmt --check`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo test --locked` (needs Rust 1.89 or newer).
