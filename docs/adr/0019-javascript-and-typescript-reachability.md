# ADR 0019: Reachability for JavaScript and TypeScript

- **Status:** Accepted
- **Date:** 2026-11-10

## Context

ADR 0012 built the reachability analyzer for C# and left the protocol open to other languages. The npm ecosystem is the other half of the product (`scan`, `match`, `rank`, `ci` already read `package-lock.json`), and without reachability every npm finding stays at the baseline. JavaScript is harder than C# for this purpose: calls go through values (callbacks, `module.exports` objects, `this`), imports are dynamic by nature (`require(x)`), and there is no type checker we can run offline and deterministically. TypeScript adds declared types, which help, and decorators and dependency injection, which hide calls.

The rule of ADR 0012 does not change: **`unreachable` is said only when nothing could hide a path; everything the analysis cannot see makes the answer `unknown`, never `unreachable`.** What changes is how much there is to see, and so how often the honest answer is weaker than for C#.

## Decision

**One analyzer, one protocol, a second front end.** The request gets an optional `language` (`csharp`, the default, or `javascript`, which covers JavaScript and TypeScript). The call graph, the edges (`static`, `dynamic`), the kinds of uncertainty, and the labeling are the code C# already uses; only what is read from the sources is new. The grammars are tree-sitter-javascript (including JSX), tree-sitter-typescript, and its TSX variant; a file's extension picks one (`.js .jsx .mjs .cjs`, `.ts .mts .cts`, `.tsx`). Declaration files (`.d.ts`) and `node_modules` are not analyzed.

**What a node is.** The module itself (its top-level code runs when it is imported), every function, arrow function, and method, and for each class an initializer (field initializers and static blocks). A function's id is `path/to/file.js::name` or `path/to/file.ts::Class.method`.

**What a call resolves to.** By names, not by running anything:
- imports and exports of ES modules and CommonJS (`import`, `export … from`, `export *`, `require('literal')`, `module.exports`, `exports.x`, `import x = require()`), with relative paths resolved against the analyzed files (extensions, `index` files, `main`, and `.js` standing for `.ts`);
- local functions, classes, methods, `this`, `super`, and instances of classes (`new X()`, TypeScript annotations, parameter properties, `as` casts, class fields);
- virtual dispatch: a method called on a base type also reaches (dynamically) its overrides in subclasses;
- `call`, `apply`, `bind`; immediately invoked functions; JSX components; getters read as properties.

**What is over-approximated (edges added, never dropped).** A function used as a value (an argument, a property, a return value) gets a `dynamic` edge from where it escaped. A call on a receiver of unknown type reaches every project method of that name and, for the packages the file imports, every symbol member of that name. An instance that escapes reaches all its methods. A package value that a module exposes (`exports.json = bodyParser.json`, `export * from 'pkg'`) or a module object that is passed on counts as used, because importers can call it without a path this analysis follows.

**What makes the answer `unknown` (never `unreachable`).**
- `eval`, `new Function`, `require` or `import()` of a computed name, a call of a computed member (`x[k]()`), `Reflect.*`, and the `vm` and `module` APIs: `unresolved-reflection`.
- An import that may be project code the analyzer could not find: a path alias (`@/x`, `~/x`, `#x`, a `tsconfig` `paths` or `baseUrl` entry, a first segment that is a folder or file at the root), a package of this repository whose code is not in the analyzed files (a monorepo workspace whose `main` points at build output that is not committed), or a relative path that does not exist: `incomplete-analysis` when the importing function is reachable. A workspace package whose code is found (`main`, a `src` folder it stands for, `index`, or a subpath) is followed like any module.
- A file the parser could not read completely, a file too large, a parse timeout, a configuration that mentions path aliases but cannot be read, and framework single-file components (`.vue`, `.svelte`, `.astro`), whose scripts the analyzer does not read.
- A call on a receiver of unknown type whose member name matches a symbol of a package the file does not import: `unresolved-receiver`.

**Entry points.** In `auto` mode: the module code of every module nobody imports (scripts, servers, tests, handlers), together with everything such a module exports (a platform or a framework calls those); every class with a decorator and every method with one (a framework instantiates and calls them: Angular, Nest, and the like). In `public-api` mode: every module and everything every module exports (for libraries). `explicit`: function ids, or `file::*`.

**Symbols.** `package::path`, where `package` is the npm specifier (`lodash`, `@scope/pkg`, `pkg/sub`) and `path` the member path from the module's exports: `lodash::template`, `xml::Parser.parse`, `pkg::default`, `pkg::*` (any use of the package, including a bare import), `pkg::Type.*` (any member, and constructing or extending it). A default import of a CommonJS package also matches the member path directly (`import d from 'cjs'; d.fn()` matches `cjs::fn`), and calling the module value itself matches `default`. A symbol for a package matches a use of a subpath of it (`lodash/fp/map` for `lodash::template`) conservatively: any symbol of the package.

## Known limits

- No type checker. A receiver whose type is not declared or inferable from `new` is resolved by name, which is sound for `unreachable` (it adds edges) but often turns `reachable` into `possibly-reachable`.
- Results of calls are not tracked: a factory that returns an instance, a promise that resolves to a module, an object stored in a map. Calls on such values are resolved by name.
- `unreachable` is rare in dynamic code and in frameworks; `unknown` and `possibly-reachable` are the common weaker answers. That is the price of soundness, and the benchmark harness (ADR 0017) measures how often each label occurs and whether `unreachable` is ever wrong.
- Frameworks that call project code by convention without a decorator (file-based routing is covered only for modules nobody imports; lifecycle methods of undecorated classes, plugins found by name) are not modeled beyond that.
- The `exports` field of `package.json` (conditional exports) and TypeScript project references are not read.
- Grammar gaps (for example `typeof import('x')` as a type argument in one form) make a file unreadable, so the answer is `unknown` for the whole tree, not wrong.
- A local variable that is assigned again loses its type; block scoping inside a function is not modeled (one scope per function).

## Consequences

- npm findings can get a reachability verdict once the CLI sends them to this analyzer (a later slice: symbol maps for npm, the ecosystem switch in `reach`, `rank`, `ci`, `explain`, `vex`).
- The analyzer reads 2,300 TypeScript files in about three seconds (measured on a large open-source monorepo) and runs within the limits of ADR 0012; hostile sources are bounded by file count, file size, per-file parse time, total source size, and recursion depth.
- The labels' meaning is unchanged, so every consumer (ranking, `ci` policy, `explain`, `vex`) treats them the same way.
