# ADR 0027: NuGet lock files and npm lockfileVersion 1

- **Status:** Accepted
- **Date:** 2026-11-24

## Context

`deprisk scan` and every command built on it read two kinds of file: the NuGet `obj/project.assets.json` (written by `dotnet restore`) and the npm `package-lock.json` of lockfileVersion 2 and 3 (ADR 0010). Two common inputs were refused or not found: the NuGet `packages.lock.json`, which is committed to a repository (a fresh checkout has no `obj/`), and the npm lockfileVersion 1 written by npm 6 and older, which was rejected with a message to upgrade.

## Decision

**NuGet `packages.lock.json`, versions 1, 2 and 3.** `NuGetLockParser` reads the resolved graph the way `NuGetAssetsParser` does and returns the same model.

- Versions 1 and 2 keep the targets under `dependencies` (`net10.0`, or `net10.0/win-x64`). Version 2 adds the `CentralTransitive` type (a package pinned by central package management).
- Version 3 keeps the targets at the top level, keyed by target framework alias, each with a `framework`. As NuGet reads it, only an object with a `framework` is a target. The key is the target name, as the alias is for version 4 of the assets file.
- Types: `Direct` is direct, with its `requested` range; `Transitive` and `CentralTransitive` are installed but not asked for by the project; `Project` is a project reference and is not a package. A missing or unknown `type` is an input error. NuGet itself would treat a missing one as `Direct`; a security tool does not guess that.
- A file with no targets is an input error: NuGet always writes one per framework, so "none" means this reader did not understand the file, and "no packages" must not be the answer to that.
- Ids are not case sensitive, so two entries that differ only in case are an input error rather than one silently shadowing the other.

A lock file has no project name or path. They come from the `.csproj`, `.fsproj` or `.vbproj` beside it when there is exactly one (the name is its file name, and it is the project file findings point to), else the name is the directory name and no project file is claimed.

**One project is never counted twice.** For a project that has an assets file in its `obj` directory, the assets file is read and the `packages.lock.json` above `obj` is not: both describe the same restore. A lock file with no assets file beside it is read on its own. This also keeps the output for every tree that worked before byte for byte the same.

**npm lockfileVersion 1.** The nested `dependencies` tree becomes the same installed instances version 2 and 3 describe, with the same paths (`node_modules/a/node_modules/b`), so the hypergraph resolves requirements the way Node does. What an installed package asks for is `requires`.

- **The lock file does not say what the project asks for**, so direct and requested come from the `package.json` beside it (dependencies, devDependencies, optionalDependencies; npm 6 installed no peers). If there is none, the file is refused with a message that says what to do, rather than reporting every package as transitive: `direct` changes policy results and reachability. The package.json is part of the inputs digest when it was read, and is not read for version 2 and 3. A `package.json` that is a link is not followed.
- **A location is not copied.** For a git, tarball or file dependency the `version` field holds the location, which can carry credentials. The package is kept, with the version `unknown`, so it is counted as skipped and never matched; an alias (`npm:name@1.2.3`) is the package `name` at `1.2.3`, as in version 2 and 3.
- There are no workspaces in this format.

## Consequences

- No schema or output change; the descriptions of `projectFile` and `assetsFile` say lock files are read too.
- `scan` on a tree with both kinds of ecosystem still asks for `--ecosystem`; the message now counts `project.assets.json` and `packages.lock.json` separately.
- A previously refused input (npm lockfileVersion 1) is now accepted: one test that pinned the refusal changed.

## Known limits

- Version 3 of the NuGet lock file is read as NuGet.Client's source describes it; no file written by an SDK that produces it was available. Versions 1 and 2 are tested with files written by the SDK; the npm lockfileVersion 1 fixture is written by hand in npm 6's format.
- Only the file name `packages.lock.json` is recognized (a lock file moved by `NuGetLockFilePath` is not found unless it is passed with `--ecosystem nuget` under that name).
- If the assets file is stale and the lock file is current, the assets file wins; restore first.
- A lock file under a different layout than `<project>/packages.lock.json` with `<project>/obj/project.assets.json` can be read together with its assets file, and the project then appears twice.
- Ranges (`requires`, `dependencies`) are copied as the file has them, as for version 2 and 3.
