# SASTFileCounter

Count files in a directory tree — total, by extension, and grouped by the programming languages a given **SAST (Static Application Security Testing) tool** supports — to estimate how many files a tool like **FalconEye**, **Checkmarx SAST**, **Semgrep**, **SonarQube**, **CodeQL**, **Snyk Code**, **Veracode**, or **Fortify** would actually analyze in a repository.

No dependencies beyond the Python standard library.

## Why

Before kicking off a SAST scan (or comparing scan scope across tools / sizing a license), it's useful to know up front: _how many files in this repo will actually be analyzed, and how many will be skipped because the tool doesn't support that language?_ This script answers that in seconds, for one tool or several side by side.

## Features

- **Total file count**, count **by extension**, and count **by supported language**, for any directory tree.
- **8 built-in tool profiles** (see table below) — pick one with `--tool`, or compare several at once with `--compare`.
- **Unknown/unsupported file types are never discarded** — they're collected in a separate bucket and printed in full (not just a top-10), so nothing is silently missed. This includes hidden files/dotfiles (`.env`, `.gitignore`, …), which are counted by default.
- Sensible defaults: recurses into subdirectories, skips common noise directories (`.git`, `node_modules`, `venv`, `dist`, `build`, …), extendable with `--exclude-dir`.
- **JSON output** (`--json`) for scripting/CI pipelines.
- Easy to extend with more tools — see [Adding a new tool](https://claude.ai/cowork/cse_01FD7VVKUr9hcug6LYKmok2H#adding-a-new-tool).

## Requirements

- Python 3.7+
- No third-party packages

## Installation

Just download the script — there's nothing to install.

```bash
curl -O https://github.com/NoAuthZone/SASTFileCounter/blob/main/SASTFileCounter.py
python3 SASTFileCounter.py --help
```

## Usage

```bash
python3 SASTFileCounter.py <path> [options]
```

### Options

|Option|Description|
|---|---|
|`path`|Path to the directory to analyze (required, unless `--list-tools` is used)|
|`--tool TOOL`, `-t TOOL`|Tool profile to use. Default: `falconeye`. See `--list-tools` for all options.|
|`--list-tools`|List all available tool profiles with their languages/extensions and exit|
|`--compare TOOLS`|Comma-separated list of tool keys to run side by side, e.g. `falconeye,cxsast`|
|`--check VALUE`, `-c VALUE`|Print a separate count for one language (e.g. `python`), one extension (e.g. `.py`), or `all` for the tool's total|
|`--no-recursive`|Don't recurse into subdirectories|
|`--exclude-hidden`|Exclude hidden files/directories (`.foo`). By default they're **included**.|
|`--exclude-dir NAME`|Exclude an additional directory name (repeatable)|
|`--json`|Print output as JSON instead of a text report|

## Supported tools

|Tool key|Tool|Notes|
|---|---|---|
|`falconeye`|FalconEye|9 languages: Python, JS/TS, Go, Rust, C/C++, Java, PHP, Ruby, Dart|
|`cxsast`|Checkmarx SAST (CxSAST)|Based on Checkmarx v9.3.0 docs; verify against your version|
|`semgrep`|Semgrep|GA languages + Apex/Dart (beta)|
|`sonarqube`|SonarQube|Representative subset; some languages need specific editions|
|`codeql`|GitHub CodeQL|Most precisely sourced — extensions taken from GitHub's own docs|
|`snyk-code`|Snyk Code|Some entries are Early Access on Enterprise plans per Snyk's docs|
|`veracode`|Veracode Static Analysis|Mobile/binary-upload entries omitted (not counted by extension)|
|`fortify`|OpenText Fortify SCA|Based on a third-party summary — Fortify's own docs are version-gated PDFs|

> **Accuracy note:** these profiles are a practical approximation for file-count _estimation_, not an exact re-implementation of any vendor's file-type detector. A few tools recognize the same extension for two languages (e.g. `.vb` for both VB6 and VB.NET, `.cls` for both VB6 and Apex); since a file can only be counted once, each such extension is assigned to one "primary" language (documented in the script's comments). For capacity/licensing decisions, verify against your vendor's current documentation.

Run `--list-tools` to see the full, current language → extension mapping for every profile.

## Examples

Basic scan with the default tool (FalconEye):

```bash
$ python3 SASTFileCounter.py ./my-repo
Directory: /home/user/my-repo
Tool: FalconEye
Total files: 7

=== By FalconEye language ===
  Python                    1
  JavaScript/TypeScript     1
  Go                        1
  Rust                      0
  C/C++                     0
  Java                      1
  PHP                       0
  Ruby                      1
  Dart                      0
  -----------------------------------
  TOTAL (FalconEye-relevant) 5

Not supported by FalconEye: 2 files (2 distinct type(s))
    .md                  1
    .yaml                1
```

Use a different tool profile:

```bash
python3 SASTFileCounter.py ./my-repo --tool cxsast
python3 SASTFileCounter.py ./my-repo --tool semgrep
```

List all available tool profiles:

```bash
python3 SASTFileCounter.py --list-tools
```

Get the count for one specific language or extension:

```bash
python3 SASTFileCounter.py ./my-repo --check python
python3 SASTFileCounter.py ./my-repo --check .py
python3 SASTFileCounter.py ./my-repo --check all
```

Compare several tools side by side:

```bash
$ python3 SASTFileCounter.py ./my-repo --compare falconeye,semgrep,sonarqube
Directory: /home/user/my-repo
Total files scanned (any type): 7

Tool                          Relevant files     Not covered
------------------------------------------------------------
FalconEye                                  5               2
Semgrep                                    5               2
SonarQube                                  5               2

Per-language breakdown:
  [FalconEye]
    Python                    1
    JavaScript/TypeScript     1
    Go                        1
    Java                      1
    Ruby                      1
  [Semgrep]
    Python                    1
    JavaScript                1
    Java                      1
    Go                        1
    Ruby                      1
  [SonarQube]
    Java                      1
    JavaScript                1
    Python                    1
    Go                        1
    Ruby                      1
```

JSON output for scripting / CI:

```bash
python3 SASTFileCounter.py ./my-repo --json --tool cxsast > report.json
```

Exclude extra noise directories or hidden files:

```bash
python3 SASTFileCounter.py ./my-repo --exclude-dir vendor --exclude-dir coverage
python3 SASTFileCounter.py ./my-repo --exclude-hidden
```

## Adding a new tool

Add one entry to the `TOOL_PROFILES` dict in the script — a `name`, a `languages` dict (`language -> set of extensions`), and an optional `special_filenames` dict (`exact lowercase filename -> language`, for files like `Gemfile` that have no extension). Reuse the shared `*_EXTS` constants at the top of the script where possible for consistency.

```python
"my-tool": {
    "name": "My Tool",
    "languages": {
        "Python": PY_EXTS,
        "Go": GO_EXTS,
        # ...
    },
    "special_filenames": {},
},
```

No other code changes are needed — `--tool`, `--list-tools`, `--check`, and `--compare` all pick up new profiles automatically.

## Limitations

- File-type detection is extension-based only (plus a small set of exact filenames like `Gemfile`). It does not inspect file contents, so a `.h` file is always counted as C/C++, even if it's actually Objective-C++.
- Language/extension lists are a practical approximation for capacity estimation — not a guarantee of what a given vendor's scanner will actually pick up. Always cross-check against your tool's current, version-specific documentation before using these numbers for licensing or scan-scope decisions.

## License

Add a license of your choice (e.g. MIT) here before publishing.
