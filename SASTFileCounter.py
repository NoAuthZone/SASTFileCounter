#!/usr/bin/env python3
"""
SASTFileCounter

Counts files in a directory tree: total count, count by file extension,
and count grouped by the programming languages supported by a given
static-analysis (SAST) tool. This helps estimate how many files a tool
like FalconEye, Checkmarx SAST, Semgrep, SonarQube, CodeQL, Snyk Code,
Veracode, or Fortify would actually analyze in a given repository/folder.

By default ALL files are counted, including ones with extensions the
selected tool does not support and hidden files/dotfiles (e.g. ".env",
".mmmikefiles"). Unrecognized types are not discarded - they are collected
in a separate "unsupported extensions" bucket and printed in full, so
nothing is missed.

Multiple tools are supported via named "tool profiles" (see TOOL_PROFILES
below). Use --list-tools to see all available profiles, --tool to pick one,
and --compare to run several profiles at once and see them side by side.

Usage:
    python SASTFileCounter.py <path> [options]

Examples:
    python SASTFileCounter.py ./my-repo
    python SASTFileCounter.py ./my-repo --tool cxsast
    python SASTFileCounter.py ./my-repo --list-tools
    python SASTFileCounter.py ./my-repo --check python
    python SASTFileCounter.py ./my-repo --check .py
    python SASTFileCounter.py ./my-repo --check falconeye
    python SASTFileCounter.py ./my-repo --compare falconeye,cxsast
    python SASTFileCounter.py ./my-repo --json > report.json

Adding a new tool:
    Add one more entry to TOOL_PROFILES below - a "name", a "languages"
    dict (language -> set of extensions), and an optional "special_filenames"
    dict (exact lowercase filename -> language, for files like "Gemfile"
    that have no extension). No other code changes are needed; --tool,
    --list-tools, --check and --compare all pick up new profiles automatically.
"""

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

# ---------------------------------------------------------------------------
# Shared extension sets, reused across the tool profiles below so common
# languages (Python, Java, Go, ...) are defined once and stay consistent.
# These sets are deliberately kept pairwise disjoint (no extension appears
# in two different constants) so that combining them inside one profile can
# never silently create a duplicate-extension conflict.
# ---------------------------------------------------------------------------
PY_EXTS = {".py"}
JS_EXTS = {".js", ".jsx", ".mjs", ".cjs"}
TS_EXTS = {".ts", ".tsx"}
JAVA_EXTS = {".java"}
KOTLIN_EXTS = {".kt", ".kts"}
GO_EXTS = {".go"}
C_CPP_EXTS = {".c", ".cc", ".cpp", ".cxx", ".c++", ".h", ".hh", ".hpp", ".hxx", ".h++"}
CSHARP_EXTS = {".cs"}
VBNET_EXTS = {".vb"}
VB6_EXTS = {".bas", ".frm", ".ctl"}  # ".cls" deliberately excluded, see APEX_EXTS
RUBY_EXTS = {".rb", ".erb", ".gemspec"}
RUBY_SPECIAL_FILENAMES = {"gemfile": "Ruby", "rakefile": "Ruby"}
SCALA_EXTS = {".scala", ".sc"}
SWIFT_EXTS = {".swift"}
OBJC_EXTS = {".m", ".mm"}
RUST_EXTS = {".rs"}
PHP_EXTS = {".php", ".phtml", ".php3", ".php4", ".php5", ".phps"}
APEX_EXTS = {".apex", ".apexp", ".cls", ".trigger", ".tgr", ".page", ".component", ".object", ".report", ".workflow"}
DART_EXTS = {".dart"}
GROOVY_EXTS = {".groovy", ".gvy", ".gy", ".gsh"}
COBOL_EXTS = {".cbl", ".cob", ".cpy"}
SQL_EXTS = {".sql", ".pls", ".pkb", ".pks", ".pkh", ".pck"}  # PL/SQL + T-SQL (indistinguishable by extension alone)
HTML_EXTS = {".html", ".htm"}
CSS_EXTS = {".css", ".scss", ".less"}
PERL_EXTS = {".pl", ".pm", ".plx", ".psgi"}
VBSCRIPT_EXTS = {".vbs"}
ASP_EXTS = {".asp"}
ASPNET_EXTS = {".aspx", ".ascx"}
COLDFUSION_EXTS = {".cfm", ".cfc"}
ACTIONSCRIPT_EXTS = {".as", ".mxml"}
ABAP_EXTS = {".abap"}
TERRAFORM_EXTS = {".tf"}

# ---------------------------------------------------------------------------
# Tool profiles: tool key -> { name, languages: {lang: {exts}}, special_filenames }
#
# "languages"          maps each language to the set of extensions it owns
#                       for THIS tool. Extensions are lowercase, with a
#                       leading dot.
# "special_filenames"  maps an exact, lowercase filename (no extension,
#                       e.g. "gemfile") to a language, for files that are
#                       recognized by name rather than by extension.
#
# NOTE ON AMBIGUOUS EXTENSIONS: some real-world tools recognize the same
# extension for more than one language (e.g. Checkmarx uses ".vb" for both
# VB6 and VB.NET, and ".cls" for both VB6 and Salesforce Apex). Since a file
# can only be counted once, each such extension is assigned to a single
# "primary" language below and the conflict is noted in a comment. This is
# a simplification for file-count estimation, not an exact re-implementation
# of any vendor's file-type detector - always verify against the vendor's
# current documentation before using these numbers for capacity/licensing
# decisions.
# ---------------------------------------------------------------------------
TOOL_PROFILES = {
    "falconeye": {
        "name": "FalconEye",
        "languages": {
            "Python": {".py", ".pyw"},
            "JavaScript/TypeScript": {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
            "Go": {".go"},
            "Rust": {".rs"},
            "C/C++": {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx"},
            "Java": {".java"},
            "PHP": {".php", ".phtml", ".php3", ".php4", ".php5", ".phps"},
            "Ruby": {".rb", ".rake", ".gemspec"},
            "Dart": {".dart"},
        },
        # Ruby files without a "classic" extension
        "special_filenames": {"gemfile": "Ruby", "rakefile": "Ruby"},
    },
    # Based on Checkmarx SAST v9.3.0 "Supported Code Languages and Frameworks"
    # documentation (docs.checkmarx.com). Exact extensions can vary by
    # CxSAST/CxOne version - check your own version's docs before relying on
    # this for scan-scope or licensing decisions.
    "cxsast": {
        "name": "Checkmarx SAST (CxSAST)",
        "languages": {
            "Java": {".java", ".jsp", ".jspf", ".tag", ".tld", ".hbs", ".properties"},
            "C#/.NET": {".sln", ".csproj", ".cs", ".cshtml", ".xaml", ".config"},
            "ASP": {".asp"},
            # ".vb" is shared with C#/.NET (VB.NET) upstream; assigned to VB6 here
            "VB6": {".bas", ".vbp", ".frm", ".dsr", ".ctl", ".vb"},
            "C/C++": {".cpp", ".c++", ".cxx", ".hpp", ".hh", ".h++", ".hxx", ".c", ".cc", ".h"},
            "PHP": {".php", ".php3", ".php4", ".php5", ".phtm", ".phtml", ".tpl", ".ctp", ".twig"},
            # ".cls" is shared with VB6 upstream; assigned to Apex here
            "Apex": {".apex", ".apexp", ".page", ".component", ".cls", ".trigger", ".tgr", ".object", ".report", ".workflow"},
            "Ruby": {".rb", ".rhtml", ".rxml", ".rjs", ".erb"},
            "JavaScript/TypeScript": {".js", ".ts", ".tsx"},
            "VBScript": {".vbs"},
            "Perl": {".pl", ".pm", ".plx", ".psgi"},
            # ".kt" from Checkmarx's "Android (Java)" section is folded in here
            "Kotlin": {".kt", ".kts"},
            "Objective-C/Swift": {".m", ".swift", ".xib"},
            "HTML": {".html", ".htm"},
            "PL/SQL": {".pls", ".sql", ".pkh", ".pks", ".pkb", ".pck"},
            "Python": {".py"},
            "Groovy": {".groovy", ".gsh", ".gvy", ".gy"},
            "Scala": {".scala", ".sc"},
            "Go": {".go"},
            "COBOL": {".cbl", ".cob", ".eco", ".pco", ".sqb", ".cpy"},
            # Multi-language config/markup files Checkmarx also scans
            "Other/Config": {".aspx", ".ascx", ".xml", ".cgi", ".inc"},
        },
        "special_filenames": {},
    },
    # Based on Semgrep's public "Supported languages" docs (docs.semgrep.dev).
    # Only Generally Available languages plus the two most common Beta
    # languages (Apex, Dart) are included; Experimental languages (Bash,
    # HTML, YAML, ...) are left out since Semgrep's coverage there is
    # minimal/rule-dependent. Terraform is included since Semgrep treats it
    # as a first-class GA "language" for IaC scanning.
    "semgrep": {
        "name": "Semgrep",
        "languages": {
            "Python": PY_EXTS,
            "JavaScript": JS_EXTS,
            "TypeScript": TS_EXTS,
            "Java": JAVA_EXTS,
            "Go": GO_EXTS,
            "C#": CSHARP_EXTS,
            "Kotlin": KOTLIN_EXTS,
            "C/C++": C_CPP_EXTS,
            "Ruby": RUBY_EXTS,
            "Scala": SCALA_EXTS,
            "Swift": SWIFT_EXTS,
            "Rust": RUST_EXTS,
            "PHP": PHP_EXTS,
            "Terraform": TERRAFORM_EXTS,
            "Apex (beta)": APEX_EXTS,
            "Dart (beta)": DART_EXTS,
        },
        "special_filenames": RUBY_SPECIAL_FILENAMES,
    },
    # Based on SonarQube Server docs (docs.sonarsource.com). Some languages
    # (ABAP, Apex, COBOL, PL/I, RPG, JCL, ...) require specific commercial
    # editions; only a representative, commonly-scanned subset is included
    # here - niche mainframe/ERP languages are left out for brevity.
    "sonarqube": {
        "name": "SonarQube",
        "languages": {
            "Java": JAVA_EXTS,
            "Kotlin": KOTLIN_EXTS,
            "JavaScript": JS_EXTS,
            "TypeScript": TS_EXTS,
            "Python": PY_EXTS,
            "Go": GO_EXTS,
            "C/C++": C_CPP_EXTS,
            "C#": CSHARP_EXTS,
            "VB.NET": VBNET_EXTS,
            "VB6": VB6_EXTS,
            "Apex": APEX_EXTS,
            "PHP": PHP_EXTS,
            "Ruby": RUBY_EXTS,
            "Scala": SCALA_EXTS,
            "Swift": SWIFT_EXTS,
            "Objective-C": OBJC_EXTS,
            "Dart": DART_EXTS,
            "Rust": RUST_EXTS,
            "Groovy": GROOVY_EXTS,
            "COBOL": COBOL_EXTS,
            "SQL (PL/SQL & T-SQL)": SQL_EXTS,
            "HTML": HTML_EXTS,
            "CSS": CSS_EXTS,
        },
        "special_filenames": RUBY_SPECIAL_FILENAMES,
    },
    # Based on GitHub's official CodeQL "Supported languages and frameworks"
    # docs (codeql.github.com) - the most precisely-sourced profile here,
    # extensions are quoted close to verbatim from that page.
    "codeql": {
        "name": "CodeQL",
        "languages": {
            "C/C++": C_CPP_EXTS,
            "C#": {".sln", ".csproj", ".cs", ".cshtml", ".xaml"},
            "Go": GO_EXTS,
            "Java": JAVA_EXTS,
            "Kotlin": {".kt"},
            "JavaScript": {".js", ".jsx", ".mjs", ".es", ".es6", ".vue", ".hbs", ".ejs", ".njk"},
            "TypeScript": {".ts", ".tsx", ".mts", ".cts"},
            "Python": PY_EXTS,
            "Ruby": RUBY_EXTS,
            "Rust": RUST_EXTS,
            "Swift": SWIFT_EXTS,
        },
        "special_filenames": {"gemfile": "Ruby"},
    },
    # Based on Snyk's "Supported languages" docs (docs.snyk.io) for the
    # Snyk Code (SAST) product specifically. Some entries (Rust, COBOL,
    # Objective-C) are Early Access on Enterprise plans per Snyk's docs.
    "snyk-code": {
        "name": "Snyk Code",
        "languages": {
            "Apex": APEX_EXTS,
            "C/C++": C_CPP_EXTS,
            "Go": GO_EXTS,
            "Java": JAVA_EXTS,
            "Kotlin": KOTLIN_EXTS,
            "JavaScript": JS_EXTS,
            "TypeScript": TS_EXTS,
            ".NET (C#/VB.NET)": {".cs", ".vb"},
            "PHP": PHP_EXTS,
            "Python": PY_EXTS,
            "Ruby": RUBY_EXTS,
            "Rust": RUST_EXTS,
            "Scala": SCALA_EXTS,
            "Swift/Objective-C": {".swift", ".m", ".mm"},
            "Dart": DART_EXTS,
            "Groovy": GROOVY_EXTS,
            "COBOL": COBOL_EXTS,
        },
        "special_filenames": RUBY_SPECIAL_FILENAMES,
    },
    # Based on Veracode's "Static Analysis supported languages and
    # platforms" docs (docs.veracode.com). Mobile-framework/binary-upload
    # entries (Xamarin, .NET MAUI, React Native, precompiled binaries, ...)
    # are left out since they aren't counted by source file extension.
    "veracode": {
        "name": "Veracode Static Analysis",
        "languages": {
            "Java": JAVA_EXTS,
            ".NET (C#/VB.NET/ASP.NET)": {".cs", ".vb", ".aspx", ".ascx"},
            "C/C++": C_CPP_EXTS,
            "JavaScript": JS_EXTS,
            "TypeScript": TS_EXTS,
            "PHP": PHP_EXTS,
            "Scala": SCALA_EXTS,
            "Groovy": GROOVY_EXTS,
            "Kotlin": KOTLIN_EXTS,
            "Dart": DART_EXTS,
            "Ruby": RUBY_EXTS,
            "Apex": APEX_EXTS,
            "SQL (PL/SQL & T-SQL)": SQL_EXTS,
            "Classic ASP": ASP_EXTS,
            "ColdFusion": COLDFUSION_EXTS,
            "Perl": PERL_EXTS,
            "Python": PY_EXTS,
            "Go": GO_EXTS,
            "COBOL": COBOL_EXTS,
            "VB6": VB6_EXTS,
        },
        "special_filenames": RUBY_SPECIAL_FILENAMES,
    },
    # Based on a third-party summary of OpenText/Micro Focus Fortify SCA's
    # ~33 supported languages (Fortify's own docs are PDF-only and version-
    # gated); treat this profile as a rough approximation and verify against
    # your Fortify version's "SCA_Guide" PDF before relying on it.
    "fortify": {
        "name": "OpenText Fortify SCA",
        "languages": {
            "Java/JSP": JAVA_EXTS | {".jsp", ".jspx"},
            "C/C++": C_CPP_EXTS,
            "C#": CSHARP_EXTS,
            "VB.NET": VBNET_EXTS,
            "ASP.NET": ASPNET_EXTS,
            "Classic ASP": ASP_EXTS,
            "ActionScript": ACTIONSCRIPT_EXTS,
            "Apex": APEX_EXTS,
            "COBOL": COBOL_EXTS,
            "ColdFusion": COLDFUSION_EXTS,
            "Go": GO_EXTS,
            "HTML": HTML_EXTS,
            "JavaScript": JS_EXTS,
            "Kotlin": KOTLIN_EXTS,
            "Objective-C": OBJC_EXTS,
            "PHP": PHP_EXTS,
            "SQL (PL/SQL & T-SQL)": SQL_EXTS,
            "Python": PY_EXTS,
            "Ruby": RUBY_EXTS,
            "Swift": SWIFT_EXTS,
            "VBScript": VBSCRIPT_EXTS,
            "ABAP": ABAP_EXTS,
        },
        "special_filenames": RUBY_SPECIAL_FILENAMES,
    },
}

DEFAULT_TOOL = "falconeye"

# Aliases so --check and --tool also accept common short forms
LANGUAGE_ALIASES = {
    "js": "JavaScript/TypeScript",
    "ts": "JavaScript/TypeScript",
    "javascript": "JavaScript/TypeScript",
    "typescript": "JavaScript/TypeScript",
    "jsx": "JavaScript/TypeScript",
    "tsx": "JavaScript/TypeScript",
    "c++": "C/C++",
    "cpp": "C/C++",
    "c": "C/C++",
    "csharp": "C#/.NET",
    "c#": "C#/.NET",
    "vbnet": "C#/.NET",
    "objc": "Objective-C/Swift",
    "swift": "Objective-C/Swift",
}

# Directories excluded by default (typical build/VCS/dependency folders)
DEFAULT_EXCLUDE_DIRS = {
    ".git", ".svn", ".hg", "__pycache__", ".venv", "venv", "env",
    "node_modules", "dist", "build", "target", ".idea", ".vscode",
    ".mypy_cache", ".pytest_cache", ".tox", "vendor", ".next", ".nuxt",
}


def get_tool_profile(tool_key: str):
    """Look up a tool profile by key, exiting with a clear error if unknown."""
    profile = TOOL_PROFILES.get(tool_key)
    if profile is None:
        available = ", ".join(sorted(TOOL_PROFILES))
        print(f"Error: unknown tool '{tool_key}'. Available: {available}", file=sys.stderr)
        sys.exit(1)
    return profile


def build_extension_to_language(languages: dict):
    """Build a flat lookup table mapping each extension to its language."""
    ext_to_lang = {}
    for lang, exts in languages.items():
        for ext in exts:
            ext_to_lang[ext] = lang
    return ext_to_lang


def classify_file(path: Path, ext_to_lang: dict, special_filenames: dict):
    """Return (extension_or_filename, language_or_None) for a single file."""
    name_lower = path.name.lower()
    if name_lower in special_filenames:
        return (path.name, special_filenames[name_lower])
    ext = path.suffix.lower()
    lang = ext_to_lang.get(ext)
    return (ext if ext else "(no extension)", lang)


def iter_files(root: Path, recursive: bool, exclude_hidden: bool, exclude_dirs: set):
    """Yield file paths under root, honoring recursion/hidden/exclude settings.

    Hidden files/directories (starting with ".") are included by default,
    since unknown/unsupported types - including dotfiles - should still be
    counted. Directories in exclude_dirs (e.g. ".git", "node_modules") are
    always skipped regardless of the hidden setting, since they are noise
    (VCS internals, dependencies), not "unknown file types" to report on.
    """
    if recursive:
        for dirpath, dirnames, filenames in os.walk(root):
            if exclude_hidden:
                dirnames[:] = [d for d in dirnames if not d.startswith(".")]
            dirnames[:] = [d for d in dirnames if d.lower() not in exclude_dirs]
            for fname in filenames:
                if exclude_hidden and fname.startswith("."):
                    continue
                yield Path(dirpath) / fname
    else:
        for entry in sorted(root.iterdir()):
            if entry.is_file():
                if exclude_hidden and entry.name.startswith("."):
                    continue
                yield entry


def count_files(root: Path, recursive: bool, exclude_hidden: bool, exclude_dirs: set, profile: dict):
    """Walk the directory and produce total/by-extension/by-language counts for one profile."""
    ext_to_lang = build_extension_to_language(profile["languages"])
    special_filenames = profile["special_filenames"]

    total = 0
    by_extension = Counter()
    by_language = Counter()
    unsupported_extensions = Counter()

    for f in iter_files(root, recursive, exclude_hidden, exclude_dirs):
        total += 1
        ext, lang = classify_file(f, ext_to_lang, special_filenames)
        by_extension[ext] += 1
        if lang:
            by_language[lang] += 1
        else:
            unsupported_extensions[ext] += 1

    return {
        "total": total,
        "by_extension": by_extension,
        "by_language": by_language,
        "unsupported_extensions": unsupported_extensions,
    }


def resolve_check_param(check: str, profile: dict):
    """
    Resolve the --check argument into a (kind, value) tuple, against one profile.

    Accepted forms:
      - a language name (e.g. 'Python', 'javascript', 'c++')
      - an extension (e.g. '.py' or 'py')
      - 'all' / '<tool key>' for the sum across all languages the profile supports

    Returns:
        (kind, value) where kind is one of
        {"tool_total", "language", "extension"}.
    """
    check_norm = check.strip().lower()

    if check_norm in ("all", "supported") or check_norm in TOOL_PROFILES:
        return ("tool_total", None)

    def normalize(s: str) -> str:
        # Strip qualifiers like " (beta)" / " (early access)" and punctuation
        # so 'apex' matches a language stored as 'Apex (beta)'.
        s = s.split("(", 1)[0]
        for ch in ("/", ".", "-", "_", " "):
            s = s.replace(ch, "")
        return s

    for lang in profile["languages"]:
        if lang.lower() == check_norm or normalize(lang.lower()) == normalize(check_norm):
            return ("language", lang)

    if check_norm in LANGUAGE_ALIASES and LANGUAGE_ALIASES[check_norm] in profile["languages"]:
        return ("language", LANGUAGE_ALIASES[check_norm])

    ext_norm = check_norm if check_norm.startswith(".") else f".{check_norm}"
    return ("extension", ext_norm)


def print_report(stats, root, profile: dict, tool_key: str, check=None):
    """Print a human-readable text report to stdout for one profile."""
    tool_name = profile["name"]
    print(f"Directory: {root}")
    print(f"Tool: {tool_name}")
    print(f"Total files: {stats['total']}")
    print()

    print(f"=== By {tool_name} language ===")
    tool_total = 0
    for lang in profile["languages"]:
        count = stats["by_language"].get(lang, 0)
        tool_total += count
        print(f"  {lang:<25} {count}")
    print(f"  {'-' * 35}")
    print(f"  {'TOTAL (' + tool_name + '-relevant)':<25} {tool_total}")
    print()

    other_total = sum(stats["unsupported_extensions"].values())
    print(f"Not supported by {tool_name}: {other_total} files ({len(stats['unsupported_extensions'])} distinct type(s))")
    for ext, count in stats["unsupported_extensions"].most_common():
        print(f"    {ext:<20} {count}")
    print()

    if check:
        kind, value = resolve_check_param(check, profile)
        print("=== Check parameter ===")
        if kind == "tool_total":
            print(f"  All {tool_name}-relevant files: {tool_total}")
        elif kind == "language":
            count = stats["by_language"].get(value, 0)
            print(f"  Language '{value}': {count} files")
        elif kind == "extension":
            count = stats["by_extension"].get(value, 0)
            print(f"  Extension '{value}': {count} files")


def print_tool_list():
    """Print all available tool profiles and the languages/extensions they cover."""
    for key in sorted(TOOL_PROFILES):
        profile = TOOL_PROFILES[key]
        print(f"{key}  ({profile['name']})")
        for lang, exts in profile["languages"].items():
            ext_list = ", ".join(sorted(exts))
            print(f"    {lang:<25} {ext_list}")
        if profile["special_filenames"]:
            names = ", ".join(sorted(profile["special_filenames"]))
            print(f"    (special filenames: {names})")
        print()


def print_compare(root, tool_keys, recursive, exclude_hidden, exclude_dirs):
    """Run several tool profiles over the same directory and print a summary table."""
    results = []
    for key in tool_keys:
        profile = get_tool_profile(key)
        stats = count_files(root, recursive, exclude_hidden, exclude_dirs, profile)
        tool_total = sum(stats["by_language"].values())
        results.append((key, profile["name"], stats, tool_total))

    print(f"Directory: {root}")
    print(f"Total files scanned (any type): {results[0][2]['total']}")
    print()
    print(f"{'Tool':<28} {'Relevant files':>15} {'Not covered':>15}")
    print("-" * 60)
    for key, name, stats, tool_total in results:
        not_covered = stats["total"] - tool_total
        print(f"{name:<28} {tool_total:>15} {not_covered:>15}")
    print()

    print("Per-language breakdown:")
    for key, name, stats, tool_total in results:
        print(f"  [{name}]")
        profile = TOOL_PROFILES[key]
        for lang in profile["languages"]:
            count = stats["by_language"].get(lang, 0)
            if count:
                print(f"    {lang:<25} {count}")


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Count files in a path - total and by type - to estimate "
            "how many files a static-analysis tool would analyze."
        )
    )
    parser.add_argument("path", type=str, nargs="?", help="Path to the directory to analyze")
    parser.add_argument(
        "--tool", "-t", type=str, default=DEFAULT_TOOL,
        help=f"Tool profile to use (default: {DEFAULT_TOOL}). See --list-tools for all options.",
    )
    parser.add_argument(
        "--list-tools", action="store_true",
        help="List all available tool profiles with their languages/extensions and exit",
    )
    parser.add_argument(
        "--compare", type=str, default=None,
        help="Comma-separated list of tool keys to run side by side (e.g. 'falconeye,cxsast')",
    )
    parser.add_argument(
        "--check", "-c", type=str, default=None,
        help=(
            "Optional: a language (e.g. 'python', 'javascript') or an "
            "extension (e.g. '.py') or 'all' for the total sum across "
            "all languages the selected tool supports."
        ),
    )
    parser.add_argument("--no-recursive", action="store_true", help="Do not recurse into subdirectories")
    parser.add_argument(
        "--exclude-hidden", action="store_true",
        help=(
            "Exclude hidden files/directories (starting with '.'). "
            "By default hidden files are INCLUDED so unknown/dotfile types "
            "are still counted; excluded directories (e.g. .git) are always "
            "skipped regardless of this flag."
        ),
    )
    parser.add_argument(
        "--exclude-dir", action="append", default=[],
        help="Additional directory name to exclude (can be used multiple times)",
    )
    parser.add_argument("--json", action="store_true", help="Print output as JSON instead of a text report")

    args = parser.parse_args()

    if args.list_tools:
        print_tool_list()
        sys.exit(0)

    if not args.path:
        parser.error("the following arguments are required: path")

    root = Path(args.path).expanduser().resolve()
    if not root.exists():
        print(f"Error: path does not exist: {root}", file=sys.stderr)
        sys.exit(1)
    if not root.is_dir():
        print(f"Error: path is not a directory: {root}", file=sys.stderr)
        sys.exit(1)

    exclude_dirs = set(DEFAULT_EXCLUDE_DIRS)
    exclude_dirs.update(d.lower() for d in args.exclude_dir)

    if args.compare:
        tool_keys = [t.strip().lower() for t in args.compare.split(",") if t.strip()]
        print_compare(root, tool_keys, not args.no_recursive, args.exclude_hidden, exclude_dirs)
        return

    profile = get_tool_profile(args.tool.strip().lower())

    stats = count_files(
        root,
        recursive=not args.no_recursive,
        exclude_hidden=args.exclude_hidden,
        exclude_dirs=exclude_dirs,
        profile=profile,
    )

    if args.json:
        tool_total = sum(stats["by_language"].values())
        result = {
            "path": str(root),
            "tool": args.tool.strip().lower(),
            "tool_name": profile["name"],
            "total_files": stats["total"],
            "by_extension": dict(stats["by_extension"]),
            "by_language": dict(stats["by_language"]),
            "unsupported_extensions": dict(stats["unsupported_extensions"]),
            "tool_total": tool_total,
        }
        if args.check:
            kind, value = resolve_check_param(args.check, profile)
            if kind == "tool_total":
                result["check_result"] = tool_total
            elif kind == "language":
                result["check_result"] = stats["by_language"].get(value, 0)
            elif kind == "extension":
                result["check_result"] = stats["by_extension"].get(value, 0)
            result["check_param"] = args.check
        print(json.dumps(result, indent=2))
    else:
        print_report(stats, root, profile, args.tool, check=args.check)


if __name__ == "__main__":
    main()
