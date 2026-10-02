//! A deterministic scan of a diff for test tampering.
//!
//! An engine that cannot make a failing check pass has two ways out: fix the cause, or
//! change what the check looks at. The second is cheap and looks like progress - the
//! check goes green. This module reads the diff of an order's branch against its base and
//! names the second way when it sees it, with no model involved, so every machine reaches
//! the same answer and the adversary is handed facts rather than asked to find them:
//!
//! - **deleted tests**: test functions removed and not re-added, or a whole test file
//!   deleted ([`Kind::DeletedTest`]);
//! - **removed assertions**: more `assert`/`expect` lines gone than added in a test
//!   ([`Kind::RemovedAssertion`]);
//! - **disabled tests**: `#[ignore]`, `skip`, `xfail`, `.only`, `it.skip`, `xit` added
//!   ([`Kind::DisabledTest`]), and assertions that cannot fail ([`Kind::TrivialAssertion`]);
//! - **forced passes**: `|| true`, `; exit 0`, `continue-on-error: true` added to a
//!   command that checks something ([`Kind::ForcedPass`]);
//! - **loosened tolerances**: the same assertion with a wider epsilon, delta or fewer
//!   places ([`Kind::LoosenedTolerance`]);
//! - **tests moved out of the checked paths**: a test file renamed or re-added outside the
//!   test directories, or the check configured to ignore them ([`Kind::MovedTests`]);
//! - **changes to the check itself**: a line that runs one of the order's required checks
//!   removed or rewritten, or the build file that decides what `cargo test` / `npm test` /
//!   `pytest` runs edited ([`Kind::CheckConfig`]).
//!
//! The scan reads text. It will miss what is hidden well and flag some honest refactors;
//! its [`Severity::High`] hits are the ones with no innocent reading common enough to
//! ignore, and those alone are enough for the adversary to block a next attempt.

use std::collections::BTreeSet;

use serde::Serialize;

use crate::adversary::{Issue, Severity};

/// What kind of tampering a hit is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    DeletedTest,
    RemovedAssertion,
    DisabledTest,
    TrivialAssertion,
    ForcedPass,
    LoosenedTolerance,
    MovedTests,
    CheckConfig,
    /// Part of the diff was too large to read, or could not be read. A fact about the scan
    /// rather than the diff: what it did not read, it did not clear.
    Unscanned,
}

impl Kind {
    #[must_use]
    pub fn title(self) -> &'static str {
        match self {
            Self::DeletedTest => "tests were deleted",
            Self::RemovedAssertion => "assertions were removed",
            Self::DisabledTest => "tests were disabled",
            Self::TrivialAssertion => "an assertion that cannot fail was added",
            Self::ForcedPass => "a check was forced to pass",
            Self::LoosenedTolerance => "a tolerance was loosened",
            Self::MovedTests => "tests were moved out of the checked paths",
            Self::CheckConfig => "the check itself was changed",
            Self::Unscanned => "part of the diff was not scanned",
        }
    }
}

/// One thing the scan found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Hit {
    pub kind: Kind,
    pub severity: Severity,
    pub file: String,
    pub detail: String,
}

impl Hit {
    /// The hit as an adversary issue, so the scan's facts and the model's findings read
    /// the same way.
    #[must_use]
    pub fn issue(&self) -> Issue {
        Issue {
            severity: self.severity,
            title: self.kind.title().to_string(),
            detail: self.detail.clone(),
            location: Some(self.file.clone()),
        }
    }
}

/// Whether any hit is [`Severity::High`].
#[must_use]
pub fn has_high(hits: &[Hit]) -> bool {
    hits.iter().any(|hit| hit.severity == Severity::High)
}

/// The hits as lines for a prompt or a person.
#[must_use]
pub fn describe(hits: &[Hit]) -> Vec<String> {
    hits.iter()
        .map(|hit| {
            format!(
                "[{}] {} in {}: {}",
                hit.severity.as_str(),
                hit.kind.title(),
                hit.file,
                hit.detail
            )
        })
        .collect()
}

// --- reading a unified diff ------------------------------------------------------------

#[derive(Debug, Default)]
struct Hunk {
    header: String,
    /// `' '`, `'-'` or `'+'`, and the line without its marker.
    lines: Vec<(char, String)>,
}

#[derive(Debug, Default)]
struct FileDiff {
    path: String,
    old_path: String,
    deleted: bool,
    added: bool,
    renamed: bool,
    hunks: Vec<Hunk>,
}

impl FileDiff {
    fn removed(&self) -> impl Iterator<Item = &str> {
        self.hunks
            .iter()
            .flat_map(|hunk| hunk.lines.iter())
            .filter(|(mark, _)| *mark == '-')
            .map(|(_, line)| line.as_str())
    }

    fn added_lines(&self) -> impl Iterator<Item = &str> {
        self.hunks
            .iter()
            .flat_map(|hunk| hunk.lines.iter())
            .filter(|(mark, _)| *mark == '+')
            .map(|(_, line)| line.as_str())
    }

    /// Whether this is test code, by its path or by the Rust test module around the change.
    /// Stricter than [`Self::looks_like_tests`]: a function's *name* is not evidence here,
    /// or a production `fn test_connection` would make its file a test file.
    fn in_test_code(&self) -> bool {
        is_test_source(&self.path)
            || self.hunks.iter().any(|hunk| {
                marks_test_module(&hunk.header)
                    || hunk.lines.iter().any(|(_, line)| marks_test_module(line))
            })
    }

    /// Whether anything in the file's diff - a line, or a hunk header's function context -
    /// says the code around it is a test.
    fn looks_like_tests(&self) -> bool {
        is_test_path(&self.path)
            || self.hunks.iter().any(|hunk| {
                is_test_context(&hunk.header)
                    || hunk.lines.iter().any(|(_, line)| is_test_context(line))
            })
    }
}

fn parse(diff: &str) -> Vec<FileDiff> {
    let mut files: Vec<FileDiff> = Vec::new();
    let mut in_hunk = false;
    for line in diff.lines() {
        if let Some(rest) = line.strip_prefix("diff --git ") {
            in_hunk = false;
            let (old, new) = rest.rsplit_once(" b/").map_or((rest, rest), |(old, new)| {
                (old.strip_prefix("a/").unwrap_or(old), new)
            });
            files.push(FileDiff {
                path: new.to_string(),
                old_path: old.to_string(),
                ..FileDiff::default()
            });
            continue;
        }
        let Some(file) = files.last_mut() else {
            continue;
        };
        if line.starts_with("@@") {
            in_hunk = true;
            file.hunks.push(Hunk {
                header: line.to_string(),
                lines: Vec::new(),
            });
            continue;
        }
        if !in_hunk {
            if line.starts_with("deleted file mode") {
                file.deleted = true;
            } else if line.starts_with("new file mode") {
                file.added = true;
            } else if let Some(from) = line.strip_prefix("rename from ") {
                file.renamed = true;
                file.old_path = from.to_string();
            } else if let Some(to) = line.strip_prefix("rename to ") {
                file.path = to.to_string();
            }
            continue;
        }
        let Some(hunk) = file.hunks.last_mut() else {
            continue;
        };
        if let Some(mark @ ('+' | '-' | ' ')) = line.chars().next() {
            hunk.lines.push((mark, line[1..].to_string()));
        }
    }
    files
}

// --- what a path or a line is ------------------------------------------------------------

fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Whether a path is one of a project's test files, by the conventions of the common
/// languages.
#[must_use]
pub fn is_test_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let name = file_name(&lower);
    lower.split('/').any(|part| {
        matches!(
            part,
            "tests" | "test" | "__tests__" | "spec" | "specs" | "e2e" | "testdata"
        )
    }) || name.starts_with("test_")
        || name == "conftest.py"
        || name == "tests.rs"
        || name.contains("_test.")
        || name.contains(".test.")
        || name.contains(".spec.")
        || name.contains("_spec.")
        || name.ends_with("test.java")
        || name.ends_with("tests.java")
        || name.ends_with("tests.cs")
}

/// Directories that hold what tests read - fixtures, snapshots, data - rather than tests.
const FIXTURE_DIRS: &[&str] = &[
    "fixtures",
    "fixture",
    "__fixtures__",
    "testdata",
    "test_data",
    "__snapshots__",
    "snapshots",
    "__mocks__",
    "golden",
    "data",
    "resources",
    "assets",
];

/// File extensions of code that can hold a test.
const CODE_EXTS: &[&str] = &[
    "rs", "py", "js", "jsx", "mjs", "cjs", "ts", "tsx", "go", "java", "kt", "kts", "scala", "cs",
    "rb", "php", "c", "cc", "cpp", "h", "hpp", "swift", "ex", "exs", "lua", "dart", "zig", "sh",
    "bash", "ps1", "bats",
];

/// Whether a path is a test *file*: a test path holding code. A fixture, a snapshot or a
/// data file under `tests/` or `testdata/` is read by tests and is not one, so deleting it
/// is not deleting a test.
#[must_use]
pub fn is_test_source(path: &str) -> bool {
    if !is_test_path(path) {
        return false;
    }
    let lower = path.to_ascii_lowercase();
    let name = file_name(&lower);
    let code = name
        .rsplit_once('.')
        .is_some_and(|(_, ext)| CODE_EXTS.contains(&ext));
    code && !lower.split('/').any(|part| FIXTURE_DIRS.contains(&part))
}

/// A line that opens or marks Rust test code, the one place a function's name alone
/// does not say whether it is a test.
fn marks_test_module(line: &str) -> bool {
    let line = line.trim();
    line.contains("#[cfg(test)]") || line.contains("mod tests") || is_test_attribute(line)
}

/// Whether `text` holds `word` as a whole word: not part of a longer identifier.
fn has_word(text: &str, word: &str) -> bool {
    let bytes = text.as_bytes();
    let ident = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
    text.match_indices(word).any(|(at, found)| {
        let before = at == 0 || !ident(bytes[at - 1]);
        let end = at + found.len();
        let after = end >= bytes.len() || !ident(bytes[end]);
        before && after
    })
}

fn is_docs(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    ["md", "txt", "rst", "adoc", "markdown"]
        .iter()
        .any(|ext| lower.ends_with(&format!(".{ext}")))
}

/// Build and CI files: where a command that runs checks is written down.
fn is_config(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let name = file_name(&lower);
    matches!(
        name,
        "makefile"
            | "justfile"
            | "taskfile.yml"
            | "taskfile.yaml"
            | "jenkinsfile"
            | "dockerfile"
            | "containerfile"
            | "package.json"
            | "tox.ini"
            | "setup.cfg"
            | "pytest.ini"
            | "noxfile.py"
    ) || [
        "yml", "yaml", "sh", "bash", "zsh", "ps1", "cmd", "bat", "mk", "toml", "cfg", "ini",
    ]
    .iter()
    .any(|ext| name.ends_with(&format!(".{ext}")))
}

fn is_test_context(line: &str) -> bool {
    let line = line.trim();
    [
        "#[test",
        "#[cfg(test)]",
        "#[tokio::test",
        "mod tests",
        "fn test_",
        "def test_",
        "func Test",
        "@Test",
        "describe(",
        "it(",
        "test(",
    ]
    .iter()
    .any(|marker| line.contains(marker))
}

/// The name of the test function a line declares, when it declares one.
fn test_decl(line: &str) -> Option<String> {
    let line = line.trim();
    for prefix in ["fn ", "async fn ", "pub fn ", "pub async fn "] {
        if let Some(rest) = line.strip_prefix(prefix) {
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            // `test_x`, `x_test`: a name that says so, not `testnet_config`.
            if name == "test" || name.starts_with("test_") || name.ends_with("_test") {
                return Some(name);
            }
        }
    }
    for prefix in ["def ", "async def "] {
        if let Some(rest) = line.strip_prefix(prefix) {
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if name == "test" || name.starts_with("test_") {
                return Some(name);
            }
        }
    }
    if let Some(rest) = line.strip_prefix("func Test") {
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        return Some(format!("Test{name}"));
    }
    for prefix in ["it(", "test(", "it.each(", "test.each("] {
        if let Some(rest) = line.strip_prefix(prefix) {
            let name: String = rest
                .trim_start_matches(['\'', '"', '`'])
                .chars()
                .take_while(|c| !matches!(c, '\'' | '"' | '`'))
                .collect();
            return Some(if name.is_empty() {
                prefix.trim_end_matches('(').to_string()
            } else {
                name
            });
        }
    }
    None
}

/// An attribute or annotation that marks the next function as a test.
fn is_test_attribute(line: &str) -> bool {
    let line = line.trim();
    line.starts_with("#[test]")
        || line.starts_with("#[tokio::test")
        || line.starts_with("#[async_std::test")
        || line.starts_with("#[rstest")
        || line.starts_with("@Test")
}

fn is_assertion(line: &str) -> bool {
    let line = line.trim();
    [
        "assert!(",
        "assert_eq!(",
        "assert_ne!(",
        "debug_assert",
        "assert(",
        "assert.",
        "assert_",
        "self.assert",
        "expect(",
        "assertThat(",
        "require.",
        "t.Errorf(",
        "t.Fatalf(",
    ]
    .iter()
    .any(|marker| line.starts_with(marker))
        || line.starts_with("assert ")
}

// --- the detectors ----------------------------------------------------------------------

/// Scan a unified diff (`git diff base...branch`) for test tampering. `required` are the
/// order's required check commands, as argv lists: edits to the lines that run them, and
/// to the build files that decide what they run, are named too.
#[must_use]
pub fn scan(diff: &str, required: &[Vec<String>]) -> Vec<Hit> {
    let files = parse(diff);
    let mut hits = Vec::new();
    deleted_tests(&files, &mut hits);
    removed_assertions(&files, &mut hits);
    disabled_tests(&files, &mut hits);
    forced_passes(&files, &mut hits);
    loosened_tolerances(&files, &mut hits);
    moved_tests(&files, &mut hits);
    check_config(&files, required, &mut hits);
    hits.sort_by_key(|hit| (std::cmp::Reverse(hit.severity), hit.kind));
    hits
}

fn names(list: &[String]) -> String {
    let shown: Vec<&str> = list.iter().take(5).map(String::as_str).collect();
    let more = list.len().saturating_sub(shown.len());
    if more > 0 {
        format!("{} and {more} more", shown.join(", "))
    } else {
        shown.join(", ")
    }
}

/// The names of the test functions `lines` declare: those named like tests, and those an
/// attribute (`#[test]`) marks - read from the function line that follows it.
///
/// A function is read as a test by its name only in test code (`in_tests`): a name is no
/// proof outside it. An attribute (`#[test]`) is proof anywhere.
fn declared(lines: &[&str], in_tests: bool) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        let found = test_decl(line).filter(|_| in_tests).or_else(|| {
            if !is_test_attribute(line) {
                return None;
            }
            lines.iter().skip(index + 1).take(3).find_map(|next| {
                let next = next.trim();
                ["fn ", "async fn ", "pub fn ", "pub async fn "]
                    .iter()
                    .find_map(|prefix| next.strip_prefix(prefix))
                    .map(|rest| {
                        rest.chars()
                            .take_while(|c| c.is_alphanumeric() || *c == '_')
                            .collect::<String>()
                    })
            })
        });
        if let Some(name) = found
            && !names.contains(&name)
        {
            names.push(name);
        }
    }
    names
}

fn deleted_tests(files: &[FileDiff], hits: &mut Vec<Hit>) {
    // A test file deleted outright, unless the same file name turns up in a test path:
    // that is a move inside the checked paths (and the other detector names the rest).
    let added_elsewhere: BTreeSet<&str> = files
        .iter()
        .filter(|file| file.added || file.renamed)
        .map(|file| file_name(&file.path))
        .collect();
    for file in files {
        // A fixture or data file under a test directory is not a test file.
        if file.deleted && is_test_source(&file.path) && !is_docs(&file.path) {
            if added_elsewhere.contains(file_name(&file.path)) {
                continue;
            }
            hits.push(Hit {
                kind: Kind::DeletedTest,
                severity: Severity::High,
                file: file.path.clone(),
                detail: "the whole test file was deleted".to_string(),
            });
            continue;
        }
        if is_docs(&file.path) {
            continue;
        }
        let removed: Vec<&str> = file.removed().collect();
        let added: Vec<&str> = file.added_lines().collect();
        let in_tests = file.in_test_code();
        let gone = declared(&removed, in_tests);
        let back = declared(&added, in_tests);
        // A moved or renamed test comes back under the same or another name: only the
        // surplus counts, and an annotation (`#[test]`) with no function line is read the
        // same way.
        let attributes = |lines: &[&str]| lines.iter().filter(|l| is_test_attribute(l)).count();
        let surplus = gone
            .len()
            .max(attributes(&removed))
            .saturating_sub(back.len().max(attributes(&added)));
        if surplus == 0 {
            continue;
        }
        let missing: Vec<String> = gone
            .iter()
            .filter(|name| !back.contains(name))
            .cloned()
            .collect();
        hits.push(Hit {
            kind: Kind::DeletedTest,
            severity: Severity::High,
            file: file.path.clone(),
            detail: if missing.is_empty() {
                format!("{surplus} test function(s) were deleted")
            } else {
                format!(
                    "{surplus} test function(s) were deleted and not re-added: {}",
                    names(&missing)
                )
            },
        });
    }
}

fn removed_assertions(files: &[FileDiff], hits: &mut Vec<Hit>) {
    for file in files {
        if is_docs(&file.path) || file.deleted || !file.looks_like_tests() {
            continue;
        }
        let gone: Vec<String> = file
            .removed()
            .filter(|line| is_assertion(line))
            .map(|line| line.trim().to_string())
            .collect();
        let back = file.added_lines().filter(|line| is_assertion(line)).count();
        let surplus = gone.len().saturating_sub(back);
        if surplus == 0 {
            continue;
        }
        hits.push(Hit {
            kind: Kind::RemovedAssertion,
            severity: if surplus >= 3 {
                Severity::High
            } else {
                Severity::Medium
            },
            file: file.path.clone(),
            detail: format!(
                "{surplus} more assertion(s) removed than added, e.g. `{}`",
                gone.first().map(String::as_str).unwrap_or_default()
            ),
        });
    }
}

/// Markers that switch a test off.
const DISABLERS: &[&str] = &[
    "#[ignore",
    "@pytest.mark.skip",
    "@pytest.mark.xfail",
    "pytest.skip(",
    "pytest.xfail(",
    "@unittest.skip",
    "unittest.skip(",
    ".skiptest(",
    "it.skip(",
    "test.skip(",
    "describe.skip(",
    "it.todo(",
    "test.todo(",
    "xit(",
    "xdescribe(",
    "xtest(",
];

/// Markers that mean "this test is off" only inside test code: `.only(`, `@Ignore` and the
/// like are ordinary words and calls elsewhere.
const TEST_CODE_DISABLERS: &[&str] = &[".only(", "t.skip(", "t.skipf(", "@disabled", "@ignore"];

/// Whether the text of `line` before byte `at` leaves `at` in code: not inside a string
/// literal and not after a comment marker. Cheap and line-local, so it can be fooled by a
/// multi-line string or block comment; it exists to stop `"#[ignore]"` in a message or
/// `// it.skip(` in a comment from reading as a test being switched off.
fn in_code(line: &str, at: usize, rust: bool) -> bool {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut previous = '\0';
    for (index, c) in line.char_indices() {
        if index >= at {
            break;
        }
        if let Some(open) = quote {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == open {
                quote = None;
            }
        } else {
            match c {
                '"' | '`' => quote = Some(c),
                // A lifetime or a char literal in Rust, a string everywhere else.
                '\'' if !rust => quote = Some(c),
                '/' if previous == '/' => return false,
                '#' => {
                    let next = line[index + 1..].chars().next();
                    if !matches!(next, Some('[' | '!')) {
                        return false;
                    }
                }
                _ => {}
            }
        }
        previous = c;
    }
    quote.is_none() && !line.trim_start().starts_with("/*") && !line.trim_start().starts_with("* ")
}

/// The first marker in `lower` (a lower-cased line) that switches a test off, where it is
/// code. `@`-annotations must end on a word boundary, so `@ignored_for_now` is not `@ignore`.
fn disabling_marker(lower: &str, in_tests: bool, rust: bool) -> Option<&'static str> {
    let bytes = lower.as_bytes();
    let markers: Vec<&'static str> = if in_tests {
        DISABLERS
            .iter()
            .chain(TEST_CODE_DISABLERS)
            .copied()
            .collect()
    } else {
        DISABLERS.to_vec()
    };
    markers.into_iter().find(|marker| {
        lower.match_indices(marker).any(|(at, _)| {
            let end = at + marker.len();
            let boundary = !marker.starts_with('@')
                || end >= bytes.len()
                || !(bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_');
            boundary && in_code(lower, at, rust)
        })
    })
}

/// Assertions that cannot fail.
const TRIVIAL: &[&str] = &[
    "assert!(true)",
    "assert_eq!(1, 1)",
    "assert_eq!(true, true)",
    "assert(true)",
    "assert true",
    "assert 1",
    "asserttrue(true)",
    "expect(true).tobe(true)",
    "expect(1).toBe(1)",
    "assert.ok(true)",
    "assert.equal(1, 1)",
];

fn disabled_tests(files: &[FileDiff], hits: &mut Vec<Hit>) {
    for file in files {
        if is_docs(&file.path) || file.deleted {
            continue;
        }
        let removed: Vec<String> = file
            .removed()
            .map(|l| l.trim().to_ascii_lowercase())
            .collect();
        let mut disabled: Vec<String> = Vec::new();
        let mut trivial: Vec<String> = Vec::new();
        let in_tests = file.looks_like_tests();
        let rust = file.path.to_ascii_lowercase().ends_with(".rs");
        for line in file.added_lines() {
            let lower = line.trim().to_ascii_lowercase();
            // A line that was already there and only moved is not new.
            if removed.contains(&lower) {
                continue;
            }
            if disabling_marker(&lower, in_tests, rust).is_some() {
                disabled.push(line.trim().to_string());
            } else if TRIVIAL.iter().any(|marker| lower.starts_with(marker)) {
                trivial.push(line.trim().to_string());
            }
        }
        if !disabled.is_empty() {
            hits.push(Hit {
                kind: Kind::DisabledTest,
                severity: Severity::High,
                file: file.path.clone(),
                detail: format!(
                    "{} line(s) switch tests off, e.g. `{}`",
                    disabled.len(),
                    disabled[0]
                ),
            });
        }
        if !trivial.is_empty() {
            hits.push(Hit {
                kind: Kind::TrivialAssertion,
                severity: Severity::Medium,
                file: file.path.clone(),
                detail: format!(
                    "{} assertion(s) that cannot fail, e.g. `{}`",
                    trivial.len(),
                    trivial[0]
                ),
            });
        }
    }
}

/// Words that make a command line a check rather than something else.
///
/// Whole words, not substrings: `ci` is `npm ci`, not the middle of `specific`. The broad
/// words that decide nothing alone (`build`, `make`, `go`) are there only in the phrases
/// that run a check.
const CHECK_WORDS: &[&str] = &[
    "test",
    "tests",
    "check",
    "lint",
    "clippy",
    "pytest",
    "unittest",
    "jest",
    "mocha",
    "vitest",
    "nextest",
    "cargo",
    "npm",
    "yarn",
    "pnpm",
    "tox",
    "ci",
    "fmt",
    "verify",
    "go test",
    "go vet",
    "make test",
    "make check",
    "make lint",
    "make ci",
];

/// The words that say a step *is* a test or a check, narrower than [`CHECK_WORDS`]: an
/// install or a cache step is not one, however many times it says `npm`.
const STEP_CHECK_WORDS: &[&str] = &[
    "test", "tests", "check", "lint", "clippy", "pytest", "unittest", "jest", "mocha", "vitest",
    "nextest", "tox", "fmt", "verify", "go vet",
];

fn is_check_line(lower: &str) -> bool {
    CHECK_WORDS.iter().any(|word| has_word(lower, word))
}

/// The lines of the YAML step that the line at `at` in `lines` belongs to, as far as the
/// hunk shows them: the nearest `- ` item above it that is less indented, down to the next
/// item or less-indented line.
fn step_lines(lines: &[(char, String)], at: usize) -> Vec<String> {
    let indent = |text: &str| text.len() - text.trim_start().len();
    let mine = indent(&lines[at].1);
    let mut start = at;
    while start > 0 {
        let above = &lines[start - 1].1;
        if above.trim().is_empty() {
            break;
        }
        let level = indent(above);
        if level < mine {
            if above.trim_start().starts_with("- ") {
                start -= 1;
            }
            break;
        }
        start -= 1;
    }
    let mut end = at + 1;
    while end < lines.len() {
        let below = &lines[end].1;
        if below.trim().is_empty() || indent(below) < mine {
            break;
        }
        end += 1;
    }
    lines[start..end]
        .iter()
        .map(|(_, text)| text.trim().trim_start_matches("- ").to_ascii_lowercase())
        .collect()
}

/// Whether `continue-on-error: true`, added at `at` in a hunk, sits on a step that runs
/// tests or checks. A step the hunk shows to be something else - a cache, a checkout, an
/// install - is not a check made unable to fail. A step the hunk does not show enough of to
/// tell is read as a check: the safe way to be wrong.
fn continue_on_error_is_on_a_check(lines: &[(char, String)], at: usize) -> bool {
    let step = step_lines(lines, at);
    let described: Vec<&String> = step
        .iter()
        .filter(|line| {
            ["run:", "uses:", "name:"]
                .iter()
                .any(|key| line.starts_with(key))
        })
        .collect();
    described.is_empty()
        || described
            .iter()
            .any(|line| STEP_CHECK_WORDS.iter().any(|word| has_word(line, word)))
}

fn forced_passes(files: &[FileDiff], hits: &mut Vec<Hit>) {
    for file in files {
        if !is_config(&file.path) || file.deleted {
            continue;
        }
        let removed: Vec<String> = file
            .removed()
            .map(|l| l.trim().to_ascii_lowercase())
            .collect();
        let mut forced: Vec<String> = Vec::new();
        for hunk in &file.hunks {
            // The file as the change leaves it: what a step looks like now, not what it was.
            let current: Vec<(char, String)> = hunk
                .lines
                .iter()
                .filter(|(mark, _)| *mark != '-')
                .cloned()
                .collect();
            for (at, (mark, line)) in current.iter().enumerate() {
                if *mark != '+' {
                    continue;
                }
                let lower = line.trim().to_ascii_lowercase();
                if removed.contains(&lower) {
                    continue;
                }
                let bypass = ["|| true", "|| exit 0", "; exit 0", "&& exit 0", "|| :"]
                    .iter()
                    .any(|marker| lower.contains(marker));
                let forced_step = lower.starts_with("continue-on-error: true")
                    && continue_on_error_is_on_a_check(&current, at);
                if (bypass && is_check_line(&lower)) || forced_step {
                    forced.push(line.trim().to_string());
                }
            }
        }
        if !forced.is_empty() {
            hits.push(Hit {
                kind: Kind::ForcedPass,
                severity: Severity::High,
                file: file.path.clone(),
                detail: format!(
                    "{} command(s) can no longer fail, e.g. `{}`",
                    forced.len(),
                    forced[0]
                ),
            });
        }
    }
}

/// The numeric literals in a line, in order. A digit run glued to a letter or an
/// underscore (`x1`, `v2`) is a name, not a number.
fn numbers(line: &str) -> Vec<f64> {
    let chars: Vec<char> = line.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let glued = i > 0 && (chars[i - 1].is_alphanumeric() || chars[i - 1] == '_');
        if chars[i].is_ascii_digit() && !glued {
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '_') {
                i += 1;
            }
            if i + 1 < chars.len() && chars[i] == '.' && chars[i + 1].is_ascii_digit() {
                i += 1;
                while i < chars.len() && chars[i].is_ascii_digit() {
                    i += 1;
                }
            }
            if i < chars.len() && matches!(chars[i], 'e' | 'E') {
                let mut j = i + 1;
                if j < chars.len() && matches!(chars[j], '+' | '-') {
                    j += 1;
                }
                if j < chars.len() && chars[j].is_ascii_digit() {
                    while j < chars.len() && chars[j].is_ascii_digit() {
                        j += 1;
                    }
                    i = j;
                }
            }
            let text: String = chars[start..i].iter().filter(|c| **c != '_').collect();
            if let Ok(value) = text.parse::<f64>() {
                out.push(value);
            }
        } else {
            i += 1;
        }
    }
    out
}

/// The line with every numeric literal replaced, so two lines that differ only in their
/// numbers compare equal.
fn skeleton(line: &str) -> String {
    let chars: Vec<char> = line.trim().chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        let glued = i > 0 && (chars[i - 1].is_alphanumeric() || chars[i - 1] == '_');
        if chars[i].is_ascii_digit() && !glued {
            while i < chars.len()
                && (chars[i].is_ascii_digit()
                    || matches!(chars[i], '.' | '_' | 'e' | 'E')
                    || (matches!(chars[i], '+' | '-')
                        && i > 0
                        && matches!(chars[i - 1], 'e' | 'E')))
            {
                i += 1;
            }
            out.push('#');
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

fn loosened_tolerances(files: &[FileDiff], hits: &mut Vec<Hit>) {
    const TOLERANCE: &[&str] = &[
        "eps",
        "tol",
        "delta",
        "approx",
        "close",
        "within",
        "almost",
        "abs",
        "margin",
        "places",
        "precision",
        "digits",
        "e-",
    ];
    const DIGITS: &[&str] = &["places", "precision", "digits", "closeto", "decimal"];
    for file in files {
        if is_docs(&file.path) || file.deleted {
            continue;
        }
        for hunk in &file.hunks {
            // A block is a run of removed lines followed by the lines that replaced them.
            let mut removed: Vec<&str> = Vec::new();
            let mut added: Vec<&str> = Vec::new();
            let mut blocks: Vec<(Vec<&str>, Vec<&str>)> = Vec::new();
            for (mark, line) in &hunk.lines {
                match mark {
                    '-' if added.is_empty() => removed.push(line),
                    '-' => {
                        blocks.push((std::mem::take(&mut removed), std::mem::take(&mut added)));
                        removed.push(line);
                    }
                    '+' => added.push(line),
                    _ => {
                        if !removed.is_empty() || !added.is_empty() {
                            blocks.push((std::mem::take(&mut removed), std::mem::take(&mut added)));
                        }
                    }
                }
            }
            if !removed.is_empty() || !added.is_empty() {
                blocks.push((removed, added));
            }
            for (old_lines, new_lines) in blocks {
                for old in old_lines {
                    let lower = old.to_ascii_lowercase();
                    if !is_assertion(old) && !lower.contains("approx") && !lower.contains("close") {
                        continue;
                    }
                    let Some(new) = new_lines.iter().find(|new| skeleton(new) == skeleton(old))
                    else {
                        continue;
                    };
                    let digits = DIGITS.iter().any(|word| lower.contains(word));
                    if !digits && !TOLERANCE.iter().any(|word| lower.contains(word)) {
                        continue;
                    }
                    let (before, after) = (numbers(old), numbers(new));
                    for (b, a) in before.iter().zip(&after) {
                        let (loosened, ratio) = if digits {
                            (a < b, if *a > 0.0 { b / a } else { f64::INFINITY })
                        } else {
                            (a > b && *b > 0.0, a / b)
                        };
                        if loosened {
                            hits.push(Hit {
                                kind: Kind::LoosenedTolerance,
                                severity: if ratio >= 10.0 && !digits {
                                    Severity::High
                                } else {
                                    Severity::Medium
                                },
                                file: file.path.clone(),
                                detail: format!("`{}` became `{}`", old.trim(), new.trim()),
                            });
                            break;
                        }
                    }
                }
            }
        }
    }
}

/// Test-runner options that narrow what is run.
const NARROWER_FLAGS: &[&str] = &[
    "--ignore",
    "--ignore-glob",
    "--deselect",
    "--no-run",
    "--exclude",
    "--skip",
];

/// Settings and expressions that narrow what a runner collects, found anywhere on a line.
const NARROWER_SETTINGS: &[&str] = &[
    "norecursedirs",
    "testpathignorepatterns",
    "modulepathignorepatterns",
    "-k \"not",
    "-k 'not",
    "-m \"not",
    "-m 'not",
];

/// The commands that run tests. A narrowing flag on one of them narrows the tests.
const RUNNERS: &[&str] = &[
    "cargo test",
    "cargo nextest",
    "npm test",
    "npm run test",
    "yarn test",
    "pnpm test",
    "pytest",
    "py.test",
    "go test",
    "jest",
    "vitest",
    "mocha",
    "tox",
    "nosetests",
    "rspec",
    "phpunit",
    "dotnet test",
    "mvn test",
    "gradle test",
    "ctest",
    "make test",
    "make check",
    "bats",
    "playwright test",
    "cypress run",
];

/// The files that configure a test runner, where a setting that narrows the tests is as
/// serious as a flag on the command.
fn is_runner_config(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let name = file_name(&lower);
    matches!(
        name,
        "pytest.ini" | "tox.ini" | "setup.cfg" | "pyproject.toml" | "package.json"
    ) || name.starts_with("jest.config")
        || name.starts_with("vitest.config")
}

fn is_runner_line(lower: &str) -> bool {
    RUNNERS.iter().any(|runner| has_word(lower, runner))
}

/// The narrowing option on a (lower-cased) line. A flag counts as a whole argument -
/// `--ignore`, `--ignore=dir` - so `npm ci --ignore-scripts` is not `--ignore`.
fn narrower(lower: &str) -> Option<&'static str> {
    let args: Vec<&str> = lower
        .split(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ',' | '[' | ']'))
        .collect();
    NARROWER_FLAGS
        .iter()
        .find(|flag| {
            let flag: &str = flag;
            args.iter().any(|arg| {
                *arg == flag
                    || arg
                        .strip_prefix(flag)
                        .is_some_and(|rest| rest.starts_with('='))
            })
        })
        .or_else(|| {
            NARROWER_SETTINGS
                .iter()
                .find(|setting| lower.contains(*setting))
        })
        .copied()
}

fn moved_tests(files: &[FileDiff], hits: &mut Vec<Hit>) {
    for file in files {
        // A test file renamed to somewhere the checks do not look.
        if file.renamed && is_test_source(&file.old_path) && !is_test_path(&file.path) {
            hits.push(Hit {
                kind: Kind::MovedTests,
                severity: Severity::High,
                file: file.path.clone(),
                detail: format!(
                    "{} was moved to {}, which is not a test path",
                    file.old_path, file.path
                ),
            });
        }
    }
    // Without rename detection a move is a delete here and an add there: the deleted test
    // file's name reappears outside the test paths.
    for gone in files
        .iter()
        .filter(|file| file.deleted && is_test_source(&file.path))
    {
        if let Some(back) = files.iter().find(|file| {
            file.added
                && !is_test_path(&file.path)
                && file_name(&file.path) == file_name(&gone.path)
        }) {
            hits.push(Hit {
                kind: Kind::MovedTests,
                severity: Severity::High,
                file: back.path.clone(),
                detail: format!(
                    "{} was deleted and {} added: the tests now sit outside the test paths",
                    gone.path, back.path
                ),
            });
        }
    }
    // The check configured to ignore tests.
    for file in files {
        if !is_config(&file.path) || file.deleted {
            continue;
        }
        let removed: Vec<String> = file
            .removed()
            .map(|l| l.trim().to_ascii_lowercase())
            .collect();
        for line in file.added_lines() {
            let lower = line.trim().to_ascii_lowercase();
            if removed.contains(&lower) {
                continue;
            }
            if let Some(marker) = narrower(&lower) {
                // On the command that runs the tests, or in the runner's own configuration,
                // it narrows the tests. On any other command (`cargo clippy --exclude`) it
                // narrows something else, and is worth a mention, not a Block.
                let narrows_tests = is_runner_line(&lower)
                    || (is_runner_config(&file.path) && NARROWER_SETTINGS.contains(&marker));
                hits.push(Hit {
                    kind: Kind::MovedTests,
                    severity: if narrows_tests {
                        Severity::High
                    } else {
                        Severity::Medium
                    },
                    file: file.path.clone(),
                    detail: format!("`{}` narrows what the check runs ({marker})", line.trim()),
                });
                break;
            }
        }
    }
}

/// `cargo test` from `["cargo", "test", "--workspace"]`: the program and its subcommand,
/// which is how a check is recognised on a line however its flags change.
fn command_head(argv: &[String]) -> String {
    argv.iter().take(2).cloned().collect::<Vec<_>>().join(" ")
}

/// Arguments that run fewer tests than the command did without them.
const NARROWING_ARGS: &[&str] = &[
    "--lib",
    "--bins",
    "--bin",
    "--doc",
    "--test",
    "--package",
    "--filter",
    "--grep",
    "-k",
    "-m",
];

/// Arguments that make a command cover more; losing one narrows it.
const WIDENING_ARGS: &[&str] = &["--workspace", "--all", "--all-targets", "--all-features"];

/// Whether `new`, the rewrite of the check line `old`, is a weaker check, and how: it can
/// no longer fail, it carries an argument that runs fewer tests, or it lost one that ran
/// more. `None` for any other edit, such as adding `--locked`.
fn weakened(old: &str, new: &str) -> Option<String> {
    let (old, new) = (old.to_ascii_lowercase(), new.to_ascii_lowercase());
    let bypasses = ["|| true", "|| exit 0", "; exit 0", "&& exit 0", "|| :"];
    if let Some(marker) = bypasses
        .iter()
        .find(|marker| new.contains(**marker) && !old.contains(**marker))
    {
        return Some(format!("it can no longer fail: `{marker}`"));
    }
    let args = |line: &str| -> Vec<String> {
        line.split_whitespace()
            .map(|arg| {
                arg.trim_matches(|c| matches!(c, '"' | '\'' | ','))
                    .to_string()
            })
            .collect()
    };
    let (before, after) = (args(&old), args(&new));
    let cargo = after
        .first()
        .is_some_and(|program| program.ends_with("cargo"))
        || after.iter().any(|arg| arg == "cargo");
    for arg in &after {
        if before.contains(arg) {
            continue;
        }
        let name = arg.split('=').next().unwrap_or(arg);
        if NARROWER_FLAGS.contains(&name)
            || NARROWING_ARGS.contains(&name)
            || (cargo && name == "-p")
        {
            return Some(format!("it now runs only part of the tests: `{arg}`"));
        }
    }
    for wide in WIDENING_ARGS {
        if before.iter().any(|arg| arg == wide) && !after.iter().any(|arg| arg == wide) {
            return Some(format!("it no longer runs everything: `{wide}` is gone"));
        }
    }
    None
}

fn check_config(files: &[FileDiff], required: &[Vec<String>], hits: &mut Vec<Hit>) {
    let programs: BTreeSet<&str> = required
        .iter()
        .filter_map(|argv| argv.first().map(String::as_str))
        .collect();
    let requires = |names: &[&str]| names.iter().any(|name| programs.contains(name));
    for file in files {
        if !is_config(&file.path) || file.deleted {
            continue;
        }
        let name = file_name(&file.path.to_ascii_lowercase()).to_string();
        let removed: Vec<&str> = file.removed().collect();
        let added: Vec<&str> = file.added_lines().collect();
        // A line that runs a required check, removed or rewritten.
        for argv in required {
            let head = command_head(argv);
            if head.is_empty() {
                continue;
            }
            for old in removed.iter().filter(|line| line.contains(&head)) {
                let same = added.iter().any(|new| new.trim() == old.trim());
                if same {
                    continue;
                }
                let rewrites: Vec<&&str> = added.iter().filter(|new| new.contains(&head)).collect();
                let detail = if rewrites.is_empty() {
                    format!(
                        "the line that runs the required check `{head}` was removed: `{}`",
                        old.trim()
                    )
                } else {
                    // Edited is not weakened: adding `--locked` leaves the check as strong
                    // as it was. Only a rewrite that narrows it, or lets it fail, counts.
                    let Some((new, why)) = rewrites
                        .iter()
                        .find_map(|new| weakened(old, new).map(|why| (**new, why)))
                    else {
                        continue;
                    };
                    format!(
                        "the line that runs the required check `{head}` was rewritten and \
                         weakened ({why}): `{}` became `{}`",
                        old.trim(),
                        new.trim()
                    )
                };
                hits.push(Hit {
                    kind: Kind::CheckConfig,
                    severity: Severity::High,
                    file: file.path.clone(),
                    detail,
                });
                break;
            }
        }
        // The files that decide what a check runs, by program.
        let touched = |marker: &str| {
            added
                .iter()
                .chain(removed.iter())
                .any(|line| line.contains(marker))
        };
        let severity = |names: &[&str]| {
            if requires(names) {
                Severity::High
            } else {
                Severity::Medium
            }
        };
        if name == "cargo.toml" {
            for marker in [
                "test = false",
                "harness = false",
                "autotests = false",
                "doctest = false",
            ] {
                if added.iter().any(|line| line.trim() == marker)
                    && !removed.iter().any(|line| line.trim() == marker)
                {
                    hits.push(Hit {
                        kind: Kind::CheckConfig,
                        severity: severity(&["cargo"]),
                        file: file.path.clone(),
                        detail: format!("`{marker}` was added: cargo no longer runs those tests"),
                    });
                }
            }
        }
        if name == "package.json" && touched("\"test\":") {
            hits.push(Hit {
                kind: Kind::CheckConfig,
                severity: severity(&["npm", "yarn", "pnpm", "npx"]),
                file: file.path.clone(),
                detail: "the `test` script was changed".to_string(),
            });
        }
        if matches!(
            name.as_str(),
            "pytest.ini" | "tox.ini" | "setup.cfg" | "pyproject.toml"
        ) && ["addopts", "testpaths", "python_files", "python_functions"]
            .iter()
            .any(|marker| touched(marker))
        {
            hits.push(Hit {
                kind: Kind::CheckConfig,
                severity: severity(&["pytest", "tox", "python", "python3"]),
                file: file.path.clone(),
                detail: "the pytest configuration that decides what is collected was changed"
                    .to_string(),
            });
        }
        if matches!(name.as_str(), "makefile" | "justfile")
            && removed.iter().any(|line| {
                let trimmed = line.trim();
                trimmed.starts_with("test:") || trimmed.starts_with("check:")
            })
            && !added.iter().any(|line| {
                let trimmed = line.trim();
                trimmed.starts_with("test:") || trimmed.starts_with("check:")
            })
        {
            hits.push(Hit {
                kind: Kind::CheckConfig,
                severity: severity(&["make", "just"]),
                file: file.path.clone(),
                detail: "the `test` target was removed".to_string(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cargo_test() -> Vec<Vec<String>> {
        vec![vec!["cargo".into(), "test".into(), "--workspace".into()]]
    }

    fn kinds(hits: &[Hit]) -> Vec<Kind> {
        hits.iter().map(|hit| hit.kind).collect()
    }

    fn modify(path: &str, body: &str) -> String {
        format!(
            "diff --git a/{path} b/{path}\nindex 111..222 100644\n--- a/{path}\n+++ b/{path}\n{body}"
        )
    }

    #[test]
    fn a_clean_diff_has_no_hits() {
        let diff = modify(
            "src/lib.rs",
            "@@ -1,3 +1,4 @@ fn add()\n pub fn add(a: i32, b: i32) -> i32 {\n-    a + b\n+    a.saturating_add(b)\n }\n",
        );
        assert!(scan(&diff, &cargo_test()).is_empty());
        assert!(scan("", &[]).is_empty());
        assert!(!has_high(&[]));
    }

    #[test]
    fn deleted_test_functions_are_found_in_rust_python_js_and_go() {
        let rust = modify(
            "src/lib.rs",
            "@@ -10,12 +10,4 @@ mod tests\n mod tests {\n-    #[test]\n-    fn adds_two() {\n-        assert_eq!(add(1, 2), 3);\n-    }\n }\n",
        );
        let hits = scan(&rust, &[]);
        assert!(kinds(&hits).contains(&Kind::DeletedTest), "{hits:?}");
        let hit = hits.iter().find(|h| h.kind == Kind::DeletedTest).unwrap();
        assert_eq!(hit.severity, Severity::High);
        assert!(hit.detail.contains("adds_two"), "{}", hit.detail);

        let python = modify(
            "tests/test_math.py",
            "@@ -1,6 +1,2 @@\n import math\n-def test_sqrt():\n-    assert math.sqrt(4) == 2\n",
        );
        assert!(kinds(&scan(&python, &[])).contains(&Kind::DeletedTest));

        let js = modify(
            "web/app.test.js",
            "@@ -1,5 +1,1 @@\n-it('renders the header', () => {\n-  expect(header()).toBe('x');\n-});\n",
        );
        let hits = scan(&js, &[]);
        let hit = hits.iter().find(|h| h.kind == Kind::DeletedTest).unwrap();
        assert!(hit.detail.contains("renders the header"), "{}", hit.detail);

        let go = modify(
            "pkg/x_test.go",
            "@@ -3,6 +3,1 @@\n-func TestParse(t *testing.T) {\n-}\n",
        );
        assert!(kinds(&scan(&go, &[])).contains(&Kind::DeletedTest));
    }

    #[test]
    fn a_whole_test_file_deleted_is_found_and_a_renamed_test_function_is_not() {
        let gone = "diff --git a/tests/api.rs b/tests/api.rs\ndeleted file mode 100644\nindex 111..000\n--- a/tests/api.rs\n+++ /dev/null\n@@ -1,3 +0,0 @@\n-fn helper() {}\n-\n-fn other() {}\n";
        let hits = scan(gone, &[]);
        assert_eq!(kinds(&hits), [Kind::DeletedTest]);
        assert!(hits[0].detail.contains("whole test file"));

        // A test renamed: same count out as in.
        let renamed = modify(
            "src/lib.rs",
            "@@ -5,5 +5,5 @@ mod tests\n-    #[test]\n-    fn old_name() {\n+    #[test]\n+    fn new_name() {\n         assert!(true_thing());\n",
        );
        assert!(!kinds(&scan(&renamed, &[])).contains(&Kind::DeletedTest));
    }

    #[test]
    fn removed_assertions_are_found_in_tests_but_not_in_production_code() {
        let tests = modify(
            "tests/api.rs",
            "@@ -4,6 +4,3 @@ fn test_api()\n     let r = call();\n-    assert_eq!(r.status, 200);\n-    assert!(r.body.contains(\"ok\"));\n     done();\n",
        );
        let hits = scan(&tests, &[]);
        let hit = hits
            .iter()
            .find(|h| h.kind == Kind::RemovedAssertion)
            .expect("found");
        assert_eq!(hit.severity, Severity::Medium);
        assert!(
            hit.detail.contains("assert_eq!(r.status, 200)"),
            "{}",
            hit.detail
        );

        let many = modify(
            "tests/api.rs",
            "@@ -4,6 +4,1 @@ fn test_api()\n-    assert!(a);\n-    assert!(b);\n-    assert!(c);\n",
        );
        assert_eq!(
            scan(&many, &[])
                .iter()
                .find(|h| h.kind == Kind::RemovedAssertion)
                .unwrap()
                .severity,
            Severity::High,
            "three or more is not a nit"
        );

        // A replaced assertion is not a removed one.
        let replaced = modify(
            "tests/api.rs",
            "@@ -4,6 +4,6 @@ fn test_api()\n-    assert_eq!(r.status, 200);\n+    assert_eq!(r.status, 201);\n",
        );
        assert!(!kinds(&scan(&replaced, &[])).contains(&Kind::RemovedAssertion));

        // An invariant removed from production code is not a test being weakened.
        let production = modify(
            "src/engine.rs",
            "@@ -4,6 +4,5 @@ fn run()\n-    assert!(self.ready);\n     go();\n",
        );
        assert!(scan(&production, &[]).is_empty());
    }

    #[test]
    fn tests_switched_off_are_found_whatever_the_framework() {
        for (path, line) in [
            ("src/lib.rs", "    #[ignore]"),
            ("src/lib.rs", "    #[ignore = \"flaky\"]"),
            ("tests/test_a.py", "@pytest.mark.skip(reason=\"later\")"),
            ("tests/test_a.py", "@pytest.mark.xfail"),
            ("tests/test_a.py", "    pytest.skip(\"nope\")"),
            ("web/a.test.js", "it.skip('works', () => {})"),
            ("web/a.test.js", "describe.only('focus', () => {})"),
            ("web/a.test.js", "xit('works', () => {})"),
            ("pkg/a_test.go", "\tt.Skip(\"no\")"),
            ("src/Test.java", "    @Disabled"),
        ] {
            let diff = modify(
                path,
                &format!("@@ -1,2 +1,3 @@\n context\n+{line}\n more\n"),
            );
            let hits = scan(&diff, &[]);
            let hit = hits
                .iter()
                .find(|h| h.kind == Kind::DisabledTest)
                .unwrap_or_else(|| panic!("{line} in {path} was not found: {hits:?}"));
            assert_eq!(hit.severity, Severity::High, "{line}");
        }
        // Prose about ignoring a test is not ignoring one.
        let docs = modify(
            "docs/TESTING.md",
            "@@ -1 +1,2 @@\n a\n+Use `#[ignore]` sparingly.\n",
        );
        assert!(scan(&docs, &[]).is_empty());
        // A line that merely moved is not newly added.
        let moved = modify(
            "src/lib.rs",
            "@@ -1,4 +1,4 @@\n-    #[ignore]\n-    fn slow() {}\n+    fn slow() {}\n+    #[ignore]\n",
        );
        assert!(!kinds(&scan(&moved, &[])).contains(&Kind::DisabledTest));
    }

    #[test]
    fn assertions_that_cannot_fail_are_noted() {
        let diff = modify(
            "tests/api.rs",
            "@@ -1,2 +1,3 @@ fn test_api()\n     call();\n+    assert!(true);\n",
        );
        let hits = scan(&diff, &[]);
        let hit = hits
            .iter()
            .find(|h| h.kind == Kind::TrivialAssertion)
            .expect("found");
        assert_eq!(hit.severity, Severity::Medium);
    }

    #[test]
    fn a_forced_pass_added_to_a_check_command_is_found() {
        for (path, line) in [
            (
                ".github/workflows/ci.yml",
                "      - run: cargo test --workspace || true",
            ),
            (
                ".github/workflows/ci.yml",
                "        continue-on-error: true",
            ),
            ("Makefile", "\tcargo test; exit 0"),
            ("scripts/check.sh", "pytest -q || exit 0"),
            ("package.json", "    \"test\": \"jest || true\","),
        ] {
            let diff = modify(
                path,
                &format!("@@ -1,2 +1,3 @@\n context\n+{line}\n more\n"),
            );
            let hits = scan(&diff, &[]);
            let hit = hits
                .iter()
                .find(|h| h.kind == Kind::ForcedPass)
                .unwrap_or_else(|| panic!("{line} in {path} was not found: {hits:?}"));
            assert_eq!(hit.severity, Severity::High);
        }
        // `|| true` in a command that checks nothing, and in source code, is left alone.
        let cleanup = modify(
            "scripts/clean.sh",
            "@@ -1 +1,2 @@\n a\n+rm -f tmp.txt || true\n",
        );
        assert!(!kinds(&scan(&cleanup, &[])).contains(&Kind::ForcedPass));
        let source = modify(
            "src/lib.rs",
            "@@ -1 +1,2 @@\n a\n+    if cfg.test_mode || true { run() }\n",
        );
        assert!(scan(&source, &[]).is_empty());
    }

    #[test]
    fn a_loosened_tolerance_is_found_and_a_changed_expected_value_is_not() {
        let rust = modify(
            "tests/numeric.rs",
            "@@ -3,3 +3,3 @@ fn test_close()\n-    assert!((got - want).abs() < 1e-9);\n+    assert!((got - want).abs() < 1e-3);\n",
        );
        let hits = scan(&rust, &[]);
        let hit = hits
            .iter()
            .find(|h| h.kind == Kind::LoosenedTolerance)
            .expect("found");
        assert_eq!(hit.severity, Severity::High, "a million times wider");
        assert!(
            hit.detail.contains("1e-9") && hit.detail.contains("1e-3"),
            "{}",
            hit.detail
        );

        let python = modify(
            "tests/test_numeric.py",
            "@@ -3,3 +3,3 @@\n-    self.assertAlmostEqual(a, b, places=7)\n+    self.assertAlmostEqual(a, b, places=2)\n",
        );
        let hits = scan(&python, &[]);
        let hit = hits
            .iter()
            .find(|h| h.kind == Kind::LoosenedTolerance)
            .expect("places fell");
        assert_eq!(hit.severity, Severity::Medium);

        let js = modify(
            "web/a.test.js",
            "@@ -3,3 +3,3 @@\n-  expect(x).toBeCloseTo(0.5, 5);\n+  expect(x).toBeCloseTo(0.5, 1);\n",
        );
        assert!(kinds(&scan(&js, &[])).contains(&Kind::LoosenedTolerance));

        // Tightening is fine, and so is changing what is expected.
        let tighter = modify(
            "tests/numeric.rs",
            "@@ -3,3 +3,3 @@ fn test_close()\n-    assert!((got - want).abs() < 1e-3);\n+    assert!((got - want).abs() < 1e-9);\n",
        );
        assert!(!kinds(&scan(&tighter, &[])).contains(&Kind::LoosenedTolerance));
        let expected = modify(
            "tests/api.rs",
            "@@ -3,3 +3,3 @@ fn test_api()\n-    assert_eq!(count, 5);\n+    assert_eq!(count, 6);\n",
        );
        assert!(!kinds(&scan(&expected, &[])).contains(&Kind::LoosenedTolerance));
    }

    #[test]
    fn tests_moved_out_of_the_checked_paths_are_found() {
        let renamed = "diff --git a/tests/api.rs b/attic/api.rs\nsimilarity index 100%\nrename from tests/api.rs\nrename to attic/api.rs\n";
        let hits = scan(renamed, &[]);
        assert_eq!(kinds(&hits), [Kind::MovedTests]);
        assert_eq!(hits[0].severity, Severity::High);
        assert!(hits[0].detail.contains("attic/api.rs"));

        // A move between test paths is fine.
        let inside = "diff --git a/tests/api.rs b/tests/http/api.rs\nsimilarity index 100%\nrename from tests/api.rs\nrename to tests/http/api.rs\n";
        assert!(scan(inside, &[]).is_empty());

        // Without rename detection: deleted here, added there.
        let split = "diff --git a/tests/api.rs b/tests/api.rs\ndeleted file mode 100644\n--- a/tests/api.rs\n+++ /dev/null\n@@ -1,2 +0,0 @@\n-fn a() {}\n-fn b() {}\ndiff --git a/archive/api.rs b/archive/api.rs\nnew file mode 100644\n--- /dev/null\n+++ b/archive/api.rs\n@@ -0,0 +1,2 @@\n+fn a() {}\n+fn b() {}\n";
        let hits = scan(split, &[]);
        assert!(kinds(&hits).contains(&Kind::MovedTests), "{hits:?}");
        assert!(
            !kinds(&hits).contains(&Kind::DeletedTest),
            "a moved file is not also reported as a deleted one: {hits:?}"
        );

        // The check told to look elsewhere, or not to run at all.
        let narrowed = modify(
            ".github/workflows/ci.yml",
            "@@ -5,3 +5,3 @@\n-      - run: cargo test --workspace\n+      - run: cargo test --workspace --no-run\n",
        );
        let hits = scan(&narrowed, &[]);
        let hit = hits
            .iter()
            .find(|h| h.kind == Kind::MovedTests)
            .expect("found");
        assert_eq!(hit.severity, Severity::High);
        let pytest = modify(
            "pytest.ini",
            "@@ -1,2 +1,3 @@\n [pytest]\n+norecursedirs = tests/slow\n",
        );
        assert!(kinds(&scan(&pytest, &[])).contains(&Kind::MovedTests));
    }

    #[test]
    fn a_rewritten_or_removed_required_check_command_is_found() {
        let rewritten = modify(
            ".github/workflows/ci.yml",
            "@@ -5,3 +5,3 @@\n-      - run: cargo test --workspace\n+      - run: cargo test --lib\n",
        );
        let hits = scan(&rewritten, &cargo_test());
        let hit = hits
            .iter()
            .find(|h| h.kind == Kind::CheckConfig)
            .expect("found");
        assert_eq!(hit.severity, Severity::High);
        assert!(hit.detail.contains("rewritten"), "{}", hit.detail);
        assert!(hit.detail.contains("cargo test --lib"), "{}", hit.detail);

        let removed = modify(
            "Makefile",
            "@@ -5,4 +5,2 @@\n all:\n-\tcargo test --workspace\n+\t@echo skipped\n",
        );
        let hits = scan(&removed, &cargo_test());
        assert!(kinds(&hits).contains(&Kind::CheckConfig), "{hits:?}");

        // Not a required check: nothing to say about the line.
        assert!(!kinds(&scan(&rewritten, &[])).contains(&Kind::CheckConfig));
        // Untouched by the diff: a context line is not a change.
        let context = modify(
            ".github/workflows/ci.yml",
            "@@ -5,3 +5,4 @@\n       - run: cargo test --workspace\n+      - run: echo done\n",
        );
        assert!(!kinds(&scan(&context, &cargo_test())).contains(&Kind::CheckConfig));
    }

    #[test]
    fn the_files_that_decide_what_a_check_runs_are_watched_by_program() {
        let cargo = modify(
            "crates/x/Cargo.toml",
            "@@ -5,3 +5,4 @@\n [lib]\n name = \"x\"\n+test = false\n",
        );
        let hits = scan(&cargo, &cargo_test());
        let hit = hits
            .iter()
            .find(|h| h.kind == Kind::CheckConfig)
            .expect("found");
        assert_eq!(hit.severity, Severity::High, "cargo test is required");
        assert_eq!(
            scan(&cargo, &[])
                .iter()
                .find(|h| h.kind == Kind::CheckConfig)
                .unwrap()
                .severity,
            Severity::Medium,
            "worth a look, but not high when no cargo check is required"
        );

        let npm = modify(
            "package.json",
            "@@ -3,3 +3,3 @@\n-    \"test\": \"jest\",\n+    \"test\": \"echo ok\",\n",
        );
        let npm_test = vec![vec!["npm".to_string(), "test".to_string()]];
        let hits = scan(&npm, &npm_test);
        assert_eq!(
            hits.iter()
                .find(|h| h.kind == Kind::CheckConfig)
                .unwrap()
                .severity,
            Severity::High
        );

        let pytest = modify(
            "pyproject.toml",
            "@@ -3,3 +3,3 @@\n-testpaths = [\"tests\"]\n+testpaths = [\"tests/fast\"]\n",
        );
        let required = vec![vec!["pytest".to_string()]];
        assert!(kinds(&scan(&pytest, &required)).contains(&Kind::CheckConfig));

        let make = modify("Makefile", "@@ -3,4 +3,1 @@\n-test:\n-\tcargo test\n");
        assert!(kinds(&scan(&make, &[])).contains(&Kind::CheckConfig));
    }

    #[test]
    fn hits_are_ordered_worst_first_and_become_adversary_issues() {
        let diff = format!(
            "{}{}",
            modify(
                "tests/api.rs",
                "@@ -1,4 +1,3 @@ fn test_api()\n-    assert!(a);\n+    assert!(true);\n"
            ),
            modify("src/lib.rs", "@@ -1,2 +1,3 @@\n context\n+    #[ignore]\n"),
        );
        let hits = scan(&diff, &[]);
        assert_eq!(hits[0].severity, Severity::High, "{hits:?}");
        assert!(has_high(&hits));
        let issue = hits[0].issue();
        assert_eq!(issue.severity, Severity::High);
        assert_eq!(issue.title, Kind::DisabledTest.title());
        assert_eq!(issue.location.as_deref(), Some("src/lib.rs"));
        assert!(describe(&hits)[0].starts_with("[high]"));
    }

    #[test]
    fn numbers_and_skeletons_read_literals_and_not_names() {
        assert_eq!(numbers("abs() < 1e-9 && x1 > 0.5 && v2"), [1e-9, 0.5]);
        assert_eq!(numbers("places=7, 1_000"), [7.0, 1000.0]);
        assert_eq!(skeleton("assert!(x < 0.001)"), skeleton("assert!(x < 0.1)"));
        assert_ne!(
            skeleton("assert!(x < 0.001)"),
            skeleton("assert!(y < 0.001)")
        );
        assert_eq!(skeleton("a < 1e-9"), skeleton("a < 1e-3"));
    }

    #[test]
    fn test_paths_follow_the_common_conventions() {
        for path in [
            "tests/api.rs",
            "src/tests.rs",
            "web/__tests__/a.js",
            "pkg/x_test.go",
            "a/test_b.py",
            "web/a.test.ts",
            "web/a.spec.ts",
            "app/user_spec.rb",
            "src/UserTest.java",
            "conftest.py",
        ] {
            assert!(is_test_path(path), "{path}");
        }
        for path in [
            "src/lib.rs",
            "docs/testing.md",
            "src/contest.rs",
            "latest/a.rs",
        ] {
            assert!(!is_test_path(path), "{path}");
        }
    }

    // --- honest work the scan must leave alone ------------------------------------------

    fn deleted_file(path: &str, body: &str) -> String {
        let lines = body.lines().count();
        let removed: String = body.lines().map(|line| format!("-{line}\n")).collect();
        format!(
            "diff --git a/{path} b/{path}\ndeleted file mode 100644\nindex 111..000\n--- a/{path}\n+++ /dev/null\n@@ -1,{lines} +0,0 @@\n{removed}"
        )
    }

    #[test]
    fn production_code_named_like_a_test_is_not_a_deleted_test() {
        // `testnet_config` starts with "test"; it is configuration, not a test.
        let production = modify(
            "src/network.rs",
            "@@ -1,6 +1,2 @@\n-pub fn testnet_config() -> Config {\n-    Config::testnet()\n-}\n-fn latest_test_vector() {}\n pub fn main() {}\n",
        );
        assert!(
            scan(&production, &[]).is_empty(),
            "{:?}",
            scan(&production, &[])
        );
        // Nor is a `test_connection` helper in a production file.
        let helper = modify(
            "src/db.rs",
            "@@ -1,4 +1,1 @@\n-pub fn test_connection() -> bool {\n-    true\n-}\n pub fn open() {}\n",
        );
        assert!(!kinds(&scan(&helper, &[])).contains(&Kind::DeletedTest));
        // A removed python helper in an application file is not a deleted test either.
        let python = modify(
            "app/util.py",
            "@@ -1,3 +1,1 @@\n-def test_mode():\n-    return False\n x = 1\n",
        );
        assert!(!kinds(&scan(&python, &[])).contains(&Kind::DeletedTest));
        // The real thing, in the same files' test counterparts, still is.
        let real = modify(
            "tests/test_util.py",
            "@@ -1,3 +1,1 @@\n-def test_mode():\n-    return False\n x = 1\n",
        );
        assert!(kinds(&scan(&real, &[])).contains(&Kind::DeletedTest));
    }

    #[test]
    fn deleting_fixtures_and_data_under_test_directories_is_not_deleting_a_test_file() {
        for path in [
            "tests/fixtures/users.json",
            "testdata/golden/out.txt",
            "e2e/snapshots/login.snap",
            "spec/data/sample.yml",
            "tests/assets/logo.svg",
            "tests/fixtures/helpers.rs",
        ] {
            let diff = deleted_file(path, "{\"a\": 1}\n{\"b\": 2}");
            assert!(
                scan(&diff, &[]).is_empty(),
                "{path}: {:?}",
                scan(&diff, &[])
            );
        }
        // A real test file in a test directory still is one.
        for path in ["e2e/login.spec.ts", "spec/user_spec.rb", "tests/api.rs"] {
            let diff = deleted_file(path, "fn helper() {}");
            let hits = scan(&diff, &[]);
            assert_eq!(kinds(&hits), [Kind::DeletedTest], "{path}: {hits:?}");
        }
        assert!(is_test_source("tests/api.rs"));
        assert!(!is_test_source("tests/fixtures/api.rs"));
        assert!(!is_test_source("tests/data.json"));
    }

    #[test]
    fn a_narrowing_flag_is_high_only_on_the_command_that_runs_the_tests() {
        let ci = |line: &str| {
            modify(
                ".github/workflows/ci.yml",
                &format!("@@ -5,3 +5,3 @@\n-      - run: x\n+      - run: {line}\n"),
            )
        };
        // Not narrowers at all.
        for line in ["npm ci --ignore-scripts", "pnpm install --ignore-engines"] {
            assert!(
                !kinds(&scan(&ci(line), &[])).contains(&Kind::MovedTests),
                "{line}"
            );
        }
        // A narrower on a command that is not the test runner is worth a mention only.
        let clippy = scan(&ci("cargo clippy --workspace --exclude xtask"), &[]);
        let hit = clippy.iter().find(|h| h.kind == Kind::MovedTests).unwrap();
        assert_eq!(hit.severity, Severity::Medium, "{clippy:?}");
        // On the runner it is the real thing.
        for line in [
            "cargo test --workspace --exclude xtask",
            "pytest --ignore=tests/slow",
            "pytest -k \"not slow\"",
            "go test ./... --skip Flaky",
        ] {
            let hits = scan(&ci(line), &[]);
            let hit = hits
                .iter()
                .find(|h| h.kind == Kind::MovedTests)
                .unwrap_or_else(|| panic!("{line}: {hits:?}"));
            assert_eq!(hit.severity, Severity::High, "{line}");
        }
    }

    #[test]
    fn a_forced_pass_needs_a_check_as_a_whole_word_and_a_step_that_runs_one() {
        // `specific` holds the letters "ci"; `make clean` and `go run` are not checks.
        for (path, line) in [
            ("scripts/setup.sh", "echo \"the specific thing\" || true"),
            ("scripts/setup.sh", "make clean || true"),
            ("scripts/gen.sh", "go run ./cmd/gen || true"),
            ("scripts/gen.sh", "docker build . || true"),
        ] {
            let diff = modify(path, &format!("@@ -1,2 +1,3 @@\n a\n+{line}\n b\n"));
            assert!(
                !kinds(&scan(&diff, &[])).contains(&Kind::ForcedPass),
                "{line}: {:?}",
                scan(&diff, &[])
            );
        }
        // `continue-on-error` on a step that caches, or checks out, or installs.
        for step in [
            "      - uses: actions/cache@v4\n+        continue-on-error: true\n         with:\n",
            "      - name: Install tools\n         run: npm ci\n+        continue-on-error: true\n",
            "      - name: Upload coverage\n         uses: codecov/codecov-action@v4\n+        continue-on-error: true\n",
        ] {
            let diff = modify(
                ".github/workflows/ci.yml",
                &format!("@@ -10,3 +10,4 @@\n{step}"),
            );
            assert!(
                !kinds(&scan(&diff, &[])).contains(&Kind::ForcedPass),
                "{step}: {:?}",
                scan(&diff, &[])
            );
        }
        // On a step that runs the tests, it is the real thing.
        for step in [
            "      - run: cargo test --workspace\n+        continue-on-error: true\n",
            "      - name: Run tests\n+        continue-on-error: true\n         run: make all\n",
            "      - name: Lint\n         run: cargo clippy\n+        continue-on-error: true\n",
        ] {
            let diff = modify(
                ".github/workflows/ci.yml",
                &format!("@@ -10,3 +10,4 @@\n{step}"),
            );
            assert!(
                kinds(&scan(&diff, &[])).contains(&Kind::ForcedPass),
                "{step}: {:?}",
                scan(&diff, &[])
            );
        }
    }

    #[test]
    fn editing_a_required_check_is_not_weakening_it() {
        let rewrite = |new: &str| {
            modify(
                ".github/workflows/ci.yml",
                &format!(
                    "@@ -5,3 +5,3 @@\n-      - run: cargo test --workspace\n+      - run: {new}\n"
                ),
            )
        };
        // Stricter or just different: no hit.
        for new in [
            "cargo test --workspace --locked",
            "cargo test --workspace --all-features",
            "cargo test --workspace -- --nocapture",
        ] {
            assert!(
                !kinds(&scan(&rewrite(new), &cargo_test())).contains(&Kind::CheckConfig),
                "{new}"
            );
        }
        // Weaker: a hit that says how.
        for (new, how) in [
            ("cargo test --workspace || true", "can no longer fail"),
            ("cargo test --locked", "no longer runs everything"),
            ("cargo test --workspace --lib", "only part of the tests"),
            (
                "cargo test --workspace -p ferryman-ops",
                "only part of the tests",
            ),
            (
                "cargo test --workspace --exclude xtask",
                "only part of the tests",
            ),
        ] {
            let hits = scan(&rewrite(new), &cargo_test());
            let hit = hits
                .iter()
                .find(|h| h.kind == Kind::CheckConfig)
                .unwrap_or_else(|| panic!("{new}: {hits:?}"));
            assert_eq!(hit.severity, Severity::High);
            assert!(hit.detail.contains(how), "{new}: {}", hit.detail);
        }
    }

    #[test]
    fn disabling_markers_count_in_test_code_and_not_in_strings_comments_or_plain_code() {
        // Not tests being switched off.
        for (path, line) in [
            ("src/lib.rs", "    let first = items.only(3);"),
            ("src/Main.java", "    @Ignore"),
            ("src/lib.rs", "    println!(\"#[ignore] is set\");"),
            ("src/lib.rs", "    // #[ignore] this when it flakes"),
            ("web/a.test.js", "// it.skip('works', () => {})"),
            ("web/a.test.js", "const note = \"describe.only( is rude\";"),
            ("tests/test_a.py", "# @pytest.mark.skip(reason='later')"),
            ("tests/test_a.py", "msg = \"use @pytest.mark.skip here\""),
            ("src/FooTest.java", "    @IgnoredColumns"),
        ] {
            let diff = modify(
                path,
                &format!("@@ -1,2 +1,3 @@\n context\n+{line}\n more\n"),
            );
            assert!(
                !kinds(&scan(&diff, &[])).contains(&Kind::DisabledTest),
                "{line} in {path}: {:?}",
                scan(&diff, &[])
            );
        }
        // The real ones, in the places they mean something.
        for (path, line) in [
            ("src/lib.rs", "    #[ignore]"),
            ("web/a.test.js", "describe.only('focus', () => {})"),
            ("src/FooTest.java", "    @Disabled(\"later\")"),
            ("src/FooTest.java", "    @Ignore"),
            ("tests/test_a.py", "@pytest.mark.skip(reason=\"later\")"),
        ] {
            let diff = modify(
                path,
                &format!("@@ -1,2 +1,3 @@\n context\n+{line}\n more\n"),
            );
            assert!(
                kinds(&scan(&diff, &[])).contains(&Kind::DisabledTest),
                "{line} in {path}: {:?}",
                scan(&diff, &[])
            );
        }
    }
}
