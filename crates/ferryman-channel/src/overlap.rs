//! File-overlap locks: noticing two orders that are heading for the same files before
//! they meet at merge.
//!
//! Parallel agents each work in their own git worktree, so nothing stops two of them
//! editing `src/api/mod.rs` at once; they find out when the second branch will not merge.
//! An order may therefore declare `touches`, repo-relative globs of the files it expects
//! to edit, and the fleet uses it three ways:
//!
//! - when an order is issued, [`issue_warnings`] lists the open or claimed orders whose
//!   `touches` overlap it;
//! - when a worker is about to claim an order, [`claim_hold`] says whether one that is
//!   currently `Claimed` overlaps it, and the worker moves on to the next task instead;
//! - after the worker commits, [`outside`] says which changed files fall outside what the
//!   order declared, as a note for the reviewer.
//!
//! It is advisory, and says so. The declaration is the issuer's estimate; the lock is a
//! courtesy between honest workers (two workers can still claim overlapping orders in the
//! same second, before either sees the other's claim); an order that really must run
//! alongside another sets `allow_overlap`. Nothing here refuses work for good or refutes
//! a result.
//!
//! # What "overlap" means
//!
//! Deliberately conservative, and cheap: only the literal text before each glob's first
//! wildcard is compared, so a false alarm is possible and a miss is not. `src/**` overlaps
//! `src/api/x.rs`; `src/api/**` does not overlap `src/apiv2/x.rs`; `**` overlaps
//! everything. Comparison ignores case, because the machines doing the work include
//! Windows ones.

use serde::Serialize;

use crate::{Order, ProjectRoute, SignatureCheck, Task, TaskState};

/// The most paths named in a scope note.
const NOTE_PATHS: usize = 20;

fn is_wild(c: char) -> bool {
    matches!(c, '*' | '?' | '[' | '{')
}

/// Forward slashes, no leading `./` or `/`, lower case.
fn normalize(text: &str) -> String {
    let swapped = text.trim().replace('\\', "/");
    swapped
        .trim_start_matches("./")
        .trim_start_matches('/')
        .to_lowercase()
}

/// A glob reduced to what the overlap test needs.
struct Pattern {
    /// The text before the first wildcard (or the whole path, if there is none).
    prefix: String,
    wild: bool,
}

fn pattern(glob: &str) -> Pattern {
    let text = normalize(glob);
    match text.find(is_wild) {
        Some(at) => Pattern {
            prefix: text[..at].to_string(),
            wild: true,
        },
        None => Pattern {
            prefix: text.trim_end_matches('/').to_string(),
            wild: false,
        },
    }
}

/// Whether `inner` is `dir` itself or lies under it, on a path-segment boundary.
fn within(dir: &str, inner: &str) -> bool {
    inner == dir || inner.starts_with(&format!("{dir}/"))
}

fn wild_against_literal(wild: &Pattern, literal: &Pattern) -> bool {
    // The wildcard may stand for anything, so a literal that begins with the wildcard's
    // prefix is reachable by it - even part-way through a segment (`src/ap*` reaches
    // `src/apiv2`). The other way round, a literal directory contains the glob outright.
    literal.prefix.starts_with(&wild.prefix) || within(&literal.prefix, &wild.prefix)
}

fn overlap_pair(a: &Pattern, b: &Pattern) -> bool {
    match (a.wild, b.wild) {
        (false, false) => within(&a.prefix, &b.prefix) || within(&b.prefix, &a.prefix),
        (true, true) => a.prefix.starts_with(&b.prefix) || b.prefix.starts_with(&a.prefix),
        (true, false) => wild_against_literal(a, b),
        (false, true) => wild_against_literal(b, a),
    }
}

/// The pairs of globs, one from each list, that may refer to the same file.
///
/// Conservative: see the module documentation. An empty list never overlaps anything.
#[must_use]
pub fn overlaps(a: &[String], b: &[String]) -> Vec<(String, String)> {
    let left: Vec<(&String, Pattern)> = a
        .iter()
        .filter(|glob| !glob.trim().is_empty())
        .map(|glob| (glob, pattern(glob)))
        .collect();
    let right: Vec<(&String, Pattern)> = b
        .iter()
        .filter(|glob| !glob.trim().is_empty())
        .map(|glob| (glob, pattern(glob)))
        .collect();
    let mut found = Vec::new();
    for (left_glob, left_pattern) in &left {
        for (right_glob, right_pattern) in &right {
            if overlap_pair(left_pattern, right_pattern) {
                found.push(((*left_glob).clone(), (*right_glob).clone()));
            }
        }
    }
    found
}

// --- matching one path against one glob ---------------------------------------------------

/// `a{b,c}d` as `abd` and `acd`. One level only, which is all a file glob needs.
fn expand_braces(glob: &str) -> Vec<String> {
    let Some(open) = glob.find('{') else {
        return vec![glob.to_string()];
    };
    let Some(close) = glob[open..].find('}').map(|at| at + open) else {
        return vec![glob.to_string()];
    };
    let (head, tail) = (&glob[..open], &glob[close + 1..]);
    glob[open + 1..close]
        .split(',')
        .flat_map(|choice| expand_braces(&format!("{head}{choice}{tail}")))
        .collect()
}

fn class_matches(class: &[char], c: char) -> bool {
    let (negated, body) = match class.first() {
        Some('!' | '^') => (true, &class[1..]),
        _ => (false, class),
    };
    let mut hit = false;
    let mut at = 0;
    while at < body.len() {
        if at + 2 < body.len() && body[at + 1] == '-' {
            hit |= body[at] <= c && c <= body[at + 2];
            at += 3;
        } else {
            hit |= body[at] == c;
            at += 1;
        }
    }
    hit != negated
}

fn glob_here(pat: &[char], text: &[char]) -> bool {
    let Some(&first) = pat.first() else {
        return text.is_empty();
    };
    match first {
        '*' if pat.get(1) == Some(&'*') => {
            let rest = &pat[2..];
            if rest.first() == Some(&'/') {
                // `**/` stands for any number of whole directories, including none.
                let after = &rest[1..];
                glob_here(after, text)
                    || (0..text.len()).any(|i| text[i] == '/' && glob_here(after, &text[i + 1..]))
            } else {
                (0..=text.len()).any(|i| glob_here(rest, &text[i..]))
            }
        }
        '*' => {
            let rest = &pat[1..];
            for i in 0..=text.len() {
                if glob_here(rest, &text[i..]) {
                    return true;
                }
                if text.get(i) == Some(&'/') {
                    break;
                }
            }
            false
        }
        '?' => text.first().is_some_and(|&c| c != '/') && glob_here(&pat[1..], &text[1..]),
        '[' => match pat.iter().skip(2).position(|&c| c == ']') {
            Some(end) => {
                let end = end + 2;
                text.first()
                    .is_some_and(|&c| c != '/' && class_matches(&pat[1..end], c))
                    && glob_here(&pat[end + 1..], &text[1..])
            }
            None => text.first() == Some(&'[') && glob_here(&pat[1..], &text[1..]),
        },
        literal => text.first() == Some(&literal) && glob_here(&pat[1..], &text[1..]),
    }
}

/// Whether `path` is one of the files `glob` stands for. `*` stays inside a directory,
/// `**` crosses them, `?` is one character, `[a-z]` a class, `{a,b}` a choice. A glob with
/// no wildcard also covers everything under it, so `src/api` covers `src/api/x.rs`.
#[must_use]
pub fn glob_matches(glob: &str, path: &str) -> bool {
    let path = normalize(path);
    let text: Vec<char> = path.chars().collect();
    expand_braces(&normalize(glob)).iter().any(|one| {
        let chars: Vec<char> = one.chars().collect();
        glob_here(&chars, &text)
            || (!one.contains(is_wild) && within(one.trim_end_matches('/'), &path))
    })
}

/// The changed paths no declared glob covers. Empty when nothing was declared: an order
/// that did not say what it would touch cannot stray from it.
#[must_use]
pub fn outside(touches: &[String], changed: &[String]) -> Vec<String> {
    if touches.iter().all(|glob| glob.trim().is_empty()) {
        return Vec::new();
    }
    changed
        .iter()
        .filter(|path| !touches.iter().any(|glob| glob_matches(glob, path)))
        .cloned()
        .collect()
}

/// The note for a reviewer when a worker's commit touched files its order did not
/// declare. Information, labelled as such: an order's `touches` is an estimate, and a
/// good change may need one file more than anyone expected. It never refutes a result.
#[must_use]
pub fn scope_note(touches: &[String], changed: &[String]) -> Option<String> {
    let strayed = outside(touches, changed);
    if strayed.is_empty() {
        return None;
    }
    let shown: Vec<&str> = strayed
        .iter()
        .take(NOTE_PATHS)
        .map(String::as_str)
        .collect();
    let more = strayed.len().saturating_sub(NOTE_PATHS);
    Some(format!(
        "note for reviewers (information, not a refutation): {} changed file(s) fall outside \
         the order's declared touches [{}]: {}{}",
        strayed.len(),
        touches.join(", "),
        shown.join(", "),
        if more > 0 {
            format!(" and {more} more")
        } else {
            String::new()
        }
    ))
}

// --- who else is on these files -----------------------------------------------------------

/// Another order whose files overlap, and why.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct OverlapWarning {
    pub order_id: String,
    /// `open`, `claimed`, `stale` or `changes-requested`.
    pub state: String,
    /// Who holds it, once someone does.
    pub holder: Option<String>,
    /// Each pair is (this order's glob, the other order's glob).
    pub pairs: Vec<(String, String)>,
}

impl OverlapWarning {
    /// One line for a person.
    #[must_use]
    pub fn describe(&self) -> String {
        let pairs: Vec<String> = self
            .pairs
            .iter()
            .map(|(a, b)| format!("{a} ~ {b}"))
            .collect();
        format!(
            "{} ({}{}): {}",
            self.order_id,
            self.state,
            self.holder
                .as_deref()
                .map(|who| format!(" by {who}"))
                .unwrap_or_default(),
            pairs.join(", ")
        )
    }
}

/// Orders somebody is, or is about to be, working on. A finished, killed or refuted
/// order is no longer a place two agents can collide.
fn active_state(task: &Task) -> Option<&'static str> {
    match task.state() {
        TaskState::Open | TaskState::Offered { .. } => Some("open"),
        TaskState::Claimed { .. } => Some("claimed"),
        TaskState::Stale { .. } => Some("stale"),
        TaskState::ChangesRequested { .. } => Some("changes-requested"),
        _ => None,
    }
}

fn warning_against(
    route: &ProjectRoute,
    touches: &[String],
    exclude: &str,
    other: &Task,
) -> Option<OverlapWarning> {
    if other.order.id == exclude || other.order.touches.is_empty() {
        return None;
    }
    let state = active_state(other)?;
    // Only orders that would be acted on count: a forged or unsigned order must not be
    // able to keep real work waiting.
    if crate::verify_order_in(route, &other.order) != SignatureCheck::Valid {
        return None;
    }
    let pairs = overlaps(touches, &other.order.touches);
    (!pairs.is_empty()).then(|| OverlapWarning {
        order_id: other.order.id.clone(),
        state: state.to_string(),
        holder: other.holder().map(str::to_string),
        pairs,
    })
}

/// The open or claimed orders in this project whose `touches` overlap `order`'s. Called
/// when an order is issued, so the issuer hears about it while it is still cheap to
/// reorder or narrow either one. Empty when `order` declares nothing.
pub fn issue_warnings(route: &ProjectRoute, order: &Order) -> anyhow::Result<Vec<OverlapWarning>> {
    if order.touches.is_empty() {
        return Ok(Vec::new());
    }
    Ok(crate::list_tasks(route)?
        .iter()
        .filter_map(|other| warning_against(route, &order.touches, &order.id, other))
        .collect())
}

/// For each order that declares `touches`, the other active orders it overlaps. What the
/// dashboard shows on an order card.
#[must_use]
pub fn overlap_map(
    route: &ProjectRoute,
    tasks: &[Task],
) -> std::collections::BTreeMap<String, Vec<OverlapWarning>> {
    let mut map = std::collections::BTreeMap::new();
    for task in tasks {
        if task.order.touches.is_empty() || active_state(task).is_none() {
            continue;
        }
        let found: Vec<OverlapWarning> = tasks
            .iter()
            .filter_map(|other| warning_against(route, &task.order.touches, &task.order.id, other))
            .collect();
        if !found.is_empty() {
            map.insert(task.order.id.clone(), found);
        }
    }
    map
}

/// Why a worker should not claim `order` right now: an order currently `Claimed` - not
/// merely stale - by anyone in this project has `touches` that overlap it. `None` when it
/// is free to claim, including whenever it says `allow_overlap` or declares nothing.
///
/// The channel is read fresh each time, so an order this same worker claimed a moment ago
/// in the same pass counts.
pub fn claim_hold(route: &ProjectRoute, order: &Order) -> anyhow::Result<Option<String>> {
    if order.allow_overlap || order.touches.is_empty() {
        return Ok(None);
    }
    for other in crate::list_tasks(route)? {
        let TaskState::Claimed { by } = other.state() else {
            continue;
        };
        if let Some(found) = warning_against(route, &order.touches, &order.id, &other) {
            // No times, no counts: the reason is compared to the last one written, and a
            // line that changed every pass would be rewritten every pass.
            let pairs: Vec<String> = found
                .pairs
                .iter()
                .map(|(a, b)| format!("{a} ~ {b}"))
                .collect();
            return Ok(Some(format!(
                "file overlap with {}, claimed by {by}: {}",
                found.order_id,
                pairs.join(", ")
            )));
        }
    }
    Ok(None)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{AgentIdentity, AgentRoute, Claim};
    use chrono::Utc;
    use serde_json::json;
    use std::fs;
    use std::path::Path;

    fn globs(list: &[&str]) -> Vec<String> {
        list.iter().map(ToString::to_string).collect()
    }

    fn overlap(a: &[&str], b: &[&str]) -> bool {
        !overlaps(&globs(a), &globs(b)).is_empty()
    }

    #[test]
    fn a_wildcard_directory_overlaps_a_file_inside_it() {
        assert!(overlap(&["src/**"], &["src/api/x.rs"]));
        assert!(overlap(&["src/api/x.rs"], &["src/**"]));
    }

    #[test]
    fn a_directory_does_not_overlap_a_sibling_that_merely_shares_its_spelling() {
        assert!(!overlap(&["src/api/**"], &["src/apiv2/x.rs"]));
        assert!(!overlap(&["src/apiv2/x.rs"], &["src/api/**"]));
        assert!(!overlap(&["src/api/**"], &["src/apiv2/**"]));
        assert!(!overlap(&["src/api"], &["src/apiv2/x.rs"]));
    }

    #[test]
    fn a_double_star_overlaps_everything() {
        assert!(overlap(&["**"], &["src/api/x.rs"]));
        assert!(overlap(&["docs/readme.md"], &["**"]));
        assert!(overlap(&["**"], &["**"]));
        assert!(
            overlap(&["*.rs"], &["docs/readme.md"]),
            "no prefix to rule it out"
        );
    }

    #[test]
    fn identical_literals_overlap_and_different_ones_do_not() {
        assert!(overlap(&["Cargo.toml"], &["Cargo.toml"]));
        assert!(!overlap(&["Cargo.toml"], &["Cargo.lock"]));
        assert!(!overlap(&["src/a.rs"], &["src/b.rs"]));
    }

    #[test]
    fn a_literal_directory_overlaps_what_is_under_it_but_not_its_namesakes() {
        assert!(overlap(&["src/api"], &["src/api/x.rs"]));
        assert!(overlap(&["src/api/"], &["src/api/**"]));
        assert!(!overlap(&["src/api"], &["src/apiary.rs"]));
    }

    #[test]
    fn two_wildcard_globs_overlap_when_their_prefixes_nest() {
        assert!(overlap(&["src/**"], &["src/api/**"]));
        assert!(overlap(&["src/a*"], &["src/api/**"]));
        assert!(!overlap(&["docs/**"], &["src/**"]));
    }

    #[test]
    fn a_wildcard_inside_a_segment_reaches_what_starts_with_its_prefix() {
        assert!(overlap(&["src/api*"], &["src/apiv2/x.rs"]));
        assert!(!overlap(&["src/api*"], &["src/ap/x.rs"]));
    }

    #[test]
    fn empty_lists_and_blank_globs_never_overlap() {
        assert!(!overlap(&[], &["**"]));
        assert!(!overlap(&["**"], &[]));
        assert!(!overlap(&[], &[]));
        assert!(!overlap(&["  "], &["**"]));
    }

    #[test]
    fn spelling_differences_that_name_the_same_path_do_not_hide_an_overlap() {
        assert!(overlap(&["./src/**"], &["src/api/x.rs"]));
        assert!(overlap(&["src\\api\\x.rs"], &["src/**"]));
        assert!(overlap(&["SRC/**"], &["src/api/x.rs"]));
    }

    #[test]
    fn the_overlapping_pairs_are_reported() {
        let found = overlaps(
            &globs(&["src/**", "docs/**"]),
            &globs(&["src/a.rs", "web/x"]),
        );
        assert_eq!(found, vec![("src/**".to_string(), "src/a.rs".to_string())]);
    }

    #[test]
    fn globs_match_paths_the_way_a_person_reads_them() {
        assert!(glob_matches("src/**", "src/a/b/c.rs"));
        assert!(glob_matches("src/*.rs", "src/a.rs"));
        assert!(!glob_matches("src/*.rs", "src/a/b.rs"));
        assert!(glob_matches("src/**/*.rs", "src/a.rs"));
        assert!(glob_matches("src/**/*.rs", "src/a/b/c.rs"));
        assert!(!glob_matches("src/**/*.rs", "src/a/b/c.txt"));
        assert!(glob_matches("**/mod.rs", "src/api/mod.rs"));
        assert!(glob_matches("**/mod.rs", "mod.rs"));
        assert!(glob_matches("src/?.rs", "src/a.rs"));
        assert!(!glob_matches("src/?.rs", "src/ab.rs"));
        assert!(glob_matches("src/[a-c].rs", "src/b.rs"));
        assert!(!glob_matches("src/[a-c].rs", "src/d.rs"));
        assert!(glob_matches("src/[!a].rs", "src/b.rs"));
        assert!(glob_matches("web/*.{ts,tsx}", "web/app.tsx"));
        assert!(!glob_matches("web/*.{ts,tsx}", "web/app.js"));
        assert!(glob_matches("SRC/Api.rs", "src/api.rs"));
    }

    #[test]
    fn a_literal_glob_covers_what_is_under_it() {
        assert!(glob_matches("src/api", "src/api/x.rs"));
        assert!(glob_matches("src/api/", "src/api/x.rs"));
        assert!(!glob_matches("src/api", "src/apiv2/x.rs"));
    }

    #[test]
    fn only_files_no_glob_covers_are_outside() {
        let touches = globs(&["src/api/**", "Cargo.toml"]);
        let changed = globs(&["src/api/a.rs", "Cargo.toml", "docs/x.md", "src/web/b.rs"]);
        assert_eq!(
            outside(&touches, &changed),
            vec!["docs/x.md", "src/web/b.rs"]
        );
        assert!(
            outside(&[], &changed).is_empty(),
            "nothing declared, nothing strayed"
        );
        assert!(outside(&touches, &globs(&["src/api/a.rs"])).is_empty());
    }

    #[test]
    fn the_scope_note_says_it_is_information_and_names_the_strays() {
        let note = scope_note(
            &globs(&["src/api/**"]),
            &globs(&["src/api/a.rs", "docs/x.md"]),
        )
        .unwrap();
        assert!(note.contains("information, not a refutation"), "{note}");
        assert!(note.contains("docs/x.md"), "{note}");
        assert!(!note.contains("src/api/a.rs,"), "{note}");
        assert!(scope_note(&globs(&["src/**"]), &globs(&["src/a.rs"])).is_none());
        assert!(scope_note(&[], &globs(&["anything"])).is_none());
    }

    #[test]
    fn a_long_list_of_strays_is_cut_short() {
        let many: Vec<String> = (0..40).map(|n| format!("other/f{n}.rs")).collect();
        let note = scope_note(&globs(&["src/**"]), &many).unwrap();
        assert!(note.contains("40 changed file(s)"), "{note}");
        assert!(note.contains("and 20 more"), "{note}");
    }

    // --- the channel-reading half ----------------------------------------------------

    struct Fixture {
        _dir: tempfile::TempDir,
        route: ProjectRoute,
        josh: AgentIdentity,
        wisp: AgentIdentity,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let josh = AgentIdentity::from_seed("josh", [1; 32]);
        let wisp = AgentIdentity::from_seed("wisp", [2; 32]);
        let communications = dir.path().join("demo-ferryman");
        fs::create_dir_all(&communications).unwrap();
        let mut route = ProjectRoute {
            project_id: "demo".into(),
            workspace: dir.path().join("demo"),
            attachment: dir.path().join("attachment"),
            communications,
            shared_remote: String::new(),
            git_remote: String::new(),
            git_visibility: String::new(),
            agents: Vec::new(),
        };
        for member in [&josh, &wisp] {
            let agent = AgentRoute {
                name: member.name().into(),
                role: "operator".into(),
                capabilities: Vec::new(),
                public_key: Some(member.public_key_hex()),
                encryption_key: None,
            };
            crate::register_agent(&route, &agent).unwrap();
            route.agents.push(agent);
        }
        crate::master::initialize_master(&route, &josh, "josh").unwrap();
        Fixture {
            _dir: dir,
            route,
            josh,
            wisp,
        }
    }

    pub(crate) fn order(id: &str, touches: &[&str]) -> Order {
        Order {
            id: id.into(),
            project_id: "demo".into(),
            issued_by: "josh".into(),
            assigned_to: None,
            created_at: Utc::now(),
            payload: json!({ "task": id }),
            requires_review: false,
            requires_approval: false,
            depends_on: Vec::new(),
            signed_by: None,
            signature: None,
            result_contract: None,
            interface: None,
            touches: globs(touches),
            allow_overlap: false,
        }
    }

    fn issue(f: &Fixture, mut order: Order) {
        f.josh.sign_order(&mut order);
        crate::issue_order(&f.route, &order).unwrap();
    }

    fn claim(f: &Fixture, id: &str) {
        crate::claim_order(&f.route, id, "wisp").unwrap();
    }

    fn mark_stale(route: &ProjectRoute, id: &str, by: &str) {
        // A claim with a heartbeat that stopped long ago reads as Stale.
        let dir = crate::task_dir(route, id);
        let old = Utc::now() - chrono::Duration::hours(2);
        let claim = Claim {
            order_id: id.into(),
            agent: by.into(),
            claimed_at: old,
        };
        fs::write(
            dir.join(format!("claim.{by}.json")),
            serde_json::to_vec(&claim).unwrap(),
        )
        .unwrap();
        let beat = crate::Heartbeat {
            order_id: id.into(),
            agent: by.into(),
            run: "r".into(),
            pid: 1,
            at: old,
        };
        crate::write_heartbeat(route, &beat).unwrap();
    }

    #[test]
    fn issuing_an_order_warns_about_open_and_claimed_orders_it_overlaps() {
        let f = fixture();
        issue(&f, order("t-open", &["src/api/**"]));
        issue(&f, order("t-claimed", &["src/api/users.rs"]));
        claim(&f, "t-claimed");
        issue(&f, order("t-elsewhere", &["docs/**"]));
        issue(&f, order("t-silent", &[]));

        let new = order("t-new", &["src/**"]);
        let warnings = issue_warnings(&f.route, &new).unwrap();
        let ids: Vec<&str> = warnings.iter().map(|w| w.order_id.as_str()).collect();
        assert_eq!(ids, vec!["t-open", "t-claimed"]);
        assert_eq!(warnings[0].state, "open");
        assert_eq!(warnings[1].state, "claimed");
        assert_eq!(warnings[1].holder.as_deref(), Some("wisp"));
        assert!(warnings[1].describe().contains("src/** ~ src/api/users.rs"));
        assert!(
            issue_warnings(&f.route, &order("t-none", &[]))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn a_finished_order_is_not_a_place_to_collide() {
        let f = fixture();
        issue(&f, order("t-done", &["src/**"]));
        claim(&f, "t-done");
        let result = crate::TaskResult {
            order_id: "t-done".into(),
            agent: "wisp".into(),
            revision: 1,
            submitted_at: Utc::now(),
            payload: json!({ "output": "ok" }),
            signed_by: None,
            signature: None,
        };
        let mut result = result;
        f.wisp.sign_result(&mut result);
        crate::submit_result(&f.route, &result).unwrap();
        let mut review = crate::Review {
            order_id: "t-done".into(),
            revision: 1,
            reviewer: "josh".into(),
            reviewed_at: Utc::now(),
            accepted: true,
            notes: None,
            signed_by: None,
            signature: None,
        };
        f.josh.sign_review(&mut review);
        crate::submit_review(&f.route, &review).unwrap();
        let task = crate::read_task(&f.route, "t-done").unwrap();
        assert!(matches!(
            task.state(),
            TaskState::Accepted | TaskState::Done
        ));
        assert!(
            issue_warnings(&f.route, &order("t-new", &["src/a.rs"]))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn an_unsigned_order_does_not_count() {
        let f = fixture();
        crate::issue_order(&f.route, &order("t-forged", &["src/**"])).unwrap();
        assert!(
            issue_warnings(&f.route, &order("t-new", &["src/a.rs"]))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn the_dashboard_map_lists_each_orders_neighbours() {
        let f = fixture();
        issue(&f, order("t-a", &["src/api/**"]));
        issue(&f, order("t-b", &["src/api/x.rs"]));
        issue(&f, order("t-c", &["docs/**"]));
        let tasks = crate::list_tasks(&f.route).unwrap();
        let map = overlap_map(&f.route, &tasks);
        assert_eq!(map.len(), 2);
        assert_eq!(map["t-a"][0].order_id, "t-b");
        assert_eq!(map["t-b"][0].order_id, "t-a");
        assert!(!map.contains_key("t-c"));
    }

    #[test]
    fn a_claimed_overlapping_order_holds_a_new_claim_back() {
        let f = fixture();
        issue(&f, order("t-first", &["src/api/**"]));
        claim(&f, "t-first");
        let second = order("t-second", &["src/api/users.rs"]);
        issue(&f, second.clone());
        let reason = claim_hold(&f.route, &second).unwrap().unwrap();
        assert!(reason.contains("t-first"), "{reason}");
        assert!(reason.contains("claimed by wisp"), "{reason}");
        // The reason is stable from one pass to the next, so it is written once.
        assert_eq!(claim_hold(&f.route, &second).unwrap().unwrap(), reason);
    }

    #[test]
    fn allow_overlap_and_unrelated_files_are_never_held() {
        let f = fixture();
        issue(&f, order("t-first", &["src/api/**"]));
        claim(&f, "t-first");
        let mut allowed = order("t-allowed", &["src/api/users.rs"]);
        allowed.allow_overlap = true;
        assert!(claim_hold(&f.route, &allowed).unwrap().is_none());
        let elsewhere = order("t-elsewhere", &["docs/**"]);
        assert!(claim_hold(&f.route, &elsewhere).unwrap().is_none());
        let declares_nothing = order("t-nothing", &[]);
        assert!(claim_hold(&f.route, &declares_nothing).unwrap().is_none());
    }

    #[test]
    fn an_open_or_stale_order_does_not_hold_a_claim_back() {
        let f = fixture();
        issue(&f, order("t-open", &["src/api/**"]));
        let wanted = order("t-wanted", &["src/api/users.rs"]);
        assert!(
            claim_hold(&f.route, &wanted).unwrap().is_none(),
            "open is not claimed"
        );

        issue(&f, order("t-stale", &["web/**"]));
        mark_stale(&f.route, "t-stale", "wisp");
        let task = crate::read_task(&f.route, "t-stale").unwrap();
        assert!(
            matches!(task.state(), TaskState::Stale { .. }),
            "{:?}",
            task.state()
        );
        let web = order("t-web", &["web/app.ts"]);
        assert!(
            claim_hold(&f.route, &web).unwrap().is_none(),
            "stale is not claimed"
        );
    }

    #[test]
    fn a_hold_is_signed_written_once_and_cleared_on_claim() {
        let f = fixture();
        issue(&f, order("t-1", &[]));
        assert!(crate::hold::record(&f.route, &f.wisp, "t-1", "waiting for x").unwrap());
        assert!(
            !crate::hold::record(&f.route, &f.wisp, "t-1", "waiting for x").unwrap(),
            "same reason, nothing written"
        );
        assert!(crate::hold::record(&f.route, &f.wisp, "t-1", "waiting for y").unwrap());
        let holds = crate::hold::read(&f.route, "t-1");
        assert_eq!(holds.len(), 1);
        assert_eq!(holds[0].reason, "waiting for y");
        assert_eq!(holds[0].agent, "wisp");

        // Edited after signing: not read.
        let file = crate::task_dir(&f.route, "t-1").join("hold.wisp.json");
        let tampered = fs::read_to_string(&file)
            .unwrap()
            .replace("waiting for y", "all clear");
        fs::write(&file, tampered).unwrap();
        assert!(crate::hold::read(&f.route, "t-1").is_empty());

        crate::hold::clear(&f.route, "t-1", "wisp");
        assert!(!Path::new(&file).exists());
    }

    #[test]
    fn a_hold_on_an_order_that_does_not_exist_is_refused() {
        let f = fixture();
        assert!(crate::hold::record(&f.route, &f.wisp, "t-nope", "why").is_err());
    }
}
