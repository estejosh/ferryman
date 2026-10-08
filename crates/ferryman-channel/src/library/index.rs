//! Full-text search over the library, rebuilt from the signed entries.
//!
//! SQLite's FTS5 (the bundled SQLite the workspace already links) held in memory: every
//! call builds the index from the facts it was given, so there is nothing on disk to go
//! stale, to be edited or to disagree with the signed entries. No embeddings. If this
//! SQLite was built without FTS5, a plain term-overlap scorer answers instead; both are
//! tested, and both apply the same relevance rule: a hit must contain at least half of the
//! question's significant words.

use std::collections::HashMap;

use rusqlite::{Connection, params};

/// One thing that can be found: a fact, or a row of a generated view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Doc {
    pub id: String,
    pub subject: String,
    pub text: String,
    pub tags: Vec<String>,
    pub project: String,
}

/// A hit: the id, how well it ranks (higher is better) and how much of the question it covers.
#[derive(Debug, Clone, PartialEq)]
pub struct Hit {
    pub id: String,
    pub score: f64,
    pub coverage: f64,
}

const STOP: &[&str] = &[
    "a", "an", "the", "is", "are", "was", "were", "be", "been", "being", "what", "which", "who",
    "whom", "where", "when", "why", "how", "do", "does", "did", "of", "on", "in", "at", "to",
    "for", "from", "by", "with", "and", "or", "not", "it", "its", "this", "that", "these", "those",
    "i", "we", "you", "our", "my", "me", "can", "could", "should", "would", "will", "about",
    "there", "here", "any", "all", "tell", "give", "show", "know", "get", "please", "has", "have",
    "had", "if", "so", "than", "then", "us", "your", "his", "her", "their",
];

/// The significant words of a question, lower-case, in order, without repeats.
#[must_use]
pub fn terms(question: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for word in question.split(|c: char| !c.is_alphanumeric()) {
        let word = word.to_lowercase();
        if word.chars().count() >= 2 && !STOP.contains(&word.as_str()) && !out.contains(&word) {
            out.push(word);
        }
    }
    out
}

/// Whether the document word `have` answers the question word `want`: the same word, or the
/// same stem (the first five letters of the shorter one).
fn same_word(want: &str, have: &str) -> bool {
    if want == have || want.strip_suffix('s') == Some(have) || have.strip_suffix('s') == Some(want)
    {
        return true;
    }
    let stem = |word: &str| word.chars().take(5).collect::<String>();
    let (short, long) = if want.chars().count() <= have.chars().count() {
        (want, have)
    } else {
        (have, want)
    };
    short.chars().count() >= 4 && long.starts_with(&stem(short))
}

fn coverage(wanted: &[String], doc: &Doc) -> f64 {
    if wanted.is_empty() {
        return 0.0;
    }
    let haystack = format!(
        "{} {} {} {}",
        doc.subject,
        doc.text,
        doc.tags.join(" "),
        doc.project
    );
    let words: Vec<String> = haystack
        .split(|c: char| !c.is_alphanumeric())
        .map(str::to_lowercase)
        .filter(|word| !word.is_empty())
        .collect();
    let matched = wanted
        .iter()
        .filter(|want| words.iter().any(|have| same_word(want, have)))
        .count();
    matched as f64 / wanted.len() as f64
}

/// The index.
pub struct Index {
    docs: HashMap<String, Doc>,
    order: Vec<String>,
    fts: Option<Connection>,
}

impl Index {
    /// Build an FTS5 index over `docs`, or the plain scorer if FTS5 is not there.
    #[must_use]
    pub fn build(docs: &[Doc]) -> Self {
        Self::build_with(docs, true)
    }

    /// As [`Index::build`], choosing whether to try FTS5 (tests use `false` to exercise the
    /// plain scorer).
    #[must_use]
    pub fn build_with(docs: &[Doc], try_fts: bool) -> Self {
        let fts = if try_fts { Self::fts(docs) } else { None };
        Self {
            order: docs.iter().map(|doc| doc.id.clone()).collect(),
            docs: docs
                .iter()
                .map(|doc| (doc.id.clone(), doc.clone()))
                .collect(),
            fts,
        }
    }

    fn fts(docs: &[Doc]) -> Option<Connection> {
        let conn = Connection::open_in_memory().ok()?;
        conn.execute_batch(
            "CREATE VIRTUAL TABLE docs USING fts5(\
             id UNINDEXED, subject, body, tags, project, tokenize = 'porter unicode61')",
        )
        .ok()?;
        {
            let mut insert = conn
                .prepare("INSERT INTO docs (id, subject, body, tags, project) VALUES (?1, ?2, ?3, ?4, ?5)")
                .ok()?;
            for doc in docs {
                insert
                    .execute(params![
                        doc.id,
                        doc.subject,
                        doc.text,
                        doc.tags.join(" "),
                        doc.project
                    ])
                    .ok()?;
            }
        }
        Some(conn)
    }

    /// Whether the index is FTS5 (and not the plain scorer).
    #[must_use]
    pub fn is_fts(&self) -> bool {
        self.fts.is_some()
    }

    /// The best `limit` documents for `question`, best first. Nothing when the question has
    /// no significant words or nothing covers at least half of them.
    #[must_use]
    pub fn search(&self, question: &str, limit: usize) -> Vec<Hit> {
        let wanted = terms(question);
        if wanted.is_empty() || limit == 0 {
            return Vec::new();
        }
        let candidates: Vec<(String, f64)> = match &self.fts {
            Some(conn) => Self::fts_candidates(conn, &wanted, limit.saturating_mul(4).max(20)),
            None => self.order.iter().map(|id| (id.clone(), 0.0)).collect(),
        };
        let mut hits: Vec<Hit> = candidates
            .into_iter()
            .filter_map(|(id, rank)| {
                let doc = self.docs.get(&id)?;
                let covered = coverage(&wanted, doc);
                if covered < 0.5 {
                    return None;
                }
                Some(Hit {
                    id,
                    // bm25 is lower for better matches; flip it, and let coverage lead.
                    score: covered * 100.0 - rank,
                    coverage: covered,
                })
            })
            .collect();
        hits.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.id.cmp(&b.id))
        });
        hits.truncate(limit);
        hits
    }

    fn fts_candidates(conn: &Connection, wanted: &[String], limit: usize) -> Vec<(String, f64)> {
        let query = wanted
            .iter()
            .map(|word| {
                let word: String = word.chars().filter(|c| c.is_alphanumeric()).collect();
                format!("\"{word}\"*")
            })
            .collect::<Vec<_>>()
            .join(" OR ");
        let Ok(mut statement) = conn.prepare(
            "SELECT id, bm25(docs, 0.0, 6.0, 1.0, 3.0, 2.0) FROM docs WHERE docs MATCH ?1 \
             ORDER BY 2 LIMIT ?2",
        ) else {
            return Vec::new();
        };
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let Ok(rows) = statement.query_map(params![query, limit], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, f64>(1)?))
        }) else {
            return Vec::new();
        };
        rows.flatten().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(id: &str, subject: &str, text: &str, tags: &[&str], project: &str) -> Doc {
        Doc {
            id: id.into(),
            subject: subject.into(),
            text: text.into(),
            tags: tags.iter().map(ToString::to_string).collect(),
            project: project.into(),
        }
    }

    fn docs() -> Vec<Doc> {
        vec![
            doc(
                "f-1",
                "NVIDIA key",
                "NVIDIA key: Custodly, name nvidiaapi",
                &["secrets", "nvidia"],
                "",
            ),
            doc(
                "f-2",
                "beastly",
                "beastly is Josh's Windows machine with WSL and an RTX 3090",
                &["machines"],
                "",
            ),
            doc(
                "f-3",
                "grouchly",
                "grouchly is the Ubuntu box that is always on and runs n8n",
                &["machines"],
                "",
            ),
            doc(
                "f-4",
                "deployments",
                "Releases are approved by the master before anything merges",
                &["process"],
                "ferryman",
            ),
        ]
    }

    #[test]
    fn the_questions_words_find_the_facts_that_hold_them() {
        for try_fts in [true, false] {
            let index = Index::build_with(&docs(), try_fts);
            let hits = index.search("Where is the NVIDIA key kept?", 5);
            assert_eq!(
                hits.first().map(|h| h.id.as_str()),
                Some("f-1"),
                "{try_fts}"
            );
            let hits = index.search("which machine is always on", 5);
            assert_eq!(
                hits.first().map(|h| h.id.as_str()),
                Some("f-3"),
                "{try_fts}"
            );
            // Stems: "deployment" finds "deployments", "approve" finds "approved".
            let hits = index.search("who approves a deployment", 5);
            assert_eq!(
                hits.first().map(|h| h.id.as_str()),
                Some("f-4"),
                "{try_fts}"
            );
        }
    }

    #[test]
    fn sqlite_here_has_fts5() {
        assert!(
            Index::build(&docs()).is_fts(),
            "the bundled SQLite should carry FTS5; if not the plain scorer answers instead"
        );
    }

    #[test]
    fn a_question_nothing_covers_finds_nothing() {
        for try_fts in [true, false] {
            let index = Index::build_with(&docs(), try_fts);
            assert!(index.search("what is the capital of France", 5).is_empty());
            assert!(index.search("the and of", 5).is_empty(), "only stop words");
            assert!(index.search("", 5).is_empty());
            // One shared word out of four significant ones is not enough.
            assert!(
                index
                    .search("kangaroo quantum nvidia pancake", 5)
                    .is_empty()
            );
        }
    }

    #[test]
    fn hostile_query_text_is_only_words() {
        let index = Index::build(&docs());
        for query in [
            "\" OR 1=1 --",
            "nvidia\" ; DROP TABLE docs; --",
            "* NEAR(a b) AND NOT",
            "(((",
            "key:nvidia",
        ] {
            let _ = index.search(query, 5);
        }
        assert_eq!(
            index.search("nvidia", 5).first().map(|h| h.id.as_str()),
            Some("f-1")
        );
    }
}
