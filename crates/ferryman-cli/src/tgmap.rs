//! `.tgferryman`: which Telegram topic is which project.
//!
//! A Telegram forum group is a good shape for a fleet. One group, a topic per project,
//! each topic a conversation with the machines working on that project - the same
//! separation the channel already has, in the one app an operator has on their phone.
//!
//! The thing standing in the way is small and permanent: **Telegram has no method that
//! lists a group's topics.** `createForumTopic` returns a `message_thread_id`, and after
//! that the id exists only where someone wrote it down. There is no `getForumTopics` to
//! recover it from, and there is no plan for one. A bridge that forgets a thread id cannot
//! ask; it can only make a second topic with the same name beside the first.
//!
//! So this file is not configuration that happens to be persisted. It is the register.
//! Ferryman writes into it every id it is given, and reads it to know where anything goes.
//!
//! # It is also the instruction
//!
//! Because the file has to exist anyway, it may as well be the place work is declared. A
//! topic listed with no `thread` is one Ferryman has not made yet: on the next start it
//! creates it, takes the id Telegram hands back, and writes it in. Adding a project to the
//! fleet is adding four lines here - the group builds itself out to match.
//!
//! That is why this is written back in full rather than patched: the file Ferryman writes
//! carries its own comments, so the format teaches itself to whoever opens it next.
//!
//! # Where it lives, and why it is not synced
//!
//! Discovered by walking up from the bridge's working directory, so the natural home is the
//! root of the comms folder, beside the per-project channels it points at.
//!
//! It is deliberately not inside a channel. Channels sync, and a synced file with one
//! writer per path is a rule this file would break: every machine that runs a bridge would
//! write its own view of the same topics. It is local, small, and plain text - and it is
//! the only copy of ids nothing can re-derive, so it is worth backing up.
//!
//! # The bot is an administrator, on purpose
//!
//! Making the topics needs the "Manage topics" administrator right, which also lets the bot
//! rename, close and delete them. That is materially more power than a bridge that only
//! posts into a chat. It is proportionate here - the operator owns the group, and a wrong
//! group is caught the moment it is adopted - but it belongs in the threat model, not
//! something to be discovered later.

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// The name to look for. Dot-prefixed because it sits beside working folders, and named
/// for both halves of what it joins.
pub const FILE: &str = ".tgferryman";

/// One topic, and the project it is tied to.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Topic {
    /// What the topic is called in Telegram. Used to create it, and to say which topic is
    /// meant in a message to a human.
    pub name: String,
    /// The project's workspace. Relative paths resolve against the directory holding the
    /// map, so a fleet that keeps its channels in one folder can copy this file between
    /// machines unchanged.
    pub workspace: PathBuf,
    /// Telegram's id for the topic. Absent means "not created yet"; Ferryman fills it in.
    #[serde(default)]
    pub thread: Option<i64>,
    /// The machine an unaddressed order in this topic goes to. Overrides the map's own
    /// default, because projects are not all cheapest on the same box.
    #[serde(default)]
    pub default_to: Option<String>,
    /// Take messages that arrive with no topic at all - a private chat, or the group's
    /// General - as belonging here. At most one topic may claim this.
    #[serde(default)]
    pub general: bool,
}

/// The whole map: one group, and every topic in it that Ferryman knows about.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct TopicMap {
    /// The forum group's chat id, negative and beginning `-100`. Absent until the operator
    /// fills it in, which is the one thing they must do by hand.
    #[serde(default)]
    pub group: Option<i64>,
    /// The fleet-wide default machine for an unaddressed order.
    #[serde(default)]
    pub default_to: Option<String>,
    #[serde(default, rename = "topic")]
    pub topics: Vec<Topic>,
}

impl TopicMap {
    /// Read a map, checking the things that would otherwise fail much later and less
    /// clearly - two topics sharing a thread id, two claiming General.
    pub fn parse(text: &str) -> Result<Self> {
        let map: Self = toml::from_str(text).context("parse the .tgferryman map")?;
        map.validate()?;
        Ok(map)
    }

    fn validate(&self) -> Result<()> {
        let generals = self.topics.iter().filter(|topic| topic.general).count();
        if generals > 1 {
            bail!(
                "{generals} topics are marked general = true; a message with no topic can only \
                 belong to one of them"
            );
        }
        for (index, topic) in self.topics.iter().enumerate() {
            if topic.name.trim().is_empty() {
                bail!("a topic has an empty name");
            }
            if topic.workspace.as_os_str().is_empty() {
                bail!("topic '{}' has no workspace", topic.name);
            }
            // A duplicated thread id means two projects reading each other's messages,
            // which is worse than either of them being unreachable.
            if let Some(thread) = topic.thread
                && let Some(other) = self.topics[..index]
                    .iter()
                    .find(|earlier| earlier.thread == Some(thread))
            {
                bail!(
                    "topics '{}' and '{}' both claim thread {thread}",
                    other.name,
                    topic.name
                );
            }
        }
        Ok(())
    }

    /// Topics Telegram has not been asked to create yet.
    #[must_use]
    pub fn unmade(&self) -> Vec<&Topic> {
        self.topics
            .iter()
            .filter(|topic| topic.thread.is_none() && !topic.general)
            .collect()
    }

    /// Record the id Telegram gave a topic. Returns false if the name is not in the map,
    /// which is a caller mistake rather than something to paper over.
    pub fn record_thread(&mut self, name: &str, thread: i64) -> bool {
        match self.topics.iter_mut().find(|topic| topic.name == name) {
            Some(topic) => {
                topic.thread = Some(thread);
                true
            }
            None => false,
        }
    }

    /// The whole file, comments and all.
    ///
    /// Rendered rather than serialised because `toml`'s serialiser cannot emit comments,
    /// and a register that has to be edited by hand and is rewritten by a program must
    /// explain itself in the copy the program leaves behind - otherwise the first write
    /// silently strips the only documentation the operator had.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::new();
        out.push_str(
            "# Which Telegram topic is which Ferryman project.\n\
             #\n\
             # Ferryman writes this file. Telegram has no way to list a group's topics, so\n\
             # the thread ids below are the only record there is - keep a copy.\n\
             #\n\
             # To add a project: add a [[topic]] with a name and a workspace, leave `thread`\n\
             # out, and restart the bridge. It creates the topic and writes the id in here.\n\n",
        );
        match self.group {
            Some(group) => out.push_str(&format!("group = {group}\n")),
            None => out.push_str(
                "# The forum group's chat id - negative, starts with -100. Add the bot to the\n\
                 # group as an admin with \"Manage topics\", then put its id here.\n\
                 # group = -1001234567890\n",
            ),
        }
        if let Some(default_to) = &self.default_to {
            out.push_str(&format!(
                "\n# The machine an unaddressed order goes to, unless a topic says otherwise.\n\
                 default_to = \"{default_to}\"\n"
            ));
        }
        for topic in &self.topics {
            out.push_str("\n[[topic]]\n");
            out.push_str(&format!("name = \"{}\"\n", escape(&topic.name)));
            out.push_str(&format!(
                "workspace = \"{}\"\n",
                escape(&topic.workspace.to_string_lossy())
            ));
            match topic.thread {
                Some(thread) => out.push_str(&format!("thread = {thread}\n")),
                None => out.push_str("# thread: not created yet\n"),
            }
            if let Some(default_to) = &topic.default_to {
                out.push_str(&format!("default_to = \"{}\"\n", escape(default_to)));
            }
            if topic.general {
                out.push_str("general = true\n");
            }
        }
        out
    }

    /// Write the file back, atomically enough that a crash mid-write cannot leave the only
    /// copy of the thread ids truncated.
    pub fn save(&self, path: &Path) -> Result<()> {
        let temporary = path.with_extension("tgferryman.tmp");
        std::fs::write(&temporary, self.render())
            .with_context(|| format!("write {}", temporary.display()))?;
        std::fs::rename(&temporary, path).with_context(|| format!("replace {}", path.display()))?;
        Ok(())
    }

    /// Read a map from disk.
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        Self::parse(&text)
    }
}

impl Topic {
    /// The workspace as an absolute path. `base` is the directory the map was read from.
    #[must_use]
    pub fn resolved_workspace(&self, base: &Path) -> PathBuf {
        if self.workspace.is_absolute() {
            self.workspace.clone()
        } else {
            base.join(&self.workspace)
        }
    }
}

/// Which of a set of topics a message belongs to, by the thread it arrived in.
///
/// The one rule, in one place, because the bridge needs it over its live desks and the map
/// needs it over what is written down - and two copies of a routing rule is how a message
/// ends up answered in one project and recorded in another.
///
/// `None` for the message's thread is a private chat or a group's General. Both mean "the
/// operator did not say which project", which is what the topic with no thread of its own
/// is for. An unrecognised thread matches nothing: answering it out of some other project's
/// channel would sign work into a project nobody asked about.
#[must_use]
pub fn index_for(threads: &[Option<i64>], thread: Option<i64>) -> Option<usize> {
    match thread {
        Some(thread) => threads.iter().position(|known| *known == Some(thread)),
        None => threads.iter().position(Option::is_none),
    }
}

/// TOML basic strings need these two escaped, and nothing else a topic name can hold.
fn escape(text: &str) -> String {
    text.replace('\\', "\\\\").replace('"', "\\\"")
}

/// A first map, written from what is already on the machine.
///
/// The alternative is asking an operator to hand-write a TOML file of paths and remember
/// which name goes with which folder - for a project whose whole complaint about tooling is
/// that it makes people do that. Every channel beside the map is a project the fleet
/// already has; listing them with no thread ids means one restart builds the whole group.
///
/// Nothing is marked `general`, because guessing which project owns untopiced messages is a
/// guess about what the operator meant. The rendered comments say how to set it.
#[must_use]
pub fn starter(dir: &Path) -> TopicMap {
    let mut topics = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return TopicMap::default();
    };
    let mut names: Vec<String> = entries
        .flatten()
        .filter(|entry| entry.path().join(".ferryman").is_dir())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect();
    // Alphabetical so two machines scanning the same folder write the same file, and so a
    // regenerated map does not shuffle under review.
    names.sort();
    for name in names {
        topics.push(Topic {
            name: topic_name(&name),
            workspace: PathBuf::from(&name),
            thread: None,
            default_to: None,
            general: false,
        });
    }
    TopicMap {
        group: None,
        default_to: None,
        topics,
    }
}

/// A folder name as a topic title: `bullship-ferryman` becomes `Bullship`.
///
/// The suffix is the channel naming convention, not part of the project's name, and a
/// group whose topics all end in "-ferryman" reads like a filesystem rather than a
/// conversation.
fn topic_name(folder: &str) -> String {
    let stem = folder.strip_suffix("-ferryman").unwrap_or(folder);
    let mut out = String::with_capacity(stem.len());
    for word in stem.split(['-', '_']).filter(|word| !word.is_empty()) {
        if !out.is_empty() {
            out.push(' ');
        }
        let mut chars = word.chars();
        if let Some(first) = chars.next() {
            out.extend(first.to_uppercase());
            out.push_str(chars.as_str());
        }
    }
    if out.is_empty() {
        folder.to_string()
    } else {
        out
    }
}

/// Find the map by walking up from `start`, the way a repository's own root is found.
#[must_use]
pub fn discover(start: &Path) -> Option<PathBuf> {
    let mut here = Some(start);
    while let Some(dir) = here {
        let candidate = dir.join(FILE);
        if candidate.is_file() {
            return Some(candidate);
        }
        here = dir.parent();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> TopicMap {
        TopicMap {
            group: Some(-1001234567890),
            default_to: Some("grouchly".to_string()),
            topics: vec![
                Topic {
                    name: "Ferryman".to_string(),
                    workspace: PathBuf::from("ferryman-ferryman"),
                    thread: Some(2),
                    default_to: None,
                    general: true,
                },
                Topic {
                    name: "Bullship".to_string(),
                    workspace: PathBuf::from("bullship-ferryman"),
                    thread: None,
                    default_to: Some("beastlywsl".to_string()),
                    general: false,
                },
            ],
        }
    }

    #[test]
    fn what_ferryman_writes_is_what_ferryman_reads() {
        // The register is rewritten every time a topic is created. A round trip that lost
        // a field would lose thread ids nothing can recover.
        let map = sample();
        assert_eq!(TopicMap::parse(&map.render()).unwrap(), map);
    }

    #[test]
    fn the_file_it_writes_explains_itself() {
        // Rendered rather than serialised precisely so this is true; if the comments go,
        // the operator's only documentation goes with them.
        let rendered = sample().render();
        assert!(rendered.contains("# Which Telegram topic is which Ferryman project."));
        assert!(rendered.contains("the only record there is"));
    }

    #[test]
    fn a_topic_with_no_thread_is_one_to_create() {
        let map = sample();
        let unmade = map.unmade();
        assert_eq!(unmade.len(), 1);
        assert_eq!(unmade[0].name, "Bullship");
    }

    #[test]
    fn the_general_topic_is_not_something_to_create() {
        // General exists in every forum group and has no id of its own. Asking Telegram to
        // create it makes a second topic called General beside the real one.
        let mut map = sample();
        map.topics[0].thread = None;
        assert!(map.unmade().iter().all(|topic| topic.name != "Ferryman"));
    }

    /// The thread ids a map routes on, in the order the topics are listed. The topic that
    /// catches untopiced messages has no thread of its own, whatever else is written there.
    fn threads(map: &TopicMap) -> Vec<Option<i64>> {
        map.topics
            .iter()
            .map(|topic| if topic.general { None } else { topic.thread })
            .collect()
    }

    #[test]
    fn a_message_lands_in_the_project_whose_topic_it_was_sent_in() {
        let mut map = sample();
        map.record_thread("Bullship", 7);
        let threads = threads(&map);
        assert_eq!(
            map.topics[index_for(&threads, Some(7)).unwrap()].name,
            "Bullship"
        );
    }

    #[test]
    fn a_message_with_no_topic_goes_where_the_map_says_it_does() {
        let map = sample();
        let threads = threads(&map);
        assert_eq!(
            map.topics[index_for(&threads, None).unwrap()].name,
            "Ferryman"
        );
    }

    #[test]
    fn the_routing_rule_is_the_same_one_the_bridge_uses() {
        // index_for is what both the map and the running bridge ask. These are the three
        // answers it can give.
        let threads = [None, Some(7), Some(9)];
        assert_eq!(index_for(&threads, Some(9)), Some(2));
        assert_eq!(index_for(&threads, None), Some(0));
        assert_eq!(index_for(&threads, Some(42)), None);
        // With nothing claiming General, an untopiced message has nowhere to go, and is
        // told so rather than being dropped into the first project on the list.
        assert_eq!(index_for(&[Some(7)], None), None);
    }

    #[test]
    fn an_unknown_thread_is_not_guessed_at() {
        // Answering an unmapped topic with some other project's channel is worse than not
        // answering: the order would be signed into a project nobody asked about.
        assert!(index_for(&threads(&sample()), Some(99)).is_none());
    }

    #[test]
    fn two_topics_may_not_share_a_thread() {
        let text = r#"
group = -100
[[topic]]
name = "One"
workspace = "one"
thread = 5
[[topic]]
name = "Two"
workspace = "two"
thread = 5
"#;
        let error = TopicMap::parse(text).unwrap_err().to_string();
        assert!(error.contains("both claim thread 5"), "{error}");
    }

    #[test]
    fn only_one_topic_may_catch_the_untopiced() {
        let text = r#"
[[topic]]
name = "One"
workspace = "one"
general = true
[[topic]]
name = "Two"
workspace = "two"
general = true
"#;
        let error = TopicMap::parse(text).unwrap_err().to_string();
        assert!(error.contains("can only belong to one"), "{error}");
    }

    #[test]
    fn a_relative_workspace_is_read_against_the_map_that_named_it() {
        // So the same file works on two machines that keep their channels in the same
        // shape under different home directories.
        let topic = &sample().topics[0];
        assert_eq!(
            topic.resolved_workspace(Path::new("/home/x/ferryman-comms")),
            PathBuf::from("/home/x/ferryman-comms/ferryman-ferryman")
        );
    }

    #[test]
    fn an_absolute_workspace_is_left_alone() {
        let topic = Topic {
            name: "Elsewhere".to_string(),
            workspace: PathBuf::from("/srv/other"),
            thread: None,
            default_to: None,
            general: false,
        };
        assert_eq!(
            topic.resolved_workspace(Path::new("/home/x")),
            PathBuf::from("/srv/other")
        );
    }

    #[test]
    fn a_first_map_is_written_from_the_channels_already_on_the_machine() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["bullship-ferryman", "ferryman-ferryman", "notes"] {
            std::fs::create_dir_all(dir.path().join(name).join(".ferryman")).unwrap();
        }
        // `notes` has a .ferryman too, so it is a channel and belongs in the list; a folder
        // without one does not.
        std::fs::create_dir_all(dir.path().join("scratch")).unwrap();
        let map = starter(dir.path());
        let names: Vec<&str> = map.topics.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, ["Bullship", "Ferryman", "Notes"]);
        assert!(map.topics.iter().all(|topic| topic.thread.is_none()));
        assert_eq!(map.topics[0].workspace, PathBuf::from("bullship-ferryman"));
    }

    #[test]
    fn a_folder_name_becomes_something_worth_reading_in_a_group() {
        assert_eq!(topic_name("bullship-ferryman"), "Bullship");
        assert_eq!(topic_name("spirit-of-ngu-ferryman"), "Spirit Of Ngu");
        assert_eq!(topic_name("ferryman"), "Ferryman");
    }

    #[test]
    fn a_group_that_has_not_been_named_yet_is_still_a_readable_file() {
        // The operator has to paste the group id in by hand; the file they get before that
        // must round-trip and must tell them what to do.
        let map = TopicMap::default();
        let rendered = map.render();
        assert!(rendered.contains("Manage topics"));
        assert_eq!(TopicMap::parse(&rendered).unwrap(), map);
    }
}
