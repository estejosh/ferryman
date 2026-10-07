use std::path::Path;

use chrono::{TimeZone, Utc};

use super::*;
use crate::suggestions::client::offer_from_page;
use crate::suggestions::inbox::MockInbox;
use crate::suggestions::record::{self, tests as rt};

const TERMS: &str =
    "Terms v1. You grant the owner a license to use your suggestion. No payment. Credit.\n";

/// The same offer every time: a fixed key, a fixed time, so the page can be compared with a
/// file in the repository.
fn offer() -> Offer {
    let dir = tempfile::tempdir().unwrap();
    let josh = rt::person("josh", 1);
    let route = rt::route(dir.path(), &[&josh]);
    let now = Utc.with_ymd_and_hms(2026, 10, 6, 12, 0, 0).unwrap();
    record::open(
        &route.communications,
        rt::PROJECT,
        &josh,
        rt::args(TERMS),
        now,
    )
    .unwrap()
    .offer
}

/// What the golden files hold where the test owner's public key goes, so no key-shaped
/// literal sits in the repository for a secret scanner to trip on.
const OWNER_KEY_PLACEHOLDER: &str = "{{OWNER_KEY}}";

/// Compare with `src/suggestions/golden/<name>`; `UPDATE_GOLDEN=1 cargo test` rewrites them.
/// The offer's owner key is swapped for a placeholder on both the write and the compare side.
fn golden(offer: &Offer, name: &str, actual: &str) {
    assert!(
        !offer.owner_key.is_empty(),
        "the offer has no owner key to mask"
    );
    let actual = actual.replace(&offer.owner_key, OWNER_KEY_PLACEHOLDER);
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/suggestions/golden")
        .join(name);
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &actual).unwrap();
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!("missing golden file {name}: run the tests with UPDATE_GOLDEN=1")
    });
    assert_eq!(
        expected.replace("\r\n", "\n"),
        actual,
        "{name} changed: if that is intended, run the tests with UPDATE_GOLDEN=1 and review the diff"
    );
}

#[test]
fn the_readme_section_is_what_the_owner_signed_and_does_not_drift() {
    let offer = offer();
    let invite = Invite::new(&offer).encode();
    golden(
        &offer,
        "README_section.md",
        &readme_section(&offer, &invite),
    );
}

#[test]
fn the_agents_file_does_not_drift() {
    let offer = offer();
    let invite = Invite::new(&offer).encode();
    golden(&offer, "AGENTS.md", &agents_md(&offer, &invite));
}

#[test]
fn the_machine_readable_page_does_not_drift() {
    let offer = offer();
    let invite = Invite::new(&offer).encode();
    let text = serde_json::to_string_pretty(&machine_page(&offer, &invite)).unwrap();
    golden(&offer, "ferryman-suggest.json", &format!("{text}\n"));
    golden(
        &offer,
        "schema-idea.json",
        &format!(
            "{}\n",
            serde_json::to_string_pretty(&schema(&offer, "idea")).unwrap()
        ),
    );
}

#[test]
fn the_page_tells_a_person_and_an_agent_the_things_that_matter() {
    let offer = offer();
    let page = files(&offer, TERMS, None);
    let readme = &page["README.md"];
    for needed in [
        "ferry suggest join",
        "ferry suggest new",
        "ferry suggest status",
        "I agree",
        "TERMS.md",
        "AGENTS.md",
        "3 open at a time",
        "1 new per day",
        "14 days",
        "`needs-clarification`",
        "credit is the reward",
    ] {
        assert!(readme.contains(needed), "README is missing: {needed}");
    }
    let agents = &page["AGENTS.md"];
    for needed in [
        "must not accept on their behalf",
        "ferry suggest new --file suggestion.json --json",
        "ferry suggest status --json",
        "ferry suggest reply <issue> --file answer.txt",
        "schemas/suggestion/<type>.json",
        "Do not run `ferry suggest join` with `--agree`",
        "Never print, log, copy or store the token",
    ] {
        assert!(agents.contains(needed), "AGENTS.md is missing: {needed}");
    }
    // The terms are the owner's, byte for byte, and hash to what the offer says.
    assert_eq!(page[TERMS_FILE], TERMS);
    assert_eq!(
        crate::suggestions::sha256_hex(page[TERMS_FILE].as_bytes()),
        offer.terms.sha256
    );
    // The words the owner does not use for their products.
    for (path, text) in &page {
        let lower = text.to_lowercase();
        assert!(
            !lower.contains("open source") && !lower.contains("open-source"),
            "{path}"
        );
    }
    // Blank issues are off, so a submission has to come through ferry.
    assert!(page[".github/ISSUE_TEMPLATE/config.yml"].contains("blank_issues_enabled: false"));
    assert!(page[".github/ISSUE_TEMPLATE/config.yml"].contains("#suggest-an-idea-for-idle-ish"));
    // One schema per kind, and the page points at each.
    for spec in &offer.types {
        let schema = &page[&format!("schemas/suggestion/{}.json", spec.id)];
        let value: serde_json::Value = serde_json::from_str(schema).unwrap();
        assert_eq!(value["properties"]["type"]["const"], spec.id.as_str());
        assert_eq!(value["additionalProperties"], false);
        assert_eq!(value["properties"]["title"]["maxLength"], 80);
        assert!(
            value["required"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r == "pitch")
        );
    }
    let machine: serde_json::Value = serde_json::from_str(&page[OFFER_FILE]).unwrap();
    assert_eq!(machine["terms"]["sha256"], offer.terms.sha256.as_str());
    assert_eq!(machine["types"][1]["schema"], "schemas/suggestion/bug.json");
}

#[test]
fn the_machine_page_carries_the_signed_offer_and_an_invite_that_decodes_to_it() {
    let offer = offer();
    let page = files(&offer, TERMS, None);
    let read = offer_from_page(&page[OFFER_FILE]).unwrap();
    assert_eq!(read, offer);
    assert!(read.verify());
    let machine: serde_json::Value = serde_json::from_str(&page[OFFER_FILE]).unwrap();
    let invite = Invite::decode(machine["invite"].as_str().unwrap()).unwrap();
    assert_eq!(invite.offer, offer);
    assert!(page["README.md"].contains(machine["invite"].as_str().unwrap()));
    assert!(page["AGENTS.md"].contains(machine["invite"].as_str().unwrap()));
}

#[test]
fn a_readme_the_owner_already_has_keeps_its_own_words() {
    let offer = offer();
    let invite = Invite::new(&offer).encode();
    let section = readme_section(&offer, &invite);
    let fresh = merge_readme(None, &section, &offer);
    assert!(fresh.starts_with("# Idle-ish ideas"));
    // Appended after what is there.
    let mine = "# My repo\n\nSome words of mine.\n";
    let added = merge_readme(Some(mine), &section, &offer);
    assert!(added.starts_with(mine.trim_end()) && added.contains(BEGIN) && added.contains(END));
    // Run again: the section is replaced in place, not added twice.
    let again = merge_readme(Some(&added), &section, &offer);
    assert_eq!(again, added);
    // Words after the section survive a replacement.
    let with_tail = format!("{added}\n## Credits\nEveryone.\n");
    let replaced = merge_readme(
        Some(&with_tail),
        &readme_section(&offer, "ferry-suggest:NEW"),
        &offer,
    );
    assert_eq!(replaced.matches(BEGIN).count(), 1);
    assert!(replaced.contains("ferry-suggest:NEW") && replaced.contains("## Credits\nEveryone."));
    assert!(replaced.starts_with("# My repo"));
}

#[test]
fn publishing_commits_only_what_changed_and_only_as_the_owner() {
    let offer = offer();
    let inbox = MockInbox::new("estejosh");
    let stranger = inbox.as_user("octo");
    assert!(
        publish(&stranger, &offer, TERMS).is_err(),
        "a stranger cannot publish"
    );
    let first = publish(&inbox, &offer, TERMS).unwrap();
    assert!(first.iter().all(|written| written.changed));
    assert!(first.iter().any(|written| written.path == "AGENTS.md"));
    assert!(inbox.labels_ensured());
    assert_eq!(inbox.read_file("TERMS.md").unwrap().as_deref(), Some(TERMS));
    let second = publish(&inbox, &offer, TERMS).unwrap();
    assert!(second.iter().all(|written| !written.changed), "{second:?}");
}

#[test]
fn a_folder_gets_every_file_for_the_owner_to_commit() {
    let offer = offer();
    let dir = tempfile::tempdir().unwrap();
    let page = files(&offer, TERMS, None);
    write_folder(dir.path(), &page).unwrap();
    for path in page.keys() {
        assert!(dir.path().join(path).is_file(), "{path}");
    }
}
