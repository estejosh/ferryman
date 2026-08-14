//! Result contracts: a schema an order can require of the result submitted for
//! it, so a malformed deliverable can be rejected mechanically rather than by a
//! human squinting at it.
//!
//! This is deliberately a *minimal* contract (required top-level keys) rather
//! than full JSON Schema: it is dependency-free, it travels inside the signed
//! order (so the requirement cannot be tampered with after issue), and it
//! covers the common failure - an agent that submits `{"output": ...}` when the
//! project's reviewer needs `{"diff": ..., "summary": ...}`.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The shape an order requires of its result payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResultContract {
    /// Top-level keys the result payload must contain, non-null.
    pub required: Vec<String>,
}

impl ResultContract {
    /// The required keys that are missing (or null) in `payload`. Empty means
    /// the payload satisfies the contract.
    #[must_use]
    pub fn violations(&self, payload: &Value) -> Vec<String> {
        let Some(obj) = payload.as_object() else {
            // A non-object result cannot carry any of the required keys.
            return self.required.clone();
        };
        self.required
            .iter()
            .filter(|key| match obj.get(*key) {
                None | Some(Value::Null) => true,
                Some(_) => false,
            })
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_satisfied_contract_has_no_violations() {
        let contract = ResultContract {
            required: vec!["output".into(), "diff".into()],
        };
        let payload = json!({ "output": "hi", "diff": "---", "extra": true });
        assert!(contract.violations(&payload).is_empty());
    }

    #[test]
    fn a_missing_or_null_key_is_a_violation() {
        let contract = ResultContract {
            required: vec!["output".into(), "diff".into()],
        };
        let missing = contract.violations(&json!({ "output": "hi" }));
        assert_eq!(missing, vec!["diff"]);
        let null = contract.violations(&json!({ "output": "hi", "diff": null }));
        assert_eq!(null, vec!["diff"]);
    }

    #[test]
    fn a_non_object_result_violates_every_key() {
        let contract = ResultContract {
            required: vec!["output".into()],
        };
        assert_eq!(contract.violations(&json!("just a string")), vec!["output"]);
    }
}
