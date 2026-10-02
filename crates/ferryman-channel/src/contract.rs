//! Result contracts: a schema an order can require of the result submitted for
//! it, so a malformed deliverable can be rejected mechanically rather than by a
//! human squinting at it.
//!
//! This is deliberately a *small* contract rather than full JSON Schema: it is
//! dependency-free, it travels inside the signed order (so the requirement
//! cannot be tampered with after issue), and it covers the common failures - an
//! agent that submits `{"output": ...}` when the project's reviewer needs
//! `{"diff": ..., "summary": ...}`, and, with a [`Shape`], two agents building
//! the two halves of one feature who disagree about what an API returns.
//!
//! Two layers, both optional and both checked by [`ResultContract::violations`]:
//!
//! - `required`: top-level keys that must be present and non-null.
//! - `schema`: a [`Shape`], a recursive description of the whole payload.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The most violations one check reports. A thousand-element array of wrong things is
/// one mistake, said a hundred times; the rest would only bury the first.
const MAX_VIOLATIONS: usize = 100;

/// The shape an order requires of its result payload.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResultContract {
    /// Top-level keys the result payload must contain, non-null.
    #[serde(default)]
    pub required: Vec<String>,
    /// A typed description of the payload. Absent on every order issued before schemas
    /// existed, which then behave exactly as they always did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<Shape>,
}

impl ResultContract {
    /// What the payload gets wrong. Empty means it satisfies the contract.
    ///
    /// The `required` part reports bare key names (as it always has); the `schema` part
    /// reports path-qualified messages such as `result.user.id: expected integer, got
    /// string`.
    #[must_use]
    pub fn violations(&self, payload: &Value) -> Vec<String> {
        let mut out = match payload.as_object() {
            // A non-object result cannot carry any of the required keys.
            None => self.required.clone(),
            Some(obj) => self
                .required
                .iter()
                .filter(|key| match obj.get(*key) {
                    None | Some(Value::Null) => true,
                    Some(_) => false,
                })
                .cloned()
                .collect(),
        };
        if let Some(schema) = &self.schema {
            out.extend(schema.check(payload));
        }
        out
    }
}

/// The JSON type a [`Shape`] demands.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ShapeType {
    String,
    /// Any JSON number.
    Number,
    /// A number with no fractional part (`3` and `3.0` both count).
    Integer,
    Boolean,
    Array,
    Object,
    Null,
    /// No constraint on the type. `properties` and `items` still apply to a value that
    /// turns out to be an object or an array.
    #[default]
    Any,
}

impl ShapeType {
    fn name(self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Number => "number",
            Self::Integer => "integer",
            Self::Boolean => "boolean",
            Self::Array => "array",
            Self::Object => "object",
            Self::Null => "null",
            Self::Any => "any",
        }
    }

    fn admits(self, value: &Value) -> bool {
        match self {
            Self::String => value.is_string(),
            Self::Number => value.is_number(),
            Self::Integer => is_integer(value),
            Self::Boolean => value.is_boolean(),
            Self::Array => value.is_array(),
            Self::Object => value.is_object(),
            Self::Null => value.is_null(),
            Self::Any => true,
        }
    }
}

/// A small, recursive description of a JSON value. Deterministic and dependency-free:
/// the same shape and the same value give the same messages on every machine.
///
/// Objects are open: a key the shape does not mention is allowed. A shape says what
/// must hold, not everything that may exist.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Shape {
    /// The JSON type. Defaults to `any`.
    #[serde(rename = "type", default)]
    pub kind: ShapeType,
    /// For objects: keys that must be present. A key present with `null` counts as
    /// present; say `"type": "string"` on the property to refuse the null.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required: Vec<String>,
    /// For objects: the shape of each named property that is present.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub properties: BTreeMap<String, Shape>,
    /// For arrays: the shape every element must have.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub items: Option<Box<Shape>>,
    /// If non-empty, the value must equal one of these literals.
    #[serde(rename = "enum", default, skip_serializing_if = "Vec::is_empty")]
    pub allowed: Vec<Value>,
}

/// The keys a shape may carry. Anything else in a schema FILE is almost certainly a typo
/// (`requird`), and a typo in a contract silently weakens it - so [`Shape::parse`]
/// refuses it rather than ignoring it.
const SHAPE_KEYS: &[&str] = &["type", "required", "properties", "items", "enum"];

impl Shape {
    /// Read a shape from JSON, refusing keys this version does not understand.
    ///
    /// Strict on purpose, and only here: the loader that reads shapes back out of signed
    /// orders and contracts stays lenient, so a newer shape never makes an older
    /// machine unable to read the file at all.
    pub fn parse(value: &Value) -> anyhow::Result<Self> {
        fn walk(value: &Value, path: &str) -> anyhow::Result<()> {
            let Some(object) = value.as_object() else {
                anyhow::bail!("{path}: a shape is a JSON object");
            };
            for key in object.keys() {
                if !SHAPE_KEYS.contains(&key.as_str()) {
                    anyhow::bail!(
                        "{path}: unknown key \"{key}\" (a shape has: {})",
                        SHAPE_KEYS.join(", ")
                    );
                }
            }
            if let Some(Value::Object(properties)) = object.get("properties") {
                for (name, shape) in properties {
                    walk(shape, &format!("{path}.properties.{name}"))?;
                }
            }
            if let Some(items) = object.get("items") {
                walk(items, &format!("{path}.items"))?;
            }
            Ok(())
        }
        walk(value, "shape")?;
        serde_json::from_value(value.clone())
            .map_err(|error| anyhow::anyhow!("shape is not valid: {error}"))
    }

    /// What `value` gets wrong, with paths rooted at `result`.
    #[must_use]
    pub fn check(&self, value: &Value) -> Vec<String> {
        self.check_at(value, "result")
    }

    /// What `value` gets wrong, with paths rooted at `path` (`result.response`, say).
    #[must_use]
    pub fn check_at(&self, value: &Value, path: &str) -> Vec<String> {
        let mut out = Vec::new();
        self.walk(value, path, &mut out);
        if out.len() >= MAX_VIOLATIONS {
            out.truncate(MAX_VIOLATIONS);
            out.push("(further violations omitted)".to_string());
        }
        out
    }

    fn walk(&self, value: &Value, path: &str, out: &mut Vec<String>) {
        if out.len() >= MAX_VIOLATIONS {
            return;
        }
        if !self.kind.admits(value) {
            out.push(format!(
                "{path}: expected {}, got {}",
                self.kind.name(),
                got(value)
            ));
            // Descending into the wrong kind of value would only say the same thing
            // again in worse words.
            return;
        }
        if !self.allowed.is_empty() && !self.allowed.iter().any(|lit| same_literal(lit, value)) {
            let options: Vec<String> = self.allowed.iter().map(Value::to_string).collect();
            out.push(format!(
                "{path}: expected one of [{}], got {value}",
                options.join(", ")
            ));
        }
        match value {
            Value::Object(object) => {
                for key in &self.required {
                    if !object.contains_key(key) {
                        out.push(format!("{path}.{key}: missing required key"));
                    }
                }
                for (key, shape) in &self.properties {
                    if let Some(child) = object.get(key) {
                        shape.walk(child, &format!("{path}.{key}"), out);
                    }
                }
            }
            Value::Array(items) => {
                if let Some(shape) = &self.items {
                    for (index, item) in items.iter().enumerate() {
                        shape.walk(item, &format!("{path}[{index}]"), out);
                    }
                }
            }
            _ => {}
        }
    }
}

fn is_integer(value: &Value) -> bool {
    match value {
        Value::Number(number) => {
            number.is_i64()
                || number.is_u64()
                || number
                    .as_f64()
                    .is_some_and(|float| float.is_finite() && float.fract() == 0.0)
        }
        _ => false,
    }
}

/// The name of a value's type, as a person would say it.
fn got(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) if is_integer(value) => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Literal equality, with `1` and `1.0` the same number.
fn same_literal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        _ => a == b,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn contract(required: &[&str]) -> ResultContract {
        ResultContract {
            required: required.iter().map(ToString::to_string).collect(),
            schema: None,
        }
    }

    fn shape(value: Value) -> Shape {
        Shape::parse(&value).unwrap()
    }

    #[test]
    fn a_satisfied_contract_has_no_violations() {
        let contract = contract(&["output", "diff"]);
        let payload = json!({ "output": "hi", "diff": "---", "extra": true });
        assert!(contract.violations(&payload).is_empty());
    }

    #[test]
    fn a_missing_or_null_key_is_a_violation() {
        let contract = contract(&["output", "diff"]);
        let missing = contract.violations(&json!({ "output": "hi" }));
        assert_eq!(missing, vec!["diff"]);
        let null = contract.violations(&json!({ "output": "hi", "diff": null }));
        assert_eq!(null, vec!["diff"]);
    }

    #[test]
    fn a_non_object_result_violates_every_key() {
        let contract = contract(&["output"]);
        assert_eq!(contract.violations(&json!("just a string")), vec!["output"]);
    }

    #[test]
    fn an_old_contract_without_a_schema_still_reads_and_writes_the_same() {
        let old: ResultContract = serde_json::from_str(r#"{"required":["output"]}"#).unwrap();
        assert_eq!(old, contract(&["output"]));
        // And a contract with no schema does not grow a `schema` key on the wire.
        assert_eq!(
            serde_json::to_string(&old).unwrap(),
            r#"{"required":["output"]}"#
        );
    }

    #[test]
    fn a_schema_only_contract_needs_no_required_list() {
        let parsed: ResultContract =
            serde_json::from_str(r#"{"schema":{"type":"object","required":["id"]}}"#).unwrap();
        assert!(parsed.required.is_empty());
        assert_eq!(
            parsed.violations(&json!({})),
            vec!["result.id: missing required key"]
        );
    }

    #[test]
    fn required_and_schema_are_both_checked() {
        let mut both = contract(&["output"]);
        both.schema = Some(shape(json!({
            "type": "object",
            "properties": { "count": { "type": "integer" } }
        })));
        let found = both.violations(&json!({ "count": "three" }));
        assert_eq!(
            found,
            vec!["output", "result.count: expected integer, got string"]
        );
    }

    #[test]
    fn each_scalar_type_accepts_its_own_and_names_the_mismatch() {
        let cases = [
            ("string", json!("x"), json!(1), "integer"),
            ("number", json!(1.5), json!("1.5"), "string"),
            ("integer", json!(3), json!(3.5), "number"),
            ("boolean", json!(true), json!("true"), "string"),
            ("array", json!([]), json!({}), "object"),
            ("object", json!({}), json!([]), "array"),
            ("null", json!(null), json!(0), "integer"),
        ];
        for (kind, good, bad, got_name) in cases {
            let one = shape(json!({ "type": kind }));
            assert!(one.check(&good).is_empty(), "{kind} should accept {good}");
            assert_eq!(
                one.check(&bad),
                vec![format!("result: expected {kind}, got {got_name}")],
                "{kind} should refuse {bad}"
            );
        }
    }

    #[test]
    fn any_accepts_everything_and_is_the_default() {
        let anything = shape(json!({ "type": "any" }));
        let untyped = shape(json!({}));
        for value in [
            json!(null),
            json!(1),
            json!("s"),
            json!([1]),
            json!({"a": 1}),
        ] {
            assert!(anything.check(&value).is_empty());
            assert!(untyped.check(&value).is_empty());
        }
    }

    #[test]
    fn an_integer_may_be_written_with_a_zero_fraction() {
        let integer = shape(json!({ "type": "integer" }));
        assert!(integer.check(&json!(3.0)).is_empty());
        assert!(integer.check(&json!(-7)).is_empty());
        assert!(integer.check(&json!(3.25)).len() == 1);
    }

    #[test]
    fn nested_objects_report_the_full_path() {
        let user = shape(json!({
            "type": "object",
            "required": ["user"],
            "properties": {
                "user": {
                    "type": "object",
                    "required": ["id", "name"],
                    "properties": {
                        "id": { "type": "integer" },
                        "name": { "type": "string" }
                    }
                }
            }
        }));
        assert!(
            user.check(&json!({ "user": { "id": 1, "name": "a", "extra": true } }))
                .is_empty()
        );
        assert_eq!(
            user.check(&json!({ "user": { "id": "1" } })),
            vec![
                "result.user.name: missing required key",
                "result.user.id: expected integer, got string",
            ]
        );
        assert_eq!(
            user.check(&json!({})),
            vec!["result.user: missing required key"]
        );
    }

    #[test]
    fn array_items_are_checked_one_by_one_with_their_index() {
        let list = shape(json!({
            "type": "array",
            "items": {
                "type": "object",
                "required": ["id"],
                "properties": { "id": { "type": "integer" } }
            }
        }));
        assert!(list.check(&json!([])).is_empty());
        assert!(list.check(&json!([{ "id": 1 }, { "id": 2 }])).is_empty());
        assert_eq!(
            list.check(&json!([{ "id": 1 }, { "id": "x" }, {}, 5])),
            vec![
                "result[1].id: expected integer, got string",
                "result[2].id: missing required key",
                "result[3]: expected object, got integer",
            ]
        );
    }

    #[test]
    fn an_enum_admits_only_its_literals() {
        let status = shape(json!({ "type": "string", "enum": ["open", "closed"] }));
        assert!(status.check(&json!("open")).is_empty());
        assert_eq!(
            status.check(&json!("pending")),
            vec![r#"result: expected one of ["open", "closed"], got "pending""#]
        );
        // A number enum treats 1 and 1.0 as the same literal.
        let level = shape(json!({ "enum": [1, 2] }));
        assert!(level.check(&json!(1.0)).is_empty());
        assert_eq!(level.check(&json!(3)).len(), 1);
        // Enum applies to a mixed-literal list too.
        let mixed = shape(json!({ "enum": [null, "a", 7] }));
        assert!(mixed.check(&json!(null)).is_empty());
        assert_eq!(mixed.check(&json!(false)).len(), 1);
    }

    #[test]
    fn a_wrong_type_is_not_descended_into() {
        let object = shape(json!({
            "type": "object",
            "required": ["id"],
            "properties": { "id": { "type": "integer" } }
        }));
        assert_eq!(
            object.check(&json!("nope")),
            vec!["result: expected object, got string"]
        );
    }

    #[test]
    fn an_untyped_shape_still_constrains_the_object_it_meets() {
        let loose =
            shape(json!({ "required": ["id"], "properties": { "id": { "type": "string" } } }));
        assert_eq!(
            loose.check(&json!({ "id": 1 })),
            vec!["result.id: expected string, got integer"]
        );
        // A non-object simply has no keys to check.
        assert!(loose.check(&json!(5)).is_empty());
    }

    #[test]
    fn a_path_can_be_rooted_somewhere_other_than_result() {
        let id = shape(json!({ "type": "object", "required": ["id"] }));
        assert_eq!(
            id.check_at(&json!({}), "result.response"),
            vec!["result.response.id: missing required key"]
        );
    }

    #[test]
    fn an_explicit_null_counts_as_present_unless_the_type_refuses_it() {
        let loose = shape(json!({ "required": ["a"] }));
        assert!(loose.check(&json!({ "a": null })).is_empty());
        let strict = shape(json!({
            "required": ["a"],
            "properties": { "a": { "type": "string" } }
        }));
        assert_eq!(
            strict.check(&json!({ "a": null })),
            vec!["result.a: expected string, got null"]
        );
    }

    #[test]
    fn a_runaway_list_of_violations_is_capped() {
        let list = shape(json!({ "type": "array", "items": { "type": "string" } }));
        let numbers: Vec<Value> = (0..1000).map(|n| json!(n)).collect();
        let found = list.check(&Value::Array(numbers));
        assert_eq!(found.len(), MAX_VIOLATIONS + 1);
        assert_eq!(found.last().unwrap(), "(further violations omitted)");
    }

    #[test]
    fn a_typo_in_a_schema_file_is_refused_not_ignored() {
        let error = Shape::parse(&json!({ "type": "object", "requird": ["id"] })).unwrap_err();
        assert!(format!("{error}").contains("requird"), "{error}");
        let nested = Shape::parse(&json!({
            "type": "object",
            "properties": { "user": { "type": "object", "propertys": {} } }
        }))
        .unwrap_err();
        assert!(
            format!("{nested}").contains("shape.properties.user"),
            "{nested}"
        );
        assert!(Shape::parse(&json!({ "type": "text" })).is_err());
        assert!(Shape::parse(&json!("object")).is_err());
    }

    #[test]
    fn a_shape_round_trips_and_serializes_deterministically() {
        let original = shape(json!({
            "type": "object",
            "required": ["b", "a"],
            "properties": { "b": { "type": "string" }, "a": { "type": "integer" } }
        }));
        let text = serde_json::to_string(&original).unwrap();
        // Properties are ordered by name, whatever order they were written in: the text
        // is what gets signed.
        assert!(text.contains(r#""properties":{"a":"#), "{text}");
        let back: Shape = serde_json::from_str(&text).unwrap();
        assert_eq!(back, original);
        assert_eq!(serde_json::to_string(&back).unwrap(), text);
    }
}
