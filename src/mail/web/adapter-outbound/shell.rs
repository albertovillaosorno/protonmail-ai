// Copyright:
//   - Copyright © 2026 Alberto Villa Osorno.
// SPDX-License-Identifier:
//   - GPL-3.0-only
// Confidential:
//   - false
// License-File:
//   - LICENSE
//
// Boundary-Contract:
// - Owns:
//   - Translation-free Proton Mail shell evidence from accessibility roles.
// - Must-Not:
//   - Retain accessible names, DOM text, selectors, or mailbox content.
// - Allows:
//   - Classify structural landmarks and blocking dialogs from role queries.
// - Split-When:
//   - Composer or mailbox-item semantics need independently versioned evidence.
// - Merge-When:
//   - Browser transport can own semantic classification without mixing policy.
// - Summary:
//   - Reduces role-filtered accessibility output to non-content shell booleans.
// - Description:
//   - Recognizes navigation/search landmarks and visible dialog blockers only.
// - Usage:
//   - Managed browser inspection calls this after revalidating Proton Mail.
// - Defaults:
//   - Missing, ignored, or malformed shell evidence fails closed.
//

//! Translation-independent Proton Mail shell evidence.

use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

const MAX_AX_ROLE_MATCH_NODES: usize = 256;
const MAX_AX_BACKEND_NODE_ID: u64 = 2_147_483_647;

/// Structural Mail-shell evidence that contains no accessible names or text.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MailShellEvidence {
    modal_blocker_visible: bool,
    navigation_visible: bool,
    search_visible: bool,
}

// Session-scoped, bounded AX node identities from four role queries.
// Relationship data is borrowed only for shell classification, never returned.
#[derive(Default)]
struct AxGraph<'nodes> {
    ids: BTreeSet<&'nodes str>,
    parents: BTreeMap<&'nodes str, &'nodes str>,
    child_owners: BTreeMap<&'nodes str, &'nodes str>,
    landmark_frame: Option<&'nodes str>,
}

impl MailShellEvidence {
    /// Returns whether a visible navigation landmark was observed.
    #[must_use]
    pub const fn navigation_visible(self) -> bool {
        self.navigation_visible
    }

    /// Returns whether a visible search landmark was observed.
    #[must_use]
    pub const fn search_visible(self) -> bool {
        self.search_visible
    }

    /// Returns whether a visible dialog-like blocker was observed.
    #[must_use]
    pub const fn modal_blocker_visible(self) -> bool {
        self.modal_blocker_visible
    }

    /// Returns whether the minimal translation-free Mail shell is ready.
    #[must_use]
    pub const fn ready(self) -> bool {
        let landmarks = self.navigation_visible && self.search_visible;
        landmarks && !self.modal_blocker_visible
    }

    pub(crate) fn from_role_queries<'role_nodes>(
        navigation: &'role_nodes Value,
        search: &'role_nodes Value,
        dialog: &'role_nodes Value,
        alerts: &'role_nodes Value,
    ) -> Result<Self, ()> {
        // CDP AXNodeId identifies one accessibility node for the session.
        // A node cannot simultaneously establish distinct role-filtered
        // landmarks; aliases across responses are contradictory shell proof.
        let mut graph = AxGraph::default();
        let modal = ax_visible(dialog, "dialog", &mut graph)?;
        let alert = ax_visible(alerts, "alertdialog", &mut graph)?;
        let nav = ax_visible(navigation, "navigation", &mut graph)?;
        let search = ax_visible(search, "search", &mut graph)?;
        if !valid_ax_parent_graph(&graph) {
            return Err(());
        }
        Ok(Self {
            modal_blocker_visible: modal || alert,
            navigation_visible: nav,
            search_visible: search,
        })
    }
}

fn ax_visible<'role_nodes>(
    result: &'role_nodes Value,
    expected_role: &str,
    graph: &mut AxGraph<'role_nodes>,
) -> Result<bool, ()> {
    let nodes = result.get("nodes").and_then(Value::as_array).ok_or(())?;
    if nodes.len() > MAX_AX_ROLE_MATCH_NODES {
        return Err(());
    }
    let mut any_visible = false;
    for node in nodes {
        // A filtered AXNode may include names, values and ordinary Chrome
        // metadata, which stay unread and unretained. Unknown extensions can
        // carry unrelated private data or change the meaning of shell proof.
        // Only accept the documented AXNode field set.
        let fields = node.as_object().ok_or(())?;
        let allowed = [
            "nodeId",
            "ignored",
            "ignoredReasons",
            "role",
            "chromeRole",
            "name",
            "description",
            "value",
            "properties",
            "parentId",
            "childIds",
            "backendDOMNodeId",
            "frameId",
        ];
        if fields
            .keys()
            .any(|field| !allowed.contains(&field.as_str()))
        {
            return Err(());
        }
        let ignored = node.get("ignored").and_then(Value::as_bool).ok_or(())?;
        // CDP AXNode requires a unique string nodeId and a typed role. A
        // sparse or aliased node cannot prove a visible browser landmark.
        let id = node.get("nodeId").and_then(Value::as_str).ok_or(())?;
        if !valid_ax_node_id(id) || !graph.ids.insert(id) {
            return Err(());
        }
        // Node relationships do not establish a landmark by themselves,
        // but they cannot claim an impossible self-parent or self-child.
        let parent_id = if let Some(parent) = node.get("parentId") {
            let parent = parent.as_str().ok_or(())?;
            if !valid_ax_node_id(parent) || parent == id {
                return Err(());
            }
            Some(parent)
        } else {
            None
        };
        if let Some(parent) = parent_id {
            graph.parents.insert(id, parent);
        }
        if let Some(children) = node.get("childIds") {
            let children = children.as_array().ok_or(())?;
            if children.len() > 4096 {
                return Err(());
            }
            for child in children {
                let child = child.as_str().ok_or(())?;
                // The same node cannot be both parent and child of this AX
                // node, even if that external ID was not in a role query.
                let same_parent = parent_id == Some(child);
                let contradictory_edge = child == id || same_parent;
                if !valid_ax_node_id(child) || contradictory_edge {
                    return Err(());
                }
                if graph.child_owners.insert(child, id).is_some() {
                    return Err(());
                }
            }
        }
        if !valid_ax_properties(node.get("properties")) {
            return Err(());
        }
        // CDP AXNode.backendDOMNodeId is an optional signed protocol
        // integer, not an arbitrary JSON value or unbounded unsigned ID.
        // A contradictory browser node identity cannot prove readiness.
        if node.get("backendDOMNodeId").is_some_and(|backend| {
            backend
                .as_u64()
                .is_none_or(|id| !(1..=MAX_AX_BACKEND_NODE_ID).contains(&id))
        }) {
            return Err(());
        }
        record_ax_landmark_frame(node, ignored, expected_role, graph)?;
        if !valid_ax_role(node.get("role"), expected_role) {
            return Err(());
        }
        // A node claiming to be visible cannot simultaneously describe
        // reasons why the accessibility tree ignored it. Bound and type
        // check optional reasons even for ignored nodes, without retaining
        // their descriptions or any other private AX properties.
        if let Some(reasons) = node.get("ignoredReasons") {
            let reasons = reasons.as_array().ok_or(())?;
            if reasons.len() > 64 || (!ignored && !reasons.is_empty()) {
                return Err(());
            }
            for reason in reasons {
                if !valid_ax_hidden_reason(reason) {
                    return Err(());
                }
            }
        }
        // Even after a visible landmark is found, malformed later nodes
        // invalidate the query instead of being silently skipped.
        any_visible |= !ignored;
    }
    Ok(any_visible)
}

// AXNode.frameId is an optional opaque Page.FrameId. When Chromium reports
// it, visible navigation/search landmarks must agree on one document frame;
// absent IDs remain compatible with older CDP responses. Never retain names.
fn record_ax_landmark_frame<'nodes>(
    node: &'nodes Value,
    ignored: bool,
    role: &str,
    graph: &mut AxGraph<'nodes>,
) -> Result<(), ()> {
    let Some(frame) = node.get("frameId") else {
        return Ok(());
    };
    let frame = frame.as_str().ok_or(())?;
    if !valid_ax_frame_id(frame) {
        return Err(());
    }
    if !ignored && matches!(role, "navigation" | "search") {
        if graph.landmark_frame.is_some_and(|known| known != frame) {
            return Err(());
        }
        graph.landmark_frame = Some(frame);
    }
    Ok(())
}

// AXNode.properties holds computed AXProperty pairs, not arbitrary
// application JSON. Bound and check every entry before letting a structural
// role establish Mail-shell readiness. Names and values are borrowed for
// validation only; they are never projected or retained.
fn valid_ax_properties(value: Option<&Value>) -> bool {
    let Some(value) = value else {
        return true;
    };
    let Some(properties) = value.as_array() else {
        return false;
    };
    if properties.len() > MAX_AX_ROLE_MATCH_NODES {
        return false;
    }
    let mut names = BTreeSet::new();
    for property in properties {
        let Some(fields) = property.as_object() else {
            return false;
        };
        if fields.len() != 2 {
            return false;
        }
        let Some(name) = fields.get("name").and_then(Value::as_str) else {
            return false;
        };
        if !valid_ax_property_name(name)
            || !names.insert(name)
            || !fields
                .get("value")
                .is_some_and(|value| valid_ax_nested_value(value, 3))
        {
            return false;
        }
    }
    true
}

// Parent IDs and child IDs can point across role-filtered query replies.
// Each local node may look valid even when those responses jointly claim a
// circular accessibility tree or conflicting ownership. Treat both kinds of
// edge as one child-to-parent graph; an explicit parent and child owner must
// agree. Every cycle includes an observed node because unobserved nodes cannot
// report their own edges. Only 4 * 256 observed starts need to be traversed.
// No private accessibility text is retained.
fn valid_ax_parent_graph(graph: &AxGraph<'_>) -> bool {
    for (child, owner) in &graph.child_owners {
        if graph
            .parents
            .get(child)
            .is_some_and(|parent| parent != owner)
        {
            return false;
        }
    }
    for &start in &graph.ids {
        let mut visited = BTreeSet::new();
        let mut current = start;
        while let Some(parent) = graph
            .parents
            .get(current)
            .or_else(|| graph.child_owners.get(current))
            .copied()
        {
            if !visited.insert(current) {
                return false;
            }
            current = parent;
        }
    }
    true
}

// Roles prove the landmark through one bounded, audited AXValue shape.
fn valid_ax_role(role: Option<&Value>, expected_role: &str) -> bool {
    let Some(role) = role.and_then(Value::as_object) else {
        return false;
    };
    let kind = role.get("type").and_then(Value::as_str);
    let value = role.get("value").and_then(Value::as_str);
    let allowed = ["type", "value", "relatedNodes", "sources"];
    let mut fields = role.keys();
    let known_fields = fields.all(|field| allowed.contains(&field.as_str()));
    let arrays_valid = valid_ax_value_arrays(role);
    let typed = kind == Some("role") && value == Some(expected_role);
    typed && known_fields && arrays_valid
}

// Type-check the reason property before an ignored AX node can participate
// in shell classification. Do not copy or project its optional content.
fn valid_ax_hidden_reason(reason: &Value) -> bool {
    let Some(fields) = reason.as_object() else {
        return false;
    };
    let name = fields.get("name").and_then(Value::as_str);
    let Some(name) = name else {
        return false;
    };
    let value_fields = fields.get("value").and_then(Value::as_object);
    let Some(value_fields) = value_fields else {
        return false;
    };
    let kind = value_fields.get("type").and_then(Value::as_str);
    let Some(kind) = kind else {
        return false;
    };
    let known = value_fields.keys().all(|field| {
        matches!(
            field.as_str(),
            "type" | "value" | "relatedNodes" | "sources"
        )
    });
    let arrays_valid = valid_ax_value_arrays(value_fields);
    fields.len() == 2
        && name.len() <= 128
        && valid_ax_hidden_reason_name(name)
        && valid_ax_value_type(kind)
        && known
        && arrays_valid
        && valid_ax_scalar(kind, value_fields.get("value"))
}

// AXValue's optional collections cannot contain untyped JSON. Validate
// browser-owned relationship identifiers and source kinds without retaining
// their private text or forwarding their content.
fn valid_ax_value_arrays(fields: &Map<String, Value>) -> bool {
    valid_ax_arrays_depth(fields, 3)
}

fn valid_ax_arrays_depth(fields: &Map<String, Value>, depth: usize) -> bool {
    ["relatedNodes", "sources"]
        .iter()
        .all(|field| match fields.get(*field) {
            None => true,
            Some(Value::Array(entries)) => {
                let bounded = entries.len() <= MAX_AX_ROLE_MATCH_NODES;
                bounded
                    && entries.iter().all(|entry| match *field {
                        "relatedNodes" => valid_ax_related_node(entry),
                        "sources" => valid_ax_source(entry, depth),
                        _ => false,
                    })
            }
            Some(_) => false,
        })
}

fn valid_ax_related_node(node: &Value) -> bool {
    let Some(fields) = node.as_object() else {
        return false;
    };
    let backend = fields.get("backendDOMNodeId").and_then(Value::as_u64);
    let max_backend = MAX_AX_BACKEND_NODE_ID;
    let valid_backend = backend.is_some_and(|id| id > 0 && id <= max_backend);
    let allowed = ["backendDOMNodeId", "idref", "text"];
    let known = fields.keys().all(|field| allowed.contains(&field.as_str()));
    let text_valid = ["idref", "text"].iter().all(|field| {
        fields.get(*field).is_none_or(|value| {
            let text = value.as_str();
            text.is_some_and(|text| text.len() <= 16_384)
        })
    });
    valid_backend && known && text_valid
}

fn valid_ax_source(source: &Value, depth: usize) -> bool {
    let Some(fields) = source.as_object() else {
        return false;
    };
    let kind = fields.get("type").and_then(Value::as_str);
    let source_kinds = [
        "attribute",
        "implicit",
        "style",
        "contents",
        "placeholder",
        "relatedElement",
    ];
    let known_kind = kind.is_some_and(|kind| source_kinds.contains(&kind));
    let allowed = [
        "type",
        "value",
        "attribute",
        "attributeValue",
        "superseded",
        "nativeSource",
        "nativeSourceValue",
        "invalid",
        "invalidReason",
    ];
    let known = fields.keys().all(|field| allowed.contains(&field.as_str()));
    let text_valid = ["attribute", "invalidReason"]
        .iter()
        .all(|key| fields.get(*key).is_none_or(valid_ax_text));
    let boolean_valid = ["superseded", "invalid"]
        .iter()
        .all(|key| fields.get(*key).is_none_or(Value::is_boolean));
    let native_kinds = [
        "description",
        "figcaption",
        "label",
        "labelfor",
        "labelwrapped",
        "legend",
        "rubyannotation",
        "tablecaption",
        "title",
        "other",
    ];
    let native_valid = fields.get("nativeSource").is_none_or(|value| {
        value
            .as_str()
            .is_some_and(|kind| native_kinds.contains(&kind))
    });
    // These optional fields are AXValue objects themselves. Limit nesting
    // so a source cannot smuggle an unbounded private object graph into a
    // structural role proof. Values are validated, never copied or logged.
    let nested_valid = ["value", "attributeValue", "nativeSourceValue"]
        .iter()
        .all(|key| {
            fields.get(*key).is_none_or(|value| {
                depth
                    .checked_sub(1)
                    .is_some_and(|next| valid_ax_nested_value(value, next))
            })
        });
    let valid = text_valid && boolean_valid && native_valid && nested_valid;
    known_kind && known && valid
}

fn valid_ax_text(value: &Value) -> bool {
    value.as_str().is_some_and(|text| text.len() <= 16_384)
}

fn valid_ax_nested_value(value: &Value, depth: usize) -> bool {
    let Some(fields) = value.as_object() else {
        return false;
    };
    let Some(kind) = fields.get("type").and_then(Value::as_str) else {
        return false;
    };
    let allowed = ["type", "value", "relatedNodes", "sources"];
    valid_ax_value_type(kind)
        && fields.keys().all(|key| allowed.contains(&key.as_str()))
        && valid_ax_scalar(kind, fields.get("value"))
        && valid_ax_arrays_depth(fields, depth)
}

fn valid_ax_scalar(kind: &str, value: Option<&Value>) -> bool {
    let text_kinds = [
        "string",
        "computedString",
        "role",
        "internalRole",
        "idref",
        "idrefList",
        "token",
        "tokenList",
        "tristate",
    ];
    match (kind, value) {
        // An undefined AXValue cannot also carry a concrete scalar. A
        // boolean-or-undefined value cannot claim a string or number.
        ("valueUndefined", Some(_)) => false,
        ("boolean" | "booleanOrUndefined", Some(raw)) => raw.is_boolean(),
        ("integer", Some(raw)) => raw.as_i64().is_some(),
        ("number", Some(raw)) => raw.is_number(),
        (_, Some(raw)) if text_kinds.contains(&kind) => raw.is_string(),
        // CDP declares AXValue.value as `any`. An object or array is not
        // required for structural Mail-shell proof and would expose an
        // unreviewed nested data shape. Treat only primitive values as safe
        // until a specific composite encoding has its own audited contract.
        (_, Some(raw)) => !raw.is_object() && !raw.is_array(),
        (_, None) => true,
    }
}

// AXNode.properties contains only the documented computed AXPropertyName
// values. Ignored reasons are checked separately; keeping their known names
// in this enum remains compatible with the shared CDP property schema.
fn valid_ax_property_name(name: &str) -> bool {
    matches!(
        name,
        "actions"
            | "busy"
            | "disabled"
            | "editable"
            | "focusable"
            | "focused"
            | "hidden"
            | "hiddenRoot"
            | "invalid"
            | "keyshortcuts"
            | "settable"
            | "roledescription"
            | "live"
            | "atomic"
            | "relevant"
            | "root"
            | "autocomplete"
            | "hasPopup"
            | "level"
            | "multiselectable"
            | "orientation"
            | "multiline"
            | "readonly"
            | "required"
            | "valuemin"
            | "valuemax"
            | "valuetext"
            | "checked"
            | "expanded"
            | "modal"
            | "pressed"
            | "selected"
            | "activedescendant"
            | "controls"
            | "describedby"
            | "details"
            | "errormessage"
            | "flowto"
            | "labelledby"
            | "owns"
            | "url"
    ) || valid_ax_hidden_reason_name(name)
}

// CDP AXPropertyName reserves this enum suffix for reasons a node is hidden.
fn valid_ax_hidden_reason_name(name: &str) -> bool {
    matches!(
        name,
        "activeFullscreenElement"
            | "activeModalDialog"
            | "activeAriaModalDialog"
            | "ariaHiddenElement"
            | "ariaHiddenSubtree"
            | "emptyAlt"
            | "emptyText"
            | "inertElement"
            | "inertSubtree"
            | "labelContainer"
            | "labelFor"
            | "notRendered"
            | "notVisible"
            | "presentationalRole"
            | "probablyPresentational"
            | "inactiveCarouselTabContent"
            | "uninteresting"
    )
}

// CDP AXValue.type is a finite enum even when the value is unused by shell.
fn valid_ax_value_type(kind: &str) -> bool {
    matches!(
        kind,
        "boolean"
            | "tristate"
            | "booleanOrUndefined"
            | "idref"
            | "idrefList"
            | "integer"
            | "node"
            | "nodeList"
            | "number"
            | "string"
            | "computedString"
            | "token"
            | "tokenList"
            | "domRelation"
            | "role"
            | "internalRole"
            | "valueUndefined"
    )
}

// Browser frame IDs have narrower syntax than AX node IDs. Keep ordinary
// AXNodeId punctuation compatible, but refuse path/query frame ID aliases.
fn valid_ax_frame_id(id: &str) -> bool {
    let allowed = id.bytes().all(|byte| match byte {
        b'-' | b'_' => true,
        _ => byte.is_ascii_alphanumeric(),
    });
    !id.is_empty() && id.len() <= 512 && allowed
}

fn valid_ax_node_id(id: &str) -> bool {
    let bounded = !id.is_empty() && id.len() <= 512;
    bounded && id.bytes().all(|byte| byte.is_ascii_graphic())
}
