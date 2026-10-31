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
//   - Synthetic CDP evidence for translation-free Mail-shell inspection.
// - Must-Not:
//   - Launch real Chrome, access an account, or expose accessible-name content.
// - Allows:
//   - Emulate DOM root and role-filtered Accessibility query responses.
// - Split-When:
//   - Composer semantics require their own independent page-state fixtures.
// - Merge-When:
//   - A broader web-adapter semantic suite owns the same shell invariants.
// - Summary:
//   - Proves Mail readiness uses structural roles and fails closed on drift.
// - Description:
//   - Exercises landmarks, blockers, malformed AX output, and origin drift.
// - Usage:
//   - Run through the `mail_web_adapter` integration-test target.
// - Defaults:
//   - Synthetic local process and filesystem state only.
//

//! Proton Mail shell accessibility-query regression tests.

use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process;

use mail_web_adapter::PageOrigin;
use mail_web_adapter::{BrowserDriverError, ManagedBrowser, ManagedBrowserPlan};

const VISIBLE: &str =
    // jig-ignore-next-line: indivisible synthetic AX privacy fixture.
    r#"[{"ignored":false,"nodeId":"ax-__AX_ROLE__","role":{"type":"role","value":"__AX_ROLE__"},"name":{"value":"no-leer"},"value":{"value":"secreto"}}]"#;
const IGNORED: &str =
    // jig-ignore-next-line: indivisible synthetic AXNode fixture.
    r#"[{"ignored":true,"nodeId":"ax-__AX_ROLE__","role":{"type":"role","value":"__AX_ROLE__"},"name":{"value":"no-leer"}}]"#;
const ABSENT: &str = "[]";

struct RoleFixture<'fixture> {
    alertdialog: &'fixture str,
    dialog: &'fixture str,
    navigation: &'fixture str,
    search: &'fixture str,
}

impl RoleFixture<'_> {
    const fn ready() -> Self {
        Self {
            alertdialog: ABSENT,
            dialog: ABSENT,
            navigation: VISIBLE,
            search: VISIBLE,
        }
    }
}

fn test_root(label: &str) -> PathBuf {
    let name = format!("protonmail-ai-shell-{label}-{}", process::id());
    env::temp_dir().join(name)
}

fn fake_browser(
    root: &Path,
    target_url: &str,
    runtime_host: &str,
    runtime_host_after: &str,
    roles: &RoleFixture<'_>,
) -> PathBuf {
    let script = root.join("fake-browser");
    let body = format!(
        r#"#!/usr/bin/env bash
set -eu
origin_probe=0
while IFS= read -r -d '' message <&3; do
  id=$(printf '%s' "$message" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
  case "$message" in
    *'Browser.getVersion'*)
      printf '{{"id":%s,"result":{{"product":"FakeChrome/1"}}}}\0' "$id" >&4;;
    *'Target.getTargets'*)
      target='[{{"targetId":"page-1","type":"page","url":"{target_url}"}}]'
      printf '{{"id":%s,"result":{{"targetInfos":%s}}}}\0' "$id" "$target" >&4;;
    *'Target.attachToTarget'*)
      printf '{{"id":%s,"result":{{"sessionId":"session-1"}}}}\0' "$id" >&4;;
    *'Runtime.evaluate'*)
      origin_probe=$((origin_probe + 1))
      host='{runtime_host}'
      if [ "$origin_probe" -gt 1 ]; then host='{runtime_host_after}'; fi
      response='{{"id":'"$id"','
      response+='"sessionId":"session-1","result":{{"result":{{"type":"object",'
      response+='"value":{{"protocol":"https:",'
      response+='"hostname":"'"$host"'",'
      response+='"port":""}}}}}}}}'
      printf '%s\0' "$response" >&4;;
    *'DOM.getDocument'*)
      reply_format='{{"id":%s,"sessionId":"session-1",'
      # jig-ignore-next-line: indivisible synthetic CDP document root.
      reply_format+='"result":{{"root":{{"nodeId":1,"backendNodeId":2,"nodeType":9,"nodeName":"\u0023document","localName":"","nodeValue":""}}}}}}\0'
      printf "$reply_format" "$id" >&4;;
    *'Accessibility.queryAXTree'*)
      case "$message" in
        *'"role":"navigation"'*) nodes='{navigation}';;
        *'"role":"search"'*) nodes='{search}';;
        *'"role":"alertdialog"'*) nodes='{alertdialog}';;
        *'"role":"dialog"'*) nodes='{dialog}';;
        *) exit 91;;
      esac
      # QueryAXTree commands carry one exact, reviewed role filter.
      requested_role=$(printf '%s' "$message" |
        sed -n 's/.*"role":"\([^"]*\)".*/\1/p')
      [ -n "$requested_role" ] || exit 91
      nodes=$(printf '%s' "$nodes" | sed "s/__AX_ROLE__/$requested_role/g")
      reply_format='{{"id":%s,"sessionId":"session-1",'
      reply_format+='"result":{{"nodes":%s}}}}\0'
      printf "$reply_format" "$id" "$nodes" >&4;;
    *'Target.detachFromTarget'*)
      printf '{{"id":%s,"result":{{}}}}\0' "$id" >&4;;
    *) exit 92;;
  esac
done
"#,
        target_url = target_url,
        runtime_host = runtime_host,
        runtime_host_after = runtime_host_after,
        navigation = roles.navigation,
        search = roles.search,
        dialog = roles.dialog,
        alertdialog = roles.alertdialog,
    );
    fs::write(&script, body).expect("write fake browser");
    // jig-ignore-next-line: canonical rustfmt line.
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).expect("chmod fake browser");
    script
}

fn plan(root: &Path, browser: &Path) -> ManagedBrowserPlan {
    ManagedBrowserPlan::under_data_home(
        browser.to_str().expect("browser path must be UTF-8"),
        &root.join("data"),
    )
    .expect("build managed browser plan")
}

fn inspect_with_hosts(
    label: &str,
    target_url: &str,
    runtime_host: &str,
    runtime_host_after: &str,
    roles: &RoleFixture<'_>,
) -> Result<mail_web_adapter::MailShellEvidence, BrowserDriverError> {
    let root = test_root(label);
    fs::create_dir_all(&root).expect("create synthetic root");
    // jig-ignore-next-line: canonical rustfmt line.
    let browser = fake_browser(&root, target_url, runtime_host, runtime_host_after, roles);
    let browser_plan = plan(&root, &browser);
    // jig-ignore-next-line: canonical rustfmt line.
    let mut managed = ManagedBrowser::launch(&browser_plan).expect("launch fake driver");
    let page = managed.provider_page().expect("discover provider page");
    let result = managed.inspect_mail_shell(&page);
    drop(managed);
    fs::remove_dir_all(root).expect("remove synthetic root");
    result
}

fn inspect(
    label: &str,
    target_url: &str,
    runtime_host: &str,
    roles: &RoleFixture<'_>,
) -> Result<mail_web_adapter::MailShellEvidence, BrowserDriverError> {
    inspect_with_hosts(label, target_url, runtime_host, runtime_host, roles)
}

#[test]
fn structural_roles_make_mail_shell_ready_without_using_names() {
    let evidence = inspect(
        "ready",
        "https://mail.proton.me/u/0/inbox",
        "mail.proton.me",
        &RoleFixture::ready(),
    )
    .expect("inspect ready Mail shell");
    assert!(evidence.navigation_visible());
    assert!(evidence.search_visible());
    assert!(!evidence.modal_blocker_visible());
    assert!(evidence.ready());
    let diagnostic = format!("{evidence:?}");
    assert!(!diagnostic.contains("no-leer"));
    assert!(!diagnostic.contains("secreto"));
}

#[test]
fn unreviewed_accessibility_role_value_fields_cannot_prove_shell() {
    let base = concat!(
        r#"[{"ignored":false,"nodeId":"ax-navigation","#,
        r#""role":{"type":"role","value":"__AX_ROLE__""#
    );
    for (label, extension) in [
        (
            "unknown-role-payload",
            r#", "futureRoleData":{"private":true}"#,
        ),
        ("unknown-role-null", r#", "futureRoleFlag":null"#),
        ("wrong-related-nodes", r#", "relatedNodes":true"#),
        ("wrong-role-sources", r#", "sources":false"#),
        ("null-related-node", r#", "relatedNodes":[null]"#),
        ("unidentified-related-node", r#", "relatedNodes":[{}]"#),
        ("wrong-source-item", r#", "sources":[true]"#),
        ("unknown-source-type", r#", "sources":[{"type":"future"}]"#),
    ] {
        let navigation = format!("{base}{extension}}}}}]");
        let roles = RoleFixture {
            navigation: &navigation,
            ..RoleFixture::ready()
        };
        assert_eq!(
            inspect(
                label,
                "https://mail.proton.me/u/0/inbox",
                "mail.proton.me",
                &roles
            ),
            Err(BrowserDriverError::Protocol)
        );
    }
}

#[test]
fn malformed_accessibility_source_values_cannot_prove_shell() {
    use serde_json::json;

    for (label, source) in [
        (
            "attribute-number",
            json!({"type":"attribute", "attribute":42i32}),
        ),
        (
            "superseded-text",
            json!({"type":"implicit", "superseded":"yes"}),
        ),
        ("invalid-null", json!({"type":"implicit", "invalid":null})),
        (
            "invalid-reason-object",
            json!({"type":"implicit", "invalidReason":{}}),
        ),
        (
            "unknown-native",
            json!({"type":"implicit", "nativeSource":"future"}),
        ),
        ("value-number", json!({"type":"implicit", "value":3i32})),
        (
            "attribute-value-array",
            json!({"type":"attribute", "attributeValue":[]}),
        ),
        (
            "native-value-type",
            json!({"type":"implicit", "nativeSourceValue":{"type":"future"}}),
        ),
        (
            "nested-source-attribute",
            json!({
                "type":"implicit", "value":{
                    "type":"string",
                    "sources":[{"type":"attribute", "attribute":7i32}]
                }
            }),
        ),
    ] {
        let navigation = json!([{
            "ignored":false,
            "nodeId":"ax-navigation",
            "role":{"type":"role", "value":"navigation", "sources":[source]}
        }])
        .to_string();
        let roles = RoleFixture {
            navigation: &navigation,
            ..RoleFixture::ready()
        };
        assert_eq!(
            inspect(
                label,
                "https://mail.proton.me/u/0/inbox",
                "mail.proton.me",
                &roles
            ),
            Err(BrowserDriverError::Protocol),
            "malformed optional AXValueSource: {label}"
        );
    }
}

#[test]
fn oversized_accessibility_role_arrays_cannot_prove_shell() {
    let oversized = format!("[{}]", vec!["null"; 257].join(","));
    for field in ["relatedNodes", "sources"] {
        let navigation = format!(
            concat!(
                r#"[{{"ignored":false,"nodeId":"ax-navigation","#,
                r#""role":{{"type":"role","value":"navigation","#,
                r#""{field}":{oversized}}}}}]"#
            ),
            field = field,
            oversized = oversized
        );
        let roles = RoleFixture {
            navigation: &navigation,
            ..RoleFixture::ready()
        };
        assert_eq!(
            inspect(
                field,
                "https://mail.proton.me/u/0/inbox",
                "mail.proton.me",
                &roles
            ),
            Err(BrowserDriverError::Protocol)
        );
    }
}

#[test]
fn documented_optional_accessibility_role_arrays_remain_compatible() {
    let navigation = concat!(
        r#"[{"ignored":false,"nodeId":"ax-navigation","#,
        r#""role":{"type":"role","value":"__AX_ROLE__","#,
        r#""relatedNodes":[{"backendDOMNodeId":3}],"#,
        r#""sources":[{"type":"attribute","attribute":"aria-label","#,
        r#""attributeValue":{"type":"string","value":"test"},"#,
        r#""nativeSource":"description","superseded":false,"#,
        r#""value":{"type":"nodeList","relatedNodes":["#,
        r#"{"backendDOMNodeId":7}]},"#,
        r#""invalid":false,"invalidReason":"none"}]}}]"#
    );
    let roles = RoleFixture {
        navigation,
        ..RoleFixture::ready()
    };
    assert!(
        inspect(
            "normal-role-arrays",
            "https://mail.proton.me/u/0/inbox",
            "mail.proton.me",
            &roles
        )
        .expect("normal role AXValue")
        .ready()
    );
}

#[test]
fn visible_accessibility_landmarks_cannot_report_hidden_reasons() {
    // CDP ignoredReasons describes why a node is hidden. An explicitly
    // visible navigation landmark cannot also carry a nonempty hidden reason.
    let contradictory = concat!(
        r#"[{"ignored":false,"nodeId":"ax-navigation", "#,
        r#""role":{"type":"role","value":"__AX_ROLE__"},"#,
        r#""ignoredReasons":[{"name":"notVisible","#,
        r#""value":{"type":"boolean","value":true}}]}]"#
    );
    let roles = RoleFixture {
        navigation: contradictory,
        ..RoleFixture::ready()
    };
    assert_eq!(
        inspect(
            "visible-with-hidden-reason",
            "https://mail.proton.me/u/0/inbox",
            "mail.proton.me",
            &roles
        ),
        Err(BrowserDriverError::Protocol)
    );
}

#[test]
fn hidden_accessibility_reasons_require_bounded_typed_metadata() {
    let bounded_reason = concat!(
        r#"{"name":"notVisible","#,
        r#""value":{"type":"boolean","value":true}}"#
    );
    let oversized = format!("[{}]", vec![bounded_reason; 65].join(","));
    let reason = |name: &str, kind: &str| {
        format!(
            concat!(
                r#"[{{"name":"{name}","#,
                r#""value":{{"type":"{kind}","value":true}}}}]"#
            ),
            name = name,
            kind = kind
        )
    };
    for (label, reasons) in [
        ("wrong-reasons-shape", String::from("true")),
        (
            "missing-ignored-reason-value",
            String::from(r#"[{"name":"notVisible"}]"#),
        ),
        ("overlarge-ignored-reasons", oversized),
        (
            "reason-boolean-as-text",
            String::from(concat!(
                r#"[{"name":"notVisible","#,
                r#""value":{"type":"boolean","value":"true"}}]"#
            )),
        ),
        (
            "reason-boolean-as-null",
            String::from(concat!(
                r#"[{"name":"notVisible","#,
                r#""value":{"type":"boolean","value":null}}]"#
            )),
        ),
        (
            "reason-sources-not-array",
            String::from(concat!(
                r#"[{"name":"notVisible","#,
                r#""value":{"type":"boolean","value":true,"sources":false}}]"#
            )),
        ),
        (
            "reason-related-nodes-not-array",
            String::from(concat!(
                r#"[{"name":"notVisible","#,
                r#""value":{"type":"boolean","value":true,"relatedNodes":{}}}]"#
            )),
        ),
        (
            "reason-null-related-node",
            String::from(concat!(
                r#"[{"name":"notVisible","#,
                r#""value":{"type":"boolean","relatedNodes":[null]}}]"#
            )),
        ),
        (
            "reason-unknown-source-type",
            String::from(concat!(
                r#"[{"name":"notVisible","#,
                r#""value":{"type":"boolean","sources":[{"type":"future"}]}}]"#
            )),
        ),
        (
            "reason-invalid-source-boolean",
            String::from(concat!(
                r#"[{"name":"notVisible","#,
                r#""value":{"type":"boolean","sources":[{"type":"implicit","#,
                r#""invalid":"false"}]}}]"#
            )),
        ),
        ("ordinary-property-as-reason", reason("selected", "boolean")),
        ("unknown-ignored-reason", reason("futureReason", "boolean")),
        (
            "unknown-ignored-reason-type",
            reason("notVisible", "unreviewed"),
        ),
        (
            "extra-ignored-reason-payload",
            String::from(concat!(
                r#"[{"name":"notVisible","#,
                r#""value":{"type":"boolean","value":true},"#,
                r#""futureValue":"private"}]"#
            )),
        ),
    ] {
        assert_malformed_ax_reason(label, &reasons);
    }
}

fn assert_malformed_ax_reason(label: &str, reasons: &str) {
    let node = format!(
        concat!(
            r#"[{{"ignored":true,"nodeId":"ax-search","#,
            r#""role":{{"type":"role","value":"__AX_ROLE__"}},"#,
            r#""ignoredReasons":{reasons}}}]"#
        ),
        reasons = reasons
    );
    let roles = RoleFixture {
        search: &node,
        ..RoleFixture::ready()
    };
    assert_eq!(
        inspect(
            label,
            "https://mail.proton.me/u/0/inbox",
            "mail.proton.me",
            &roles
        ),
        Err(BrowserDriverError::Protocol)
    );
}

#[test]
fn ordinary_accessibility_ignored_reasons_remain_compatible() {
    let visible = concat!(
        r#"[{"ignored":false,"nodeId":"ax-navigation","#,
        r#""role":{"type":"role","value":"__AX_ROLE__"},"#,
        r#""ignoredReasons":[]}]"#
    );
    let hidden = concat!(
        r#"[{"ignored":true,"nodeId":"ax-search","#,
        r#""role":{"type":"role","value":"__AX_ROLE__"},"#,
        r#""ignoredReasons":[{"name":"notVisible","#,
        r#""value":{"type":"boolean","value":true}}]}]"#
    );
    let visible_roles = RoleFixture {
        navigation: visible,
        ..RoleFixture::ready()
    };
    assert!(
        inspect(
            "empty-ignored-reasons",
            "https://mail.proton.me/u/0/inbox",
            "mail.proton.me",
            &visible_roles
        )
        .expect("empty reasons")
        .ready()
    );
    let ignored_roles = RoleFixture {
        search: hidden,
        ..visible_roles
    };
    let evidence = inspect(
        "typed-hidden-reasons",
        "https://mail.proton.me/u/0/inbox",
        "mail.proton.me",
        &ignored_roles,
    )
    .expect("ignored reason");
    assert!(!evidence.search_visible());
    assert!(!evidence.ready());
}

#[test]
fn accessibility_node_cannot_be_its_own_parent_or_child() {
    let base = concat!(
        r#"[{"ignored":false,"nodeId":"ax-navigation","#,
        r#""role":{"type":"role","value":"__AX_ROLE__"}"#
    );
    for (label, extra) in [
        ("self-parent", r#", "parentId":"ax-navigation""#),
        ("self-child", r#", "childIds":["ax-navigation"]"#),
    ] {
        let node = format!("{base}{extra}}}]");
        let roles = RoleFixture {
            navigation: &node,
            ..RoleFixture::ready()
        };
        assert_eq!(
            inspect(
                label,
                "https://mail.proton.me/u/0/inbox",
                "mail.proton.me",
                &roles
            ),
            Err(BrowserDriverError::Protocol)
        );
    }
}

#[test]
fn accessibility_parent_cannot_also_be_a_child() {
    let navigation = concat!(
        r#"[{"ignored":false,"nodeId":"ax-navigation","#,
        r#""role":{"type":"role","value":"__AX_ROLE__"},"#,
        r#""parentId":"ax-root","childIds":["ax-one","ax-root"]}]"#
    );
    let roles = RoleFixture {
        navigation,
        ..RoleFixture::ready()
    };
    assert_eq!(
        inspect(
            "parent-listed-as-child",
            "https://mail.proton.me/u/0/inbox",
            "mail.proton.me",
            &roles
        ),
        Err(BrowserDriverError::Protocol)
    );
}

#[test]
fn ordinary_ax_node_parent_and_child_metadata_remains_compatible() {
    let navigation = concat!(
        r#"[{"ignored":false,"nodeId":"ax-navigation","#,
        r#""role":{"type":"role","value":"__AX_ROLE__"},"#,
        r#""parentId":"ax-root","childIds":["ax-one","ax-two"]}]"#
    );
    let roles = RoleFixture {
        navigation,
        ..RoleFixture::ready()
    };
    assert!(
        inspect(
            "valid-ax-relationships",
            "https://mail.proton.me/u/0/inbox",
            "mail.proton.me",
            &roles
        )
        .expect("valid AX topology")
        .ready()
    );
}

#[test]
fn malformed_ax_node_relationships_cannot_prove_landmarks() {
    let base = concat!(
        r#"[{"ignored":false,"nodeId":"ax-navigation","#,
        r#""role":{"type":"role","value":"__AX_ROLE__"}"#
    );
    for (label, extra) in [
        ("numeric-parent", r#", "parentId":4"#),
        ("missing-child-id", r#", "childIds":[null]"#),
        ("duplicate-children", r#", "childIds":["ax-one","ax-one"]"#),
        ("wrong-children-type", r#", "childIds":false"#),
    ] {
        let node = format!("{base}{extra}}}]");
        let roles = RoleFixture {
            navigation: &node,
            ..RoleFixture::ready()
        };
        assert_eq!(
            inspect(
                label,
                "https://mail.proton.me/u/0/inbox",
                "mail.proton.me",
                &roles
            ),
            Err(BrowserDriverError::Protocol)
        );
    }
}

#[test]
fn malformed_ax_backend_dom_node_id_cannot_prove_landmarks() {
    // AXNode.backendDOMNodeId is an optional CDP BackendNodeId integer.
    // A malformed node identity must not still authorize the Mail shell.
    let base = concat!(
        r#"[{"ignored":false,"nodeId":"ax-navigation","#,
        r#""role":{"type":"role","value":"__AX_ROLE__"}"#
    );
    for (label, id) in [
        ("zero-backend-id", "0"),
        ("negative-backend-id", "-1"),
        ("large-backend-id", "2147483648"),
        ("string-backend-id", "\"123\""),
        ("null-backend-id", "null"),
        ("fractional-backend-id", "1.5"),
    ] {
        let navigation = format!(r#"{base},"backendDOMNodeId":{id}}}]"#);
        let roles = RoleFixture {
            navigation: &navigation,
            ..RoleFixture::ready()
        };
        assert_eq!(
            inspect(
                label,
                "https://mail.proton.me/u/0/inbox",
                "mail.proton.me",
                &roles
            ),
            Err(BrowserDriverError::Protocol),
            "invalid optional backend identity {label} must fail closed"
        );
    }
    let valid_ids = [("small-backend-id", 1i32), ("max-backend-id", i32::MAX)];
    for (label, id) in valid_ids {
        let navigation = format!(r#"{base},"backendDOMNodeId":{id}}}]"#);
        let roles = RoleFixture {
            navigation: &navigation,
            ..RoleFixture::ready()
        };
        assert!(
            inspect(
                label,
                "https://mail.proton.me/u/0/inbox",
                "mail.proton.me",
                &roles
            )
            .expect("valid optional backend identity")
            .ready()
        );
    }
}

#[test]
fn malformed_ax_frame_id_cannot_prove_landmarks() {
    // Page.FrameId is a bounded opaque browser identity when supplied.
    let base = concat!(
        r#"[{"ignored":false,"nodeId":"ax-navigation","#,
        r#""role":{"type":"role","value":"__AX_ROLE__"}"#
    );
    for (label, frame) in [
        ("empty-frame-id", String::from(r#""""#)),
        ("null-frame-id", String::from("null")),
        ("numeric-frame-id", String::from("123")),
        ("hidden-frame-id", String::from(r#""f\u200b1""#)),
        ("control-frame-id", String::from(r#""f\n1""#)),
        ("slash-frame-id", String::from(r#""frame/other""#)),
        ("query-frame-id", String::from(r#""frame?other""#)),
        ("colon-frame-id", String::from(r#""frame:other""#)),
        ("oversized-frame-id", format!("\"{}\"", "f".repeat(513))),
    ] {
        let navigation = format!(r#"{base},"frameId":{frame}}}]"#);
        let roles = RoleFixture {
            navigation: &navigation,
            ..RoleFixture::ready()
        };
        assert_eq!(
            inspect(
                label,
                "https://mail.proton.me/u/0/inbox",
                "mail.proton.me",
                &roles
            ),
            Err(BrowserDriverError::Protocol),
            "invalid optional frame identity {label} must fail closed"
        );
    }
    let navigation = format!(r#"{base},"frameId":"frame-A1_2"}}]"#);
    let roles = RoleFixture {
        navigation: &navigation,
        ..RoleFixture::ready()
    };
    assert!(
        inspect(
            "ordinary-frame-id",
            "https://mail.proton.me/u/0/inbox",
            "mail.proton.me",
            &roles
        )
        .expect("valid optional browser frame identity")
        .ready()
    );
}

#[test]
fn oversized_ax_child_list_cannot_prove_navigation_landmark() {
    let children = (0..4097u32)
        .map(|index| format!(r#""ax-child-{index}""#))
        .collect::<Vec<_>>()
        .join(",");
    let navigation = format!(
        concat!(
            r#"[{{"ignored":false,"nodeId":"ax-navigation","#,
            r#""role":{{"type":"role","value":"__AX_ROLE__"}},"#,
            r#""childIds":[{children}]}}]"#
        ),
        children = children
    );
    let roles = RoleFixture {
        navigation: &navigation,
        ..RoleFixture::ready()
    };
    assert_eq!(
        inspect(
            "oversized-ax-children",
            "https://mail.proton.me/u/0/inbox",
            "mail.proton.me",
            &roles
        ),
        Err(BrowserDriverError::Protocol)
    );
}

#[test]
fn one_accessibility_node_cannot_prove_two_different_shell_roles() {
    // One AX node cannot prove incompatible navigation and search roles.
    let shared =
        // jig-ignore-next-line: indivisible cross-role AX protocol fixture.
        r#"[{"ignored":false,"nodeId":"ax-shared","role":{"type":"role","value":"__AX_ROLE__"}}]"#;
    let roles = RoleFixture {
        navigation: shared,
        search: shared,
        ..RoleFixture::ready()
    };
    assert_eq!(
        inspect(
            "cross-role-node-alias",
            "https://mail.proton.me/u/0/inbox",
            "mail.proton.me",
            &roles
        ),
        Err(BrowserDriverError::Protocol)
    );
}

#[test]
fn ignored_dialog_node_cannot_alias_a_visible_navigation_node() {
    // Even an ignored dialog node cannot alias the navigation landmark.
    let dialog =
        // jig-ignore-next-line: indivisible cross-role AX protocol fixture.
        r#"[{"ignored":true,"nodeId":"ax-shared","role":{"type":"role","value":"__AX_ROLE__"}}]"#;
    let navigation =
        // jig-ignore-next-line: indivisible cross-role AX protocol fixture.
        r#"[{"ignored":false,"nodeId":"ax-shared","role":{"type":"role","value":"__AX_ROLE__"}}]"#;
    let roles = RoleFixture {
        dialog,
        navigation,
        ..RoleFixture::ready()
    };
    assert_eq!(
        inspect(
            "ignored-dialog-node-alias",
            "https://mail.proton.me/u/0/inbox",
            "mail.proton.me",
            &roles
        ),
        Err(BrowserDriverError::Protocol)
    );
}

#[test]
fn unreviewed_dom_and_ax_result_fields_cannot_authorize_shell() {
    for (label, from, to) in [
        (
            "ax-result-extra",
            r#""nodes":%s}}"#,
            r#""nodes":%s,"unreviewed":true}}"#,
        ),
        (
            "dom-result-extra",
            // jig-ignore-next-line: indivisible synthetic CDP document root.
            r#""root":{"nodeId":1,"backendNodeId":2,"nodeType":9,"nodeName":"\u0023document","localName":"","nodeValue":""}}"#,
            // jig-ignore-next-line: indivisible synthetic CDP document root.
            r#""root":{"nodeId":1,"backendNodeId":2,"nodeType":9,"nodeName":"\u0023document","localName":"","nodeValue":""},"unreviewed":true}"#,
        ),
    ] {
        let root = test_root(label);
        fs::create_dir_all(&root).expect("create synthetic root");
        let browser = fake_browser(
            &root,
            "https://mail.proton.me/u/0/inbox",
            "mail.proton.me",
            "mail.proton.me",
            &RoleFixture::ready(),
        );
        let source = fs::read_to_string(&browser).expect("read fixture");
        assert!(source.contains(from), "fixture {label} must be present");
        fs::write(&browser, source.replacen(from, to, 1))
            .expect("insert unreviewed CDP result property");
        let browser_plan = plan(&root, &browser);
        let mut managed = ManagedBrowser::launch(&browser_plan).expect("CDP");
        let page = managed.provider_page().expect("discover Mail page");
        assert_eq!(
            managed.require_mail_shell(&page),
            Err(BrowserDriverError::Protocol),
            "{label} must fail closed"
        );
        drop(managed);
        fs::remove_dir_all(root).expect("remove synthetic root");
    }
}

#[test]
fn required_mail_shell_rejects_missing_landmark() {
    let roles = RoleFixture {
        search: IGNORED,
        ..RoleFixture::ready()
    };
    let root = test_root("required-shell");
    fs::create_dir_all(&root).expect("create synthetic root");
    let browser = fake_browser(
        &root,
        "https://mail.proton.me/u/0/inbox",
        "mail.proton.me",
        "mail.proton.me",
        &roles,
    );
    let browser_plan = plan(&root, &browser);
    // jig-ignore-next-line: canonical rustfmt line.
    let mut managed = ManagedBrowser::launch(&browser_plan).expect("launch fake driver");
    let page = managed.provider_page().expect("discover Mail page");
    let error = managed
        .require_mail_shell(&page)
        .expect_err("missing search landmark must block mailbox workflows");
    assert_eq!(error, BrowserDriverError::MailShellNotReady);
    drop(managed);
    fs::remove_dir_all(root).expect("remove synthetic root");
}

#[test]
fn ignored_search_landmark_fails_closed() {
    let roles = RoleFixture {
        search: IGNORED,
        ..RoleFixture::ready()
    };
    let evidence = inspect(
        "ignored-search",
        "https://mail.proton.me/u/0/inbox",
        "mail.proton.me",
        &roles,
    )
    .expect("inspect shell with ignored search");
    assert!(!evidence.search_visible());
    assert!(!evidence.ready());
}

#[test]
fn visible_dialog_roles_block_readiness() {
    for (label, roles) in [
        (
            "dialog",
            RoleFixture {
                dialog: VISIBLE,
                ..RoleFixture::ready()
            },
        ),
        (
            "alertdialog",
            RoleFixture {
                alertdialog: VISIBLE,
                ..RoleFixture::ready()
            },
        ),
    ] {
        let evidence = inspect(
            label,
            "https://mail.proton.me/u/0/inbox",
            "mail.proton.me",
            &roles,
        )
        .expect("inspect blocked shell");
        assert!(evidence.modal_blocker_visible());
        assert!(!evidence.ready());
    }
}

#[test]
fn malformed_role_query_is_protocol_failure() {
    let roles = RoleFixture {
        search: "null",
        ..RoleFixture::ready()
    };
    let error = inspect(
        "malformed",
        "https://mail.proton.me/u/0/inbox",
        "mail.proton.me",
        &roles,
    )
    .expect_err("malformed AX response must fail closed");
    assert_eq!(error, BrowserDriverError::Protocol);
}

#[test]
fn missing_or_ambiguous_ax_node_identity_cannot_prove_mail_shell() {
    for (label, node) in [
        (
            "missing-ax-id",
            r#"[{"ignored":false,"role":{"type":"role","value":"search"}}]"#,
        ),
        (
            "missing-ax-role",
            r#"[{"ignored":false,"nodeId":"search-1"}]"#,
        ),
        (
            "numeric-ax-id",
            // jig-ignore-next-line: synthetic invalid AX protocol fixture.
            r#"[{"ignored":false,"nodeId":42,"role":{"type":"role","value":"search"}}]"#,
        ),
        (
            "duplicate-ax-id",
            // jig-ignore-next-line: synthetic invalid AX protocol fixture.
            r#"[{"ignored":false,"nodeId":"search-1","role":{"type":"role","value":"search"}},{"ignored":true,"nodeId":"search-1","role":{"type":"role","value":"search"}}]"#,
        ),
    ] {
        let roles = RoleFixture {
            search: node,
            ..RoleFixture::ready()
        };
        assert_eq!(
            inspect(
                label,
                "https://mail.proton.me/u/0/inbox",
                "mail.proton.me",
                &roles,
            ),
            Err(BrowserDriverError::Protocol),
            "invalid accessibility identity must fail before shell readiness"
        );
    }
}

#[test]
fn ax_explicit_role_contradictions_fail_closed() {
    for (label, roles) in [
        (
            "wrong-search-role",
            RoleFixture {
                // jig-ignore-next-line: indivisible synthetic AX role fixture.
                search: r#"[{"ignored":false,"role":{"type":"role","value":"navigation"}}]"#,
                ..RoleFixture::ready()
            },
        ),
        (
            "malformed-search-role",
            RoleFixture {
                search: r#"[{"ignored":false,"role":{"value":42}}]"#,
                ..RoleFixture::ready()
            },
        ),
        (
            "wrong-dialog-role",
            RoleFixture {
                // jig-ignore-next-line: indivisible synthetic AX role fixture.
                dialog: r#"[{"ignored":false,"role":{"type":"role","value":"button"}}]"#,
                ..RoleFixture::ready()
            },
        ),
    ] {
        assert_eq!(
            inspect(
                label,
                "https://mail.proton.me/u/0/inbox",
                "mail.proton.me",
                &roles
            ),
            Err(BrowserDriverError::Protocol),
        );
    }
    let roles = RoleFixture {
        // jig-ignore-next-line: indivisible synthetic AX role fixture.
        search: r#"[{"ignored":false,"nodeId":"ax-matched","role":{"type":"role","value":"search"}}]"#,
        ..RoleFixture::ready()
    };
    assert!(
        inspect(
            "matching-search-role",
            "https://mail.proton.me/u/0/inbox",
            "mail.proton.me",
            &roles
        )
        .expect("matching AX role")
        .ready()
    );
}

#[test]
fn account_origin_is_not_mail_shell() {
    let error = inspect(
        "account",
        "https://account.proton.me/login",
        "account.proton.me",
        &RoleFixture::ready(),
    )
    .expect_err("Account page must not be inspected as Mail");
    assert_eq!(error, BrowserDriverError::MailOriginRequired);
}

#[test]
fn origin_drift_precedes_accessibility_queries() {
    let error = inspect(
        "origin-drift",
        "https://mail.proton.me/u/0/inbox",
        "account.proton.me",
        &RoleFixture::ready(),
    )
    .expect_err("origin drift must fail before shell evidence");
    assert_eq!(
        error,
        BrowserDriverError::OriginDrift {
            expected: PageOrigin::ProtonMail,
            observed: PageOrigin::ProtonAccount,
        }
    );
}

#[test]
fn origin_drift_after_accessibility_queries_fails_closed() {
    let error = inspect_with_hosts(
        "late-origin-drift",
        "https://mail.proton.me/u/0/inbox",
        "mail.proton.me",
        "account.proton.me",
        &RoleFixture::ready(),
    )
    .expect_err("late origin drift must invalidate ready AX evidence");
    assert_eq!(
        error,
        BrowserDriverError::OriginDrift {
            expected: PageOrigin::ProtonMail,
            observed: PageOrigin::ProtonAccount,
        }
    );
}

#[test]
fn visible_ax_landmark_cannot_hide_malformed_trailing_nodes() {
    for (label, malformed) in [
        (
            "missing-ignored",
            // jig-ignore-next-line: indivisible synthetic AXNode fixture.
            r#"[{"ignored":false,"nodeId":"ax-1","role":{"type":"role","value":"__AX_ROLE__"}},{"name":"synthetic"}]"#,
        ),
        (
            "wrong-ignored-type",
            // jig-ignore-next-line: indivisible synthetic AXNode fixture.
            r#"[{"ignored":false,"nodeId":"ax-1","role":{"type":"role","value":"__AX_ROLE__"}},{"ignored":"false"}]"#,
        ),
        (
            "null-node",
            // jig-ignore-next-line: indivisible synthetic AXNode fixture.
            r#"[{"ignored":false,"nodeId":"ax-1","role":{"type":"role","value":"__AX_ROLE__"}},null]"#,
        ),
        (
            "late-conflicting-role",
            // jig-ignore-next-line: indivisible synthetic AX role fixture.
            r#"[{"ignored":false,"nodeId":"ax-1","role":{"type":"role","value":"__AX_ROLE__"}},{"ignored":false,"nodeId":"ax-2","role":{"type":"role","value":"button"}}]"#,
        ),
    ] {
        for (role_name, roles) in [
            (
                "navigation",
                RoleFixture {
                    navigation: malformed,
                    ..RoleFixture::ready()
                },
            ),
            (
                "search",
                RoleFixture {
                    search: malformed,
                    ..RoleFixture::ready()
                },
            ),
            (
                "dialog",
                RoleFixture {
                    dialog: malformed,
                    ..RoleFixture::ready()
                },
            ),
            (
                "alertdialog",
                RoleFixture {
                    alertdialog: malformed,
                    ..RoleFixture::ready()
                },
            ),
        ] {
            let case = format!("{label}-{role_name}");
            assert_eq!(
                inspect(
                    &case,
                    "https://mail.proton.me/u/0/inbox",
                    "mail.proton.me",
                    &roles
                ),
                Err(BrowserDriverError::Protocol),
                "malformed role node cannot be ignored after a valid landmark"
            );
        }
    }
}

#[test]
fn well_formed_multiple_role_nodes_preserve_ready_shell_without_names() {
    let roles = RoleFixture {
        // jig-ignore-next-line: canonical rustfmt line.
        navigation: r#"[{"ignored":false,"nodeId":"nav-1","role":{"type":"role","value":"__AX_ROLE__"},"name":{"value":"secret"}},{"ignored":true,"nodeId":"nav-2","role":{"type":"role","value":"__AX_ROLE__"}}]"#,
        // jig-ignore-next-line: canonical rustfmt line.
        search: r#"[{"ignored":true,"nodeId":"search-1","role":{"type":"role","value":"__AX_ROLE__"}},{"ignored":false,"nodeId":"search-2","role":{"type":"role","value":"__AX_ROLE__"},"name":{"value":"hidden"}}]"#,
        // jig-ignore-next-line: indivisible synthetic AXNode fixture.
        dialog: r#"[{"ignored":true,"nodeId":"dialog-1","role":{"type":"role","value":"__AX_ROLE__"}},{"ignored":true,"nodeId":"dialog-2","role":{"type":"role","value":"__AX_ROLE__"}}]"#,
        alertdialog: ABSENT,
    };
    let evidence = inspect(
        "multi-valid-roles",
        "https://mail.proton.me/u/0/inbox",
        "mail.proton.me",
        &roles,
    )
    .expect("every well-formed role node permits ready Mail shell");
    assert!(evidence.ready());
    let debug = format!("{evidence:?}");
    assert!(!debug.contains("secret"));
    assert!(!debug.contains("hidden"));
}

#[test]
fn accessibility_role_query_has_bounded_node_count() {
    let nodes = (0usize..=256)
        .map(|index| {
            format!(
                // jig-ignore-next-line: indivisible synthetic AXNode fixture.
                r#"{{"ignored":{},"nodeId":"ax-{index}","role":{{"type":"role","value":"__AX_ROLE__"}}}}"#,
                index != 0
            )
        })
        .collect::<Vec<_>>();
    let bounded = format!("[{}]", nodes[..256].join(","));
    let oversized = format!("[{}]", nodes.join(","));
    let valid = RoleFixture {
        navigation: &bounded,
        ..RoleFixture::ready()
    };
    let evidence = inspect(
        "role-count-at-bound",
        "https://mail.proton.me/u/0/inbox",
        "mail.proton.me",
        &valid,
    )
    .expect("256 bounded AX role nodes remain valid");
    assert!(evidence.ready());
    for (role, roles) in [
        (
            "navigation",
            RoleFixture {
                navigation: &oversized,
                ..RoleFixture::ready()
            },
        ),
        (
            "search",
            RoleFixture {
                search: &oversized,
                ..RoleFixture::ready()
            },
        ),
        (
            "dialog",
            RoleFixture {
                dialog: &oversized,
                ..RoleFixture::ready()
            },
        ),
        (
            "alertdialog",
            RoleFixture {
                alertdialog: &oversized,
                ..RoleFixture::ready()
            },
        ),
    ] {
        let label = format!("role-count-over-{role}");
        assert_eq!(
            inspect(
                &label,
                "https://mail.proton.me/u/0/inbox",
                "mail.proton.me",
                &roles
            ),
            Err(BrowserDriverError::Protocol),
        );
    }
}

#[test]
fn invalid_dom_root_node_cannot_authorize_accessibility_queries() {
    let root = test_root("zero-dom-root");
    fs::create_dir_all(&root).expect("create isolated synthetic profile");
    let browser = fake_browser(
        &root,
        "https://mail.proton.me/u/0/inbox",
        "mail.proton.me",
        "mail.proton.me",
        &RoleFixture::ready(),
    );
    // jig-ignore-next-line: canonical rustfmt line.
    let script = fs::read_to_string(&browser).expect("read fake Chrome fixture");
    let valid = "\"nodeId\":1";
    assert!(script.contains(valid));
    let invalid = script.replace(valid, "\"nodeId\":0");
    let ax_branch = "    *'Accessibility.queryAXTree'*)";
    let ax_audit = format!(
        "{ax_branch}\n      printf 'unexpected-ax\\n' >> '{}'",
        root.join("ax-audit.log").display()
    );
    fs::write(&browser, invalid.replacen(ax_branch, &ax_audit, 1))
        .expect("install invalid DOM root and access-audit fixture");
    let mut managed =
        // jig-ignore-next-line: canonical rustfmt line.
        ManagedBrowser::launch(&plan(&root, &browser)).expect("launch isolated fake browser");
    let page = managed
        .provider_page()
        .expect("discover synthetic Mail target");
    assert_eq!(
        managed.require_mail_shell(&page),
        Err(BrowserDriverError::Protocol)
    );
    drop(managed);
    assert!(!root.join("ax-audit.log").exists());
    fs::remove_dir_all(root).expect("remove synthetic test tree");
}

#[test]
fn runtime_javascript_exception_cannot_become_ready_shell_evidence() {
    let root = test_root("runtime-exception");
    fs::create_dir_all(&root).expect("create isolated synthetic profile");
    let browser = fake_browser(
        &root,
        "https://mail.proton.me/u/0/inbox",
        "mail.proton.me",
        "mail.proton.me",
        &RoleFixture::ready(),
    );
    // jig-ignore-next-line: canonical rustfmt line.
    let script = fs::read_to_string(&browser).expect("read fake Chrome fixture");
    let expected = "      printf '%s\\0' \"$response\" >&4;;";
    assert!(script.contains(expected));
    let error_reply = concat!(
        "      printf '{\"id\":%s,\"sessionId\":\"session-1\",\"result\":",
        "{\"result\":{\"value\":{\"protocol\":\"https:\",",
        "\"hostname\":\"mail.proton.me\",\"port\":\"\"}},",
        "\"exceptionDetails\":{\"text\":\"synthetic-private-message\"}}}\\0' ",
        "\"$id\" >&4;;"
    );
    fs::write(&browser, script.replacen(expected, error_reply, 1))
        // jig-ignore-next-line: canonical rustfmt line.
        .expect("inject reported JavaScript exception alongside plausible value");
    let mut managed =
        // jig-ignore-next-line: canonical rustfmt line.
        ManagedBrowser::launch(&plan(&root, &browser)).expect("launch isolated fake browser");
    let page = managed
        .provider_page()
        .expect("discover synthetic Mail target");
    let error = managed
        .require_mail_shell(&page)
        .expect_err("JavaScript exception invalidates apparent Mail origin");
    assert_eq!(error, BrowserDriverError::Protocol);
    let text = format!("{error:?} {error}");
    assert!(!text.contains("synthetic-private-message"));
    drop(managed);
    fs::remove_dir_all(root).expect("remove synthetic test tree");
}

#[test]
fn runtime_thrown_flag_cannot_authorize_mail_shell_with_plausible_value() {
    for (label, flag, expected) in [
        ("runtime-thrown", "true", Err(BrowserDriverError::Protocol)),
        (
            "runtime-unknown-throw",
            "null",
            Err(BrowserDriverError::Protocol),
        ),
        ("runtime-not-thrown", "false", Ok(true)),
    ] {
        let root = test_root(label);
        fs::create_dir_all(&root).expect("create synthetic profile root");
        let browser = fake_browser(
            &root,
            "https://mail.proton.me/u/0/inbox",
            "mail.proton.me",
            "mail.proton.me",
            &RoleFixture::ready(),
        );
        let script = fs::read_to_string(&browser).expect("read fake browser");
        let original = "      printf '%s\\0' \"$response\" >&4;;";
        assert!(script.contains(original));
        let remote = format!(
            // jig-ignore-next-line: canonical rustfmt line.
            r#"{{"result":{{"value":{{"protocol":"https:","hostname":"mail.proton.me","port":""}}}},"wasThrown":{flag}}}"#
        );
        let replacement =
            // jig-ignore-next-line: canonical rustfmt line.
            format!("      printf '{{\"id\":%s,\"sessionId\":\"session-1\",\"result\":{remote}}}\\0' \"$id\" >&4;;");
        fs::write(&browser, script.replacen(original, &replacement, 1))
            .expect("inject a bounded old-CDP throw flag");
        let mut managed =
            // jig-ignore-next-line: canonical rustfmt line.
            ManagedBrowser::launch(&plan(&root, &browser)).expect("launch synthetic browser");
        let page = managed.provider_page().expect("discover fake Mail target");
        assert_eq!(
            managed
                .require_mail_shell(&page)
                .map(mail_web_adapter::MailShellEvidence::ready),
            expected
        );
        drop(managed);
        fs::remove_dir_all(root).expect("remove synthetic fixture");
    }
}
