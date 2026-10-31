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
//   - Shared passive CDP request and response-source gates for read-only GETs.
// - Must-Not:
//   - Retain HTTP headers, request URLs, bodies, or browser session secrets.
// - Allows:
//   - Reject body-bearing, speculative, cached, or worker-served read evidence.
// - Split-When:
//   - Response provenance becomes provider-specific or authenticated.
// - Merge-When:
//   - One read adapter owns all CDP lifecycle and provenance validation.
// - Summary:
//   - Requires body-free, non-speculative GETs and direct HTTP responses.
// - Description:
//   - Inspects CDP request and response metadata without allocation or logging.
// - Usage:
//   - Call on exact requestWillBeSent and responseReceived read notifications.
// - Defaults:
//   - Omitted optional hints pass; explicit contradictory hints fail closed.
//

//! Shared cached-response provenance gate for passive provider evidence.

use crate::driver::safe_cdp_request_id;
use serde_json::Map;
use serde_json::Value;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::hash_map::RandomState;
use std::hash::BuildHasher as _;
use std::mem::take;
use std::sync::OnceLock;
use zeroize::Zeroize as _;

// Validate the HTTP field shape, not its private content. A malformed CDP
// Headers object cannot establish a meaningful body-free HTTP request.
fn cdp_header_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn cdp_header_name_is_token(name: &str) -> bool {
    if name.starts_with(':') {
        // CDP can report HTTP/2 and HTTP/3 request pseudo-headers in the
        // raw wire map. Admit only their exact lowercase standard spellings.
        return matches!(name, ":authority" | ":method" | ":scheme" | ":path");
    }
    !name.is_empty() && name.bytes().all(cdp_header_token_byte)
}

const fn mail_http_authority(value: &str) -> bool {
    // jig-ignore-next-line: canonical rustfmt logical expression.
    value.eq_ignore_ascii_case("mail.proton.me") || value.eq_ignore_ascii_case("mail.proton.me:443")
}

fn safe_http_pseudo_header(name: &str, value: &Value) -> bool {
    match name {
        ":authority" => value.as_str().is_some_and(mail_http_authority),
        ":method" => value.as_str() == Some("GET"),
        ":scheme" => value.as_str() == Some("https"),
        ":path" => value.as_str().is_some_and(|path| {
            path.len() <= 16 * 1024
                && path.starts_with("/api/")
                && path
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic() && byte != b'#')
        }),
        _ => false,
    }
}

// The URL reported by CDP must match any HTTP/2 :path actually carried on
// the wire. Compare borrowed strings only; no Mail query text is stored.
// jig-ignore-next-line: canonical rustfmt signature.
fn same_mail_http_path(headers: &Map<String, Value>, url: Option<&str>) -> bool {
    match headers.get(":path") {
        None => true,
        Some(Value::String(path)) => url
            .and_then(|url| url.strip_prefix("https://mail.proton.me"))
            .is_some_and(|suffix| suffix == path),
        Some(_) => false,
    }
}

// Early/late wire events cannot retain query parameters; use two independent
// keyed digests of the exact serialized request path for correlation only.
// Keys are per-process and never exported or included in diagnostic output.
static HTTP_PATH_HASHERS: OnceLock<[RandomState; 2]> = OnceLock::new();

fn http_path_fingerprint(path: &str) -> [u64; 2] {
    // jig-ignore-next-line: canonical rustfmt hasher initialization.
    let hashers = HTTP_PATH_HASHERS.get_or_init(|| [RandomState::new(), RandomState::new()]);
    [hashers[0].hash_one(path), hashers[1].hash_one(path)]
}

// An HTTP method-override header makes the effective operation ambiguous
// despite CDP reporting GET. These aliases cannot prove a read-only request.
fn method_override_header(name: &str) -> bool {
    [
        "X-HTTP-Method-Override",
        "X-Method-Override",
        "X-HTTP-Method",
        "X-Original-HTTP-Method",
        "X-Original-Method",
        "X-Rewrite-Method",
    ]
    .iter()
    .any(|header| name.eq_ignore_ascii_case(header))
}

fn cdp_header_value_is_safe(value: &Value) -> bool {
    value.as_str().is_some_and(|text| {
        text.chars()
            .all(|character| character == '\t' || !character.is_control())
    })
}

// Both early Request.headers and refined Response.requestHeaders describe
// potential wire framing. Reject ambiguous transport and method metadata
// without copying or recording any private HTTP fields.
fn bodyless_cdp_headers(headers: &Map<String, Value>) -> bool {
    let mut seen_content_length = false;
    headers.iter().all(|(name, value)| {
        if !cdp_header_name_is_token(name) {
            return false;
        }
        let safe_value = cdp_header_value_is_safe(value);
        if !safe_value || method_override_header(name) {
            return false;
        }
        if name.starts_with(':') {
            return safe_http_pseudo_header(name, value);
        }
        if name.eq_ignore_ascii_case("content-length") {
            if seen_content_length {
                return false;
            }
            seen_content_length = true;
            return value.as_str() == Some("0");
        }
        !name.eq_ignore_ascii_case("transfer-encoding")
    })
}

// A CDP Request claiming GET does not prove body-free read semantics when
// transport metadata also reports payload bytes. `Network.enable` may omit
// postData text, so the boolean and entry-array flags need checking too.
// Absence and an explicit false boolean are normal browser GET metadata.
#[expect(
    clippy::redundant_pub_crate,
    reason = "private sibling read observers share one request-body predicate"
)]
pub(super) fn bodyless_cdp_get(request: &Value) -> bool {
    request.as_object().is_some_and(|fields| {
        // Request protocol names are ASCII. Future payload metadata, alias
        // spellings, or Unicode lookalikes cannot silently establish the
        // absence of a GET body, regardless of their reported value.
        let unreviewed_body_marker = fields.keys().any(|field| {
            if !field.is_ascii() {
                return true;
            }
            let body_markers = ["postdata", "body", "payload"];
            let length_markers = ["upload", "contentlength"];
            field != "hasPostData"
                && body_markers
                    .iter()
                    .chain(length_markers.iter())
                    .any(|marker| {
                        field.as_bytes().windows(marker.len()).any(|part| {
                            let needle = marker.as_bytes();
                            part.eq_ignore_ascii_case(needle)
                        })
                    })
        });
        // An explicit HTTP body framing header contradicts a CDP GET with
        // no postData. A zero Content-Length is benign; any transfer coding
        // or malformed length fails closed without inspecting header values
        // beyond the relevant key or retaining private request headers.
        let bodyless_headers = match fields.get("headers") {
            None => true,
            Some(Value::Object(headers)) => {
                let url = fields.get("url").and_then(Value::as_str);
                let bodyless = bodyless_cdp_headers(headers);
                bodyless && same_mail_http_path(headers, url)
            }
            Some(_) => false,
        };
        let body_flag = fields.get("hasPostData");
        let bodyless = matches!(body_flag, None | Some(Value::Bool(false)));
        !unreviewed_body_marker
            && bodyless_headers
            && bodyless
            && !fields.contains_key("postData")
            && !fields.contains_key("postDataEntries")
    })
}

// The audited Mail API endpoints return JSON to application XHR/Fetch reads.
// A navigation, image, script, or other resource may independently GET the
// same URL, but must not establish the active mailbox's API read evidence.
fn read_api_cdp_resource_type(kind: &str) -> bool {
    matches!(kind, "XHR" | "Fetch")
}

// A browser-request purpose header is not proof of an active Mail AJAX
// fetch, even when ResourceType has the ordinary Fetch/XHR classification.
const fn speculative_purpose_header(name: &str) -> bool {
    let legacy = name.eq_ignore_ascii_case("Purpose");
    let current = name.eq_ignore_ascii_case("Sec-Purpose");
    legacy || current
}

// Optional document and Referer URLs must describe the same Mail origin.
// Chromium supplies serialized URLs; a textual prefix without an origin
// boundary could otherwise accept an unrelated host or userinfo authority.
fn serialized_mail_document_url(url: &str) -> bool {
    let bounded = url.len() <= 16 * 1024;
    let serialized = url.bytes().all(|byte| byte.is_ascii_graphic());
    let same_origin = url
        .strip_prefix("https://mail.proton.me")
        .is_some_and(|suffix| {
            suffix.is_empty()
                || suffix.starts_with('/')
                || suffix.starts_with('?')
                || suffix.starts_with('#')
        });
    bounded && serialized && same_origin
}

// Proxy authority or route overrides do not corroborate the Mail app's
// endpoint, even when the browser reports a matching GET URL and Host.
// Never inspect or store these potentially private routing values.
fn proxy_routing_header(name: &str) -> bool {
    [
        "Forwarded",
        "X-Forwarded-Host",
        "X-Forwarded-Proto",
        "X-Forwarded-Port",
        "X-Original-Host",
        "X-Original-URL",
        "X-Original-URI",
        "X-Rewrite-URL",
        "X-Forwarded-URI",
    ]
    .iter()
    .any(|header| name.eq_ignore_ascii_case(header))
}

// An only-if-cached request expressly forbids using provider network HTTP.
// Other Cache-Control directives may legitimately revalidate via HTTP 200.
fn cache_only_directive(value: &str) -> bool {
    value.split(',').any(|part| {
        let directive = part.trim_ascii();
        directive.eq_ignore_ascii_case("only-if-cached")
    })
}

// Fetch Metadata headers describe the actual browser request destination.
// Navigation, embedded resources, or cross-site requests cannot corroborate
// an active first-party Mail XHR/Fetch, regardless of CDP ResourceType.
fn active_mail_fetch_headers(headers: &Map<String, Value>) -> bool {
    // HTTP singletons cannot be supplied twice under different case aliases.
    // Otherwise competing client and intermediary interpretations are unclear.
    let singleton_names = [
        "Host",
        "Origin",
        "Referer",
        "Sec-Fetch-Mode",
        "Sec-Fetch-Dest",
        "Sec-Fetch-Site",
    ];
    let mut seen_singletons = [false; 6];
    headers.iter().all(|(name, value)| {
        for (index, singleton) in singleton_names.iter().enumerate() {
            if name.eq_ignore_ascii_case(singleton) {
                if seen_singletons[index] {
                    return false;
                }
                seen_singletons[index] = true;
            }
        }
        if proxy_routing_header(name) {
            return false;
        }
        if name.starts_with(':') {
            return safe_http_pseudo_header(name, value);
        }
        if name.eq_ignore_ascii_case("Cache-Control") {
            return value
                .as_str()
                .is_some_and(|text| !cache_only_directive(text));
        }
        if name.eq_ignore_ascii_case("Host") {
            // A conflicting HTTP authority cannot establish a direct
            // Mail read merely because the observed URL looks exact.
            let host = value.as_str();
            return host.is_some_and(mail_http_authority);
        }
        if name.eq_ignore_ascii_case("Origin") {
            // A foreign/sandboxed document cannot become Mail-owned just
            // because CDP omitted documentURL and classified it Fetch.
            return value.as_str() == Some("https://mail.proton.me");
        }
        if name.eq_ignore_ascii_case("Referer") {
            // A foreign embedding document cannot establish an active
            // Mail read when optional documentURL is missing from CDP.
            return value.as_str().is_some_and(serialized_mail_document_url);
        }
        if name.eq_ignore_ascii_case("Sec-Fetch-Mode") {
            let mode = value.as_str();
            return matches!(mode, Some("cors" | "same-origin"));
        }
        if name.eq_ignore_ascii_case("Sec-Fetch-Dest") {
            return value.as_str() == Some("empty");
        }
        if name.eq_ignore_ascii_case("Sec-Fetch-Site") {
            return value.as_str() == Some("same-origin");
        }
        !name.eq_ignore_ascii_case("Sec-Fetch-User")
    })
}

fn active_mail_fetch_metadata(request: &Map<String, Value>) -> bool {
    match request.get("headers") {
        None => true,
        Some(Value::Object(headers)) => active_mail_fetch_headers(headers),
        Some(_) => false,
    }
}

// Unknown CDP Request fields that advertise speculative scheduling are
// ambiguous even when the documented isLinkPreload boolean is false.
// Compare ASCII protocol names without allocating private request metadata.
fn unreviewed_speculation_field(name: &str) -> bool {
    if name == "isLinkPreload" {
        return false;
    }
    let hints = [
        "preload",
        "prefetch",
        "preflight",
        "prerender",
        "speculative",
    ];
    hints.iter().any(|hint| {
        name.as_bytes()
            .windows(hint.len())
            .any(|part| part.eq_ignore_ascii_case(hint.as_bytes()))
    })
}

fn unreviewed_event_speculation_field(name: &str) -> bool {
    name == "isLinkPreload" || unreviewed_speculation_field(name)
}

// A speculative preload or prefetch can fetch an endpoint and return 200
// without the active Mail view requesting those records. Chromium reports
// these separately in Request, requestWillBeSent resource type and initiator.
// A foreign document/frame can likewise request a Mail API URL without the
// active Mail document owning it. Optional CDP hints must not contradict
// ordinary first-party activity; omission remains legacy-compatible.
#[expect(
    clippy::redundant_pub_crate,
    reason = "private sibling read observers share speculative GET provenance"
)]
pub(super) fn non_speculative_cdp_get(event: &Value) -> bool {
    let Some(params) = event.get("params").and_then(Value::as_object) else {
        return false;
    };
    let Some(request) = params.get("request").and_then(Value::as_object) else {
        return false;
    };
    let normal_link = matches!(
        request.get("isLinkPreload"),
        None | Some(Value::Bool(false))
    );
    let normal_hints = !request
        .keys()
        .any(|field| unreviewed_speculation_field(field));
    let normal_fetch_metadata = active_mail_fetch_metadata(request);
    // isSameSite is relative to this target's main frame. A false hint
    // contradicts activity owned by the selected Mail document; true is
    // necessary only when the optional hint is reported, not sufficient.
    let site_hint = request.get("isSameSite");
    let normal_same_site = matches!(site_hint, None | Some(Value::Bool(true)));
    // The enclosing event and initiator can also carry speculative metadata.
    // Only the Request object owns the documented isLinkPreload marker.
    let normal_event_hints = !params
        .keys()
        .any(|field| unreviewed_event_speculation_field(field));
    // Browsers also identify speculative requests with purpose headers.
    // Reject the header itself regardless of value: a future purpose token
    // cannot silently establish active Mail API read evidence.
    let normal_purpose = match request.get("headers") {
        None => true,
        Some(Value::Object(headers)) => {
            !headers.keys().any(|name| speculative_purpose_header(name))
        }
        Some(_) => false,
    };
    // CDP resource and initiator types are closed enums, not arbitrary text.
    // Browser navigations and resource fetches cannot prove Mail API reads.
    // In particular, unknown, speculative, or FedCM types fail closed.
    let normal_resource = match params.get("type") {
        None => true,
        Some(Value::String(kind)) => read_api_cdp_resource_type(kind),
        Some(_) => false,
    };
    let normal_initiator = match params.get("initiator") {
        None => true,
        Some(Value::Object(initiator)) => {
            let normal_type = matches!(
                initiator.get("type").and_then(Value::as_str),
                Some("parser" | "script" | "SignedExchange" | "other")
            );
            let normal_hints = !initiator
                .keys()
                .any(|field| unreviewed_event_speculation_field(field));
            normal_type && normal_hints
        }
        Some(_) => false,
    };
    // documentURL is the requesting document, not the API URL. Binding an
    // explicit hint to the active Mail origin prevents foreign iframes and
    // unrelated documents from laundering their GET as mailbox activity.
    // CDP URL strings are browser-serialized; reject raw Unicode/whitespace,
    // alternate ports or ambiguous host prefixes without retaining the URL.
    let normal_document = match params.get("documentURL") {
        None => true,
        Some(Value::String(url)) => serialized_mail_document_url(url),
        Some(_) => false,
    };
    let request_active = normal_link && normal_hints && normal_purpose;
    let request_active = request_active && normal_fetch_metadata;
    let request_active = request_active && normal_same_site;
    let event_active = normal_event_hints && normal_resource;
    request_active && event_active && normal_initiator && normal_document
}

// Network.requestWillBeSentExtraInfo reports the actual request headers,
// independently of provisional Request.headers and optional response headers.
// CDP may deliver this notification before requestWillBeSent, so retain only
// bounded IDs with contradictory evidence until their request can be matched.
// Never retain any request-header text or values.
const MAX_UNSAFE_EXTRA_REQUEST_IDS: usize = 1_024;

#[derive(Clone, Default, Eq, PartialEq)]
#[expect(
    clippy::redundant_pub_crate,
    reason = "sibling CDP readers share wire header evidence"
)]
pub(super) struct RequestExtraInfoEvidence {
    unsafe_ids: BTreeSet<String>,
    expected_paths: BTreeMap<String, [u64; 2]>,
    observed_paths: BTreeMap<String, [u64; 2]>,
}

#[expect(
    clippy::allow_attributes,
    reason = "Drop lint behavior differs between toolchains"
)]
#[allow(clippy::missing_trait_methods, reason = "Drop::pin_drop is unstable")]
impl Drop for RequestExtraInfoEvidence {
    fn drop(&mut self) {
        for mut id in take(&mut self.unsafe_ids) {
            id.zeroize();
        }
        for (mut id, mut hash) in take(&mut self.expected_paths) {
            id.zeroize();
            hash.zeroize();
        }
        for (mut id, mut hash) in take(&mut self.observed_paths) {
            id.zeroize();
            hash.zeroize();
        }
    }
}

impl RequestExtraInfoEvidence {
    // Returns the borrowed, validated correlation ID or None for a malformed
    // event or exhausted bounded custody. Unsafe headers are remembered even
    // if this event precedes the corresponding requestWillBeSent.
    // jig-ignore-next-line: canonical rustfmt lifetime signature.
    pub(super) fn note_event<'event>(&mut self, event: &'event Value) -> Option<&'event str> {
        let params = event.get("params")?.as_object()?;
        let request_id = params.get("requestId")?.as_str()?;
        if !safe_cdp_request_id(request_id) {
            return None;
        }
        let headers = params.get("headers")?.as_object()?;
        let safe_headers = bodyless_cdp_headers(headers)
            && active_mail_fetch_headers(headers)
            && !headers.keys().any(|key| speculative_purpose_header(key));
        let same_path = match headers.get(":path").and_then(Value::as_str) {
            None => true,
            Some(path) => {
                let observed = http_path_fingerprint(path);
                if let Some(expected) = self.expected_paths.get(request_id) {
                    *expected == observed
                // jig-ignore-next-line: canonical rustfmt else-if expression.
                } else if let Some(earlier) = self.observed_paths.get(request_id) {
                    *earlier == observed
                } else {
                    let count = self.observed_paths.len();
                    if count >= MAX_UNSAFE_EXTRA_REQUEST_IDS {
                        return None;
                    }
                    self.observed_paths
                        .insert(String::from(request_id), observed);
                    true
                }
            }
        };
        if (!safe_headers || !same_path) && !self.mark_unsafe(request_id) {
            return None;
        }
        Some(request_id)
    }

    // Track only a keyed digest of a validated Mail API path, not request URL
    // or query parameters. Both CDP event orders fail closed.
    // jig-ignore-next-line: canonical rustfmt correlation signature.
    pub(super) fn observe_request_url(&mut self, request_id: &str, url: &str) -> bool {
        if self.rejects(request_id) {
            return false;
        }
        let Some(path) = url.strip_prefix("https://mail.proton.me") else {
            return false;
        };
        if path.len() > 16 * 1024 || !path.starts_with("/api/") {
            return false;
        }
        let expected = http_path_fingerprint(path);
        if let Some(observed) = self.observed_paths.get(request_id)
            && *observed != expected
        {
            let _marked = self.mark_unsafe(request_id);
            return false;
        }
        if !self.expected_paths.contains_key(request_id)
            && self.expected_paths.len() >= MAX_UNSAFE_EXTRA_REQUEST_IDS
        {
            return false;
        }
        self.expected_paths
            .insert(String::from(request_id), expected);
        true
    }

    fn mark_unsafe(&mut self, request_id: &str) -> bool {
        if !self.unsafe_ids.contains(request_id)
            && self.unsafe_ids.len() >= MAX_UNSAFE_EXTRA_REQUEST_IDS
        {
            return false;
        }
        self.unsafe_ids.insert(String::from(request_id));
        true
    }

    pub(super) fn rejects(&self, request_id: &str) -> bool {
        self.unsafe_ids.contains(request_id)
    }
}

// Browser source flags may be absent on some CDP versions, but present values
// must be explicitly false. Other optional cache/SW hints cannot prove a
// direct provider response even if the booleans are absent or contradictory.
#[expect(
    clippy::redundant_pub_crate,
    reason = "private sibling read observers share one provenance predicate"
)]
pub(super) fn uncached_provider_response(response: &Value) -> bool {
    response.as_object().is_some_and(|fields| {
        let direct_source = uncached_source_fields(fields);
        direct_source && refined_request_headers_are_safe(fields)
    })
}

// CDP Response.requestHeaders may contain the refined HTTP request headers
// actually transmitted, not just provisional Request.headers. If present,
// they must not contradict the previously verified body-free Mail GET.
fn refined_request_headers_are_safe(response: &Map<String, Value>) -> bool {
    match response.get("requestHeaders") {
        None => true,
        Some(Value::Object(headers)) => {
            let safe_headers = bodyless_cdp_headers(headers);
            let active_headers = active_mail_fetch_headers(headers);
            let url = response.get("url").and_then(Value::as_str);
            let matching_path = same_mail_http_path(headers, url);
            let mut names = headers.keys();
            let has_purpose = names.any(|key| speculative_purpose_header(key));
            safe_headers && active_headers && matching_path && !has_purpose
        }
        Some(_) => false,
    }
}

// Interpret source/security markers consistently in the response metadata
// and in the enclosing CDP event. Otherwise contradictory explicit origin
// flags at the event level could silently authorize a passive read.
fn uncached_source_fields(fields: &Map<String, Value>) -> bool {
    let source_flags = [
        "fromDiskCache",
        "fromServiceWorker",
        "fromPrefetchCache",
        "fromEarlyHints",
    ];
    let source_hints = [
        "serviceWorkerResponseSource",
        "cacheStorageCacheName",
        "serviceWorkerRouterInfo",
    ];
    // Future CDP releases may introduce cache/SW or security-state markers.
    // Check markers anywhere in the name: an extension such as `isCached`
    // or `responseSource` is ambiguous even though it does not start with a
    // known prefix. Avoid allocating or retaining untrusted field content.
    let unknown_source_marker = fields.keys().any(|field| {
        // CDP response properties are ASCII protocol names. A Unicode
        // lookalike can disguise a source/security marker from ASCII checks.
        if !field.is_ascii() {
            return true;
        }
        let contains_marker = [
            "cache",
            "prefetch",
            "preload",
            "prerender",
            "preflight",
            "speculative",
            "serviceworker",
            "source",
            "securitystate",
        ]
        .iter()
        .any(|marker| {
            field
                .as_bytes()
                .windows(marker.len())
                .any(|window| window.eq_ignore_ascii_case(marker.as_bytes()))
        });
        let source_prefix = ["from", "isFrom", "servedFrom", "wasServedFrom"]
            .iter()
            .any(|prefix| {
                field
                    .get(..prefix.len())
                    .is_some_and(|start| start.eq_ignore_ascii_case(prefix))
            });
        (contains_marker || source_prefix)
            && !source_flags.contains(&field.as_str())
            && !source_hints.contains(&field.as_str())
            && field != "securityState"
    });
    // An HTTPS endpoint cannot establish a trusted direct response if the
    // browser explicitly reports insecure, neutral, or unknown transport.
    // Keep omission compatible with older/synthetic CDP response shapes;
    // a reported value must be exactly the documented secure state.
    let security_valid = fields
        .get("securityState")
        .is_none_or(|state| state.as_str() == Some("secure"));
    !unknown_source_marker
        && security_valid
        && source_flags.iter().all(|field| {
            let value = fields.get(*field);
            matches!(value, None | Some(Value::Bool(false)))
        })
        && source_hints
            .iter()
            .all(|field| fields.get(*field).is_none())
}

// The request's resource hint alone cannot prove that the response belongs
// to an active read: responseReceived has its own ResourceType. Reject new,
// speculative or authentication types before any response-body consumption.
#[expect(
    clippy::redundant_pub_crate,
    reason = "private sibling read observers share response type provenance"
)]
pub(super) fn direct_cdp_read_response(event: &Value) -> bool {
    let Some(params) = event.get("params").and_then(Value::as_object) else {
        return false;
    };
    let normal_type = match params.get("type") {
        None => true,
        Some(Value::String(kind)) => read_api_cdp_resource_type(kind),
        Some(_) => false,
    };
    normal_type
        && uncached_source_fields(params)
        && params
            .get("response")
            .is_some_and(uncached_provider_response)
}

// CDP can report a nominal 200 in responseReceived before the actual HTTP
// status arrives via responseReceivedExtraInfo. When hasExtraInfo is true,
// that separate status is required before a provider GET can be consumed.
// Extra-info notifications may precede responseReceived or loadingFinished.
#[expect(
    clippy::redundant_pub_crate,
    reason = "private sibling observers share one status-evidence type"
)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct ExtraStatusEvidence {
    declared: Option<bool>,
    seen_200: bool,
}

impl ExtraStatusEvidence {
    pub(super) fn note_response(&mut self, params: &Value) -> bool {
        match params.get("hasExtraInfo") {
            None => true,
            Some(Value::Bool(expects)) => {
                self.declared = Some(*expects);
                *expects || !self.seen_200
            }
            Some(_) => false,
        }
    }

    pub(super) fn note_200(&mut self) -> bool {
        if self.seen_200 || self.declared == Some(false) {
            return false;
        }
        self.seen_200 = true;
        true
    }

    pub(super) fn ready(self) -> bool {
        self.declared != Some(true) || self.seen_200
    }
}

// A conditional HTTP-cache revalidation can report 200 in responseReceived
// while the network stack reports 304 here. Accept only exact 200 if the
// optional extra-info event is provided for a tracked provider GET.
#[expect(
    clippy::redundant_pub_crate,
    reason = "private sibling observers share the extra-info status predicate"
)]
pub(super) fn direct_extra_status_is_200(event: &Value) -> bool {
    event
        .get("params")
        .and_then(|params| params.get("statusCode"))
        .and_then(Value::as_u64)
        == Some(200)
}

#[cfg(test)]
#[path = "../../../../tests/mail/web/adapter-outbound/response_provenance.rs"]
mod tests;
