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
//   - Bounded projection of Proton Mail's passive folder/label list responses.
// - Must-Not:
//   - Retain colors, counts, contacts, headers, cookies, tokens, or mutation
//     data.
// - Allows:
//   - Retain stable IDs, names, order, type, and custom-folder parent IDs.
// - Split-When:
//   - Public mailbox/label pagination needs independent snapshot ownership.
// - Merge-When:
//   - A complete read adapter owns catalog projection and paging together.
// - Summary:
//   - Reduces browser-owned label GETs to a provider-neutral mail catalog.
// - Description:
//   - Tracks exact core-v4 label GET lifecycles for mail-relevant label types.
// - Usage:
//   - Managed browser capture supplies all three typed responses after reload.
// - Defaults:
//   - Contact groups and unrelated requests are ignored; diagnostics redact
//     data.
//

//! Content-minimizing projection of Proton Mail mailbox and label inventory.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde_json::Value;

const LABELS_URL_PREFIX: &str = "https://mail.proton.me/api/core/v4/labels";
const MAX_CATALOG_ITEMS: usize = 2_048;
const MAX_CATALOG_ID_BYTES: usize = 512;
const MAX_CATALOG_NAME_BYTES: usize = 1_024;
const MAX_TRACKED_CATALOG_REQUESTS: usize = 16;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum CatalogRequestState {
    Requested,
    Responded,
    Finished,
}

/// Mail-relevant category type from Proton's labels endpoint.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MailboxCatalogKind {
    /// Built-in provider mailbox/location.
    SystemFolder,
    /// User-created message folder.
    Folder,
    /// User-created message label.
    Label,
}

impl MailboxCatalogKind {
    const fn type_code(self) -> u64 {
        match self {
            Self::Label => 1,
            Self::Folder => 3,
            Self::SystemFolder => 4,
        }
    }

    const fn from_type_code(value: u64) -> Option<Self> {
        match value {
            1 => Some(Self::Label),
            3 => Some(Self::Folder),
            4 => Some(Self::SystemFolder),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TrackedCatalogRequest {
    state: CatalogRequestState,
    kind: MailboxCatalogKind,
}

/// Bounded CDP Network lifecycle state for exact mail catalog GETs.
#[derive(Clone, Eq, PartialEq)]
pub struct MailboxCatalogNetworkCapture {
    session_id: String,
    requests: BTreeMap<String, TrackedCatalogRequest>,
}

impl MailboxCatalogNetworkCapture {
    /// Creates an empty capture scoped to one flattened CDP target session.
    #[must_use]
    pub fn new(session_id: &str) -> Self {
        Self {
            session_id: String::from(session_id),
            requests: BTreeMap::new(),
        }
    }

    /// Consumes one unsolicited CDP event without retaining request content.
    ///
    /// # Errors
    ///
    /// Fails closed for redirects, invalid event order, unsafe responses, or
    /// capacity exhaustion. App-owned failed attempts are discarded so a retry
    /// of the same safe GET can still satisfy the bounded capture.
    // jig-ignore-next-line: canonical rustfmt line.
    pub fn observe(&mut self, event: &Value) -> Result<(), MailboxCatalogNetworkError> {
        // jig-ignore-next-line: canonical rustfmt line.
        if event.get("sessionId").and_then(Value::as_str) != Some(self.session_id.as_str()) {
            return Ok(());
        }
        match event.get("method").and_then(Value::as_str) {
            Some("Network.requestWillBeSent") => self.observe_request(event),
            Some("Network.responseReceived") => self.observe_response(event),
            Some("Network.loadingFinished") => self.observe_finished(event),
            Some("Network.loadingFailed") => self.observe_failed(event),
            _ => Ok(()),
        }
    }

    /// Removes completed exact catalog requests and returns only request IDs.
    pub fn take_finished_request_ids(&mut self) -> Vec<String> {
        self.take_finished_requests()
            .into_iter()
            .map(|(request_id, _kind)| request_id)
            .collect()
    }

    /// Removes completed exact catalog requests as request ID plus safe type.
    // jig-ignore-next-line: canonical rustfmt line.
    pub(crate) fn take_finished_requests(&mut self) -> Vec<(String, MailboxCatalogKind)> {
        let finished = self
            .requests
            .iter()
            // jig-ignore-next-line: canonical rustfmt line.
            .filter(|(_id, request)| request.state == CatalogRequestState::Finished)
            .map(|(id, request)| (id.clone(), request.kind))
            .collect::<Vec<_>>();
        self.requests
            // jig-ignore-next-line: canonical rustfmt line.
            .retain(|_id, request| request.state != CatalogRequestState::Finished);
        finished
    }

    /// Returns how many matching request lifecycles are still retained.
    #[must_use]
    pub(crate) fn tracked_request_count(&self) -> usize {
        self.requests.len()
    }

    // jig-ignore-next-line: canonical rustfmt line.
    fn observe_request(&mut self, event: &Value) -> Result<(), MailboxCatalogNetworkError> {
        let params = event
            .get("params")
            .ok_or(MailboxCatalogNetworkError::MalformedEvent)?;
        let request_id = params
            .get("requestId")
            .and_then(Value::as_str)
            .ok_or(MailboxCatalogNetworkError::MalformedEvent)?;
        let request = params
            .get("request")
            .ok_or(MailboxCatalogNetworkError::MalformedEvent)?;
        let method = request
            .get("method")
            .and_then(Value::as_str)
            .ok_or(MailboxCatalogNetworkError::MalformedEvent)?;
        let url = request
            .get("url")
            .and_then(Value::as_str)
            .ok_or(MailboxCatalogNetworkError::MalformedEvent)?;
        let tracked = self.requests.contains_key(request_id);
        let kind = if method == "GET" {
            catalog_kind_from_url(url)?
        } else {
            None
        };
        if tracked && kind.is_none() {
            return Err(MailboxCatalogNetworkError::RedirectedAway);
        }
        let Some(kind) = kind else {
            return Ok(());
        };
        if tracked {
            return Err(MailboxCatalogNetworkError::InvalidSequence);
        }
        if self.requests.len() >= MAX_TRACKED_CATALOG_REQUESTS {
            return Err(MailboxCatalogNetworkError::CapacityExceeded);
        }
        self.requests.insert(
            String::from(request_id),
            TrackedCatalogRequest {
                state: CatalogRequestState::Requested,
                kind,
            },
        );
        Ok(())
    }

    // jig-ignore-next-line: canonical rustfmt line.
    fn observe_response(&mut self, event: &Value) -> Result<(), MailboxCatalogNetworkError> {
        let params = event
            .get("params")
            .ok_or(MailboxCatalogNetworkError::MalformedEvent)?;
        let request_id = params
            .get("requestId")
            .and_then(Value::as_str)
            .ok_or(MailboxCatalogNetworkError::MalformedEvent)?;
        if !self.requests.contains_key(request_id) {
            return Ok(());
        }
        let response = params
            .get("response")
            .ok_or(MailboxCatalogNetworkError::MalformedEvent)?;
        let url = response
            .get("url")
            .and_then(Value::as_str)
            .ok_or(MailboxCatalogNetworkError::MalformedEvent)?;
        let response_kind = catalog_kind_from_url(url)
            .map_err(|_error| MailboxCatalogNetworkError::ResponseRejected)?;
        let status = response.get("status").and_then(Value::as_u64);
        let mime = response.get("mimeType").and_then(Value::as_str);
        let request = self
            .requests
            .get_mut(request_id)
            .ok_or(MailboxCatalogNetworkError::MalformedEvent)?;
        if request.state != CatalogRequestState::Requested {
            return Err(MailboxCatalogNetworkError::InvalidSequence);
        }
        if status != Some(200)
            || mime != Some("application/json")
            || response_kind != Some(request.kind)
        {
            return Err(MailboxCatalogNetworkError::ResponseRejected);
        }
        request.state = CatalogRequestState::Responded;
        Ok(())
    }

    // jig-ignore-next-line: canonical rustfmt line.
    fn observe_finished(&mut self, event: &Value) -> Result<(), MailboxCatalogNetworkError> {
        let request_id = network_request_id(event)?;
        let Some(request) = self.requests.get_mut(request_id) else {
            return Ok(());
        };
        if request.state != CatalogRequestState::Responded {
            return Err(MailboxCatalogNetworkError::InvalidSequence);
        }
        request.state = CatalogRequestState::Finished;
        Ok(())
    }

    // jig-ignore-next-line: canonical rustfmt line.
    fn observe_failed(&mut self, event: &Value) -> Result<(), MailboxCatalogNetworkError> {
        let request_id = network_request_id(event)?;
        self.requests.remove(request_id);
        Ok(())
    }
}

impl fmt::Debug for MailboxCatalogNetworkCapture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MailboxCatalogNetworkCapture")
            .field("session_id", &"<redacted>")
            .field("tracked_request_count", &self.requests.len())
            .finish()
    }
}

/// One bounded mail catalog entry projected from a label response.
#[derive(Clone, Eq, PartialEq)]
pub struct ObservedMailboxCatalogItem {
    kind: MailboxCatalogKind,
    id: String,
    name: String,
    order: i64,
    parent_id: Option<String>,
}

impl ObservedMailboxCatalogItem {
    /// Returns whether this is a system folder, custom folder, or label.
    #[must_use]
    pub const fn kind(&self) -> MailboxCatalogKind {
        self.kind
    }

    /// Returns the stable provider identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the provider-supplied display name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the provider ordering value without assigning public semantics.
    #[must_use]
    pub const fn order(&self) -> i64 {
        self.order
    }

    /// Returns the custom-folder parent identifier when present.
    #[must_use]
    pub fn parent_id(&self) -> Option<&str> {
        self.parent_id.as_deref()
    }
}

impl fmt::Debug for ObservedMailboxCatalogItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObservedMailboxCatalogItem")
            .field("kind", &self.kind)
            .field("id", &"<redacted>")
            .field("name", &"<redacted>")
            .field("order", &"<redacted>")
            .field("parent_id", &self.parent_id.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// One exact typed response from the provider label endpoint.
#[derive(Clone, Eq, PartialEq)]
pub struct ObservedMailboxCatalogResponse {
    kind: MailboxCatalogKind,
    items: Vec<ObservedMailboxCatalogItem>,
}

impl ObservedMailboxCatalogResponse {
    pub(crate) const MAX_BODY_BYTES: usize = 262_144;

    /// Parses one exact GET response and retains only mail catalog fields.
    ///
    /// # Errors
    ///
    /// Rejects wrong endpoints/types, oversized or malformed bodies, more than
    /// 2,048 entries, invalid field bounds, type mismatch, or duplicate IDs.
    pub fn parse(
        kind: MailboxCatalogKind,
        method: &str,
        url: &str,
        body: &str,
    ) -> Result<Self, MailboxCatalogResponseError> {
        // jig-ignore-next-line: canonical rustfmt line.
        if method != "GET" || catalog_kind_from_url(url).ok().flatten() != Some(kind) {
            return Err(MailboxCatalogResponseError::UnexpectedEndpoint);
        }
        if body.len() > Self::MAX_BODY_BYTES {
            return Err(MailboxCatalogResponseError::BodyTooLarge);
        }
        let value: Value =
            // jig-ignore-next-line: canonical rustfmt line.
            serde_json::from_str(body).map_err(|_error| MailboxCatalogResponseError::Malformed)?;
        if value.get("Code").and_then(Value::as_u64) != Some(1000) {
            return Err(MailboxCatalogResponseError::ProviderRejected);
        }
        let labels = value
            .get("Labels")
            .and_then(Value::as_array)
            .ok_or(MailboxCatalogResponseError::Malformed)?;
        if labels.len() > MAX_CATALOG_ITEMS {
            return Err(MailboxCatalogResponseError::TooManyItems);
        }
        let mut ids = BTreeSet::new();
        let mut items = Vec::with_capacity(labels.len());
        for label in labels {
            let item = parse_item(kind, label)?;
            if !ids.insert(item.id.clone()) {
                return Err(MailboxCatalogResponseError::DuplicateId);
            }
            items.push(item);
        }
        // jig-ignore-next-line: canonical rustfmt line.
        items.sort_by(|left, right| left.order.cmp(&right.order).then(left.id.cmp(&right.id)));
        Ok(Self { kind, items })
    }

    /// Projects one decoded `Network.getResponseBody` envelope.
    ///
    /// # Errors
    ///
    /// Rejects base64 envelopes and every invalid provider response accepted by
    /// [`Self::parse`].
    pub fn parse_cdp_body(
        kind: MailboxCatalogKind,
        result: &Value,
    ) -> Result<Self, MailboxCatalogResponseError> {
        let encoded = result
            .get("base64Encoded")
            .and_then(Value::as_bool)
            .ok_or(MailboxCatalogResponseError::Malformed)?;
        if encoded {
            return Err(MailboxCatalogResponseError::UnsupportedEncoding);
        }
        let body = result
            .get("body")
            .and_then(Value::as_str)
            .ok_or(MailboxCatalogResponseError::Malformed)?;
        let url = format!("{LABELS_URL_PREFIX}?Type={}", kind.type_code());
        Self::parse(kind, "GET", &url, body)
    }

    /// Returns the response category.
    #[must_use]
    pub const fn kind(&self) -> MailboxCatalogKind {
        self.kind
    }

    /// Returns projected entries in deterministic provider-order order.
    #[must_use]
    pub fn items(&self) -> &[ObservedMailboxCatalogItem] {
        &self.items
    }
}

impl fmt::Debug for ObservedMailboxCatalogResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObservedMailboxCatalogResponse")
            .field("kind", &self.kind)
            .field("item_count", &self.items.len())
            .finish()
    }
}

/// Combined passive system-folder, custom-folder, and message-label snapshot.
#[derive(Clone, Eq, PartialEq)]
pub struct ObservedMailboxCatalog {
    mailboxes: Vec<ObservedMailboxCatalogItem>,
    labels: Vec<ObservedMailboxCatalogItem>,
}

impl ObservedMailboxCatalog {
    /// Combines exactly one response for each mail-relevant provider type.
    ///
    /// # Errors
    ///
    /// Rejects missing/duplicated response kinds or identifiers repeated across
    /// the combined catalog.
    pub fn from_responses(
        responses: Vec<ObservedMailboxCatalogResponse>,
    ) -> Result<Self, MailboxCatalogResponseError> {
        let mut by_kind = BTreeMap::new();
        for response in responses {
            if by_kind.insert(response.kind, response.items).is_some() {
                return Err(MailboxCatalogResponseError::DuplicateKind);
            }
        }
        let system = by_kind
            .remove(&MailboxCatalogKind::SystemFolder)
            .ok_or(MailboxCatalogResponseError::MissingKind)?;
        let folders = by_kind
            .remove(&MailboxCatalogKind::Folder)
            .ok_or(MailboxCatalogResponseError::MissingKind)?;
        let labels = by_kind
            .remove(&MailboxCatalogKind::Label)
            .ok_or(MailboxCatalogResponseError::MissingKind)?;
        if !by_kind.is_empty() {
            return Err(MailboxCatalogResponseError::Malformed);
        }
        let mut ids = BTreeSet::new();
        for item in system.iter().chain(&folders).chain(&labels) {
            if !ids.insert(item.id.as_str()) {
                return Err(MailboxCatalogResponseError::DuplicateId);
            }
        }
        let mut mailboxes = system;
        mailboxes.extend(folders);
        // jig-ignore-next-line: canonical rustfmt line.
        mailboxes.sort_by(|left, right| left.order.cmp(&right.order).then(left.id.cmp(&right.id)));
        Ok(Self { mailboxes, labels })
    }

    /// Returns built-in and custom folders in deterministic provider order.
    #[must_use]
    pub fn mailboxes(&self) -> &[ObservedMailboxCatalogItem] {
        &self.mailboxes
    }

    /// Returns custom message labels in deterministic provider order.
    #[must_use]
    pub fn labels(&self) -> &[ObservedMailboxCatalogItem] {
        &self.labels
    }
}

impl fmt::Debug for ObservedMailboxCatalog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObservedMailboxCatalog")
            .field("mailbox_count", &self.mailboxes.len())
            .field("label_count", &self.labels.len())
            .finish()
    }
}

/// Why exact mailbox/label Network evidence failed closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MailboxCatalogNetworkError {
    /// Required CDP event structure or exact query shape is malformed.
    MalformedEvent,
    /// A tracked request redirected away from its exact safe endpoint.
    RedirectedAway,
    /// Response status, MIME, endpoint, or category type is unsafe.
    ResponseRejected,
    /// A lifecycle event repeated or arrived out of order.
    InvalidSequence,
    /// Too many exact catalog requests are retained simultaneously.
    CapacityExceeded,
}

/// Why a captured label response cannot become catalog evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MailboxCatalogResponseError {
    /// HTTP method, endpoint, or query type is not the expected read-only GET.
    UnexpectedEndpoint,
    /// Response body exceeds the bounded parser input size.
    BodyTooLarge,
    /// JSON shape or a required bounded field is malformed.
    Malformed,
    /// Provider response does not carry the normal success code.
    ProviderRejected,
    /// Response contains more catalog rows than the projection bound.
    TooManyItems,
    /// Response or combined catalog repeats a provider identifier.
    DuplicateId,
    /// More than one response was supplied for the same category type.
    DuplicateKind,
    /// A required category response is absent.
    MissingKind,
    /// CDP returned an encoded body instead of decoded JSON text.
    UnsupportedEncoding,
}

fn parse_item(
    kind: MailboxCatalogKind,
    value: &Value,
) -> Result<ObservedMailboxCatalogItem, MailboxCatalogResponseError> {
    let id = bounded_string(value, "ID", MAX_CATALOG_ID_BYTES)?;
    let name = bounded_string(value, "Name", MAX_CATALOG_NAME_BYTES)?;
    let item_kind = value
        .get("Type")
        .and_then(Value::as_u64)
        .and_then(MailboxCatalogKind::from_type_code)
        .ok_or(MailboxCatalogResponseError::Malformed)?;
    if item_kind != kind {
        return Err(MailboxCatalogResponseError::Malformed);
    }
    let order = value
        .get("Order")
        .and_then(Value::as_i64)
        .ok_or(MailboxCatalogResponseError::Malformed)?;
    let parent_id = if kind == MailboxCatalogKind::Folder {
        bounded_parent_id(value.get("ParentID"))?
    } else {
        None
    };
    Ok(ObservedMailboxCatalogItem {
        kind,
        id,
        name,
        order,
        parent_id,
    })
}

fn bounded_string(
    value: &Value,
    field: &str,
    max_bytes: usize,
) -> Result<String, MailboxCatalogResponseError> {
    let text = value
        .get(field)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty() && text.len() <= max_bytes)
        .ok_or(MailboxCatalogResponseError::Malformed)?;
    Ok(String::from(text))
}

// jig-ignore-next-line: canonical rustfmt line.
fn bounded_parent_id(value: Option<&Value>) -> Result<Option<String>, MailboxCatalogResponseError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(parent)) => {
            if parent.is_empty() || parent.len() > MAX_CATALOG_ID_BYTES {
                return Err(MailboxCatalogResponseError::Malformed);
            }
            Ok(Some(parent.clone()))
        }
        Some(Value::Number(parent)) if parent.is_i64() || parent.is_u64() => {
            let parent = parent.to_string();
            if parent.len() > MAX_CATALOG_ID_BYTES {
                return Err(MailboxCatalogResponseError::Malformed);
            }
            Ok(Some(parent))
        }
        Some(_) => Err(MailboxCatalogResponseError::Malformed),
    }
}

fn catalog_kind_from_url(
    url: &str,
) -> Result<Option<MailboxCatalogKind>, MailboxCatalogNetworkError> {
    let Some(remainder) = url.strip_prefix(LABELS_URL_PREFIX) else {
        return Ok(None);
    };
    let Some(query) = remainder.strip_prefix('?') else {
        return Ok(None);
    };
    if query.contains('#') {
        return Err(MailboxCatalogNetworkError::MalformedEvent);
    }
    let mut pairs = query.split('&');
    let first = pairs
        .next()
        .ok_or(MailboxCatalogNetworkError::MalformedEvent)?;
    if pairs.next().is_some() {
        return Ok(None);
    }
    let (key, value) = first
        .split_once('=')
        .ok_or(MailboxCatalogNetworkError::MalformedEvent)?;
    if key != "Type" {
        return Ok(None);
    }
    let raw = value
        .parse::<u64>()
        .map_err(|_error| MailboxCatalogNetworkError::MalformedEvent)?;
    Ok(MailboxCatalogKind::from_type_code(raw))
}

// jig-ignore-next-line: canonical rustfmt line.
fn network_request_id(event: &Value) -> Result<&str, MailboxCatalogNetworkError> {
    event
        .get("params")
        .and_then(|params| params.get("requestId"))
        .and_then(Value::as_str)
        .ok_or(MailboxCatalogNetworkError::MalformedEvent)
}
