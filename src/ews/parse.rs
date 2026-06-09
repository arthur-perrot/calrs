//! Response parsers for the EWS operations defined in [`super::operations`].
//!
//! The parsing strategy matches the rest of calrs: deterministic SOAP shapes
//! are extracted with the namespace-agnostic helpers in [`super::soap`]. We
//! do not pull in a full XML library — EWS payloads are structured but
//! consistent enough that targeted extraction is reliable, and the test
//! suite (alongside `cargo clippy`) catches regressions.

use anyhow::{bail, Result};
use base64::Engine;

use super::soap::{attr, collect_blocks, collect_tag_contents, first_tag_content};

/// One calendar folder discovered via `FindFolder`.
#[derive(Debug, Clone)]
pub struct EwsCalendarFolder {
    pub id: String,
    pub change_key: Option<String>,
    pub display_name: Option<String>,
}

/// Calendar item metadata returned by `FindItem` (no MIME content yet — that
/// requires a follow-up `GetItem`).
#[derive(Debug, Clone)]
pub struct EwsCalendarItem {
    pub item_id: String,
    pub change_key: Option<String>,
    pub uid: Option<String>,
    pub subject: Option<String>,
    pub start: Option<String>,
    pub end: Option<String>,
    pub location: Option<String>,
    pub is_all_day: bool,
    pub is_cancelled: bool,
    pub free_busy_status: Option<String>,
    pub has_recurrence: bool,
}

/// Page of calendar items + total count + how many were included in this
/// response, so the caller can drive offset paging.
#[derive(Debug, Clone, Default)]
pub struct EwsItemPage {
    pub items: Vec<EwsCalendarItem>,
    pub total: Option<u64>,
    pub included_count: usize,
}

/// Outcome of `SyncFolderItems` — added / changed items (with iCal text), and
/// deleted item ids/UIDs.
#[derive(Debug, Clone, Default)]
pub struct EwsSyncDelta {
    pub added_or_changed: Vec<(String, String)>,
    pub deleted_uids: Vec<String>,
    pub deleted_item_ids: Vec<String>,
    pub new_sync_state: Option<String>,
    pub includes_last: bool,
}

/// Parse a `FindFolderResponse` body into a vector of calendar folders.
pub fn parse_find_folder_response(xml: &str) -> Result<Vec<EwsCalendarFolder>> {
    let mut out = Vec::new();
    for block in collect_blocks(xml, "CalendarFolder") {
        let id_tag = find_first_open_tag(&block, "FolderId");
        let (id, change_key) = match id_tag {
            Some(tag) => (
                attr(&tag, "Id").unwrap_or_default(),
                attr(&tag, "ChangeKey"),
            ),
            None => continue,
        };
        if id.is_empty() {
            continue;
        }
        let display_name = first_tag_content(&block, "DisplayName");
        out.push(EwsCalendarFolder {
            id,
            change_key,
            display_name,
        });
    }
    Ok(out)
}

/// Parse a `FindItemResponse` body for calendar items.
pub fn parse_calendar_items_response(xml: &str) -> Result<EwsItemPage> {
    let mut page = EwsItemPage::default();

    // RootFolder TotalItemsInView / IncludesLastItemInRange / IndexedPagingOffset
    if let Some(root_tag) = find_first_open_tag(xml, "RootFolder") {
        if let Some(total) = attr(&root_tag, "TotalItemsInView") {
            page.total = total.parse().ok();
        }
    }

    let item_blocks = collect_blocks(xml, "CalendarItem");
    page.included_count = item_blocks.len();
    for block in item_blocks {
        if let Some(item) = parse_calendar_item_block(&block) {
            page.items.push(item);
        }
    }
    Ok(page)
}

fn parse_calendar_item_block(block: &str) -> Option<EwsCalendarItem> {
    let id_tag = find_first_open_tag(block, "ItemId")?;
    let item_id = attr(&id_tag, "Id").unwrap_or_default();
    if item_id.is_empty() {
        return None;
    }
    let change_key = attr(&id_tag, "ChangeKey");
    let uid = first_tag_content(block, "UID");
    let subject = first_tag_content(block, "Subject");
    let start = first_tag_content(block, "Start");
    let end = first_tag_content(block, "End");
    let location = first_tag_content(block, "Location");
    let is_all_day = first_tag_content(block, "IsAllDayEvent")
        .map(|s| s.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let is_cancelled = first_tag_content(block, "IsCancelled")
        .map(|s| s.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let free_busy_status = first_tag_content(block, "LegacyFreeBusyStatus");
    // `has_recurrence` here narrowly means "needs RECURRENCE-ID to disambiguate
    // siblings sharing the master UID" — i.e. an expanded `Occurrence` or
    // `Exception` returned by `CalendarView`. A raw `RecurringMaster` (only
    // surfaced by the non-windowed `fetch_events` path, which production sync
    // doesn't use) must NOT get a `RECURRENCE-ID`: masters are a single logical
    // item and emitting one would store an iCal value with `RECURRENCE-ID` but
    // no `RRULE`, which is meaningless.
    let calendar_item_type = first_tag_content(block, "CalendarItemType");
    let has_recurrence = matches!(
        calendar_item_type.as_deref(),
        Some(t) if t.eq_ignore_ascii_case("Occurrence") || t.eq_ignore_ascii_case("Exception")
    );
    Some(EwsCalendarItem {
        item_id,
        change_key,
        uid,
        subject,
        start,
        end,
        location,
        is_all_day,
        is_cancelled,
        free_busy_status,
        has_recurrence,
    })
}

/// Parse a `GetItemResponse` body. Returns one (item_id, ical) pair per item
/// successfully retrieved. Items without MIME content are skipped (the server
/// occasionally returns a placeholder for unsupported types).
pub fn parse_get_item_response(xml: &str) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    let blocks = collect_blocks(xml, "CalendarItem");
    let blocks = if blocks.is_empty() {
        // Some servers return MeetingRequest etc.
        let mut alt = collect_blocks(xml, "MeetingRequest");
        alt.extend(collect_blocks(xml, "MeetingResponse"));
        alt.extend(collect_blocks(xml, "MeetingCancellation"));
        alt
    } else {
        blocks
    };

    for block in blocks {
        let id_tag = match find_first_open_tag(&block, "ItemId") {
            Some(t) => t,
            None => continue,
        };
        let item_id = attr(&id_tag, "Id").unwrap_or_default();
        if item_id.is_empty() {
            continue;
        }
        let mime_b64 = match first_tag_content(&block, "MimeContent") {
            Some(s) => s,
            None => continue,
        };
        let decoded = match base64::engine::general_purpose::STANDARD.decode(mime_b64.trim()) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::warn!(error = %e, "EWS MimeContent base64 decode failed; skipping item");
                continue;
            }
        };
        let mime_text = match String::from_utf8(decoded) {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(error = %e, "EWS MimeContent not valid UTF-8; skipping item");
                continue;
            }
        };
        if let Some(ical) = extract_vcalendar(&mime_text) {
            out.push((item_id, ical));
        }
    }
    Ok(out)
}

/// Pull the BEGIN:VCALENDAR…END:VCALENDAR block out of a MIME message body.
/// EWS returns the full RFC 5322 envelope plus calendar attachment; we only
/// care about the iCalendar portion.
pub fn extract_vcalendar(mime: &str) -> Option<String> {
    let begin = mime.find("BEGIN:VCALENDAR")?;
    let end = mime.find("END:VCALENDAR")?;
    if end <= begin {
        return None;
    }
    let close = end + "END:VCALENDAR".len();
    let mut block = mime[begin..close].to_string();
    // MIME line endings are CRLF; iCal already requires CRLF, so we leave it
    // alone. RFC 5545 §3.1 long-content lines are folded with a CRLF followed
    // by a single space or tab; unfold them here so downstream parsers see
    // logical lines rather than the wire format.
    block = block.replace("\r\n ", "");
    block = block.replace("\r\n\t", "");
    Some(block)
}

/// Parse the response of `CreateItem` and return the new ItemId.
pub fn parse_create_item_response(xml: &str) -> Result<String> {
    if let Some(tag) = find_first_open_tag(xml, "ItemId") {
        if let Some(id) = attr(&tag, "Id") {
            if !id.is_empty() {
                return Ok(id);
            }
        }
    }
    bail!("CreateItem response did not include an ItemId")
}

/// Parse `SyncFolderItemsResponse` body (single page). Caller loops until
/// `includes_last` is true.
pub fn parse_sync_folder_items_response(xml: &str) -> Result<EwsSyncDelta> {
    let new_sync_state = first_tag_content(xml, "SyncState");
    let includes_last = first_tag_content(xml, "IncludesLastItemInRange")
        .map(|s| s.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let mut delta = EwsSyncDelta {
        new_sync_state,
        includes_last,
        ..Default::default()
    };

    // Changes come as <t:Create><t:CalendarItem>…</t:CalendarItem></t:Create>
    // or <t:Update> with the same shape, and <t:Delete><t:ItemId/></t:Delete>.
    for block in collect_blocks(xml, "Create") {
        if let Some(item) = item_id_with_uid(&block) {
            delta.added_or_changed.push(item);
        }
    }
    for block in collect_blocks(xml, "Update") {
        if let Some(item) = item_id_with_uid(&block) {
            delta.added_or_changed.push(item);
        }
    }
    for block in collect_blocks(xml, "Delete") {
        if let Some(tag) = find_first_open_tag(&block, "ItemId") {
            if let Some(id) = attr(&tag, "Id") {
                if !id.is_empty() {
                    delta.deleted_item_ids.push(id);
                }
            }
        }
    }
    // ReadFlagChange is a sync change type that doesn't matter for calendars
    // but EWS may emit it if we ever sync read flags — silently ignore.
    Ok(delta)
}

fn item_id_with_uid(block: &str) -> Option<(String, String)> {
    let id = find_first_open_tag(block, "ItemId").and_then(|t| attr(&t, "Id"))?;
    let uid = first_tag_content(block, "UID").unwrap_or_default();
    Some((id, uid))
}

/// Locate the opening tag (with attributes) of `local_name` and return it as
/// a substring like `<t:ItemId Id="..." ChangeKey="..."/>`. Used to pull
/// attributes out without dragging in a real XML parser.
pub fn find_first_open_tag(xml: &str, local_name: &str) -> Option<String> {
    let needle = format!(":{local_name}");
    let mut search_from = 0;
    while let Some(pos) = xml[search_from..].find(&needle) {
        let abs = search_from + pos;
        let before = &xml[..abs];
        let lt = match before.rfind('<') {
            Some(i) => i,
            None => {
                search_from = abs + needle.len();
                continue;
            }
        };
        let prefix_part = &xml[lt + 1..abs];
        if prefix_part.is_empty()
            || prefix_part.len() > 16
            || !prefix_part.chars().all(|c| c.is_alphanumeric() || c == '_')
        {
            search_from = abs + needle.len();
            continue;
        }
        let open_tag_end = abs + needle.len();
        if let Some(close) = xml[open_tag_end..].find('>') {
            let end = open_tag_end + close + 1;
            return Some(xml[lt..end].to_string());
        }
        break;
    }
    None
}

/// Convenience for diagnostics: count how many response messages succeeded
/// vs failed in a batched response.
pub fn count_response_messages(xml: &str) -> (usize, usize) {
    let codes = collect_tag_contents(xml, "ResponseCode");
    let total = codes.len();
    let ok = codes.iter().filter(|c| c.as_str() == "NoError").count();
    (ok, total)
}

#[cfg(test)]
mod tests;
