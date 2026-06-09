use super::*;

// --- extract_tag ---

#[test]
fn extract_simple_tag() {
    let xml = "<d:href>/principals/users/alice/</d:href>";
    assert_eq!(
        extract_tag(xml, "d:href"),
        Some("/principals/users/alice/".to_string())
    );
}

#[test]
fn extract_tag_with_attributes() {
    let xml = r#"<aic:calendar-color symbolic-color="custom">#1F6BFF</aic:calendar-color>"#;
    assert_eq!(
        extract_tag(xml, "aic:calendar-color"),
        Some("#1F6BFF".to_string())
    );
}

#[test]
fn extract_tag_not_found() {
    let xml = "<d:href>/path/</d:href>";
    assert_eq!(extract_tag(xml, "d:displayname"), None);
}

#[test]
fn extract_tag_empty_content() {
    let xml = "<d:displayname></d:displayname>";
    assert_eq!(extract_tag(xml, "d:displayname"), None);
}

#[test]
fn extract_tag_whitespace_content() {
    let xml = "<d:displayname>  My Calendar  </d:displayname>";
    assert_eq!(
        extract_tag(xml, "d:displayname"),
        Some("My Calendar".to_string())
    );
}

#[test]
fn extract_tag_nested() {
    let xml =
        "<d:current-user-principal><d:href>/principals/alice/</d:href></d:current-user-principal>";
    // Searching for d:href within the principal block
    assert_eq!(
        extract_tag(xml, "d:href"),
        Some("/principals/alice/".to_string())
    );
}

// --- extract_tag case variants (SOGo uses D: and C:) ---

#[test]
fn extract_tag_uppercase_dav_prefix() {
    let xml = "<D:href>/principals/users/alice/</D:href>";
    assert_eq!(
        extract_tag(xml, "d:href"),
        Some("/principals/users/alice/".to_string())
    );
}

#[test]
fn extract_tag_uppercase_caldav_prefix() {
    let xml = "<C:calendar-home-set><D:href>/cal/home/</D:href></C:calendar-home-set>";
    assert_eq!(
        extract_tag(xml, "cal:calendar-home-set"),
        Some("<D:href>/cal/home/</D:href>".to_string())
    );
}

#[test]
fn extract_tag_unprefixed() {
    let xml = "<href>/dav/principals/user/</href>";
    assert_eq!(
        extract_tag(xml, "d:href"),
        Some("/dav/principals/user/".to_string())
    );
}

// --- extract_tag arbitrary prefix (SOGo uses a: for CalDAV namespace) ---

#[test]
fn extract_tag_arbitrary_prefix() {
    let xml = r#"<a:calendar-home-set><D:href xmlns:D="DAV:">/SOGo/dav/user/Calendar/</D:href></a:calendar-home-set>"#;
    assert_eq!(
        extract_tag(xml, "cal:calendar-home-set"),
        Some(r#"<D:href xmlns:D="DAV:">/SOGo/dav/user/Calendar/</D:href>"#.to_string())
    );
}

#[test]
fn extract_tag_sogo_calendar_home_full_flow() {
    // Real SOGo response from issue #15
    let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:" xmlns:a="urn:ietf:params:xml:ns:caldav"><D:response><D:href>/SOGo/dav/guess.who@echirolles.fr/</D:href><D:propstat><D:status>HTTP/1.1 200 OK</D:status><D:prop><a:calendar-home-set><D:href xmlns:D="DAV:">/SOGo/dav/guess.who@echirolles.fr/Calendar/</D:href></a:calendar-home-set></D:prop></D:propstat></D:response></D:multistatus>"#;
    // extract_tag should find calendar-home-set even with a: prefix
    let inner = extract_tag(xml, "cal:calendar-home-set").unwrap();
    let href = extract_tag(&inner, "d:href").unwrap();
    assert_eq!(href, "/SOGo/dav/guess.who@echirolles.fr/Calendar/");
}

// --- split_responses ---

#[test]
fn split_responses_uppercase() {
    let xml = r#"<D:multistatus><D:response><D:href>/a</D:href></D:response><D:response><D:href>/b</D:href></D:response></D:multistatus>"#;
    let blocks = split_responses(xml);
    assert_eq!(blocks.len(), 2);
}

// --- parse_calendar_list with uppercase prefixes (SOGo) ---

#[test]
fn parse_calendars_sogo_uppercase() {
    let xml = r#"
<D:multistatus xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:response>
<D:href>/SOGo/dav/user/Calendar/personal/</D:href>
<D:propstat><D:prop>
  <D:resourcetype><D:collection/><C:calendar/></D:resourcetype>
  <D:displayname>Personal Calendar</D:displayname>
</D:prop></D:propstat>
  </D:response>
  <D:response>
<D:href>/SOGo/dav/user/Calendar/</D:href>
<D:propstat><D:prop>
  <D:resourcetype><D:collection/></D:resourcetype>
</D:prop></D:propstat>
  </D:response>
</D:multistatus>"#;

    let cals = parse_calendar_list(xml);
    assert_eq!(cals.len(), 1);
    assert_eq!(cals[0].href, "/SOGo/dav/user/Calendar/personal/");
    assert_eq!(cals[0].display_name, Some("Personal Calendar".to_string()));
}

#[test]
fn parse_calendars_sogo_unprefixed_xmlns() {
    // SoGo uses unprefixed <calendar xmlns="urn:ietf:params:xml:ns:caldav"/> instead of <C:calendar/>
    let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:" xmlns:b="http://calendarserver.org/ns/" xmlns:a="http://apple.com/ns/ical/"><D:response><D:href>/SOGo/dav/user@example.com/Calendar/</D:href><D:propstat><D:status>HTTP/1.1 200 OK</D:status><D:prop><D:resourcetype><D:collection/></D:resourcetype><D:displayname>Calendar</D:displayname></D:prop></D:propstat></D:response><D:response><D:href>/SOGo/dav/user@example.com/Calendar/personal/</D:href><D:propstat><D:status>HTTP/1.1 200 OK</D:status><D:prop><D:resourcetype><D:collection/><calendar xmlns="urn:ietf:params:xml:ns:caldav"/><vevent-collection xmlns="http://groupdav.org/"/><vtodo-collection xmlns="http://groupdav.org/"/><schedule-outbox xmlns="urn:ietf:params:xml:ns:caldav"/></D:resourcetype><D:displayname>Personal Calendar</D:displayname><a:calendar-color>#AAAAAAFF</a:calendar-color><b:getctag>-1</b:getctag><D:sync-token>-1</D:sync-token></D:prop></D:propstat></D:response></D:multistatus>"#;

    let cals = parse_calendar_list(xml);
    assert_eq!(cals.len(), 1);
    assert_eq!(
        cals[0].href,
        "/SOGo/dav/user@example.com/Calendar/personal/"
    );
    assert_eq!(cals[0].display_name, Some("Personal Calendar".to_string()));
    assert_eq!(cals[0].color, Some("#AAAAAAFF".to_string()));
    assert_eq!(cals[0].ctag, Some("-1".to_string()));
    assert_eq!(cals[0].sync_token, Some("-1".to_string()));
}

// --- resolve_url ---

#[test]
fn resolve_absolute_path() {
    let client = CaldavClient::new(
        "https://nextcloud.example.com/remote.php/dav",
        "user",
        "pass",
    );
    assert_eq!(
        client.resolve_url("/principals/users/alice/"),
        "https://nextcloud.example.com/principals/users/alice/"
    );
}

#[test]
fn resolve_full_url_passthrough() {
    let client = CaldavClient::new(
        "https://nextcloud.example.com/remote.php/dav",
        "user",
        "pass",
    );
    assert_eq!(
        client.resolve_url("https://other.server.com/calendars/"),
        "https://other.server.com/calendars/"
    );
}

#[test]
fn resolve_with_port() {
    let client = CaldavClient::new("https://cal.example.com:8443/dav", "user", "pass");
    assert_eq!(
        client.resolve_url("/calendars/alice/"),
        "https://cal.example.com:8443/calendars/alice/"
    );
}

// Regression test for https://github.com/olivierlambert/calrs/issues/42 —
// Nextcloud on a non-standard port returns site-absolute principal hrefs;
// resolve_url must preserve the port so PROPFIND hits the right server.
#[test]
fn resolve_with_port_nextcloud_principal() {
    let client = CaldavClient::new("https://my-nextcloud:8080/remote.php/dav/", "user", "pass");
    assert_eq!(
        client.resolve_url("/remote.php/dav/principals/users/alice/"),
        "https://my-nextcloud:8080/remote.php/dav/principals/users/alice/"
    );
}

#[test]
fn resolve_without_port_https_default() {
    let client = CaldavClient::new("https://cal.example.com/dav", "user", "pass");
    assert_eq!(
        client.resolve_url("/calendars/alice/"),
        "https://cal.example.com/calendars/alice/"
    );
}

#[test]
fn resolve_with_explicit_default_port_stripped() {
    // Port 443 on https is the default; url crate strips it, which is fine —
    // it reaches the same server.
    let client = CaldavClient::new("https://cal.example.com:443/dav", "user", "pass");
    assert_eq!(
        client.resolve_url("/calendars/alice/"),
        "https://cal.example.com/calendars/alice/"
    );
}

// --- parse_calendar_list ---

#[test]
fn parse_calendars_filters_non_calendar() {
    let xml = r#"
<d:multistatus>
  <d:response>
<d:href>/dav/calendars/alice/</d:href>
<d:propstat><d:prop>
  <d:resourcetype><d:collection/></d:resourcetype>
</d:prop></d:propstat>
  </d:response>
  <d:response>
<d:href>/dav/calendars/alice/default/</d:href>
<d:propstat><d:prop>
  <d:resourcetype><d:collection/><cal:calendar/></d:resourcetype>
  <d:displayname>Personal</d:displayname>
</d:prop></d:propstat>
  </d:response>
  <d:response>
<d:href>/dav/calendars/alice/work/</d:href>
<d:propstat><d:prop>
  <d:resourcetype><d:collection/><cal:calendar/></d:resourcetype>
  <d:displayname>Work</d:displayname>
  <aic:calendar-color>#FF0000</aic:calendar-color>
  <cso:getctag>ctag-123</cso:getctag>
</d:prop></d:propstat>
  </d:response>
</d:multistatus>"#;

    let cals = parse_calendar_list(xml);
    assert_eq!(cals.len(), 2);

    assert_eq!(cals[0].href, "/dav/calendars/alice/default/");
    assert_eq!(cals[0].display_name, Some("Personal".to_string()));
    assert_eq!(cals[0].color, None);

    assert_eq!(cals[1].href, "/dav/calendars/alice/work/");
    assert_eq!(cals[1].display_name, Some("Work".to_string()));
    assert_eq!(cals[1].color, Some("#FF0000".to_string()));
    assert_eq!(cals[1].ctag, Some("ctag-123".to_string()));
}

#[test]
fn parse_calendars_alternative_namespaces() {
    // BlueMind uses x1: for colors and cs: for ctags
    let xml = r#"
<d:multistatus>
  <d:response>
<d:href>/dav/cal/</d:href>
<d:propstat><d:prop>
  <d:resourcetype><d:collection/><cal:calendar/></d:resourcetype>
  <d:displayname>BlueMind Cal</d:displayname>
  <x1:calendar-color>#00FF00</x1:calendar-color>
  <cs:getctag>ctag-bm</cs:getctag>
</d:prop></d:propstat>
  </d:response>
</d:multistatus>"#;

    let cals = parse_calendar_list(xml);
    assert_eq!(cals.len(), 1);
    assert_eq!(cals[0].color, Some("#00FF00".to_string()));
    assert_eq!(cals[0].ctag, Some("ctag-bm".to_string()));
}

#[test]
fn parse_calendars_empty_response() {
    let xml = "<d:multistatus></d:multistatus>";
    let cals = parse_calendar_list(xml);
    assert!(cals.is_empty());
}

// --- parse_event_responses ---

// --- parse_sync_response ---

#[test]
fn parse_sync_changes_and_deletions() {
    let xml = r#"
<d:multistatus xmlns:d="DAV:" xmlns:cal="urn:ietf:params:xml:ns:caldav">
  <d:response>
<d:href>/cal/event1.ics</d:href>
<d:propstat>
  <d:prop>
    <d:getetag>"etag1"</d:getetag>
    <cal:calendar-data>BEGIN:VCALENDAR
BEGIN:VEVENT
UID:ev1
SUMMARY:Changed event
END:VEVENT
END:VCALENDAR</cal:calendar-data>
  </d:prop>
  <d:status>HTTP/1.1 200 OK</d:status>
</d:propstat>
  </d:response>
  <d:response>
<d:href>/cal/deleted-event.ics</d:href>
<d:status>HTTP/1.1 404 Not Found</d:status>
  </d:response>
  <d:sync-token>https://example.com/sync/new-token-456</d:sync-token>
</d:multistatus>"#;

    let result = parse_sync_response(xml);
    assert_eq!(result.changed.len(), 1);
    assert_eq!(result.changed[0].href, "/cal/event1.ics");
    assert!(result.changed[0].ical_data.contains("UID:ev1"));
    assert_eq!(result.deleted_hrefs, vec!["/cal/deleted-event.ics"]);
    assert_eq!(
        result.new_sync_token,
        Some("https://example.com/sync/new-token-456".to_string())
    );
}

#[test]
fn parse_sync_empty_delta() {
    let xml = r#"
<d:multistatus xmlns:d="DAV:">
  <d:sync-token>https://example.com/sync/token-789</d:sync-token>
</d:multistatus>"#;

    let result = parse_sync_response(xml);
    assert!(result.changed.is_empty());
    assert!(result.deleted_hrefs.is_empty());
    assert_eq!(
        result.new_sync_token,
        Some("https://example.com/sync/token-789".to_string())
    );
}

#[test]
fn parse_sync_multiple_deletions() {
    let xml = r#"
<d:multistatus xmlns:d="DAV:">
  <d:response>
<d:href>/cal/a.ics</d:href>
<d:status>HTTP/1.1 404 Not Found</d:status>
  </d:response>
  <d:response>
<d:href>/cal/b.ics</d:href>
<d:status>HTTP/1.1 404 Not Found</d:status>
  </d:response>
  <d:sync-token>token-new</d:sync-token>
</d:multistatus>"#;

    let result = parse_sync_response(xml);
    assert!(result.changed.is_empty());
    assert_eq!(result.deleted_hrefs.len(), 2);
}

/// Regression test for issue #107 / 2026-05-14 production incident.
///
/// Per RFC 4918 §9.1, a `<d:response>` for an existing resource may carry
/// one or more `<d:propstat>` blocks, each with its own `<d:status>` that
/// describes which requested properties succeeded vs which were not found.
/// A 404 inside a propstat is a property-level "this prop doesn't exist on
/// this resource", NOT a resource-level deletion. Before the fix, the
/// parser took the first `<d:status>` it found anywhere in the response
/// block and misread a property-level 404 as a deleted href — which is
/// what cancelled customer bookings in production.
///
/// This XML reproduces the failure shape: a response with a 404 propstat
/// (a property that doesn't exist on the resource) ordered BEFORE a 200
/// propstat that carries the actual calendar-data. The parser must
/// classify this as a `changed` event, not as a deletion.
#[test]
fn parse_sync_ignores_property_level_404_in_propstat() {
    let xml = r#"
<d:multistatus xmlns:d="DAV:" xmlns:cal="urn:ietf:params:xml:ns:caldav">
  <d:response>
<d:href>/cal/live-event.ics</d:href>
<d:propstat>
  <d:prop><d:getetag/></d:prop>
  <d:status>HTTP/1.1 404 Not Found</d:status>
</d:propstat>
<d:propstat>
  <d:prop>
    <d:getetag>"abc-123"</d:getetag>
    <cal:calendar-data>BEGIN:VCALENDAR
BEGIN:VEVENT
UID:still-here
END:VEVENT
END:VCALENDAR</cal:calendar-data>
  </d:prop>
  <d:status>HTTP/1.1 200 OK</d:status>
</d:propstat>
  </d:response>
  <d:sync-token>https://example.com/sync/t1</d:sync-token>
</d:multistatus>"#;

    let result = parse_sync_response(xml);
    assert!(
        result.deleted_hrefs.is_empty(),
        "a 404 propstat must NOT be classified as a resource-level deletion; \
         got deleted_hrefs={:?}",
        result.deleted_hrefs
    );
    assert_eq!(result.changed.len(), 1);
    assert_eq!(result.changed[0].href, "/cal/live-event.ics");
    assert!(result.changed[0].ical_data.contains("UID:still-here"));
}

/// Companion to the above: confirm a genuine resource-level deletion
/// (a single `<d:status>` directly under `<d:response>`, no propstat)
/// is still correctly classified as a deleted href. Strip-only-propstat
/// must not over-correct and ignore real deletions.
#[test]
fn parse_sync_still_detects_real_resource_deletion() {
    let xml = r#"
<d:multistatus xmlns:d="DAV:">
  <d:response>
<d:href>/cal/actually-gone.ics</d:href>
<d:status>HTTP/1.1 404 Not Found</d:status>
  </d:response>
  <d:sync-token>https://example.com/sync/t2</d:sync-token>
</d:multistatus>"#;

    let result = parse_sync_response(xml);
    assert_eq!(result.deleted_hrefs, vec!["/cal/actually-gone.ics"]);
    assert!(result.changed.is_empty());
}

/// 410 Gone (per RFC 7231) means the resource was deliberately removed.
/// Some CalDAV servers return 410 instead of 404 for deletions. The parser
/// must treat both as resource-level deletions.
#[test]
fn parse_sync_treats_410_as_deletion() {
    let xml = r#"
<d:multistatus xmlns:d="DAV:">
  <d:response>
<d:href>/cal/gone.ics</d:href>
<d:status>HTTP/1.1 410 Gone</d:status>
  </d:response>
</d:multistatus>"#;

    let result = parse_sync_response(xml);
    assert_eq!(result.deleted_hrefs, vec!["/cal/gone.ics"]);
}

/// Mixed response: a true deletion (no propstat, resource-level 404),
/// a "changed with property-level 404 propstat" entry, and a vanilla
/// 200 addition should all coexist in one multistatus and parse correctly.
#[test]
fn parse_sync_mixed_real_deletion_and_propstat_404() {
    let xml = r#"
<d:multistatus xmlns:d="DAV:" xmlns:cal="urn:ietf:params:xml:ns:caldav">
  <d:response>
<d:href>/cal/deleted.ics</d:href>
<d:status>HTTP/1.1 404 Not Found</d:status>
  </d:response>
  <d:response>
<d:href>/cal/has-propstat-404.ics</d:href>
<d:propstat>
  <d:prop><d:displayname/></d:prop>
  <d:status>HTTP/1.1 404 Not Found</d:status>
</d:propstat>
<d:propstat>
  <d:prop>
    <d:getetag>"e1"</d:getetag>
    <cal:calendar-data>BEGIN:VCALENDAR
BEGIN:VEVENT
UID:withpropstat404
END:VEVENT
END:VCALENDAR</cal:calendar-data>
  </d:prop>
  <d:status>HTTP/1.1 200 OK</d:status>
</d:propstat>
  </d:response>
  <d:response>
<d:href>/cal/normal.ics</d:href>
<d:propstat>
  <d:prop>
    <d:getetag>"e2"</d:getetag>
    <cal:calendar-data>BEGIN:VCALENDAR
BEGIN:VEVENT
UID:normal
END:VEVENT
END:VCALENDAR</cal:calendar-data>
  </d:prop>
  <d:status>HTTP/1.1 200 OK</d:status>
</d:propstat>
  </d:response>
</d:multistatus>"#;

    let result = parse_sync_response(xml);
    assert_eq!(result.deleted_hrefs, vec!["/cal/deleted.ics"]);
    assert_eq!(result.changed.len(), 2);
    let hrefs: Vec<&str> = result.changed.iter().map(|e| e.href.as_str()).collect();
    assert!(hrefs.contains(&"/cal/has-propstat-404.ics"));
    assert!(hrefs.contains(&"/cal/normal.ics"));
}

#[test]
fn strip_propstat_blocks_handles_uppercase_and_unprefixed() {
    // Lowercase prefix
    let s = "<d:response><d:href>/a</d:href><d:propstat><d:status>404</d:status></d:propstat></d:response>";
    let out = strip_propstat_blocks(s);
    assert_eq!(out, "<d:response><d:href>/a</d:href></d:response>");

    // Uppercase prefix (SOGo style)
    let s = "<D:response><D:href>/b</D:href><D:propstat><D:status>404</D:status></D:propstat></D:response>";
    let out = strip_propstat_blocks(s);
    assert_eq!(out, "<D:response><D:href>/b</D:href></D:response>");

    // Unprefixed
    let s = "<response><href>/c</href><propstat><status>404</status></propstat></response>";
    let out = strip_propstat_blocks(s);
    assert_eq!(out, "<response><href>/c</href></response>");

    // `<propstats>` (different element with similar prefix) must NOT be stripped
    let s = "<d:response><d:propstats-wrapper>keep me</d:propstats-wrapper></d:response>";
    let out = strip_propstat_blocks(s);
    assert!(out.contains("propstats-wrapper"));
    assert!(out.contains("keep me"));
}

// --- parse_event_responses ---

#[test]
fn parse_events_extracts_ical() {
    let xml = r#"
<d:multistatus>
  <d:response>
<d:href>/cal/event1.ics</d:href>
<d:propstat><d:prop>
  <cal:calendar-data>BEGIN:VCALENDAR
BEGIN:VEVENT
UID:ev1
END:VEVENT
END:VCALENDAR</cal:calendar-data>
</d:prop></d:propstat>
  </d:response>
  <d:response>
<d:href>/cal/event2.ics</d:href>
<d:propstat><d:prop>
  <c:calendar-data>BEGIN:VCALENDAR
BEGIN:VEVENT
UID:ev2
END:VEVENT
END:VCALENDAR</c:calendar-data>
</d:prop></d:propstat>
  </d:response>
</d:multistatus>"#;

    let events = parse_event_responses(xml);
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].href, "/cal/event1.ics");
    assert!(events[0].ical_data.contains("UID:ev1"));
    assert_eq!(events[1].href, "/cal/event2.ics");
    assert!(events[1].ical_data.contains("UID:ev2"));
}

#[test]
fn parse_events_skips_empty_data() {
    let xml = r#"
<d:multistatus>
  <d:response>
<d:href>/cal/no-data.ics</d:href>
<d:propstat><d:prop></d:prop></d:propstat>
  </d:response>
</d:multistatus>"#;

    let events = parse_event_responses(xml);
    assert!(events.is_empty());
}

// --- CaldavClient::new origin parsing ---

#[test]
fn client_origin_parsing() {
    let client = CaldavClient::new("https://cloud.example.com/remote.php/dav", "u", "p");
    assert_eq!(client.origin, "https://cloud.example.com");
    assert_eq!(client.base_url, "https://cloud.example.com/remote.php/dav");
}

#[test]
fn client_trims_trailing_slash() {
    let client = CaldavClient::new("https://cloud.example.com/dav/", "u", "p");
    assert_eq!(client.base_url, "https://cloud.example.com/dav");
}

// Google CalDAV's PROPFIND on the base URL doesn't reliably expose
// <current-user-principal>, but the URL we configure for Google OAuth2
// sources is already the per-user principal endpoint, so discover_principal
// short-circuits and returns it directly. discover_calendar_home then does
// a real PROPFIND so any error from Google surfaces with its actual body.
#[tokio::test]
async fn google_discover_principal_short_circuits() {
    let url = "https://apidata.googleusercontent.com/caldav/v2/alice%40gmail.com/user";
    let client = CaldavClient::with_bearer(url, "fake-token");

    let principal = client.discover_principal().await.unwrap();
    assert_eq!(principal, url);
}

// --- private-host allowlist (SSRF opt-out) ---

#[test]
fn allowlist_matches_case_insensitively() {
    let list = vec!["radicale".to_string(), "nextcloud.local".to_string()];
    assert!(is_host_allowlisted("radicale", &list));
    assert!(is_host_allowlisted("RADICALE", &list));
    assert!(is_host_allowlisted("Nextcloud.Local", &list));
    assert!(!is_host_allowlisted("evil.example.com", &list));
    assert!(!is_host_allowlisted("radicale.example.com", &list));
}

#[test]
fn empty_allowlist_matches_nothing() {
    assert!(!is_host_allowlisted("radicale", &[]));
}

/// All env-var assertions live in one test: Rust runs tests in parallel
/// within a process, so a second test touching the same env var would race.
#[test]
fn allowlist_env_var_opts_host_out_of_private_ip_check() {
    // Loopback literal is rejected by default.
    std::env::remove_var("CALRS_ALLOW_PRIVATE_HOSTS");
    assert!(private_host_allowlist().is_empty());
    assert!(validate_caldav_url("http://127.0.0.1:5232").is_err());

    // ...but allowed once its host is on the allowlist.
    std::env::set_var("CALRS_ALLOW_PRIVATE_HOSTS", " 127.0.0.1 , radicale ");
    assert_eq!(private_host_allowlist(), vec!["127.0.0.1", "radicale"]);
    assert!(validate_caldav_url("http://127.0.0.1:5232").is_ok());

    // Non-http schemes are still rejected even when host is allowlisted.
    assert!(validate_caldav_url("ftp://127.0.0.1:5232").is_err());

    // A host not on the allowlist still gets the private-IP check.
    assert!(validate_caldav_url("http://10.0.0.1").is_err());

    std::env::remove_var("CALRS_ALLOW_PRIVATE_HOSTS");
}
