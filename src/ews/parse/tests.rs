use super::*;

#[test]
fn parses_find_folder_response() {
    let xml = r#"<m:FindFolderResponseMessage>
  <m:RootFolder TotalItemsInView="1">
<t:Folders>
  <t:CalendarFolder>
    <t:FolderId Id="AAMkADUw" ChangeKey="CK1" />
    <t:DisplayName>Calendar</t:DisplayName>
  </t:CalendarFolder>
  <t:CalendarFolder>
    <t:FolderId Id="AAMkADUx" />
    <t:DisplayName>Birthdays</t:DisplayName>
  </t:CalendarFolder>
</t:Folders>
  </m:RootFolder>
</m:FindFolderResponseMessage>"#;
    let folders = parse_find_folder_response(xml).unwrap();
    assert_eq!(folders.len(), 2);
    assert_eq!(folders[0].id, "AAMkADUw");
    assert_eq!(folders[0].change_key, Some("CK1".into()));
    assert_eq!(folders[0].display_name.as_deref(), Some("Calendar"));
    assert_eq!(folders[1].id, "AAMkADUx");
    assert_eq!(folders[1].display_name.as_deref(), Some("Birthdays"));
}

#[test]
fn parses_find_item_calendar_view() {
    let xml = r#"<m:FindItemResponseMessage>
  <m:RootFolder TotalItemsInView="2" IncludesLastItemInRange="true">
<t:Items>
  <t:CalendarItem>
    <t:ItemId Id="AB1" ChangeKey="CK1" />
    <t:Subject>Sync sync</t:Subject>
    <t:Start>2026-05-06T09:00:00Z</t:Start>
    <t:End>2026-05-06T09:30:00Z</t:End>
    <t:Location>Room 1</t:Location>
    <t:IsAllDayEvent>false</t:IsAllDayEvent>
    <t:IsCancelled>false</t:IsCancelled>
    <t:LegacyFreeBusyStatus>Busy</t:LegacyFreeBusyStatus>
    <t:UID>uid-1</t:UID>
  </t:CalendarItem>
  <t:CalendarItem>
    <t:ItemId Id="AB2" />
    <t:Subject>All-day off</t:Subject>
    <t:Start>2026-05-08T00:00:00Z</t:Start>
    <t:End>2026-05-09T00:00:00Z</t:End>
    <t:IsAllDayEvent>true</t:IsAllDayEvent>
    <t:LegacyFreeBusyStatus>OOF</t:LegacyFreeBusyStatus>
    <t:UID>uid-2</t:UID>
  </t:CalendarItem>
</t:Items>
  </m:RootFolder>
</m:FindItemResponseMessage>"#;
    let page = parse_calendar_items_response(xml).unwrap();
    assert_eq!(page.total, Some(2));
    assert_eq!(page.items.len(), 2);
    assert_eq!(page.items[0].item_id, "AB1");
    assert_eq!(page.items[0].uid.as_deref(), Some("uid-1"));
    assert_eq!(page.items[0].subject.as_deref(), Some("Sync sync"));
    assert_eq!(page.items[0].start.as_deref(), Some("2026-05-06T09:00:00Z"));
    assert!(!page.items[0].is_all_day);
    assert!(page.items[1].is_all_day);
    assert_eq!(page.items[1].free_busy_status.as_deref(), Some("OOF"));
}

/// Regression: Exchange 2019 omits `<t:Recurrence>` on expanded occurrences
/// returned by `CalendarView`, signaling recurrence via `CalendarItemType`
/// instead. The parser must flag these as `has_recurrence=true` so that
/// `synth_vcalendar` emits a `RECURRENCE-ID` and the upsert keys siblings
/// uniquely.
#[test]
fn occurrence_calendar_item_type_marks_has_recurrence() {
    let xml = r#"<m:FindItemResponseMessage>
  <m:RootFolder TotalItemsInView="1">
<t:Items>
  <t:CalendarItem>
    <t:ItemId Id="OC1" />
    <t:Subject>Daily standup</t:Subject>
    <t:Start>2026-06-10T07:45:00Z</t:Start>
    <t:End>2026-06-10T08:00:00Z</t:End>
    <t:CalendarItemType>Occurrence</t:CalendarItemType>
    <t:IsAllDayEvent>false</t:IsAllDayEvent>
    <t:UID>shared-master-uid</t:UID>
  </t:CalendarItem>
</t:Items>
  </m:RootFolder>
</m:FindItemResponseMessage>"#;
    let page = parse_calendar_items_response(xml).unwrap();
    assert_eq!(page.items.len(), 1);
    assert!(
        page.items[0].has_recurrence,
        "Occurrence items must be flagged as recurring"
    );
}

#[test]
fn single_calendar_item_type_does_not_mark_has_recurrence() {
    let xml = r#"<m:FindItemResponseMessage>
  <m:RootFolder TotalItemsInView="1">
<t:Items>
  <t:CalendarItem>
    <t:ItemId Id="SI1" />
    <t:Subject>One-off</t:Subject>
    <t:Start>2026-06-10T09:00:00Z</t:Start>
    <t:End>2026-06-10T09:30:00Z</t:End>
    <t:CalendarItemType>Single</t:CalendarItemType>
    <t:IsAllDayEvent>false</t:IsAllDayEvent>
    <t:UID>standalone-uid</t:UID>
  </t:CalendarItem>
</t:Items>
  </m:RootFolder>
</m:FindItemResponseMessage>"#;
    let page = parse_calendar_items_response(xml).unwrap();
    assert!(!page.items[0].has_recurrence);
}

#[test]
fn parses_create_item_response_returns_id() {
    let xml = r#"<m:CreateItemResponseMessage>
  <m:Items>
<t:CalendarItem>
  <t:ItemId Id="NEW123" ChangeKey="CK99" />
</t:CalendarItem>
  </m:Items>
</m:CreateItemResponseMessage>"#;
    assert_eq!(parse_create_item_response(xml).unwrap(), "NEW123");
}

#[test]
fn extract_vcalendar_from_mime() {
    let mime = "MIME-Version: 1.0\r\nContent-Type: text/calendar\r\n\r\nBEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:abc@example.com\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
    let block = extract_vcalendar(mime).unwrap();
    assert!(block.starts_with("BEGIN:VCALENDAR"));
    assert!(block.ends_with("END:VCALENDAR"));
    assert!(block.contains("UID:abc@example.com"));
}

#[test]
fn parses_sync_delta_with_create_update_delete() {
    let xml = r#"<m:SyncFolderItemsResponseMessage>
  <m:SyncState>STATE2</m:SyncState>
  <m:IncludesLastItemInRange>true</m:IncludesLastItemInRange>
  <m:Changes>
<t:Create>
  <t:CalendarItem>
    <t:ItemId Id="N1" ChangeKey="CK1" />
    <t:UID>uid-new</t:UID>
  </t:CalendarItem>
</t:Create>
<t:Update>
  <t:CalendarItem>
    <t:ItemId Id="N2" ChangeKey="CK2" />
    <t:UID>uid-upd</t:UID>
  </t:CalendarItem>
</t:Update>
<t:Delete>
  <t:ItemId Id="GONE" />
</t:Delete>
  </m:Changes>
</m:SyncFolderItemsResponseMessage>"#;
    let d = parse_sync_folder_items_response(xml).unwrap();
    assert_eq!(d.new_sync_state.as_deref(), Some("STATE2"));
    assert!(d.includes_last);
    assert_eq!(d.added_or_changed.len(), 2);
    assert_eq!(d.added_or_changed[0].0, "N1");
    assert_eq!(d.added_or_changed[0].1, "uid-new");
    assert_eq!(d.deleted_item_ids, vec!["GONE"]);
}

#[test]
fn count_response_messages_works() {
    let xml = r#"<m:ResponseMessages>
        <m:Resp1><m:ResponseCode>NoError</m:ResponseCode></m:Resp1>
        <m:Resp2><m:ResponseCode>ErrorAccessDenied</m:ResponseCode></m:Resp2>
    </m:ResponseMessages>"#;
    assert_eq!(count_response_messages(xml), (1, 2));
}
