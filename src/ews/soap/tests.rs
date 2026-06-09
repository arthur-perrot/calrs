use super::*;

#[test]
fn extract_simple_tag_content() {
    let xml = "<m:ResponseCode>NoError</m:ResponseCode>";
    assert_eq!(
        first_tag_content(xml, "ResponseCode"),
        Some("NoError".to_string())
    );
}

#[test]
fn extract_with_attributes() {
    let xml = r#"<t:Body BodyType="HTML">hello</t:Body>"#;
    assert_eq!(first_tag_content(xml, "Body"), Some("hello".to_string()));
}

#[test]
fn extract_returns_none_for_self_closing() {
    let xml = r#"<t:ItemId Id="AAA" ChangeKey="BBB" />"#;
    // Self-closing tags have no content, so no match.
    assert_eq!(first_tag_content(xml, "ItemId"), None);
}

#[test]
fn fault_detection() {
    let xml = "<soap:Fault><faultstring>auth required</faultstring></soap:Fault>";
    assert_eq!(extract_soap_fault(xml), Some("auth required".to_string()));
}

#[test]
fn fault_from_response_code() {
    let xml = "<m:ResponseCode>ErrorAccessDenied</m:ResponseCode><m:MessageText>Access is denied.</m:MessageText>";
    assert_eq!(
        extract_soap_fault(xml),
        Some("ErrorAccessDenied: Access is denied.".to_string())
    );
}

#[test]
fn fault_no_error_returns_none() {
    let xml = "<m:ResponseCode>NoError</m:ResponseCode>";
    assert_eq!(extract_soap_fault(xml), None);
}

#[test]
fn collect_blocks_returns_each_record() {
    let xml = r#"<m:Items>
        <t:CalendarItem><t:Subject>One</t:Subject></t:CalendarItem>
        <t:CalendarItem><t:Subject>Two</t:Subject></t:CalendarItem>
    </m:Items>"#;
    let blocks = collect_blocks(xml, "CalendarItem");
    assert_eq!(blocks.len(), 2);
    assert!(blocks[0].contains("One"));
    assert!(blocks[1].contains("Two"));
}

#[test]
fn attr_extracts_value() {
    let tag = r#"<t:ItemId Id="AAAB" ChangeKey="CK1"/>"#;
    assert_eq!(attr(tag, "Id"), Some("AAAB".to_string()));
    assert_eq!(attr(tag, "ChangeKey"), Some("CK1".to_string()));
    assert_eq!(attr(tag, "Missing"), None);
}

#[test]
fn escape_special_chars() {
    assert_eq!(escape("a & b < c"), "a &amp; b &lt; c");
}

#[test]
fn unescape_roundtrip() {
    let original = "a & b < c > d";
    assert_eq!(unescape(&escape(original)), original);
}
