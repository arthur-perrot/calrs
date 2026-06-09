use super::*;

#[test]
fn parse_modern_autodiscover_response() {
    let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">
  <Response xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
<Account>
  <Protocol>
    <Type>EXCH</Type>
    <EwsUrl>https://mail.example.com/EWS/Exchange.asmx</EwsUrl>
    <EmwsUrl>https://mail.example.com/EWS/Exchange.asmx</EmwsUrl>
  </Protocol>
</Account>
  </Response>
</Autodiscover>"#;
    assert_eq!(
        parse_pox_response(xml),
        Some("https://mail.example.com/EWS/Exchange.asmx".to_string())
    );
}

#[test]
fn fallback_to_asurl() {
    let xml = r#"<Response><Action><Settings>
        <ASUrl>https://mail.example.com/Microsoft-Server-ActiveSync</ASUrl>
    </Settings></Action></Response>"#;
    assert_eq!(
        parse_pox_response(xml),
        Some("https://mail.example.com/EWS/Exchange.asmx".to_string())
    );
}

#[test]
fn no_match_returns_none() {
    let xml = "<Autodiscover><Response><Error>NotFound</Error></Response></Autodiscover>";
    assert_eq!(parse_pox_response(xml), None);
}

#[test]
fn conventional_url_format() {
    assert_eq!(
        conventional_ews_url("mail.example.com"),
        "https://mail.example.com/EWS/Exchange.asmx",
    );
}
