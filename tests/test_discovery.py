"""Provider settings discovery (offline parts)."""

from __future__ import annotations

from mail_mcp.discovery import parse_autoconfig, preset_for

AUTOCONFIG_XML = """<?xml version="1.0"?>
<clientConfig version="1.1">
  <emailProvider id="example.test">
    <displayName>Example Mail</displayName>
    <incomingServer type="pop3">
      <hostname>pop.example.test</hostname><port>995</port>
      <socketType>SSL</socketType><authentication>password-cleartext</authentication>
    </incomingServer>
    <incomingServer type="imap">
      <hostname>imap.example.test</hostname><port>993</port>
      <socketType>SSL</socketType><username>%EMAILADDRESS%</username>
    </incomingServer>
    <outgoingServer type="smtp">
      <hostname>smtp.example.test</hostname><port>587</port>
      <socketType>STARTTLS</socketType><username>%EMAILADDRESS%</username>
    </outgoingServer>
  </emailProvider>
</clientConfig>
"""


def test_imap_is_preferred_over_pop3():
    settings = parse_autoconfig(AUTOCONFIG_XML, source="ispdb")
    assert settings.imap_host == "imap.example.test"
    assert settings.imap_port == 993
    assert settings.imap_security == "ssl"
    assert settings.smtp_host == "smtp.example.test"
    assert settings.smtp_port == 587
    assert settings.smtp_security == "starttls"
    assert settings.provider_name == "Example Mail"
    assert settings.source == "ispdb"


def test_pop3_only_provider_yields_nothing():
    xml = AUTOCONFIG_XML.replace('type="imap"', 'type="pop3"')
    assert parse_autoconfig(xml) is None


def test_local_part_username_is_reported():
    xml = AUTOCONFIG_XML.replace(
        "<username>%EMAILADDRESS%</username>\n    </incomingServer>",
        "<username>%EMAILLOCALPART%</username>\n    </incomingServer>",
    )
    assert parse_autoconfig(xml).username_is_address is False


def test_broken_xml_is_not_fatal():
    assert parse_autoconfig("<not xml") is None


def test_presets_are_copies_and_carry_guidance():
    preset = preset_for("gmail.com")
    assert preset.imap_host == "imap.gmail.com"
    assert preset.source == "preset"
    assert any("App Password" in note for note in preset.notes)

    preset.imap_host = "changed"
    assert preset_for("gmail.com").imap_host == "imap.gmail.com"
    assert preset_for("unknown-domain.test") is None
