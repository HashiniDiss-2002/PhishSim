"""
attack_mapping.py
--------------------
Maps a campaign's observed delivery characteristics to the real MITRE
ATT&CK® techniques it demonstrates, under the Initial Access tactic's
"Phishing" technique (T1566): https://attack.mitre.org/techniques/T1566/

This exists to ground the platform's generated content in a published,
industry-standard framework rather than leaving it as "an LLM wrote an
email" — every campaign is tagged with the specific, citable technique
ID(s) it exercises, shown on the campaign dashboard and in the downloadable
compliance report, exactly the same way a real red-team/purple-team
engagement report would reference ATT&CK technique IDs.

Only two sub-techniques are relevant to what this platform actually does
(it never delivers a real executable or macro — see tracking.py's
explicit limitation note on attachment tracking), and the mapping is
intentionally a simple, documented table rather than anything
LLM-derived, so it can be defended in a viva on its own terms.
"""

ATTACK_TECHNIQUES = {
    "T1566.002": {
        "id": "T1566.002",
        "name": "Phishing: Spearphishing Link",
        "url": "https://attack.mitre.org/techniques/T1566/002/",
        "description": (
            "Delivery via a malicious/tracked hyperlink embedded in the email "
            "body, used here to measure click-through and credential-submission "
            "behaviour. Present in every campaign this platform generates."
        ),
    },
    "T1566.001": {
        "id": "T1566.001",
        "name": "Phishing: Spearphishing Attachment",
        "url": "https://attack.mitre.org/techniques/T1566/001/",
        "description": (
            "Delivery via a reference to a malicious attachment. Simulated only — "
            "see tracking.py's track_download(): no executable, macro, or real "
            "document content is ever present, only a disclosure text file."
        ),
    },
}


def get_campaign_attack_techniques(has_any_attachment: bool) -> list:
    """
    has_any_attachment: True if at least one employee's generated email in
    this campaign included an attachment element (campaign_emails.has_attachment).

    Every campaign uses a tracked link (T1566.002) — that's the platform's
    baseline delivery mechanism. T1566.001 is added on top of that only
    when at least one recipient's pretext included a (simulated) attachment.
    """
    techniques = [ATTACK_TECHNIQUES["T1566.002"]]
    if has_any_attachment:
        techniques.append(ATTACK_TECHNIQUES["T1566.001"])
    return techniques
