"""MITRE ATT&CK reference data (Enterprise matrix).

Only what the platform needs: every tactic, and names for the techniques
the built-in rules map to. Unknown technique IDs are still accepted in
rules; they are just shown without a name.
"""

from __future__ import annotations

# Ordered as in the ATT&CK Enterprise matrix.
TACTICS: dict[str, str] = {
    "TA0043": "Reconnaissance",
    "TA0042": "Resource Development",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0011": "Command and Control",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
}

# Sigma writes tactics as tags such as "attack.credential_access".
TACTIC_IDS_BY_TAG: dict[str, str] = {
    name.lower().replace(" ", "_"): tactic_id for tactic_id, name in TACTICS.items()
}

TECHNIQUES: dict[str, str] = {
    "T1003.001": "OS Credential Dumping: LSASS Memory",
    "T1003.008": "OS Credential Dumping: /etc/passwd and /etc/shadow",
    "T1021.004": "Remote Services: SSH",
    "T1027": "Obfuscated Files or Information",
    "T1053.005": "Scheduled Task/Job: Scheduled Task",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1070.001": "Indicator Removal: Clear Windows Event Logs",
    "T1078": "Valid Accounts",
    "T1083": "File and Directory Discovery",
    "T1098": "Account Manipulation",
    "T1110": "Brute Force",
    "T1110.001": "Brute Force: Password Guessing",
    "T1110.003": "Brute Force: Password Spraying",
    "T1136.001": "Create Account: Local Account",
    "T1190": "Exploit Public-Facing Application",
    "T1204.002": "User Execution: Malicious File",
    "T1547.001": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
    "T1548.003": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
    "T1566.001": "Phishing: Spearphishing Attachment",
    "T1595.002": "Active Scanning: Vulnerability Scanning",
    "T1595.003": "Active Scanning: Wordlist Scanning",
}


# The tactics each technique above serves, as listed in ATT&CK.
TECHNIQUE_TACTICS: dict[str, tuple[str, ...]] = {
    "T1003.001": ("TA0006",),
    "T1003.008": ("TA0006",),
    "T1021.004": ("TA0008",),
    "T1027": ("TA0005",),
    "T1053.005": ("TA0002", "TA0003", "TA0004"),
    "T1059.001": ("TA0002",),
    "T1070.001": ("TA0005",),
    "T1078": ("TA0001", "TA0003", "TA0004", "TA0005"),
    "T1083": ("TA0007",),
    "T1098": ("TA0003", "TA0004"),
    "T1110": ("TA0006",),
    "T1110.001": ("TA0006",),
    "T1110.003": ("TA0006",),
    "T1136.001": ("TA0003",),
    "T1190": ("TA0001",),
    "T1204.002": ("TA0002",),
    "T1547.001": ("TA0003", "TA0004"),
    "T1548.003": ("TA0004", "TA0005"),
    "T1566.001": ("TA0001",),
    "T1595.002": ("TA0043",),
    "T1595.003": ("TA0043",),
}


def technique_name(technique_id: str) -> str | None:
    """Name of a technique, falling back to its parent for unknown sub-techniques."""
    return TECHNIQUES.get(technique_id) or TECHNIQUES.get(technique_id.split(".", 1)[0])


def technique_tactics(technique_id: str) -> tuple[str, ...]:
    """Tactics of a technique (or its parent), empty when it is not in the reference data."""
    return TECHNIQUE_TACTICS.get(technique_id) or TECHNIQUE_TACTICS.get(
        technique_id.split(".", 1)[0], ()
    )
