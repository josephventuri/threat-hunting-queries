# Threat Hunting Queries

A collection of SIEM queries, detection rules, and threat hunting techniques for identifying malicious activity in enterprise environments.

## Overview

This repository contains practical threat hunting queries and detection logic developed from real-world SOC operations. Queries are organized by threat category and include context for when and why to use them.

## Query Categories

### Authentication and Access
- Brute force attempts
- Password spraying
- Unusual login patterns
- Privileged account usage
- Failed authentication spikes
- Lateral movement via authentication

### Malware and Execution
- Suspicious process execution
- Malware persistence mechanisms
- Living-off-the-land binaries (LOLBins)
- PowerShell obfuscation
- Suspicious command-line arguments
- Unsigned or rare executables

### Network Activity
- Command and control (C2) communication
- DNS tunneling
- Unusual outbound connections
- Port scanning behavior
- Data exfiltration patterns
- Tor or VPN usage

### Data Access and Exfiltration
- Large file transfers
- Unusual data access patterns
- Sensitive file access
- Cloud storage uploads
- Email forwarding rules
- USB device usage

### Endpoint Security
- Disabled security tools
- Suspicious service creation
- Registry persistence
- Scheduled task anomalies
- DLL hijacking indicators
- Credential dumping activity

### Web and Email Threats
- Phishing indicators
- Web shell detection
- SQL injection attempts
- XSS attack patterns
- Malicious file downloads
- Suspicious user agents

## Query Formats

Queries are provided in multiple formats where applicable:
- **KQL (Kusto Query Language)** - Azure Sentinel, Microsoft 365 Defender
- **SPL (Search Processing Language)** - Splunk
- **Generic SQL** - Adaptable to various SIEMs
- **Elastic Query DSL** - Elastic Security

## Usage Guidelines

**Before Running Queries:**
1. Understand the query logic and expected results
2. Adjust time ranges based on your environment
3. Modify field names to match your data sources
4. Test in limited scope before broad deployment
5. Consider performance impact on SIEM

**Query Customization:**
- Adjust thresholds based on baseline activity
- Add environment-specific exclusions
- Filter out known benign sources
- Tune for your organization's risk tolerance

**Detection Engineering:**
- Start with hypothesis about threat behavior
- Map to MITRE ATT&CK techniques
- Test with known-good and known-bad data
- Monitor for false positives
- Refine based on analyst feedback

## MITRE ATT&CK Mapping

Queries are tagged with relevant MITRE ATT&CK techniques:
- Initial Access
- Execution
- Persistence
- Privilege Escalation
- Defense Evasion
- Credential Access
- Discovery
- Lateral Movement
- Collection
- Exfiltration
- Command and Control

## Repository Structure

```
threat-hunting-queries/
├── authentication/
│   ├── brute-force-detection.md
│   ├── password-spraying.md
│   └── suspicious-login-patterns.md
├── malware/
│   ├── suspicious-process-execution.md
│   ├── persistence-mechanisms.md
│   └── lolbin-usage.md
├── network/
│   ├── c2-detection.md
│   ├── dns-tunneling.md
│   └── unusual-outbound.md
├── data-exfiltration/
│   ├── large-transfers.md
│   └── cloud-uploads.md
└── endpoint/
    ├── security-tool-tampering.md
    └── credential-dumping.md
```

## Example Query Format

Each query file includes:
- **Threat Description** - What you're hunting for
- **MITRE ATT&CK Mapping** - Relevant techniques
- **Detection Logic** - How the query works
- **Query Code** - Multiple SIEM formats
- **Expected Results** - What to look for
- **False Positives** - Common benign causes
- **Investigation Steps** - Next actions if triggered
- **Remediation** - How to respond

## Hunting Methodologies

**Hypothesis-Driven Hunting:**
1. Form hypothesis about attacker behavior
2. Identify data sources needed
3. Create queries to test hypothesis
4. Analyze results and refine
5. Document findings

**Baseline-Driven Hunting:**
1. Establish normal baseline activity
2. Hunt for deviations from baseline
3. Investigate anomalies
4. Create detections for confirmed threats

**Indicator-Driven Hunting:**
1. Start with known IOCs or TTPs
2. Search for indicators in your environment
3. Pivot to related activity
4. Uncover additional compromise

## Data Sources

Common log sources for threat hunting:
- Windows Event Logs (Security, System, Application)
- Sysmon events
- EDR/XDR telemetry
- Firewall and proxy logs
- DNS query logs
- Authentication logs (AD, VPN, cloud services)
- Email security logs
- Cloud platform logs (Azure, AWS, GCP)

## Performance Considerations

**Query Optimization:**
- Use time ranges to limit data volume
- Index commonly searched fields
- Avoid wildcards at beginning of strings
- Use summary/stats commands when possible
- Test with small time windows first

**SIEM Best Practices:**
- Schedule resource-intensive hunts during off-peak hours
- Use saved searches for recurring hunts
- Archive and document successful hunts
- Share findings with team

## Contributing

Contributions welcome. Please include:
- Clear description of threat being detected
- MITRE ATT&CK mapping
- At least one working query format
- Expected false positive rate
- Investigation guidance

## Resources

**Threat Intelligence:**
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Sigma Rules](https://github.com/SigmaHQ/sigma)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)

**Detection Engineering:**
- [Splunk Security Content](https://github.com/splunk/security_content)
- [Elastic Detection Rules](https://github.com/elastic/detection-rules)
- [Microsoft Sentinel Rules](https://github.com/Azure/Azure-Sentinel)

**Hunting Frameworks:**
- [TaHiTI](https://www.betaalvereniging.nl/en/safety/tahiti/) - Threat Hunting Methodology
- [PEAK Threat Hunting Framework](https://www.sans.org/webcasts/peak-threat-hunting-framework/)

## Disclaimer

These queries are for authorized security operations only. Always:
- Follow your organization's data handling policies
- Obtain proper authorization before hunting
- Respect privacy and legal requirements
- Document all hunting activities
- Use findings responsibly

## License

MIT License - Adapt for your organization's needs.
