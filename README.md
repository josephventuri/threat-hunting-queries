# Threat Hunting Queries

SIEM queries and detection notes for finding malicious activity. Each write-up covers the threat, its MITRE ATT&CK mapping, the detection logic, queries, likely false positives, and what to investigate next.

## Contents

| Write-up | ATT&CK | Covers |
| --- | --- | --- |
| [Brute force detection](authentication/brute-force-detection.md) | T1110 | Password guessing, spraying, and failed-login spikes |

More write-ups will be added as I finish them.

## Using these

Field names and thresholds vary between environments. Adjust time ranges, field names, and thresholds to match your data, and test on a small scope before running anything broadly.
