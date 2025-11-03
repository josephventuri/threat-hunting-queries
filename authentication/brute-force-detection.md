# Brute Force Attack Detection

## Threat Description

Brute force attacks involve repeated authentication attempts with different passwords to gain unauthorized access to accounts. Attackers may target single accounts, multiple accounts, or use distributed sources to avoid detection.

**Attack Patterns:**
- Multiple failed login attempts from single source to single account
- Multiple failed attempts from single source to multiple accounts
- Distributed attacks from multiple IPs (credential stuffing)
- Slow brute force (low-and-slow to evade rate limiting)

## MITRE ATT&CK Mapping

- **T1110** - Brute Force
  - T1110.001 - Password Guessing
  - T1110.002 - Password Cracking
  - T1110.003 - Password Spraying

## Detection Logic

**High Confidence Indicators:**
- 10+ failed login attempts to single account within 5 minutes
- 20+ failed login attempts from single IP within 10 minutes
- Failed attempts followed by successful login from same source
- Multiple accounts with same failure pattern from single IP

**Medium Confidence Indicators:**
- Elevated failed login rate compared to baseline
- Failed attempts outside normal business hours
- Failed attempts from unusual geographic locations
- Sequential username attempts (user1, user2, user3...)

## Query Code

### KQL (Azure Sentinel / Microsoft 365)

```kql
// Detect multiple failed login attempts from single IP
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != "0" // Non-successful logins
| summarize
    FailedAttempts = count(),
    TargetedAccounts = dcount(UserPrincipalName),
    AccountList = make_set(UserPrincipalName),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by IPAddress, Location
| where FailedAttempts >= 10
| extend Duration = LastAttempt - FirstAttempt
| project
    IPAddress,
    Location,
    FailedAttempts,
    TargetedAccounts,
    AccountList,
    FirstAttempt,
    LastAttempt,
    Duration
| order by FailedAttempts desc
```

```kql
// Detect failed attempts followed by successful login (potential compromise)
let timeframe = 1h;
let threshold = 5;
let FailedLogins = SigninLogs
    | where TimeGenerated > ago(timeframe)
    | where ResultType != "0"
    | project TimeGenerated, UserPrincipalName, IPAddress, ResultType, Location;
let SuccessfulLogins = SigninLogs
    | where TimeGenerated > ago(timeframe)
    | where ResultType == "0"
    | project TimeGenerated, UserPrincipalName, IPAddress, Location;
FailedLogins
| summarize
    FailedAttempts = count(),
    FirstFailed = min(TimeGenerated)
    by UserPrincipalName, IPAddress
| where FailedAttempts >= threshold
| join kind=inner (
    SuccessfulLogins
    | project SuccessTime = TimeGenerated, UserPrincipalName, SuccessIP = IPAddress, SuccessLocation = Location
) on UserPrincipalName
| where SuccessTime > FirstFailed
| where IPAddress == SuccessIP
| project
    UserPrincipalName,
    IPAddress,
    FailedAttempts,
    FirstFailed,
    SuccessTime,
    TimeDifference = SuccessTime - FirstFailed,
    SuccessLocation
```

### SPL (Splunk)

```spl
# Failed login attempts by source IP
index=windows EventCode=4625
| bin _time span=5m
| stats
    count as FailedAttempts,
    dc(TargetUserName) as UniqueAccounts,
    values(TargetUserName) as AccountList,
    min(_time) as FirstAttempt,
    max(_time) as LastAttempt
    by IpAddress, _time
| where FailedAttempts >= 10
| eval Duration = LastAttempt - FirstAttempt
| table IpAddress, FailedAttempts, UniqueAccounts, AccountList, FirstAttempt, LastAttempt, Duration
| sort - FailedAttempts
```

```spl
# Failed attempts followed by success (same IP)
index=windows (EventCode=4625 OR EventCode=4624)
| transaction TargetUserName, IpAddress maxspan=10m
| where eventcount > 1
| search EventCode=4625 EventCode=4624
| eval failed_count = mvcount(mvfilter(match(EventCode, "4625")))
| eval success_count = mvcount(mvfilter(match(EventCode, "4624")))
| where failed_count >= 5 AND success_count >= 1
| table _time, TargetUserName, IpAddress, failed_count, success_count, EventCode
```

### Generic SQL

```sql
-- Failed login attempts by IP address (adjust for your schema)
SELECT
    source_ip,
    COUNT(*) as failed_attempts,
    COUNT(DISTINCT username) as unique_accounts,
    MIN(timestamp) as first_attempt,
    MAX(timestamp) as last_attempt,
    TIMESTAMPDIFF(MINUTE, MIN(timestamp), MAX(timestamp)) as duration_minutes
FROM authentication_logs
WHERE
    timestamp > DATE_SUB(NOW(), INTERVAL 1 HOUR)
    AND auth_result = 'failed'
GROUP BY source_ip
HAVING failed_attempts >= 10
ORDER BY failed_attempts DESC;
```

## Expected Results

**High Priority Alerts:**
- 20+ failed attempts within 5 minutes
- Failed attempts followed by success from same IP
- Failed attempts to multiple privileged accounts
- Failed attempts from known malicious IPs

**Investigation Required:**
- 10-20 failed attempts (may be legitimate user)
- Failed attempts from new geographic location
- Pattern matching automated attack tools

## False Positives

**Common Benign Causes:**
- Users with incorrect password/expired credentials
- Automated services with wrong credentials
- VPN or proxy IP addresses aggregating multiple users
- SSO integration issues
- Mobile devices with cached incorrect passwords
- Development/test environment authentication

**Reducing False Positives:**
```kql
// Exclude known service accounts
| where UserPrincipalName !has "svc-"
| where UserPrincipalName !has "service"

// Exclude internal automation IPs
| where IPAddress !in ("10.1.2.3", "10.1.2.4")

// Exclude specific error codes (expired password)
| where ResultType !in ("50055", "50056") // Azure AD expired password codes
```

## Investigation Steps

**Initial Triage:**
1. Check if IP is known malicious (threat intel lookup)
2. Review geolocation of source IP
3. Identify targeted accounts (privileged users?)
4. Check for successful logins from same source
5. Review timing pattern (automated vs manual)

**If Successful Login Detected:**
1. Immediately notify account owner
2. Review account activity post-authentication
3. Check for:
   - Data access
   - Configuration changes
   - Lateral movement
   - Persistence mechanisms
4. Force password reset
5. Revoke active sessions

**For Failed Attempts Only:**
1. Monitor for continued attempts
2. Block IP at firewall if confirmed malicious
3. Notify user if targeting specific account
4. Consider MFA enforcement
5. Document for pattern analysis

## Remediation Actions

**Immediate:**
- Block source IP at firewall/WAF if malicious
- Force password reset for compromised accounts
- Revoke all active sessions
- Enable MFA if not already enforced
- Isolate affected systems if compromise confirmed

**Short-term:**
- Implement account lockout policies
- Deploy rate limiting on authentication endpoints
- Enable CAPTCHA after threshold failures
- Configure alerts for future attempts
- Document incident and lessons learned

**Long-term:**
- Enforce MFA across all accounts
- Implement adaptive authentication (risk-based)
- Deploy password manager for users
- Regular password policy review
- User awareness training
- Consider passwordless authentication

## Advanced Detection

**Correlation Rules:**
```kql
// Detect distributed brute force (same user, multiple IPs)
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != "0"
| summarize
    SourceIPs = dcount(IPAddress),
    FailedAttempts = count(),
    IPList = make_set(IPAddress)
    by UserPrincipalName, bin(TimeGenerated, 5m)
| where SourceIPs >= 5 and FailedAttempts >= 20
| project TimeGenerated, UserPrincipalName, SourceIPs, FailedAttempts, IPList
```

**Slow Brute Force Detection:**
```kql
// Detect low-and-slow brute force over longer period
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != "0"
| summarize
    FailedAttempts = count(),
    HoursSeen = dcount(bin(TimeGenerated, 1h))
    by IPAddress, UserPrincipalName
| where FailedAttempts >= 50 and HoursSeen >= 12
| order by FailedAttempts desc
```

## Metrics and Tuning

**Baseline Establishment:**
- Average failed logins per hour
- Peak failed login times
- Common failure reasons
- Expected rate from VPN/proxy IPs

**Tuning Thresholds:**
- Start conservative (higher threshold)
- Monitor false positive rate
- Adjust based on environment size
- Consider different thresholds for privileged accounts

**Alert Fatigue Prevention:**
- Aggregate related attempts
- Suppress known false positives
- Prioritize by account criticality
- Daily summary for low-priority events

## References

- MITRE ATT&CK T1110: https://attack.mitre.org/techniques/T1110/
- NIST SP 800-63B: Digital Identity Guidelines
- OWASP Authentication Cheat Sheet
