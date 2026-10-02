# Lab 02 — Remote RDP Brute-Force Investigation

## Objective

The objective of this lab was to investigate suspicious remote authentication activity against a Windows endpoint using Splunk.

The lab simulates multiple failed RDP authentication attempts against a Windows user account followed by a successful authentication.

The investigation was performed from the perspective of a SOC Analyst L1.

---

## Lab Environment

| System | Role | IP Address |
|---|---|---|
| Kali Linux | Attack simulation | 192.168.8.131 |
| Windows 11 Pro — SOC-WIN11 | Target endpoint | 192.168.8.132 |
| Ubuntu Server — SOC-SIEM | Splunk SIEM | 192.168.8.136 |

Windows Security Events were collected from `SOC-WIN11` using the Splunk Universal Forwarder and sent to the Splunk server.

---

## Scenario

A Windows user account named `ayman` received multiple remote authentication attempts from the same source IP address.

The activity consisted of:

- 10 failed authentication attempts
- Same source IP address
- Same target account
- Attempts occurring within a short period
- Successful authentication shortly after the failed attempts

The purpose of the SOC investigation was to determine whether the activity represented normal user behavior or suspicious authentication activity requiring escalation.

---

## Attack Simulation

The authentication attempts were generated from the Kali Linux machine against the Windows endpoint using RDP.

The test was performed only inside an isolated and authorized VMware lab environment.

### Evidence — Brute-Force Simulation

![RDP Brute-Force Simulation] #Attached in Lab 02 Remote RDP brute force Investigation

The simulation generated repeated authentication attempts against the `ayman` account. After multiple incorrect password attempts, a valid credential was accepted.

---

## Investigation

### Step 1 — Review Failed Authentication Events

Windows records failed authentication attempts using:

**Event ID 4625 — An account failed to log on**

The Splunk search used to review failed authentication events was:

```spl
index=windows EventCode=4625
```

This confirmed that multiple failed authentication events were being recorded by `SOC-WIN11`.

---

### Step 2 — Identify the Source

The failed authentication events showed the following source:

```text
Source IP: 192.168.8.131
Target User: ayman
Target Host: SOC-WIN11
Logon Type: 3
```

The same source IP repeatedly attempted authentication against the same account within a short period.

---

### Step 3 — Correlate Failed and Successful Authentication

To view both failed and successful authentication events from the source, the following SPL search was used:

```spl
index=windows (EventCode=4625 OR EventCode=4624) IpAddress="192.168.8.131"
| table _time EventCode TargetUserName IpAddress LogonType host
| sort _time
```

Where:

- `4625` = failed authentication
- `4624` = successful authentication
- `table` displays the relevant investigation fields
- `sort _time` arranges the events chronologically

### Evidence — Splunk Authentication Events

![Splunk Authentication Events](screenshots/02-splunk-authentication-events.png)

The logs showed approximately the following sequence:

```text
4625 → Failed Authentication
4625 → Failed Authentication
4625 → Failed Authentication
4625 → Failed Authentication
4625 → Failed Authentication
4625 → Failed Authentication
4625 → Failed Authentication
4625 → Failed Authentication
4625 → Failed Authentication
4625 → Failed Authentication
4624 → Successful Authentication
```

A total of **10 failed authentication attempts** were observed, followed shortly by a **successful authentication** from the same source IP.

---

## Event Analysis

The investigation identified the following indicators:

| Indicator | Observation |
|---|---|
| Source IP | 192.168.8.131 |
| Target Account | ayman |
| Target Host | SOC-WIN11 |
| Failed Event | Windows Event ID 4625 |
| Successful Event | Windows Event ID 4624 |
| Failed Attempts | 10 |
| Logon Type | 3 — Network Logon |
| Pattern | Multiple failures followed by successful authentication |

The repeated failures from a single remote source followed by successful authentication are consistent with password-guessing activity.

It is important to note that Event ID 4624 with Logon Type 3 confirms successful network authentication. By itself, it does not prove that an interactive RDP desktop session was established. In this controlled lab, the attack-side evidence confirms that a valid credential was eventually accepted during the RDP authentication testing.

---

## SOC Analyst Assessment

### Classification

**True Positive — Suspicious Authentication Activity / Possible Account Compromise**

### Severity

**High**

### Escalation

**Yes**

The activity should be escalated because:

1. Multiple authentication failures originated from the same remote source.
2. The same account was repeatedly targeted.
3. The attempts occurred within a short period.
4. Successful authentication occurred shortly after the failed attempts.

In a real SOC environment, the analyst should verify whether the source IP and authentication activity are authorized before concluding that the account has been compromised.

---

## SOC L1 Response

As a SOC Analyst L1, the appropriate response would include:

- Document the source IP, target account, hostname, timestamps, and relevant Event IDs.
- Verify whether the source IP belongs to an expected or authorized system.
- Check whether the account owner recognizes the authentication activity according to the organization's procedure.
- Review surrounding authentication events for additional suspicious activity.
- Preserve the relevant evidence.
- Escalate the incident for further investigation.

Any containment action such as disabling the account, resetting credentials, or blocking the source IP should follow the organization's incident-response procedures and authorization requirements.

---

## MITRE ATT&CK Mapping

**T1110 — Brute Force**

**T1110.001 — Password Guessing**

The activity involved repeated password attempts against the same user account until valid authentication was achieved.

---

## Final Verdict

```text
Classification : True Positive — Suspicious Authentication Activity
Severity       : High
Affected User  : ayman
Affected Host  : SOC-WIN11
Source IP      : 192.168.8.131
Failed Logons  : 10
Successful Auth: Yes
Escalation     : Yes
MITRE ATT&CK   : T1110.001 — Password Guessing
```

The alert should **not be closed as benign** without further investigation because successful authentication occurred after repeated failed attempts from the same remote source.

---

## Skills Demonstrated

This lab demonstrates basic SOC Analyst L1 skills including:

- Windows Security Event investigation
- Event ID 4625 analysis
- Event ID 4624 analysis
- Basic Splunk SPL searching
- Authentication log correlation
- Source IP identification
- Brute-force pattern recognition
- True-positive classification
- Incident severity assessment
- SOC escalation procedures
- MITRE ATT&CK mapping

---

## Lab Conclusion

This lab demonstrated how a SOC Analyst can identify and investigate a remote password-guessing pattern using Windows Security Events and Splunk.

The key indicator was not simply the presence of failed logins, but the combination of **multiple failed authentication attempts from the same source followed by successful authentication**.

From an L1 SOC perspective, this pattern warrants documentation and escalation for further investigation.
