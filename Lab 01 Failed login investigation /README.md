# Lab 01 — Multiple Failed Windows Login Investigation

## Objective

The objective of this lab was to simulate and investigate multiple failed Windows authentication attempts using Splunk Enterprise.

The investigation focused on identifying the affected user and endpoint, analyzing the authentication failure reason, determining whether the activity originated locally or remotely, correlating the failed attempts with subsequent authentication activity, and making an appropriate SOC L1 triage decision.

---

## Lab Environment

The lab was built using the following components:

- **Hypervisor:** VMware Workstation
- **SIEM:** Splunk Enterprise
- **SIEM Server:** Ubuntu Server (`SOC-SIEM`)
- **Endpoint:** Windows 11 (`SOC-WIN11`)
- **Log Collector:** Splunk Universal Forwarder
- **Splunk Add-on:** Splunk Add-on for Microsoft Windows
- **Log Source:** Windows Security Event Log
- **Splunk Index:** `windows`
- **Test Account:** `ayman`

Windows Security logs were collected from `SOC-WIN11` using the Splunk Universal Forwarder and forwarded to the Splunk Enterprise server for analysis.

---

## Scenario

A Windows endpoint generated multiple failed authentication events for the local account `ayman`.

The simulated activity consisted of:

- 5 consecutive failed interactive logon attempts
- Followed by a successful interactive logon

The scenario was investigated from the perspective of a SOC L1 analyst to determine whether the authentication failures represented suspicious activity or normal user behavior.

---

## Alert Information

**Alert Type:** Multiple Failed Windows Logins

**Affected Host:** `SOC-WIN11`

**Affected User:** `ayman`

**Failed Logon Event ID:** `4625`

**Successful Logon Event ID:** `4624`

**Number of Failed Attempts:** 5

---

## Investigation

### 1. Initial Triage

The investigation began by searching the Windows Security logs in Splunk for failed authentication events:

```spl
index=windows EventCode=4625
```

Five Windows Event ID `4625` records were identified for the test account.

The events originated from the endpoint:

`SOC-WIN11`

The events were then examined to identify the account, authentication type, source, and reason for failure.

---

### 2. Authentication Analysis

Analysis of the failed authentication events identified the following important fields:

| Field | Value | Interpretation |
|---|---|---|
| Event ID | `4625` | Failed Windows logon |
| Target User | `ayman` | Account receiving the authentication attempts |
| Host | `SOC-WIN11` | Endpoint where authentication occurred |
| Logon Type | `2` | Interactive/local logon |
| Status | `0xC000006D` | Authentication failure |
| SubStatus | `0xC000006A` | Incorrect password |
| Source IP | `127.0.0.1` | Local loopback address |

The `LogonType=2` value indicated that the attempts were interactive logons occurring locally on the Windows endpoint.

The `0xC000006A` SubStatus provided additional context showing that the authentication failures occurred because an incorrect password was supplied.

The source address `127.0.0.1`, together with the interactive logon type, supported the conclusion that the attempts originated locally rather than from an external remote system.

---

### 3. Event Correlation

Failed and successful authentication events were correlated using:

```spl
index=windows (EventCode=4625 OR EventCode=4624) TargetUserName="ayman"
| table _time EventCode TargetUserName LogonType IpAddress Status SubStatus host
| sort _time
```

The resulting timeline showed five failed authentication attempts followed by a successful authentication for the same account.

The successful authentication event contained:

| Field | Value |
|---|---|
| Event ID | `4624` |
| Target User | `ayman` |
| Logon Type | `2` |
| Source IP | `127.0.0.1` |
| Host | `SOC-WIN11` |

Both the failed and successful authentication events therefore represented interactive activity involving the same user and endpoint.

The observed sequence was:

```text
4625 — Failed Logon — ayman
4625 — Failed Logon — ayman
4625 — Failed Logon — ayman
4625 — Failed Logon — ayman
4625 — Failed Logon — ayman
              ↓
4624 — Successful Logon — ayman
```

---

## Key Evidence

The investigation identified the following key evidence:

- Five consecutive failed authentication attempts occurred.
- All failures targeted the same account: `ayman`.
- All events occurred on the same endpoint: `SOC-WIN11`.
- The failed attempts used `LogonType 2`, indicating interactive/local authentication.
- Status `0xC000006D` confirmed authentication failure.
- SubStatus `0xC000006A` indicated an incorrect password.
- The source address was `127.0.0.1`.
- The failed attempts were followed by a successful `4624` interactive logon for the same account.
- No evidence of remote authentication attempts was identified during the investigation.

---

## Analysis

The authentication pattern was consistent with a legitimate local user entering an incorrect password multiple times before successfully authenticating.

Although the multiple failed authentication events correctly triggered investigation, the surrounding context did not indicate brute-force activity or unauthorized remote access.

The relatively small number of failures, single affected account, local interactive logon type, local source, and subsequent successful authentication all supported a benign explanation.

---

## Verdict

**Classification:** True Positive — Benign Activity

**Severity:** Low

**Escalation Required:** No

**Disposition:** Close Alert

The authentication failures genuinely occurred, meaning the underlying detection was valid. However, investigation determined that the activity was consistent with legitimate user error rather than malicious authentication activity.

---

## SOC Analyst Notes

Five Windows failed-logon events (Event ID `4625`) were identified on `SOC-WIN11` for the local account `ayman`.

Analysis showed `LogonType 2`, indicating interactive authentication. Status `0xC000006D` and SubStatus `0xC000006A` indicated authentication failure caused by an incorrect password.

The authentication attempts originated locally (`127.0.0.1`) and were followed by a successful Event ID `4624` interactive logon for the same account.

No evidence of remote authentication attempts or additional suspicious authentication activity was identified.

The activity was assessed as benign user authentication failure. No escalation was required, and the alert was closed.

---

## Skills Demonstrated

This lab demonstrated practical SOC L1 skills including:

- Splunk SIEM investigation
- SPL searching and filtering
- Windows Security Event Log analysis
- Event ID `4625` failed-logon analysis
- Event ID `4624` successful-logon analysis
- Windows Logon Type interpretation
- Authentication failure-code analysis
- User and endpoint identification
- Authentication event correlation
- Timeline analysis
- Alert triage
- True-positive vs. benign-activity classification
- SOC incident documentation
- Escalation decision-making
