# Lab 04 — Privileged Group Membership Change Investigation

## Overview

This lab focuses on investigating an unauthorized Windows local Administrators group membership change using Splunk Enterprise.

The objective is to identify which account performed the modification, determine which user received administrative privileges, analyze the associated Windows Security Event, and assess the potential security impact from a SOC Analyst L1 perspective.

**SOC Level:** L1  
**SIEM:** Splunk Enterprise  
**Operating System:** Windows 11  
**Affected Host:** SOC-WIN11  
**Primary Event ID:** 4732  
**MITRE ATT&CK:** T1098.007 — Account Manipulation: Additional Local or Domain Groups

---

## 1. Incident Scenario

Following the previous investigation involving suspicious local account creation, another security-relevant activity was identified on the same Windows endpoint.

The account `ayman`, which possessed local administrator privileges, added the previously created account `backup_admin` to the local Administrators group.

As a result, `backup_admin` received administrative privileges on `SOC-WIN11`.

In this incident scenario, the membership change was unauthorized and could indicate an attempt to maintain privileged access to the compromised endpoint.

The SOC investigation focuses on identifying the account responsible for the modification, verifying the affected group, and determining the appropriate response.

---

## 2. Investigation Objectives

The investigation was conducted to:

1. Identify the account responsible for the group membership change.
2. Determine which account was granted administrative privileges.
3. Confirm the affected Windows security group.
4. Analyze Windows Security Event ID 4732.
5. Investigate the activity using Splunk Enterprise.
6. Evaluate the potential security impact.
7. Classify the incident and determine whether escalation is required.

---

## 3. Tools and Environment

| Component | Description |
|---|---|
| Windows 11 | Investigated endpoint |
| Splunk Enterprise | Security Information and Event Management (SIEM) |
| Splunk Universal Forwarder | Windows Security log forwarding |
| Kali Linux | Remote-access environment |
| Windows Event Viewer | Local security event verification |
| Local Users and Groups | Windows account and group management |
| MITRE ATT&CK | Threat behavior classification |

### Network Environment

| System | IP Address |
|---|---|
| SOC-WIN11 | 192.168.8.132 |
| SOC-SIEM | 192.168.8.136 |
| Kali Linux | 192.168.8.131 |

Windows Security logs were collected through Splunk Universal Forwarder and forwarded to Splunk Enterprise for investigation.

---

## 4. Evidence Collection

### Evidence 01 — Administrators Group Membership

The Windows Local Users and Groups console confirmed that the account `backup_admin` had been added to the local Administrators group.

This modification granted the account administrative privileges on the endpoint.

**You can find the supporting screenshot and explanation in the `screenshots/` directory of this lab.**

### Evidence 02 — Windows Security Event 4732

Windows Event Viewer recorded the following event:

**Event ID: 4732 — A member was added to a security-enabled local group.**

The event provided information about the account performing the action, the group being modified, and the account added to that group.

The investigation identified:

| Field | Value |
|---|---|
| Event ID | 4732 |
| Computer | SOC-WIN11 |
| Subject Account | ayman |
| Added Account | backup_admin |
| Target Group | Administrators |
| Action | Security group membership addition |

**You can find the supporting screenshot and explanation in the `screenshots/` directory of this lab.**

### Evidence 03 — Splunk Investigation

The Windows Security event was forwarded to Splunk Enterprise and investigated using the `windows` index.

The following SPL query was used to identify local security group membership additions:

```spl
index=windows EventCode=4732
```

This search retrieves Windows Security events associated with members being added to security-enabled local groups.

The investigation was then narrowed to the relevant event to examine the account responsible for the change, the account added, and the affected Windows group.

The analysis confirmed that `ayman` added `backup_admin` to the local Administrators group on `SOC-WIN11`.

The added account was identified through the Windows event's membership information, including verification of its Security Identifier (SID).

**You can find the supporting screenshot and explanation in the `screenshots/` directory of this lab.**

---

## 5. Investigation Analysis

Windows Event ID 4732 indicates that a member was added to a security-enabled local group.

This event is important for SOC investigations because changes to privileged groups can provide accounts with additional access to sensitive system resources.

The investigation established the following findings:

**Finding 01 — Privileged Group Modification**

The local Administrators group on `SOC-WIN11` was modified.

**Finding 02 — Account Responsible**

The modification was performed using the account `ayman`.

**Finding 03 — Privileged Account Added**

The account `backup_admin` was added to the local Administrators group.

**Finding 04 — Administrative Access Granted**

The membership change provided `backup_admin` with local administrative privileges.

**Finding 05 — Potential Security Impact**

An unauthorized privileged account could be used to maintain access, change security settings, install software, or perform additional administrative operations.

### Investigation Limitations

Event ID 4732 confirms the group membership modification but does not independently establish malicious intent or prove that administrator credentials were stolen.

Authorization status and related authentication activity must be considered when determining whether the change represents a security incident.

In this incident scenario, the group membership modification was unauthorized.

---

## 6. MITRE ATT&CK Mapping

**Technique ID:** T1098.007

**Technique Name:** Account Manipulation: Additional Local or Domain Groups

**Tactics:** Persistence, Privilege Escalation

**Official Reference:** https://attack.mitre.org/techniques/T1098/007/

### Technique Explanation

Attackers may modify account group memberships to maintain access or obtain additional privileges.

Adding an account to a privileged group, such as the Windows local Administrators group, can provide elevated access to the affected endpoint.

In this investigation, the addition of `backup_admin` to the Administrators group is consistent with this technique.

### MITRE ATT&CK Technique Evidence

The MITRE ATT&CK technique was reviewed to understand how attackers can abuse group membership modifications.

**You can find the supporting screenshot and explanation in the `screenshots/` directory of this lab.**

### MITRE ATT&CK Detection Strategy

Detection of suspicious group membership changes involves monitoring account management events, identifying modifications to privileged groups, and correlating the activity with authentication and administrative context.

Windows Event ID 4732 provides evidence of a member being added to a security-enabled local group.

An analyst should determine whether the modification was expected, approved, and performed by an authorized account.

**You can find the supporting screenshot and explanation in the `screenshots/` directory of this lab.**

---

## 7. SOC L1 Incident Assessment

| Category | Assessment |
|---|---|
| Incident Type | Unauthorized Privileged Group Membership Change |
| Alert Classification | True Positive |
| Severity | High |
| Affected Endpoint | SOC-WIN11 |
| Account Performing Change | ayman |
| Account Granted Privileges | backup_admin |
| Target Group | Administrators |
| Windows Event ID | 4732 |
| MITRE ATT&CK | T1098.007 |
| Escalation Required | Yes |
| Recommended Disposition | Escalate to SOC L2 |

### Classification Justification

The event confirmed that `backup_admin` was added to the local Administrators group.

Because the modification was unauthorized within the incident scenario, the activity was classified as a **True Positive**.

### Severity Justification

The incident was assigned **High severity** because an unauthorized account received local administrator privileges.

Administrative access can enable significant changes to an endpoint, including modifying security configurations, accessing protected resources, and maintaining privileged access.

The severity assessment reflects both the observed privilege assignment and the unauthorized-access context.

---

## 8. Recommended Incident Response

Based on the investigation findings, the following actions are recommended:

1. **Escalate the incident:** Forward the investigation findings to SOC L2 or the incident-response team.

2. **Preserve evidence:** Retain relevant Windows Security events and Splunk investigation results.

3. **Verify authorization:** Confirm whether the membership modification was approved by the responsible system administrator.

4. **Investigate related activity:** Review authentication events and other administrative actions involving `ayman` and `backup_admin`.

5. **Review privileged access:** Recommend reviewing and removing unauthorized administrative privileges through the organization's approved response process.

6. **Assess further compromise:** Determine whether either account was involved in additional suspicious activity.

The SOC L1 analyst's responsibility is to identify, validate, document, and escalate the suspicious activity according to established procedures.

---

## 9. Investigation Conclusion

The investigation identified an unauthorized privileged group membership modification on the Windows endpoint `SOC-WIN11`.

Windows Security Event ID 4732 confirmed that the account `ayman` added `backup_admin` to the local Administrators group.

The event was successfully collected and investigated using Splunk Enterprise.

Based on the incident scenario and supporting evidence, the activity was classified as a **True Positive**, assigned **High severity**, and recommended for escalation to SOC L2.

The activity was mapped to MITRE ATT&CK technique **T1098.007 — Account Manipulation: Additional Local or Domain Groups**.

### Skills Demonstrated

- Windows Security Event Log Analysis
- Splunk SIEM Investigation
- Privileged Account Monitoring
- Windows Event ID 4732 Analysis
- Security Event Validation
- MITRE ATT&CK Mapping
- SOC L1 Incident Classification
- Incident Severity Assessment
- Evidence Documentation and Escalation

---

## 10. Supporting Evidence

All investigation screenshots are stored separately in the `screenshots/` directory.

The supporting evidence includes Windows group membership verification, Windows Event Viewer findings, Splunk investigation results, MITRE ATT&CK technique mapping, and detection strategy references.

**Lab Status: Investigation Completed — Escalation Recommended**
