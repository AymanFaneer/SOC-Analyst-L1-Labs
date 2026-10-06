## Scenario

Following the RDP brute-force incident investigated in Lab 02, the attacker obtained access to the Windows endpoint `SOC-WIN11` using the compromised account `ayman`.

The attacker also had access to administrator credentials, allowing elevated privileges to be granted to `ayman`.

After connecting remotely through RDP, the attacker created a new local account named `backup_admin`, potentially establishing an additional method of maintaining access to the compromised endpoint.

The SOC investigation focused on identifying the account creation, determining which user performed the action, reviewing the related Windows Security Events, and assessing the security impact.

---

## SOC Analyst Assessment

### Investigation Findings

The investigation identified the following activity:

1. The attacker accessed `SOC-WIN11` through RDP using the compromised `ayman` account.
2. The account `ayman` had administrator privileges.
3. A new local account named `backup_admin` was created.
4. Windows generated Security Event ID `4720`.
5. The event identified `ayman` as the account responsible for creating `backup_admin`.
6. Splunk successfully collected the event and confirmed the account creation.

### Classification

**True Positive — Unauthorized Account Creation**

### Severity

**High**

The creation of an unauthorized local account following compromised-account access represents a potential persistence mechanism.

### Escalation

**Yes — Escalate to SOC L2 / Incident Response**

The analyst should escalate the incident for further investigation, including validation of the new account's privileges and assessment of any additional activity performed using the compromised account.

---

## MITRE ATT&CK Mapping

**T1136.001 — Create Account: Local Account**

The attacker created a new local Windows account that could potentially be used to maintain access to the endpoint.

## MITRE ATT&CK Mapping

**Technique:** T1136.001 — Create Account: Local Account  
**Tactic:** Persistence  
**Framework:** MITRE ATT&CK Enterprise

The investigation identified the creation of a new local Windows account named `backup_admin` by the compromised account `ayman`.

Windows Security Event ID 4720 confirmed the account creation, and Splunk was used to identify the responsible account and affected endpoint.

This behavior maps to MITRE ATT&CK technique **T1136.001**, which describes adversaries creating local accounts to maintain access to compromised systems.

### MITRE Technique Reference

![MITRE ATT&CK T1136.001](screenshots/08-mitre-technique-T1136-001.png)

### MITRE Detection Guidance

![MITRE ATT&CK Detection Guidance](screenshots/09-mitre-account-creation-detection.png)

**Official reference:** https://attack.mitre.org/techniques/T1136/001/
---

## Final Verdict

| Category | Finding |
|---|---|
| Alert | Unauthorized Local Account Creation |
| Classification | True Positive — Unauthorized Account Creation |
| Severity | High |
| Affected Host | SOC-WIN11 |
| Compromised Account | ayman |
| Created Account | backup_admin |
| Windows Event ID | 4720 |
| MITRE ATT&CK | T1136.001 |
| Escalation | Required |
| Incident Status | Escalated for further investigation |

---

## Conclusion

The SOC investigation identified unauthorized local account creation on `SOC-WIN11` following the compromise of the `ayman` account.

Using Windows Security Event ID `4720` and Splunk SIEM, the analyst confirmed that `ayman` created a new local account named `backup_admin`.

Considering the preceding unauthorized access and the creation of an additional account, the activity was classified as a **True Positive with High severity**, requiring escalation for further investigation.

This lab demonstrates how a SOC Analyst L1 can investigate suspicious account-management activity, identify relevant evidence, assess the security impact, and make an appropriate escalation decision.
