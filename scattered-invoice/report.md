
# Scattered-Invoice-Threat-Hunt
## Business Email Compromise (BEC) — Incident Response Report

**Analyst:** Robert Anaele  
**Role:** Cybersecurity Analyst  
**Hunt Platform:** `hunt.lognpacific.com`  
**SIEM:** Microsoft Sentinel — Workspace: `law-cyber-range`  
**Investigation Window:** 25 February 2026, 21:00–23:00 UTC  
**Tables Queried:** `SignInLogs`, `EmailEvents`, `CloudAppEvents`  
**Threat Actor Attribution:** Scattered Spider  

---

## Executive Summary

On 25 February 2026, a threat actor compromised the Microsoft 365 account belonging to Mark Smith (`m.smith@lognpacific.org`) through an MFA fatigue attack after obtaining valid credentials via infostealer malware. After successfully authenticating, the attacker immediately accessed Mark's mailbox, created two concealed inbox rules to exfiltrate finance-related communications and suppress security notifications, and sent a fraudulent invoice email that resulted in a **£24,500 wire transfer** to an attacker-controlled bank account.

The attacker subsequently accessed **Microsoft SharePoint Online** and **OneDrive for Business**, expanding the scope of exposure beyond email. Correlation across telemetry showed that the activity was tied to a single authenticated session. No Conditional Access controls were applied, and no policy existed to prevent an unmanaged Linux device from authenticating from the Netherlands.

---

## Environment Details

| Field | Value |
|---|---|
| Workspace | `law-cyber-range` |
| Compromised Account | `m.smith@lognpacific.org` |
| Tenant ID | `939e93f3-04f6-479d-82ff-345c231abb4d` |
| Attacker IP | `205.147.16.190` |
| Attacker Location | Amsterdam, Noord-Holland, NL |
| Attacker ASN | `AS51809` — BRSK Limited (UK ISP) |
| Attacker Operating System | Linux (Ubuntu x86_64) |
| Attacker Browser | Firefox 147.0 |
| Attacker Session ID | `00225cfa-a0ff-fb46-a079-5d152fcdf72a` |

---

## Attack Chain Overview

```text
[Infostealer Malware]
        ↓
  Credentials Stolen
        ↓
  MFA Fatigue Attack (3 failed push attempts)
        ↓
  User approves prompt → Session Compromised
        ↓
  Mailbox Reconnaissance (MailItemsAccessed)
        ↓
  Inbox Rule 1: Forward finance emails → insights@duck.com
  Inbox Rule 2: Delete security-related alerts
        ↓
  Fraudulent BEC email sent to j.reynolds@lognpacific.org
        ↓
  £24,500 wire transfer processed
        ↓
  SharePoint + OneDrive accessed
```

---

## Phase 1 — Credential Access

The attacker likely obtained Mark Smith's credentials through **infostealer malware**, a malware category designed to collect browser-stored passwords, session tokens, and autofill data from compromised hosts. Threat groups such as **Scattered Spider** commonly acquire these stolen credentials from underground marketplaces before initiating targeted MFA abuse campaigns.

This explains why the attacker already possessed valid credentials before the defined investigation window. No brute-force activity, password spraying, or phishing telemetry was observed directly against Mark's account during this incident window.

**MITRE ATT&CK:**
- `T1078` — Valid Accounts
- `T1539` — Steal Web Session Cookie

---

## Phase 2 — Account Compromise and MFA Fatigue

### Query

```kql
SignInLogs
| where TimeGenerated >= datetime(2026-04-11)
| where UserDisplayName contains "Mark"
| project TimeGenerated, UserPrincipalName, UserDisplayName, IPAddress, ResultType
| order by TimeGenerated desc
```

![Q01 Compromised Account](https://github.com/robertanaele/Scattered-Invoice---Threat-Hunt/blob/main/scattered-invoice/screanshoots/Q01_Compromised_Account.png)
📷 *Evidence 1. Sign-in telemetry showing compromised account activity associated with Mark Smith.*

---

### Query

```kql
SignInLogs
| where TimeGenerated between (datetime(2026-02-25T21:00:00Z) .. datetime(2026-02-25T23:00:00Z))
| where UserPrincipalName == "m.smith@lognpacific.org"
| project TimeGenerated, IPAddress, LocationDetails, ResultType, AppDisplayName, DeviceDetail
| order by TimeGenerated asc
```

![Q02 Attacker Source IP](https://github.com/robertanaele/Scattered-Invoice---Threat-Hunt/blob/main/scattered-invoice/screanshoots/Q02_Attacker_Source_IP.png)

📷 *Evidence 2. Sign-in records identifying attacker source IP address `205.147.16.190` during the incident window.*

---

### Findings

Mark's legitimate session originated from `172.175.65.103` in **Boydton, Virginia** at **21:44 UTC**. At **21:54 UTC**, the attacker initiated repeated MFA push attempts from `205.147.16.190` in **Amsterdam, Netherlands**. Mark received **three unsuccessful prompt events** before approving one at **21:59 UTC**, which provided the attacker with a valid authenticated session.

| Time (UTC) | IP Address | ResultType | Observation |
|---|---|---|---|
| 21:44 | `172.175.65.103` | 0 | Legitimate user session from Virginia |
| 21:54 | `205.147.16.190` | 50074 | Strong authentication required but not completed |
| 21:54 | `205.147.16.190` | 50140 | Keep-me-signed-in interruption |
| 21:55 | `205.147.16.190` | 50140 | Keep-me-signed-in interruption |
| 21:59 | `205.147.16.190` | 0 | **Successful attacker authentication** |

**Attack source country:** Netherlands  
**Primary MFA-related error code:** `50074`  
**MFA push attempts prior to success:** 3

![Q04 MFA Denial Error Code](https://github.com/robertanaele/Scattered-Invoice---Threat-Hunt/blob/main/scattered-invoce/screenshoots/Q04_MFA_Denial_Error_Code.png)

📷 *Evidence 3. MFA-related sign-in event showing denied or incomplete strong authentication attempts.*

![Q05 MFA Fatigue Intensity](https://github.com/robertanaele/Scattered-Invoice---Threat-Hunt/blob/main/img/Q05_MFA_Fatigue_Intensity.png)

📷 *Evidence 4. Repeated MFA push activity consistent with MFA fatigue behavior.*

**MITRE ATT&CK:**
- `T1621` — MFA Request Generation

---

## Phase 3 — Application Access and Device Profiling

### Query

```kql
SignInLogs
| where TimeGenerated between (datetime(2026-02-25T21:00:00Z) .. datetime(2026-02-25T23:00:00Z))
| where UserPrincipalName == "m.smith@lognpacific.org"
| where IPAddress == "205.147.16.190"
| where ResultType == 0
| distinct AppDisplayName
```

![Q06 Application Accessed](https://github.com/robertanaele/Scattered-Invoice---Threat-Hunt/blob/main/img/Q06_Application_Accessed.png)

📷 *Evidence 5. Successful application access records showing the attacker authenticated to Exchange Online services.*

---

### Query

```kql
SignInLogs
| where TimeGenerated between (datetime(2026-02-25T21:00:00Z) .. datetime(2026-02-25T23:00:00Z))
| where UserPrincipalName == "m.smith@lognpacific.org"
| where IPAddress == "205.147.16.190"
| where ResultType == 0
| project TimeGenerated, UserAgent, DeviceDetail
| take 1
```

![Q07 Attacker Operating System](https://github.com/robertanaele/Scattered-Invoice---Threat-Hunt/blob/main/img/Q07_Attacker_Operating_System.png)

📷 *Evidence 6. Device fingerprint data identifying Linux as the operating system used during attacker authentication.*

![Q08 Attacker Browser](https://github.com/robertanaele/Scattered-Invoice---Threat-Hunt/blob/main/img/Q08_Attacker_Browser.png)

📷 *Evidence 7. Browser fingerprint evidence showing Firefox 147.0 as the client used in the malicious session.*

---

### Findings

The attacker authenticated to **One Outlook Web** (Exchange Online) from an unmanaged and non-compliant **Linux** host using **Firefox 147.0**.

**Observed User-Agent:**  
`Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:147.0) Gecko/20100101 Firefox/147.0`

Compared to Mark's expected access profile, three anomalies were immediately evident:

- Unexpected operating system
- Unexpected browser
- Unexpected source geography

These indicators significantly increased confidence that the session was malicious.

---

## Phase 4 — Mailbox Reconnaissance

### Query

```kql
CloudAppEvents
| where TimeGenerated between (datetime(2026-02-25T21:00:00Z) .. datetime(2026-02-25T23:00:00Z))
| where IPAddress == "205.147.16.190"
| project TimeGenerated, ActionType, Application, AccountDisplayName, IPAddress
| order by TimeGenerated asc
| take 5
```

![Q09 First Post-Auth Action](https://github.com/robertanaele/Scattered-Invoice---Threat-Hunt/blob/main/img/Q09_First_Post_Auth_Auction.png)

📷 *Evidence 8. First post-authentication action recorded as `MailItemsAccessed`, indicating immediate mailbox reconnaissance.*

---

### Findings

The first observed post-authentication action was `MailItemsAccessed` at **21:56 UTC**. This indicates that the attacker immediately reviewed the victim's inbox to identify active financial conversations before making any mailbox changes.

This activity reflects deliberate BEC tradecraft rather than opportunistic account access.

**First post-authentication action:** `MailItemsAccessed`

**MITRE ATT&CK:**
- `T1114.002` — Remote Email Collection

---

## Phase 5 — Inbox Rule Persistence and Defense Evasion

### Query

```kql
CloudAppEvents
| where TimeGenerated between (datetime(2026-02-25T21:00:00Z) .. datetime(2026-02-25T23:00:00Z))
| where IPAddress == "205.147.16.190"
| where ActionType == "New-InboxRule"
| project TimeGenerated, RawEventData
| order by TimeGenerated asc
```

**Rule creation event type:** `New-InboxRule`

![Q10 Rule Creation Method](https://github.com/robertanaele/Scattered-Invoice---Threat-Hunt/blob/main/img/Q10_Rule_Creation_Method.png)

📷 *Evidence 9. CloudAppEvents evidence showing inbox rule creation activity from the attacker session.*

Two inbox rules were created within a short time window. Both rule names were intentionally minimal and designed to avoid notice.

---

### Rule 1 — Email Exfiltration Rule

![Q11 Forward Rule Name](https://github.com/robertanaele/Scattered-Invoice---Threat-Hunt/blob/main/img/Q11_Forward_Rule_Name.png)

📷 *Evidence 10. Malicious forwarding rule name configured as `.` to avoid casual detection.*

![Q12 Forward Destination](https://github.com/robertanaele/Scattered-Invoice---Threat-Hunt/blob/main/img/Q12_Forward_Destination.png)

📷 *Evidence 11. External forwarding destination configured as `insights@duck.com`.*

![Q13 Forward Keywords](https://github.com/robertanaele/Scattered-Invoice---Threat-Hunt/blob/main/img/Q13_Forward_Keywords.png)

📷 *Evidence 12. Financially themed trigger keywords used to capture invoice and payment-related messages.*

![Q14 Rule Processing Flag](https://github.com/robertanaele/Scattered-Invoice---Threat-Hunt/blob/main/img/Q14_Rule_Processing_Flag.png)

📷 *Evidence 13. `StopProcessingRules` enabled to suppress additional mailbox rule processing.*

| Parameter | Value |
|---|---|
| Rule Name | `.` |
| ForwardTo | `insights@duck.com` |
| Trigger Keywords | `invoice`, `payment`, `wire`, `transfer` |
| StopProcessingRules | `True` |

This rule silently forwarded financially relevant messages to an attacker-controlled Duck.com mailbox. The `StopProcessingRules` setting prevented additional mailbox rules from processing those messages, further reducing the chance of user awareness.

---

### Rule 2 — Security Alert Deletion Rule

![Q15 Delete Rule Name](https://github.com/robertanaele/Scattered-Invoice---Threat-Hunt/blob/main/img/Q15_Delete_Rule_Name.png)

📷 *Evidence 14. Malicious deletion rule name configured as `..` to remain visually inconspicuous.*

![Q16 Delete Keywords](https://github.com/robertanaele/Scattered-Invoice---Threat-Hunt/blob/main/img/Q16_Delete_Keywords.png)

📷 *Evidence 15. Security-related trigger keywords used to automatically remove warning and alert messages.*

| Parameter | Value |
|---|---|
| Rule Name | `..` |
| Action | `DeleteMessage` |
| Trigger Keywords | `suspicious`, `security`, `phishing`, `unusual`, `compromised`, `verify` |
| StopProcessingRules | `True` |

This rule automatically deleted security-related messages, including alerts that could have warned the victim of suspicious activity.

**MITRE ATT&CK:**
- `T1564.008` — Hide Artifacts: Email Hiding Rules

---

## Phase 6 — Business Email Compromise Execution

### Query

```kql
EmailEvents
| where TimeGenerated between (datetime(2026-02-25T21:00:00Z) .. datetime(2026-02-25T23:00:00Z))
| where SenderFromAddress == "m.smith@lognpacific.org"
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, Subject, SenderIPv4, EmailDirection
| order by TimeGenerated asc
```

![Q17 BEC Target](https://github.com/robertanaele/Scattered-Invoice---Threat-Hunt/blob/main/img/Q17_BEC_Target.png)

📷 *Evidence 16. Email telemetry identifying the target recipient of the fraudulent BEC message.*

![Q18 BEC Subject Line](https://github.com/robertanaele/Scattered-Invoice---Threat-Hunt/blob/main/img/Q18_BEC_Subject_Line.png)

📷 *Evidence 17. Subject line evidence showing invoice-thread hijacking using updated banking details.*

![Q19 Email Direction](https://github.com/robertanaele/Scattered-Invoice---Threat-Hunt/blob/main/img/Q18_BEC_Subject_Line.png)

📷 *Evidence 18. Message direction recorded as intra-organizational, allowing the email to bypass external filtering controls.*

---

### Findings

At **22:06 UTC**, the attacker sent a fraudulent email from Mark's compromised mailbox:

| Field | Value |
|---|---|
| Sender | `m.smith@lognpacific.org` |
| Recipient | `j.reynolds@lognpacific.org` |
| Subject | `RE: Invoice #INV-2026-0892 - Updated Banking Details` |
| Sender IP | `205.147.16.190` |
| Email Direction | `Intra-org` |

The `RE:` prefix is a key social engineering element. Instead of creating a new message, the attacker replied within an existing invoice conversation identified during mailbox reconnaissance. To the recipient, the email appeared to be a legitimate continuation of an existing business exchange.

Because the email originated internally from a valid compromised mailbox, it bypassed traditional external sender filtering controls. As a result, the recipient processed the **£24,500 wire transfer** through normal business workflow.

**MITRE ATT&CK:**
- `T1657` — Financial Theft

---

## Phase 7 — Lateral Cloud Resource Access

### Query

```kql
CloudAppEvents
| where TimeGenerated between (datetime(2026-02-25T21:00:00Z) .. datetime(2026-02-25T23:00:00Z))
| where IPAddress == "205.147.16.190"
| distinct Application, ActionType
| order by Application asc
```

![Q21 Cloud App Accessed](https://github.com/robertanaele/Scattered-Invoice---Threat-Hunt/blob/main/img/Q21_Cloud_App_Accessed.png)

📷 *Evidence 19. Cloud application activity showing attacker access extending beyond Exchange into SharePoint and OneDrive.*

---

### Findings

In addition to Exchange Online, the attacker accessed multiple Microsoft cloud services:

| Application | Actions Observed |
|---|---|
| Microsoft Exchange Online | `MailItemsAccessed`, `New-InboxRule`, `Send`, `Create` |
| Microsoft OneDrive for Business | `FileAccessed`, `PageViewed`, `ListCreated`, `ListViewed`, `Broke sharing inheritance` |
| Microsoft SharePoint Online | `SignInEvent`, `PageViewed` |

The `FileAccessed` and `Broke sharing inheritance` actions recorded in OneDrive suggest potential document access, permission manipulation, or preparation for future exfiltration.

**MITRE ATT&CK:**
- `T1530` — Data from Cloud Storage

---

## Defensive Control Gaps

**ConditionalAccessStatus:** `notApplied`

Security Defaults were the only active control and were effectively bypassed once the victim approved the MFA prompt. The following controls were absent:

| Missing Control | Potential Defensive Value |
|---|---|
| Device compliance enforcement | Would have blocked unmanaged Linux device access |
| Location-based Conditional Access | Would have challenged or blocked login from the Netherlands |
| Impossible travel detection | Would have identified Virginia-to-Netherlands anomaly |
| Risk-based Conditional Access | Would have increased scrutiny for risky authentication activity |
| MFA number matching | Would have significantly reduced MFA fatigue effectiveness |

---

## Full Attack Timeline

| Time (UTC) | Event |
|---|---|
| 21:44 | Mark authenticates from Virginia (`172.175.65.103`) |
| 21:54 | Attacker begins MFA fatigue from Amsterdam (`205.147.16.190`) |
| 21:54 | Failed MFA prompt #1 — ResultType `50074` |
| 21:54 | Failed MFA prompt #2 — ResultType `50140` |
| 21:55 | Failed MFA prompt #3 — ResultType `50140` |
| 21:59 | MFA approved — attacker authenticated |
| 21:56 | Mailbox accessed — `MailItemsAccessed` |
| 22:02 | Inbox rule created — forwards messages to `insights@duck.com` |
| 22:03 | Inbox rule created — deletes security alerts |
| 22:06 | Fraudulent BEC email sent to `j.reynolds@lognpacific.org` |
| 22:09+ | SharePoint Online and OneDrive activity observed |

---

## Indicators of Compromise

| Type | Value |
|---|---|
| Attacker IPv4 | `205.147.16.190` |
| Attacker ASN | `AS51809` — BRSK Limited |
| Exfiltration Email | `insights@duck.com` |
| Malicious Rule 1 | `.` |
| Malicious Rule 2 | `..` |
| Session ID | `00225cfa-a0ff-fb46-a079-5d152fcdf72a` |
| Compromised UPN | `m.smith@lognpacific.org` |

---

## Containment Actions

1. **Revoke Session**  
   Immediately invalidate session `00225cfa-a0ff-fb46-a079-5d152fcdf72a`.

2. **Remove Inbox Rules**  
   Delete the malicious inbox rules named `.` and `..`.

3. **Reset Credentials and Re-register MFA**  
   Force a password reset for `m.smith@lognpacific.org` and require new MFA enrollment.

4. **Block IOCs**  
   Block `205.147.16.190` at relevant perimeter controls and block `insights@duck.com` at the email layer.

5. **Notify Finance and Initiate Recovery**  
   Notify `j.reynolds@lognpacific.org` and begin wire recall procedures with the financial institution.

6. **Review Cloud Data Exposure**  
   Audit OneDrive and SharePoint activity for accessed files, sharing changes, and possible data exposure.

---

## Recommendations

| Priority | Recommendation | Security Benefit |
|---|---|---|
| Critical | Enable MFA number matching | Reduces the effectiveness of MFA fatigue attacks |
| Critical | Enforce Conditional Access based on device compliance | Blocks unmanaged devices from authenticating |
| High | Deploy location-based Conditional Access policies | Detects or blocks foreign sign-in attempts |
| High | Alert on `New-InboxRule` events involving forwarding or deletion logic | Improves visibility into mailbox persistence activity |
| High | Monitor for infostealer-exposed credentials | Provides earlier warning before MFA abuse occurs |
| Medium | Implement out-of-band wire verification | Reduces BEC-driven financial fraud |
| Medium | Enable Entra ID Identity Protection | Improves risk-based authentication and alerting |

---

## MITRE ATT&CK Mapping

| Tactic | ID | Technique |
|---|---|---|
| Initial Access | `T1078` | Valid Accounts |
| Credential Access | `T1539` | Steal Web Session Cookie |
| Credential Access | `T1621` | MFA Request Generation |
| Persistence / Defense Evasion | `T1564.008` | Hide Artifacts: Email Hiding Rules |
| Collection | `T1114.002` | Remote Email Collection |
| Collection / Cloud Access | `T1530` | Data from Cloud Storage |
| Impact | `T1657` | Financial Theft |

---

## Analyst Notes

> **The investigation window was critical.** Early queries focused on April 2026 logs and surfaced unrelated attacker activity from a different session. The case brief identified the actual incident window as **25 February 2026, 21:00–23:00 UTC**. Query scope must always align to the known timeline.

> **Internal BEC can bypass traditional email filtering.** Because the fraudulent email was sent from a legitimate internal mailbox to another internal user, typical external sender-based controls did not apply. Detection depended on behavioral anomalies rather than sender reputation.

> **Session-level correlation was essential.** The `AADSessionId` value in `CloudAppEvents` aligned with the session identifiers observed in `SignInLogs`, linking mailbox access, inbox rule creation, message transmission, and cloud application activity to a single attacker-controlled session.

> **MFA alone is not sufficient if implemented weakly.** Push-based MFA can be abused through repeated approval requests. Number matching, phishing-resistant MFA, or FIDO2 security keys would have significantly reduced the likelihood of compromise.

---

**Report Prepared By:** Robert Anaele  
**Case:** Scattered Invoice // Hunt 02  
**Date:** April 2026
```
