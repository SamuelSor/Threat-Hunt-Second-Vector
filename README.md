<img width="1110" height="328" alt="Boarder" src="https://github.com/user-attachments/assets/2085561e-793d-4558-a01e-8beaf2fce474" />  

# THREAT HUNT REPORT - Second Vector 📨
### Report by: Samuel Sorto
## Platforms and Languages Leveraged

* **Kusto Query Language (KQL)**
* **Microsoft Sentinel** (`law-cyber-range`)
* **Microsoft Defender XDR**

## Scenario

`Timeframe: 2026-06-11 03:00 UTC → 2026-06-11 13:00 UTC`  
`Incident ID 87241: Anonymous IP address involving one user`  
`Company: LOG(N) Pacific`  

Microsoft Entra ID Protection raised an incident against a finance user's account overnight. The account was accessed by an anonymous IP address, flagged on the account `m.smith`, and rated **Low**. The rating may not be accurate and requires further investigation to verify the status of the account and determine whether the activity was benign or malicious.

---

## Steps Taken

### 1. Review the Incident in Defender XDR

<img width="740" height="460" alt="Incident-87241-XDR" src="https://github.com/user-attachments/assets/ecc43f99-4d35-497a-88f3-143c9a35499a" />

The incident shows an anonymous IP address (`103.69.224.136`) coming from Amsterdam and registered under `Proton`, a trusted vendor that is often used for VPN services. It also indicated that the activity began at `11:13:10 on Jun 10th`. The user's principal name is `m.smith@lognpacific.org`.

---

### 2. Review the AADUserRiskEvents Table in Sentinel

The first step was to verify whether this incident was the only event logged for this user. Looking into the `AADUserRiskEvents` table displayed other events that may not have triggered alerts.

<img width="967" height="510" alt="AADUserRiskEvents" src="https://github.com/user-attachments/assets/23763fdd-80f4-456b-b7a6-ea252714a2cb" />

This incident was not isolated. There were six total events from the same IP address, and all but one were labeled `dismissed`. Looking back at the initial ticket, the account was still active, which means the operator did not trigger any rules to disable the account.

**KQL:**

```kql
AADUserRiskEvents  
| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))  
| where UserPrincipalName has "m.smith"  
| project TimeGenerated, UserPrincipalName, RiskEventType, RiskLevel, RiskState, IpAddress  
| order by TimeGenerated asc
```

---

### 3. Pivot to the SigninLogs Table

Signin logs show which applications the operator was able to access.

<img width="1485" height="476" alt="SigninLogs" src="https://github.com/user-attachments/assets/365241fa-bae4-468b-ba43-f3367ce6ba81" />

The attacker was able to use single sign-on authentication to access Microsoft Outlook, Teams, SharePoint, Flow Portal, and several other applications. Seven different applications were accessed. These apps were accessed without any re-prompting for user credentials.

Flow Portal was an outlier because it would most likely not be used by finance personnel during normal business operations. Outlook access also created risk because the compromised account could be used to send fraudulent messages, spread malicious content, or interact with other users within the company.

The session ID for these incidents was:

```text
005d431a-380b-1f5e-e554-16d5010dc28e
```

The initial successful access occurred at:

```text
2026-06-11T03:15:45.7848573Z
```

**KQL:**

```kql
SigninLogs
| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
| where UserPrincipalName contains "m.smith"
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, AppDisplayName, AuthenticationRequirement, ResultSignature, IPAddress, SessionId
| order by TimeGenerated asc
```

---

### 4. Switch to the MicrosoftGraphActivityLogs Table

The attacker appeared to understand which apps they could access with single sign-on. This suggested that they may have conducted reconnaissance. The `MicrosoftGraphActivityLogs` table was reviewed to determine what the attacker may have queried.

<img width="1770" height="169" alt="Graph-authentication Methods" src="https://github.com/user-attachments/assets/7427b895-9e10-4c95-a0e6-a3c6eddf9e21" />

The directory `/reports/authenticationMethods/userRegistrationDetails` was accessed three times by the attacker. The first access occurred at `2026-06-11T03:09:37.4068572Z`, roughly three minutes before the first successful app sign-in. The attacker most likely used this information to review the account's authentication posture and identify how the session could continue without MFA.

**KQL:**

```kql
MicrosoftGraphActivityLogs
| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
| where IPAddress == "103.69.224.136"
| where RequestUri contains "/reports/"
| project TimeGenerated, RequestMethod, RequestUri, IPAddress, AppId, SessionId
| order by TimeGenerated asc
```

The attacker also checked what groups the victim belonged to using the following Microsoft Graph path:

```text
/me/memberOf
```

This activity indicates cloud account and permission group discovery.

**KQL:**

```kql
MicrosoftGraphActivityLogs
| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
| where IPAddress == "103.69.224.136"
| where RequestUri has "/me/"
| project TimeGenerated, RequestMethod, RequestUri
| order by TimeGenerated asc
```

---

### 5. Investigate the EmailEvents Table

The attacker accessed Outlook first, so the `EmailEvents` table was reviewed to determine what messages may have been sent while the attacker had access to the mailbox.

<img width="1064" height="71" alt="AttackerEmail" src="https://github.com/user-attachments/assets/ad543521-28e9-4539-bb47-a8fcfecbe0ea" />

At `2026-06-11T04:13:54Z`, the attacker sent an email using the victim's account to update banking details. This was most likely an attempt to redirect payments. The email was sent to:

```text
j.reynolds@lognpacific.org
```

**KQL:**

```kql
EmailEvents
| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
| where SenderIPv4 == "103.69.224.136"
| project TimeGenerated, EmailDirection, Subject, SenderDisplayName, RecipientEmailAddress
```

---

### 6. Search Historical Email for Payment Process Reconnaissance

The attacker found an email thread with the subject:

```text
Q1 Vendor Payment Schedule - Review Required
```

This thread outlined the payment approval process and gave the attacker information needed to craft a believable payment-change request. Because this email predated the intrusion by months, the search window had to be expanded earlier into 2026.

**KQL:**

```kql
EmailEvents
| where TimeGenerated between (datetime(2026-01-01) .. datetime(2026-06-11 13:00:00))
| where SenderFromAddress endswith "@lognpacific.org"
| where RecipientEmailAddress endswith "@lognpacific.org"
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, Subject
| order by TimeGenerated asc
```

<img width="1027" height="345" alt="HistoricalEmail" src="https://github.com/user-attachments/assets/aca0b656-9436-4bcd-bc78-6fc41507600e" />


---

### 7. Identify a Second Service Used for the Fraud Request

The attacker used `MicrosoftTeams` as another method of sending the payment update. This showed that the fraud attempt was not limited to email. The same request was pushed through a second Microsoft 365 service.  

<img width="1033" height="72" alt="TeamsMessage" src="https://github.com/user-attachments/assets/1fafb34d-29a6-4e25-ae6e-ead253d86950" />  


---

### 8. Review Exchange Inbox Rules

The attacker created a rule that hid emails from `j.reynolds@lognpacific.org` by automatically moving them to the Archive folder at `2026-06-11T03:28:22Z`.

The attacker also created another rule that forwarded emails from `j.reynolds@lognpacific.org` to the external email address:

```text
merovingian1337@proton.me
```

The first rule was named:

```text
Invoice Processing
```

The second rule was named:

```text
Backup Copy
```

These rules controlled one side of the conversation. Replies from the fraud target would not appear in the victim's inbox, while the attacker still received a copy externally.

**KQL:**

```kql
OfficeActivity
| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
| where UserId =~ "m.smith@lognpacific.org"
| where OfficeWorkload == "Exchange"
| where Operation == "New-InboxRule"
| project TimeGenerated, Operation, Parameters
```
<img width="575" height="318" alt="rule2" src="https://github.com/user-attachments/assets/9a99eae7-4f65-4c50-81a0-645225d2285b" />

<img width="575" height="318" alt="rule1" src="https://github.com/user-attachments/assets/25d8f01d-2727-44bb-bc7b-79c19cb01cb4" />


---

### 9. Investigate File Access and Downloads

The attacker downloaded three items from SharePoint. This behavior was abnormal because the user typically accessed information without downloading it. The distinction between ordinary file access and possible exfiltration was the operation type. `FileAccessed`, `PageViewed`, and `ListViewed` indicate viewing content in place, while `FileDownloaded` indicates a copy was taken out.

**KQL:**

```kql
OfficeActivity
| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
| where UserId =~ "m.smith@lognpacific.org"
| where Operation == "FileDownloaded"
| project TimeGenerated, Operation, OfficeObjectId
```

<img width="1270" height="130" alt="FilesDownloaded" src="https://github.com/user-attachments/assets/27566f77-7931-4b56-9de7-24df0b3f9492" />


---

### 10. Review Access to yomark.pdf

The attacker also accessed a file named:

```text
yomark.pdf
```

This file may have pointed to a credential store. It was not downloaded, but it was opened. This suggests the attacker may have only needed to read the file to learn where credentials or password-management information were stored.

**KQL:**

```kql
OfficeActivity
| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
| where UserId =~ "m.smith@lognpacific.org"
| where OfficeObjectId != ""
| where Operation has_any ("FileAccessed")
| project TimeGenerated, Operation, OfficeObjectId
```

<img width="1117" height="190" alt="FilesAccessed" src="https://github.com/user-attachments/assets/41f97121-35bd-4556-a897-c0ca231c9236" />


---

### 11. Validate MFA Was Not Satisfied

This activity was legitimate attacker behavior because the entire session had no MFA used. A legitimate user would normally satisfy MFA during authentication. The lack of MFA satisfaction supported the conclusion that the attacker was using a compromised session or credentials that were not challenged by Conditional Access.

**KQL:**

```kql
SigninLogs
| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
| where SessionId == "005d431a-380b-1f5e-e554-16d5010dc28e"
| extend AD = todynamic(AuthenticationDetails)
| where tostring(AD.authenticationStepResultDetail) has "MFA"
    or tostring(AD.authenticationMethod) has "MFA"
| summarize NumberOfMFA = count()
```

<img width="156" height="70" alt="MFA" src="https://github.com/user-attachments/assets/308e00ed-f121-42b6-9628-efd9ea9a2c31" />


---

### 12. Investigate Microsoft Flow Portal Activity and Correlate Automated Forwarding with Microsoft Graph

The attacker's session tried to blend in with normal applications, but one app stood out:

```text
Microsoft Flow Portal
```

This was most likely used to build automation into the attack. Flow Portal would not normally be expected for finance personnel and aligned with later automated forwarding behavior.The attacker forwarded details using an automated script. The `EmailEvents` table showed the forwarded email but did not provide the cause. Pivoting to `MicrosoftGraphActivityLogs` showed that the source IP for the forwarding action was:

```text
20.150.129.194
```

This IP was not the original attacker IP and did not represent the victim's device. Instead, it indicated that the forwarding action was being driven through Microsoft cloud automation.

**KQL:**

```kql
EmailEvents
| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
| where Subject startswith "FW:"
| project TimeGenerated, Subject, SenderIPv4, NetworkMessageId
| order by TimeGenerated asc
```

```kql
MicrosoftGraphActivityLogs
| where TimeGenerated between (datetime(2026-06-11 03:00:00) .. datetime(2026-06-11 13:00:00))
| where RequestUri has_any ("forward", "sendMail")
| project TimeGenerated, IPAddress, AppID, RequestUri
| order by TimeGenerated asc
```

<img width="952" height="98" alt="FWEmails" src="https://github.com/user-attachments/assets/307a9b7a-1d88-4d9e-ba80-62baa384b526" />


The App ID (`7ab7862c-4c57-491e-8a45-d52a7e023983`) used to forward the mail is most commonly associated with Power Automate services. Because the attacker accessed `Microsoft Flow Portal`, the forwarding behavior was attributed to Microsoft Power Automate.


<img width="1707" height="189" alt="GraphAPPID" src="https://github.com/user-attachments/assets/e11f6609-875b-49d9-a65c-40a4f74be3ec" />


---

## Summary of Findings

The investigation determined that the low-severity anonymous IP alert was part of a full Microsoft 365 identity compromise. The attacker authenticated to `m.smith@lognpacific.org` from anonymous IP `103.69.224.136` using single-factor authentication and accessed seven Microsoft 365 applications without MFA re-prompting.

The attacker performed reconnaissance using Microsoft Graph by querying authentication registration details and group membership information. They also searched historical finance-related email and identified the thread `Q1 Vendor Payment Schedule - Review Required`, which helped them understand payment timing and approval processes.

The attacker then attempted business email compromise by sending updated banking details to `j.reynolds@lognpacific.org`. They used both email and Microsoft Teams to push the request. To hide the fraud, they created inbox rules that moved replies from `j.reynolds@lognpacific.org` to the Archive folder and forwarded copies to `merovingian1337@proton.me`.

The attacker also downloaded files from SharePoint and accessed `yomark.pdf`, which may have pointed to a credential store. Finally, the attacker accessed Microsoft Flow Portal and used Microsoft Graph/Power Automate activity to automate forwarding, allowing activity to continue when the user was not actively online.

---

## MITRE ATT&CK Mapping

| ATT&CK Tactic | Technique | MITRE ID | Evidence Correlation |
|---------------|-----------|----------|----------------------|
| Initial Access | Valid Accounts: Cloud Accounts | T1078.004 | Successful M365 sign-in |
| Discovery | Account Discovery: Cloud Account | T1087.004 | `userRegistrationDetails` |
| Discovery | Permission Groups Discovery: Cloud Groups | T1069.003 | `/me/memberOf` |
| Collection | Email Collection | T1114 | Historical payment thread |
| Collection | Data from Information Repositories | T1213 | Finance email reconnaissance |
| Collection | Data from Cloud Storage | T1530 | SharePoint file access/downloads |
| Collection | Automated Collection | T1119 | Power Automate workflow |
| Exfiltration | Automated Exfiltration | T1020 | Graph-driven mail forwarding |
| Persistence | Email Forwarding Rule | T1114.003 | `Backup Copy` inbox rule |
| Defense Evasion | Hide Artifacts: Email Hiding Rules | T1564 | `Invoice Processing` archive rule |
| Command and Control | Cloud Service | T1102 | Microsoft Graph API abuse |

---

## Response Taken

* Treated the incident as a confirmed identity compromise rather than a benign VPN login.
* Identified the compromised user account: `m.smith@lognpacific.org`.
* Identified the primary attacker IP: `103.69.224.136`.
* Identified the suspicious session ID: `005d431a-380b-1f5e-e554-16d5010dc28e`.
* Reviewed and documented risk detections in `AADUserRiskEvents`.
* Reviewed successful sign-ins, authentication requirements, and app access in `SigninLogs`.
* Confirmed no MFA was satisfied during the attacker session.
* Identified Microsoft Graph reconnaissance activity.
* Identified fraudulent mail activity targeting `j.reynolds@lognpacific.org`.
* Identified malicious inbox rules:

  * `Invoice Processing`
  * `Backup Copy`
* Identified external forwarding to:

  * `merovingian1337@proton.me`
* Identified abnormal SharePoint file downloads.
* Identified suspicious access to `yomark.pdf`.
* Identified Microsoft Flow Portal / Power Automate involvement.

### Recommended Remediation

* Immediately revoke all active sessions and refresh tokens for `m.smith@lognpacific.org`.
* Reset the user's password only after revoking active sessions.
* Disable or temporarily block sign-in for the account until containment is complete.
* Remove malicious inbox rules from Exchange:

  * `Invoice Processing`
  * `Backup Copy`
* Search all mailboxes for similar inbox rules forwarding to external addresses.
* Remove the malicious Power Automate flow from the **Power Platform Admin Center**.
* Review Power Automate connectors and app consent tied to the compromised user.
* Review all messages sent from the user during the compromise window.
* Notify `j.reynolds@lognpacific.org` and finance leadership of the attempted payment redirection.
* Validate whether any payments were changed, approved, or redirected.
* Review downloaded SharePoint files for data exposure.
* Investigate `yomark.pdf` and any credential-store references it contained.
* Strengthen Conditional Access policies to block or challenge anonymous/VPN sign-ins.
* Require MFA for all cloud applications, including Outlook, Teams, SharePoint, and Power Automate.
* Alert on finance users accessing Microsoft Flow Portal or creating new automation unexpectedly.
* Alert on new inbox rules that move, delete, or forward mail from finance-related contacts.
* Alert on Graph API `sendMail` or `forward` calls from unusual App IDs or service principals.
