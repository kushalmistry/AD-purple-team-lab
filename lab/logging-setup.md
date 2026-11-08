# Logging Setup

Detections are only as good as the telemetry. Run these on every Windows VM
(elevated PowerShell), or push them with a GPO on DC01.

## 1. Advanced audit policy

```powershell
$subcategories = @(
  'Logon',
  'Kerberos Authentication Service',
  'Kerberos Service Ticket Operations',
  'Directory Service Access',
  'Security System Extension',
  'Process Creation'
)
foreach ($s in $subcategories) { auditpol /set /subcategory:"$s" /success:enable /failure:enable }

# Include command lines in 4688 process events
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

auditpol /get /category:*   # verify
```

| Rule | Event | Needs |
|---|---|---|
| Kerberoasting (RC4 TGS) | 4769 | Kerberos Service Ticket Operations (DC) |
| AS-REP roasting | 4768 | Kerberos Authentication Service (DC) |
| DCSync | 4662 | Directory Service Access (DC) **+ SACL below** |
| NTLM null-key logon | 4624 | Logon (targets) |
| Remote service execution | 7045 | On by default (System log) |

## 2. SACL for DCSync visibility (DC01 only)

Event 4662 only fires for objects with an auditing entry.

1. Open **Active Directory Users and Computers**, enable **View > Advanced Features**.
2. Right-click the domain root (`lab.local`) > Properties > Security > Advanced > **Auditing** > Add.
3. Principal: `Everyone`, Type: `Success`, Applies to: `This object only`.
4. Under permissions, check **Replicating Directory Changes**, **Replicating Directory Changes All**,
   and **Replicating Directory Changes In Filtered Set**.

## 3. Sysmon (recommended)

Not required by the current rules, but gives you process and network telemetry for
future detections.

```powershell
.\Sysmon64.exe -accepteula -i .\sysmonconfig-export.xml
```

Config: SwiftOnSecurity `sysmon-config` (GitHub).

## 4. Log size

Default Security log size rolls over quickly on a DC. Bump it:

```powershell
wevtutil sl Security /ms:1073741824
```
