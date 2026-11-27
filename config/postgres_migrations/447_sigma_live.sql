-- SigmaHQ starter rules, Detection Rule License 1.1 (config/sigma/licenses/DRL-1.1.txt).
-- YAML literals are the exact bytes in config/sigma/starter, pinned to the SHA below.
begin;
set local lock_timeout='5s';
select pg_advisory_xact_lock(hashtext('sli_sigma_live447_migration'));
do $$ begin
    if not pg_has_role(session_user,'adlog_storage_owner','MEMBER')
        or not exists(select 1 from public.schema_migrations where version=445 and name='file_audit_check_receipt_retention')
        or exists(select 1 from public.schema_migrations where version>=447) then
        raise exception 'sigma_live447_preflight' using errcode='55000';
    end if;
end $$;
set local role adlog_storage_owner;

-- Staging stays inside this transaction and requires only schema privileges.
create table public.sigma_seed433(
    rule_id uuid primary key, sha text, path text, title text, author text, level text, status text, yaml text, canonical jsonb,
    check(encode(sha256(convert_to(yaml,'UTF8')),'hex')=sha)
);
revoke all on public.sigma_seed433 from public,adlog_user,adlog_semantic_worker,adlog_storage_worker;
insert into public.sigma_seed433 values
('14c71865-6cd3-44ae-adaa-1db923fae5f2','5b5ec26c8f1bc18f2f62fa4b0f062aeda129942cdebf5f6993aa23ba64449cba','rules/windows/powershell/powershell_script/posh_ps_tamper_windows_defender_set_mp.yml','Tamper Windows Defender - ScriptBlockLogging','frack113, elhoim, Tim Shelton (fps, alias support), Swachchhanda Shrawan Poudel, Nasreddine Bencherchali (Nextron Systems)','high','test',$sigma$title: Tamper Windows Defender - ScriptBlockLogging
id: 14c71865-6cd3-44ae-adaa-1db923fae5f2
related:
    - id: ec19ebab-72dc-40e1-9728-4c0b805d722c
      type: derived
status: test
description: Detects PowerShell scripts attempting to disable scheduled scanning and other parts of Windows Defender ATP or set default actions to allow.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.001/T1562.001.md
    - https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=windowsserver2022-ps
    - https://bidouillesecurity.com/disable-windows-defender-in-powershell/
author: frack113, elhoim, Tim Shelton (fps, alias support), Swachchhanda Shrawan Poudel, Nasreddine Bencherchali (Nextron Systems)
date: 2022-01-16
modified: 2024-01-02
tags:
    - attack.defense-impairment
    - attack.t1685
logsource:
    product: windows
    category: ps_script
    definition: 'Requirements: Script Block Logging must be enabled'
detection:
    selection_options_disabling_preference:
        ScriptBlockText|contains: 'Set-MpPreference'
    selection_options_disabling_function:
        ScriptBlockText|contains:
            - '-dbaf $true'
            - '-dbaf 1'
            - '-dbm $true'
            - '-dbm 1'
            - '-dips $true'
            - '-dips 1'
            - '-DisableArchiveScanning $true'
            - '-DisableArchiveScanning 1'
            - '-DisableBehaviorMonitoring $true'
            - '-DisableBehaviorMonitoring 1'
            - '-DisableBlockAtFirstSeen $true'
            - '-DisableBlockAtFirstSeen 1'
            - '-DisableCatchupFullScan $true'
            - '-DisableCatchupFullScan 1'
            - '-DisableCatchupQuickScan $true'
            - '-DisableCatchupQuickScan 1'
            - '-DisableIntrusionPreventionSystem $true'
            - '-DisableIntrusionPreventionSystem 1'
            - '-DisableIOAVProtection $true'
            - '-DisableIOAVProtection 1'
            - '-DisableRealtimeMonitoring $true'
            - '-DisableRealtimeMonitoring 1'
            - '-DisableRemovableDriveScanning $true'
            - '-DisableRemovableDriveScanning 1'
            - '-DisableScanningMappedNetworkDrivesForFullScan $true'
            - '-DisableScanningMappedNetworkDrivesForFullScan 1'
            - '-DisableScanningNetworkFiles $true'
            - '-DisableScanningNetworkFiles 1'
            - '-DisableScriptScanning $true'
            - '-DisableScriptScanning 1'
            - '-MAPSReporting $false'
            - '-MAPSReporting 0'
            - '-drdsc $true'
            - '-drdsc 1'
            - '-drtm $true'
            - '-drtm 1'
            - '-dscrptsc $true'
            - '-dscrptsc 1'
            - '-dsmndf $true'
            - '-dsmndf 1'
            - '-dsnf $true'
            - '-dsnf 1'
            - '-dss $true'
            - '-dss 1'
    selection_other_default_actions_allow:
        ScriptBlockText|contains: 'Set-MpPreference'
    selection_other_default_actions_func:
        ScriptBlockText|contains:
            - 'HighThreatDefaultAction Allow'
            - 'htdefac Allow'
            - 'LowThreatDefaultAction Allow'
            - 'ltdefac Allow'
            - 'ModerateThreatDefaultAction Allow'
            - 'mtdefac Allow'
            - 'SevereThreatDefaultAction Allow'
            - 'stdefac Allow'
    condition: all of selection_options_disabling_* or all of selection_other_default_actions_*
falsepositives:
    - Legitimate PowerShell scripts that disable Windows Defender for troubleshooting purposes. Must be investigated.
level: high
regression_tests_path: regression_data/rules/windows/powershell/powershell_script/posh_ps_tamper_windows_defender_set_mp/info.yml
$sigma$,$canonical${"title":"Tamper Windows Defender - ScriptBlockLogging","id":"14c71865-6cd3-44ae-adaa-1db923fae5f2","related":[{"id":"ec19ebab-72dc-40e1-9728-4c0b805d722c","type":"derived"}],"status":"test","description":"Detects PowerShell scripts attempting to disable scheduled scanning and other parts of Windows Defender ATP or set default actions to allow.","references":["https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1562.001/T1562.001.md","https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference?view=windowsserver2022-ps","https://bidouillesecurity.com/disable-windows-defender-in-powershell/"],"author":"frack113, elhoim, Tim Shelton (fps, alias support), Swachchhanda Shrawan Poudel, Nasreddine Bencherchali (Nextron Systems)","date":"2022-01-16","modified":"2024-01-02","tags":["attack.defense-impairment","attack.t1685"],"logsource":{"product":"windows","category":"ps_script","definition":"Requirements: Script Block Logging must be enabled"},"detection":{"selection_options_disabling_preference":{"ScriptBlockText|contains":"Set-MpPreference"},"selection_options_disabling_function":{"ScriptBlockText|contains":["-dbaf $true","-dbaf 1","-dbm $true","-dbm 1","-dips $true","-dips 1","-DisableArchiveScanning $true","-DisableArchiveScanning 1","-DisableBehaviorMonitoring $true","-DisableBehaviorMonitoring 1","-DisableBlockAtFirstSeen $true","-DisableBlockAtFirstSeen 1","-DisableCatchupFullScan $true","-DisableCatchupFullScan 1","-DisableCatchupQuickScan $true","-DisableCatchupQuickScan 1","-DisableIntrusionPreventionSystem $true","-DisableIntrusionPreventionSystem 1","-DisableIOAVProtection $true","-DisableIOAVProtection 1","-DisableRealtimeMonitoring $true","-DisableRealtimeMonitoring 1","-DisableRemovableDriveScanning $true","-DisableRemovableDriveScanning 1","-DisableScanningMappedNetworkDrivesForFullScan $true","-DisableScanningMappedNetworkDrivesForFullScan 1","-DisableScanningNetworkFiles $true","-DisableScanningNetworkFiles 1","-DisableScriptScanning $true","-DisableScriptScanning 1","-MAPSReporting $false","-MAPSReporting 0","-drdsc $true","-drdsc 1","-drtm $true","-drtm 1","-dscrptsc $true","-dscrptsc 1","-dsmndf $true","-dsmndf 1","-dsnf $true","-dsnf 1","-dss $true","-dss 1"]},"selection_other_default_actions_allow":{"ScriptBlockText|contains":"Set-MpPreference"},"selection_other_default_actions_func":{"ScriptBlockText|contains":["HighThreatDefaultAction Allow","htdefac Allow","LowThreatDefaultAction Allow","ltdefac Allow","ModerateThreatDefaultAction Allow","mtdefac Allow","SevereThreatDefaultAction Allow","stdefac Allow"]},"condition":"all of selection_options_disabling_* or all of selection_other_default_actions_*"},"falsepositives":["Legitimate PowerShell scripts that disable Windows Defender for troubleshooting purposes. Must be investigated."],"level":"high","regression_tests_path":"regression_data/rules/windows/powershell/powershell_script/posh_ps_tamper_windows_defender_set_mp/info.yml"}$canonical$::jsonb),
('d99b79d2-0a6f-4f46-ad8b-260b6e17f982','ac270c491cfcd9f5ed3b69f3d7cd73b7e87166d761ca0b5ded4238e5117476b9','rules/windows/builtin/security/win_security_audit_log_cleared.yml','Security Eventlog Cleared','Florian Roth (Nextron Systems)','high','test',$sigma$title: Security Eventlog Cleared
id: d99b79d2-0a6f-4f46-ad8b-260b6e17f982
related:
    - id: f2f01843-e7b8-4f95-a35a-d23584476423
      type: obsolete
    - id: a122ac13-daf8-4175-83a2-72c387be339d
      type: obsolete
status: test
description: One of the Windows Eventlogs has been cleared. e.g. caused by "wevtutil cl" command execution
references:
    - https://twitter.com/deviouspolack/status/832535435960209408
    - https://www.hybrid-analysis.com/sample/027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745?environmentId=100
    - https://github.com/Azure/Azure-Sentinel/blob/f99542b94afe0ad2f19a82cc08262e7ac8e1428e/Detections/SecurityEvent/SecurityEventLogCleared.yaml
author: Florian Roth (Nextron Systems)
date: 2017-01-10
modified: 2022-02-24
tags:
    - attack.defense-impairment
    - attack.t1685.005
    - car.2016-04-002
logsource:
    product: windows
    service: security
detection:
    selection_517:
        EventID: 517
        Provider_Name: Security
    selection_1102:
        EventID: 1102
        Provider_Name: Microsoft-Windows-Eventlog
    condition: 1 of selection_*
falsepositives:
    - Rollout of log collection agents (the setup routine often includes a reset of the local Eventlog)
    - System provisioning (system reset before the golden image creation)
level: high
$sigma$,$canonical${"title":"Security Eventlog Cleared","id":"d99b79d2-0a6f-4f46-ad8b-260b6e17f982","related":[{"id":"f2f01843-e7b8-4f95-a35a-d23584476423","type":"obsolete"},{"id":"a122ac13-daf8-4175-83a2-72c387be339d","type":"obsolete"}],"status":"test","description":"One of the Windows Eventlogs has been cleared. e.g. caused by \"wevtutil cl\" command execution","references":["https://twitter.com/deviouspolack/status/832535435960209408","https://www.hybrid-analysis.com/sample/027cc450ef5f8c5f653329641ec1fed91f694e0d229928963b30f6b0d7d3a745?environmentId=100","https://github.com/Azure/Azure-Sentinel/blob/f99542b94afe0ad2f19a82cc08262e7ac8e1428e/Detections/SecurityEvent/SecurityEventLogCleared.yaml"],"author":"Florian Roth (Nextron Systems)","date":"2017-01-10","modified":"2022-02-24","tags":["attack.defense-impairment","attack.t1685.005","car.2016-04-002"],"logsource":{"product":"windows","service":"security"},"detection":{"selection_517":{"EventID":517,"Provider_Name":"Security"},"selection_1102":{"EventID":1102,"Provider_Name":"Microsoft-Windows-Eventlog"},"condition":"1 of selection_*"},"falsepositives":["Rollout of log collection agents (the setup routine often includes a reset of the local Eventlog)","System provisioning (system reset before the golden image creation)"],"level":"high"}$canonical$::jsonb),
('7b449a5e-1db5-4dd0-a2dc-4e3a67282538','f455ebd3c6ea873c0e9ac3c059b3a0a62200fea73674ea4080c111b4325846d3','rules/windows/builtin/security/win_security_hidden_user_creation.yml','Hidden Local User Creation','Christian Burkard (Nextron Systems)','high','test',$sigma$title: Hidden Local User Creation
id: 7b449a5e-1db5-4dd0-a2dc-4e3a67282538
status: test
description: Detects the creation of a local hidden user account which should not happen for event ID 4720.
references:
    - https://twitter.com/SBousseaden/status/1387743867663958021
author: Christian Burkard (Nextron Systems)
date: 2021-05-03
modified: 2024-01-16
tags:
    - attack.persistence
    - attack.t1136.001
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4720
        TargetUserName|endswith: '$'
    filter_main_homegroup:
        TargetUserName: 'HomeGroupUser$'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: high
$sigma$,$canonical${"title":"Hidden Local User Creation","id":"7b449a5e-1db5-4dd0-a2dc-4e3a67282538","status":"test","description":"Detects the creation of a local hidden user account which should not happen for event ID 4720.","references":["https://twitter.com/SBousseaden/status/1387743867663958021"],"author":"Christian Burkard (Nextron Systems)","date":"2021-05-03","modified":"2024-01-16","tags":["attack.persistence","attack.t1136.001"],"logsource":{"product":"windows","service":"security"},"detection":{"selection":{"EventID":4720,"TargetUserName|endswith":"$"},"filter_main_homegroup":{"TargetUserName":"HomeGroupUser$"},"condition":"selection and not 1 of filter_main_*"},"falsepositives":["Unknown"],"level":"high"}$canonical$::jsonb),
('cfeed607-6aa4-4bbd-9627-b637deb723c8','b6c0b0480d29657c914dd954a6e581cb2c9bad347231f8461a21dca50e89522b','rules/windows/builtin/security/win_security_new_or_renamed_user_account_with_dollar_sign.yml','New or Renamed User Account with ''$'' Character','Ilyas Ochkov, oscd.community','medium','test',$sigma$title: New or Renamed User Account with '$' Character
id: cfeed607-6aa4-4bbd-9627-b637deb723c8
status: test
description: |
    Detects the creation of a user with the "$" character. This can be used by attackers to hide a user or trick detection systems that lack the parsing mechanisms.
references:
    - https://twitter.com/SBousseaden/status/1387743867663958021
author: Ilyas Ochkov, oscd.community
date: 2019-10-25
modified: 2024-01-16
tags:
    - attack.stealth
    - attack.t1036
logsource:
    product: windows
    service: security
detection:
    selection_create:
        EventID: 4720 # create user
        SamAccountName|contains: '$'
    selection_rename:
        EventID: 4781 # rename user
        NewTargetUserName|contains: '$'
    filter_main_homegroup:
        EventID: 4720
        TargetUserName: 'HomeGroupUser$'
    condition: 1 of selection_* and not 1 of filter_main_*
falsepositives:
    - Unknown
level: medium
$sigma$,$canonical${"title":"New or Renamed User Account with '$' Character","id":"cfeed607-6aa4-4bbd-9627-b637deb723c8","status":"test","description":"Detects the creation of a user with the \"$\" character. This can be used by attackers to hide a user or trick detection systems that lack the parsing mechanisms.\n","references":["https://twitter.com/SBousseaden/status/1387743867663958021"],"author":"Ilyas Ochkov, oscd.community","date":"2019-10-25","modified":"2024-01-16","tags":["attack.stealth","attack.t1036"],"logsource":{"product":"windows","service":"security"},"detection":{"selection_create":{"EventID":4720,"SamAccountName|contains":"$"},"selection_rename":{"EventID":4781,"NewTargetUserName|contains":"$"},"filter_main_homegroup":{"EventID":4720,"TargetUserName":"HomeGroupUser$"},"condition":"1 of selection_* and not 1 of filter_main_*"},"falsepositives":["Unknown"],"level":"medium"}$canonical$::jsonb),
('192a0330-c20b-4356-90b6-7b7049ae0b87','2368ea5cb7b418337f984ed0a6045a01b3e418d65ccb1568629b8a061ce1632c','rules/windows/builtin/security/account_management/win_security_overpass_the_hash.yml','Successful Overpass the Hash Attempt','Roberto Rodriguez (source), Dominik Schaudel (rule)','high','test',$sigma$title: Successful Overpass the Hash Attempt
id: 192a0330-c20b-4356-90b6-7b7049ae0b87
status: test
description: Detects successful logon with logon type 9 (NewCredentials) which matches the Overpass the Hash behavior of e.g Mimikatz's sekurlsa::pth module.
references:
    - https://web.archive.org/web/20220419045003/https://cyberwardog.blogspot.com/2017/04/chronicles-of-threat-hunter-hunting-for.html
author: Roberto Rodriguez (source), Dominik Schaudel (rule)
date: 2018-02-12
modified: 2021-11-27
tags:
    - attack.lateral-movement
    - attack.s0002
    - attack.t1550.002
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 9
        LogonProcessName: seclogo
        AuthenticationPackageName: Negotiate
    condition: selection
falsepositives:
    - Runas command-line tool using /netonly parameter
level: high
$sigma$,$canonical${"title":"Successful Overpass the Hash Attempt","id":"192a0330-c20b-4356-90b6-7b7049ae0b87","status":"test","description":"Detects successful logon with logon type 9 (NewCredentials) which matches the Overpass the Hash behavior of e.g Mimikatz's sekurlsa::pth module.","references":["https://web.archive.org/web/20220419045003/https://cyberwardog.blogspot.com/2017/04/chronicles-of-threat-hunter-hunting-for.html"],"author":"Roberto Rodriguez (source), Dominik Schaudel (rule)","date":"2018-02-12","modified":"2021-11-27","tags":["attack.lateral-movement","attack.s0002","attack.t1550.002"],"logsource":{"product":"windows","service":"security"},"detection":{"selection":{"EventID":4624,"LogonType":9,"LogonProcessName":"seclogo","AuthenticationPackageName":"Negotiate"},"condition":"selection"},"falsepositives":["Runas command-line tool using /netonly parameter"],"level":"high"}$canonical$::jsonb),
('8eef149c-bd26-49f2-9e5a-9b00e3af499b','81e9c4aabcbbe001c879e06b5990737616772404174fb2138ff616cddf0a4443','rules/windows/builtin/security/account_management/win_security_pass_the_hash_2.yml','Pass the Hash Activity 2','Dave Kennedy, Jeff Warren (method) / David Vassallo (rule)','medium','stable',$sigma$title: Pass the Hash Activity 2
id: 8eef149c-bd26-49f2-9e5a-9b00e3af499b
status: stable
description: Detects the attack technique pass the hash which is used to move laterally inside the network
references:
    - https://github.com/iadgov/Event-Forwarding-Guidance/tree/master/Events
    - https://web.archive.org/web/20170909091934/https://blog.binarydefense.com/reliably-detecting-pass-the-hash-through-event-log-analysis
    - https://blog.stealthbits.com/how-to-detect-pass-the-hash-attacks/
author: Dave Kennedy, Jeff Warren (method) / David Vassallo (rule)
date: 2019-06-14
modified: 2022-10-05
tags:
    - attack.lateral-movement
    - attack.t1550.002
logsource:
    product: windows
    service: security
    definition: The successful use of PtH for lateral movement between workstations would trigger event ID 4624
detection:
    selection_logon3:
        EventID: 4624
        SubjectUserSid: 'S-1-0-0'
        LogonType: 3
        LogonProcessName: 'NtLmSsp'
        KeyLength: 0
    selection_logon9:
        EventID: 4624
        LogonType: 9
        LogonProcessName: 'seclogo'
    filter:
        TargetUserName: 'ANONYMOUS LOGON'
    condition: 1 of selection_* and not filter
falsepositives:
    - Administrator activity
level: medium
$sigma$,$canonical${"title":"Pass the Hash Activity 2","id":"8eef149c-bd26-49f2-9e5a-9b00e3af499b","status":"stable","description":"Detects the attack technique pass the hash which is used to move laterally inside the network","references":["https://github.com/iadgov/Event-Forwarding-Guidance/tree/master/Events","https://web.archive.org/web/20170909091934/https://blog.binarydefense.com/reliably-detecting-pass-the-hash-through-event-log-analysis","https://blog.stealthbits.com/how-to-detect-pass-the-hash-attacks/"],"author":"Dave Kennedy, Jeff Warren (method) / David Vassallo (rule)","date":"2019-06-14","modified":"2022-10-05","tags":["attack.lateral-movement","attack.t1550.002"],"logsource":{"product":"windows","service":"security","definition":"The successful use of PtH for lateral movement between workstations would trigger event ID 4624"},"detection":{"selection_logon3":{"EventID":4624,"SubjectUserSid":"S-1-0-0","LogonType":3,"LogonProcessName":"NtLmSsp","KeyLength":0},"selection_logon9":{"EventID":4624,"LogonType":9,"LogonProcessName":"seclogo"},"filter":{"TargetUserName":"ANONYMOUS LOGON"},"condition":"1 of selection_* and not filter"},"falsepositives":["Administrator activity"],"level":"medium"}$canonical$::jsonb),
('749c9f5e-b353-4b90-a9c1-05243357ca4b','360241bead399ee3e55e57776325e16a6833d78fadea76647a6187d33f1cbf79','rules/windows/builtin/security/account_management/win_security_susp_privesc_kerberos_relay_over_ldap.yml','Potential Privilege Escalation via Local Kerberos Relay over LDAP','Elastic, @SBousseaden','high','test',$sigma$title: Potential Privilege Escalation via Local Kerberos Relay over LDAP
id: 749c9f5e-b353-4b90-a9c1-05243357ca4b
status: test
description: |
    Detects a suspicious local successful logon event where the Logon Package is Kerberos, the remote address is set to localhost, and the target user SID is the built-in local Administrator account.
    This may indicate an attempt to leverage a Kerberos relay attack variant that can be used to elevate privilege locally from a domain joined limited user to local System privileges.
references:
    - https://twitter.com/sbousseaden/status/1518976397364056071?s=12&t=qKO5eKHvWhAP19a50FTZ7g
    - https://github.com/elastic/detection-rules/blob/5fe7833312031a4787e07893e27e4ea7a7665745/rules/_deprecated/privilege_escalation_krbrelayup_suspicious_logon.toml#L38
author: Elastic, @SBousseaden
date: 2022-04-27
modified: 2024-08-13
tags:
    - attack.privilege-escalation
    - attack.credential-access
    - attack.t1548
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 3
        AuthenticationPackageName: 'Kerberos'
        IpAddress: '127.0.0.1'
        TargetUserSid|startswith: 'S-1-5-21-'
        TargetUserSid|endswith: '-500'
    filter_main_ip_null:
        IpPort: '0'
    condition: selection and not 1 of filter_main_*
falsepositives:
    - Unknown
level: high
$sigma$,$canonical${"title":"Potential Privilege Escalation via Local Kerberos Relay over LDAP","id":"749c9f5e-b353-4b90-a9c1-05243357ca4b","status":"test","description":"Detects a suspicious local successful logon event where the Logon Package is Kerberos, the remote address is set to localhost, and the target user SID is the built-in local Administrator account.\nThis may indicate an attempt to leverage a Kerberos relay attack variant that can be used to elevate privilege locally from a domain joined limited user to local System privileges.\n","references":["https://twitter.com/sbousseaden/status/1518976397364056071?s=12&t=qKO5eKHvWhAP19a50FTZ7g","https://github.com/elastic/detection-rules/blob/5fe7833312031a4787e07893e27e4ea7a7665745/rules/_deprecated/privilege_escalation_krbrelayup_suspicious_logon.toml#L38"],"author":"Elastic, @SBousseaden","date":"2022-04-27","modified":"2024-08-13","tags":["attack.privilege-escalation","attack.credential-access","attack.t1548"],"logsource":{"product":"windows","service":"security"},"detection":{"selection":{"EventID":4624,"LogonType":3,"AuthenticationPackageName":"Kerberos","IpAddress":"127.0.0.1","TargetUserSid|startswith":"S-1-5-21-","TargetUserSid|endswith":"-500"},"filter_main_ip_null":{"IpPort":"0"},"condition":"selection and not 1 of filter_main_*"},"falsepositives":["Unknown"],"level":"high"}$canonical$::jsonb),
('3a734d25-df5c-4b99-8034-af1ddb5883a4','0351c4d3781057a81e1312fb947d27d18685b4683e6a4ff473e23b5a0df34888','rules/windows/builtin/security/win_security_susp_scheduled_task_creation.yml','Suspicious Scheduled Task Creation','Nasreddine Bencherchali (Nextron Systems)','high','test',$sigma$title: Suspicious Scheduled Task Creation
id: 3a734d25-df5c-4b99-8034-af1ddb5883a4
status: test
description: Detects suspicious scheduled task creation events. Based on attributes such as paths, commands line flags, etc.
references:
    - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698
author: Nasreddine Bencherchali (Nextron Systems)
date: 2022-12-05
modified: 2022-12-07
tags:
    - attack.execution
    - attack.privilege-escalation
    - attack.persistence
    - attack.t1053.005
logsource:
    product: windows
    service: security
    definition: 'The Advanced Audit Policy setting Object Access > Audit Other Object Access Events has to be configured to allow this detection. We also recommend extracting the Command field from the embedded XML in the event data.'
detection:
    selection_eid:
        EventID: 4698
    selection_paths:
        TaskContent|contains:
            - '\AppData\Local\Temp\'
            - '\AppData\Roaming\'
            - '\Users\Public\'
            - '\WINDOWS\Temp\'
            - 'C:\Temp\'
            - '\Desktop\'
            - '\Downloads\'
            - '\Temporary Internet'
            - 'C:\ProgramData\'
            - 'C:\Perflogs\'
    selection_commands:
        TaskContent|contains:
            - 'regsvr32'
            - 'rundll32'
            - 'cmd.exe</Command>'
            - 'cmd</Command>'
            - '<Arguments>/c '
            - '<Arguments>/k '
            - '<Arguments>/r '
            - 'powershell'
            - 'pwsh'
            - 'mshta'
            - 'wscript'
            - 'cscript'
            - 'certutil'
            - 'bitsadmin'
            - 'bash.exe'
            - 'bash '
            - 'scrcons'
            - 'wmic '
            - 'wmic.exe'
            - 'forfiles'
            - 'scriptrunner'
            - 'hh.exe'
    condition: all of selection_*
falsepositives:
    - Unknown
level: high
$sigma$,$canonical${"title":"Suspicious Scheduled Task Creation","id":"3a734d25-df5c-4b99-8034-af1ddb5883a4","status":"test","description":"Detects suspicious scheduled task creation events. Based on attributes such as paths, commands line flags, etc.","references":["https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698"],"author":"Nasreddine Bencherchali (Nextron Systems)","date":"2022-12-05","modified":"2022-12-07","tags":["attack.execution","attack.privilege-escalation","attack.persistence","attack.t1053.005"],"logsource":{"product":"windows","service":"security","definition":"The Advanced Audit Policy setting Object Access > Audit Other Object Access Events has to be configured to allow this detection. We also recommend extracting the Command field from the embedded XML in the event data."},"detection":{"selection_eid":{"EventID":4698},"selection_paths":{"TaskContent|contains":["\\AppData\\Local\\Temp\\","\\AppData\\Roaming\\","\\Users\\Public\\","\\WINDOWS\\Temp\\","C:\\Temp\\","\\Desktop\\","\\Downloads\\","\\Temporary Internet","C:\\ProgramData\\","C:\\Perflogs\\"]},"selection_commands":{"TaskContent|contains":["regsvr32","rundll32","cmd.exe</Command>","cmd</Command>","<Arguments>/c ","<Arguments>/k ","<Arguments>/r ","powershell","pwsh","mshta","wscript","cscript","certutil","bitsadmin","bash.exe","bash ","scrcons","wmic ","wmic.exe","forfiles","scriptrunner","hh.exe"]},"condition":"all of selection_*"},"falsepositives":["Unknown"],"level":"high"}$canonical$::jsonb),
('c265cf08-3f99-46c1-8d59-328247057d57','dd8c29a1518185705daaee566abe921e1ffbe2d5801a3549a52dd59bfefb2885','rules/windows/builtin/security/win_security_user_added_to_local_administrators.yml','User Added to Local Administrator Group','Florian Roth (Nextron Systems)','medium','stable',$sigma$title: User Added to Local Administrator Group
id: c265cf08-3f99-46c1-8d59-328247057d57
status: stable
description: Detects the addition of a new member to the local administrator group, which could be legitimate activity or a sign of privilege escalation activity
references:
    - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4732
    - https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers
author: Florian Roth (Nextron Systems)
date: 2017-03-14
modified: 2021-01-17
tags:
    - attack.initial-access
    - attack.privilege-escalation
    - attack.stealth
    - attack.t1078
    - attack.persistence
    - attack.t1098
logsource:
    product: windows
    service: security
detection:
    selection_eid:
        EventID: 4732
    selection_group:
        - TargetUserName|startswith: 'Administr'
        - TargetSid: 'S-1-5-32-544'
    filter_main_computer_accounts:
        SubjectUserName|endswith: '$'
    condition: all of selection_* and not 1 of filter_*
falsepositives:
    - Legitimate administrative activity
level: medium
$sigma$,$canonical${"title":"User Added to Local Administrator Group","id":"c265cf08-3f99-46c1-8d59-328247057d57","status":"stable","description":"Detects the addition of a new member to the local administrator group, which could be legitimate activity or a sign of privilege escalation activity","references":["https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4732","https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers"],"author":"Florian Roth (Nextron Systems)","date":"2017-03-14","modified":"2021-01-17","tags":["attack.initial-access","attack.privilege-escalation","attack.stealth","attack.t1078","attack.persistence","attack.t1098"],"logsource":{"product":"windows","service":"security"},"detection":{"selection_eid":{"EventID":4732},"selection_group":[{"TargetUserName|startswith":"Administr"},{"TargetSid":"S-1-5-32-544"}],"filter_main_computer_accounts":{"SubjectUserName|endswith":"$"},"condition":"all of selection_* and not 1 of filter_*"},"falsepositives":["Legitimate administrative activity"],"level":"medium"}$canonical$::jsonb),
('1d61f71d-59d2-479e-9562-4ff5f4ead16b','c4b04eaee895b9ff9f4eac96ecdec9782ac88f06967a1a7cf8da86c97ab09313','rules/windows/builtin/system/service_control_manager/win_system_service_install_susp.yml','Suspicious Service Installation','pH-T (Nextron Systems), Florian Roth (Nextron Systems)','high','test',$sigma$title: Suspicious Service Installation
id: 1d61f71d-59d2-479e-9562-4ff5f4ead16b
related:
    - id: ca83e9f3-657a-45d0-88d6-c1ac280caf53
      type: obsolete
    - id: 26481afe-db26-4228-b264-25a29fe6efc7
      type: similar
status: test
description: Detects suspicious service installation commands
references:
    - Internal Research
author: pH-T (Nextron Systems), Florian Roth (Nextron Systems)
date: 2022-03-18
modified: 2023-12-04
tags:
    - attack.persistence
    - attack.privilege-escalation
    - car.2013-09-005
    - attack.t1543.003
logsource:
    product: windows
    service: system
detection:
    selection:
        Provider_Name: 'Service Control Manager'
        EventID: 7045
        ImagePath|contains:
            - ' -nop '
            - ' -sta '
            - ' -w hidden '
            - ':\Temp\'
            - '.downloadfile(' # PowerShell download command
            - '.downloadstring(' # PowerShell download command
            - '\ADMIN$\'
            - '\Perflogs\'
            - '&&'
    condition: selection
falsepositives:
    - Unknown
level: high
$sigma$,$canonical${"title":"Suspicious Service Installation","id":"1d61f71d-59d2-479e-9562-4ff5f4ead16b","related":[{"id":"ca83e9f3-657a-45d0-88d6-c1ac280caf53","type":"obsolete"},{"id":"26481afe-db26-4228-b264-25a29fe6efc7","type":"similar"}],"status":"test","description":"Detects suspicious service installation commands","references":["Internal Research"],"author":"pH-T (Nextron Systems), Florian Roth (Nextron Systems)","date":"2022-03-18","modified":"2023-12-04","tags":["attack.persistence","attack.privilege-escalation","car.2013-09-005","attack.t1543.003"],"logsource":{"product":"windows","service":"system"},"detection":{"selection":{"Provider_Name":"Service Control Manager","EventID":7045,"ImagePath|contains":[" -nop "," -sta "," -w hidden ",":\\Temp\\",".downloadfile(",".downloadstring(","\\ADMIN$\\","\\Perflogs\\","&&"]},"condition":"selection"},"falsepositives":["Unknown"],"level":"high"}$canonical$::jsonb),
('42c575ea-e41e-41f1-b248-8093c3e82a28','aa4917e80e3568079a2ab65a9700bb541e44cc94f920c6906ccbc1a2e339c476','rules/windows/builtin/system/service_control_manager/win_system_service_install_sysinternals_psexec.yml','PsExec Service Installation','Thomas Patzke','medium','test',$sigma$title: PsExec Service Installation
id: 42c575ea-e41e-41f1-b248-8093c3e82a28
status: test
description: Detects PsExec service installation and execution events
references:
    - https://www.jpcert.or.jp/english/pub/sr/ir_research.html
    - https://jpcertcc.github.io/ToolAnalysisResultSheet
author: Thomas Patzke
date: 2017-06-12
modified: 2023-08-04
tags:
    - attack.execution
    - attack.t1569.002
    - attack.s0029
logsource:
    product: windows
    service: system
detection:
    selection_eid:
        Provider_Name: 'Service Control Manager'
        EventID: 7045
    selection_service:
        - ServiceName: 'PSEXESVC'
        - ImagePath|endswith: '\PSEXESVC.exe'
    condition: all of selection_*
falsepositives:
    - Unknown
level: medium
$sigma$,$canonical${"title":"PsExec Service Installation","id":"42c575ea-e41e-41f1-b248-8093c3e82a28","status":"test","description":"Detects PsExec service installation and execution events","references":["https://www.jpcert.or.jp/english/pub/sr/ir_research.html","https://jpcertcc.github.io/ToolAnalysisResultSheet"],"author":"Thomas Patzke","date":"2017-06-12","modified":"2023-08-04","tags":["attack.execution","attack.t1569.002","attack.s0029"],"logsource":{"product":"windows","service":"system"},"detection":{"selection_eid":{"Provider_Name":"Service Control Manager","EventID":7045},"selection_service":[{"ServiceName":"PSEXESVC"},{"ImagePath|endswith":"\\PSEXESVC.exe"}],"condition":"all of selection_*"},"falsepositives":["Unknown"],"level":"medium"}$canonical$::jsonb);


-- The installation identity exists before this migration. A reserved source in
-- the Sigma registry holds package revisions independently of DC enrollment.
alter table public.sigma_seed433 add column installation_id uuid;
update public.sigma_seed433 set installation_id=(select installation_id from public.semantic_default_installation);
grant select on public.sigma_seed433 to adlog_sigma_owner;
set local role adlog_sigma_owner;
insert into sli_sigma.sigma_rule_revisions(
    installation_id,plugin_id,source_instance_id,rule_id,raw_yaml,canonical_rule,
    upstream_commit,status,level,tags,author,license,source_uri)
select installation_id,'sli.sigma','starter',rule_id,yaml,
    canonical,
    '7d8b152a5fc062ebd309f62ae4d8276aca2786af',status,level,coalesce(canonical->'tags','[]'::jsonb),canonical->>'author','DRL-1.1',
    'https://github.com/SigmaHQ/sigma/blob/7d8b152a5fc062ebd309f62ae4d8276aca2786af/'||path
from public.sigma_seed433 on conflict do nothing;
set local role adlog_plugin_lifecycle_owner;
grant select(plugin_id,package_lifecycle,desired_activation,component_runtime)
    on public.plugin_installations_v1 to adlog_storage_owner;
set local role adlog_storage_owner;

create table public.sigma_live_rules433 (
    rule_id uuid primary key,
    raw_sha256 text not null,
    enabled boolean not null default true,
    enabled_at timestamptz not null default clock_timestamp()
);
insert into public.sigma_live_rules433(rule_id,raw_sha256,enabled)
select s.rule_id,s.sha,coalesce(a.enabled,true) from public.sigma_seed433 s
left join lateral (
    select (details->>'enabled')::boolean as enabled from public.semantic_control_audit
    where action='sigma_rule_live' and target=s.rule_id::text order by id desc limit 1
) a on true;
drop table public.sigma_seed433;

-- The inbox fills in the event transaction. A numeric event-id frontier alone
-- would miss allocated IDs whose transactions commit after the frontier moves.
create table public.sigma_live_inbox433 (
    event_id bigint not null,
    occurred_at timestamptz not null,
    collected_at timestamptz not null default clock_timestamp(),
    primary key(event_id,occurred_at)
);
create index sigma_live_inbox_collected433 on public.sigma_live_inbox433(collected_at);
create table public.sigma_live_position433 (
    singleton boolean primary key check(singleton),
    last_event_id bigint not null,
    processed bigint not null,
    rejected bigint not null
);
insert into public.sigma_live_position433 values(true,0,0,0);

create table public.sigma_live_hits433 (
    rule_id uuid not null references public.sigma_live_rules433,
    event_id bigint not null,
    occurred_at timestamptz not null,
    scope_key text not null,
    entity_key text not null,
    representative boolean not null default false,
    hour timestamptz not null,
    document jsonb,
    primary key(rule_id,event_id,occurred_at)
);
create index sigma_live_hits_hour433 on public.sigma_live_hits433(rule_id,scope_key,hour);
create index sigma_live_hits_stats433 on public.sigma_live_hits433(rule_id,occurred_at);
create unique index sigma_live_hits_representative433 on public.sigma_live_hits433(rule_id,scope_key,hour) where representative;
create index sigma_live_hits_pending433 on public.sigma_live_hits433(hour) where document is not null;
create table public.sigma_live_subjects433 (
    rule_id uuid not null references public.sigma_live_rules433,
    entity_key text not null,
    match_id text not null unique,
    repeat_count bigint not null default 0 check(repeat_count>=0),
    primary key(rule_id,entity_key)
);
-- A previously published subject remains claimed after a rollback and reinstall.
insert into public.sigma_live_subjects433(rule_id,entity_key,match_id,repeat_count)
select distinct on (m.rule_id,m.document_json->>'entity_key')
    m.rule_id::uuid,m.document_json->>'entity_key',m.match_id,f.repeat_count
from public.semantic_detection_matches m
join public.sigma_live_rules433 r on r.rule_id::text=m.rule_id
join public.semantic_risk_evaluation_jobs j on j.detection_match_id=m.match_id
join public.semantic_risk_evaluation_results result using(job_id)
join public.semantic_finding_publications published using(scenario_id)
join public.findings f on f.id=published.finding_id
where m.document_json ? 'sigma_starter' and j.policy_id like 'default:sigma:%'
order by m.rule_id,m.document_json->>'entity_key',m.created_at,m.match_id;

revoke all on public.sigma_live_rules433,public.sigma_live_inbox433,public.sigma_live_position433,
    public.sigma_live_hits433,public.sigma_live_subjects433 from public,adlog_user,adlog_semantic_worker,adlog_storage_worker;
grant select on public.sigma_live_rules433 to adlog_semantic_worker;
grant update on public.sigma_live_position433 to adlog_semantic_worker;
grant select,delete on public.sigma_live_inbox433 to adlog_semantic_worker;
grant select,insert,update(document,representative),delete on public.sigma_live_hits433 to adlog_semantic_worker;
grant select,insert,update(repeat_count),delete on public.sigma_live_subjects433 to adlog_semantic_worker;
grant select on public.sigma_live_position433 to adlog_semantic_worker;

-- Repeats advance a published problem's count without creating a new
-- evaluation job or attributing another subject's evidence to that problem.
create function public.apply_sigma_repeats433(p_match text,p_delta integer) returns void
language plpgsql security invoker set search_path=pg_catalog,pg_temp as $$
begin
    if p_delta is null or p_delta not between 0 and 64 then
        raise exception 'sigma_repeat_bounds' using errcode='22023';
    end if;
    with counted as (
        update public.sigma_live_subjects433 set repeat_count=repeat_count+p_delta
        where match_id=p_match returning match_id,repeat_count
    )
    update public.findings f set repeat_count=c.repeat_count,updated_at=now()
    from counted c join public.semantic_risk_evaluation_jobs j on j.detection_match_id=c.match_id
    join public.semantic_risk_evaluation_results r using(job_id)
    join public.semantic_finding_publications p using(scenario_id)
    where j.policy_id like 'default:sigma:%' and f.id=p.finding_id and f.repeat_count<c.repeat_count;
end $$;
revoke all on function public.apply_sigma_repeats433(text,integer) from public,adlog_user,adlog_storage_worker;
grant execute on function public.apply_sigma_repeats433(text,integer) to adlog_semantic_worker;

create function public.sigma_enqueue433() returns trigger
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
begin
    if tg_op='UPDATE' and new.source_sha256 is not distinct from old.source_sha256 then
        return null;
    end if;
    if new.source_sha256 is not null and new.method#>>'{$origin,plugin_id}'='sli.windows.ad-dc'
       and ((new.event_kind in (1102,4624,4698,4720,4732,4781) and new.method->>'$channel'='Security')
         or (new.event_kind=7045 and new.method->>'$channel'='System')
         or (new.event_kind=4104 and new.method->>'$channel'='Microsoft-Windows-PowerShell/Operational'))
       and exists(select 1 from public.plugin_installations_v1 where plugin_id='sli.sigma'
           and package_lifecycle='registered' and desired_activation='enabled_manual' and component_runtime='running') then
        insert into public.sigma_live_inbox433(event_id,occurred_at) values(new.event_id,new.time_created_utc)
        on conflict do nothing;
    end if;
    return null;
end $$;
revoke all on function public.sigma_enqueue433() from public;
create trigger sigma_enqueue433 after insert or update of source_sha256 on public.event_hot
for each row execute function public.sigma_enqueue433();

-- The reader exposes original data only for the worker's exact active binding.
-- Denied and unbound rows stay in the inbox for discovery or bounded expiry.
create function public.read_admitted_sigma_events(p_limit integer)
returns table(source_event_id bigint, occurred_at timestamptz, collected_at timestamptz,
    domain_id bigint, kind integer, channel text, provider text, record_id bigint,
    scope jsonb, sha256 text, representation_sha256 text, representation text)
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    with batch as materialized (
        select h.event_id,h.time_created_utc,q.collected_at,h.domain_id,h.event_kind,h.method,h.event_record_id,
            origin.scope,h.source_sha256
        from public.sigma_live_inbox433 q join public.event_hot h
          on (h.time_created_utc,h.event_id)=(q.occurred_at,q.event_id)
        cross join lateral (select (h.method->'$origin')-'agent_id'-'log_source_id' as scope) origin
        where q.collected_at>=transaction_timestamp()-interval '24 hours'
          and public.short_ref_allowed337(origin.scope,h.event_id::text,encode(h.source_sha256,'hex'))
        order by q.event_id,q.occurred_at
        limit least(greatest(coalesce(p_limit,0),0),64)
    )
    select b.event_id,b.time_created_utc,b.collected_at,b.domain_id,b.event_kind,b.method->>'$channel',
        b.method->>'$provider',b.event_record_id,b.scope,encode(b.source_sha256,'hex'),
        encode(r.representation_sha256,'hex'),
        case when octet_length(r.representation::text)<=262144 then r.representation::text end
    from batch b left join public.event_source_representations_v2 r
        on r.event_id=b.event_id and r.normalized_hash=b.source_sha256
    order by b.event_id,b.time_created_utc
$$;
revoke all on function public.read_admitted_sigma_events(integer) from public,adlog_user,adlog_storage_worker;
grant execute on function public.read_admitted_sigma_events(integer) to adlog_semantic_worker;

create function public.sigma_starter433()
returns table(rule_id uuid,raw_sha256 text,raw_yaml text,title text,level text,author text,license text,
    source_uri text,enabled boolean,enabled_at timestamptz,manifest_sha256 text)
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select r.rule_id,r.raw_sha256,r.raw_yaml,r.canonical_rule->>'title',r.level,r.author,r.license,
        r.source_uri,c.enabled,c.enabled_at,
        (select encode(sha256(convert_to(string_agg(raw_sha256,'' order by rule_id),'UTF8')),'hex')
            from public.sigma_live_rules433)
    from public.semantic_default_installation i
    join sli_sigma.sigma_rule_revisions r on r.installation_id=i.installation_id
        and r.plugin_id='sli.sigma' and r.source_instance_id='starter'
    join public.sigma_live_rules433 c using(rule_id,raw_sha256)
    order by r.rule_id
$$;
revoke all on function public.sigma_starter433() from public,adlog_user,adlog_storage_worker;
grant execute on function public.sigma_starter433() to adlog_semantic_worker;

create function public.sigma_live_list433()
returns table(rule_id uuid,title text,level text,author text,license text,source_uri text,enabled boolean,matches_24h bigint)
language sql stable security definer set search_path=pg_catalog,pg_temp as $$
    select r.rule_id,r.title,r.level,r.author,r.license,r.source_uri,r.enabled,
        (select count(*) from public.sigma_live_hits433 h where h.rule_id=r.rule_id
          and h.occurred_at>=transaction_timestamp()-interval '24 hours' and h.occurred_at<=transaction_timestamp())
    from public.sigma_starter433() r order by r.title,r.rule_id
$$;
revoke all on function public.sigma_live_list433() from public,adlog_storage_worker,adlog_semantic_worker;
grant execute on function public.sigma_live_list433() to adlog_user;

create function public.sigma_live_toggle433(p_rule uuid,p_enabled boolean,p_actor text) returns boolean
language plpgsql security definer set search_path=pg_catalog,pg_temp as $$
begin
    perform pg_advisory_xact_lock(hashtext('sli_sigma_live433_worker'));
    if not exists(select 1 from public.sigma_live_rules433 where rule_id=p_rule) then return false; end if;
    update public.sigma_live_rules433 set enabled=p_enabled,enabled_at=clock_timestamp()
        where rule_id=p_rule and enabled<>p_enabled;
    if found then
        -- Purge deferred alerts on either transition. Atomic match counts stay.
        update public.sigma_live_hits433 set document=null where rule_id=p_rule and document is not null;
        insert into public.semantic_control_audit(action,target,actor,details)
            values('sigma_rule_live',p_rule::text,p_actor,jsonb_build_object('rule_id',p_rule,'enabled',p_enabled));
    end if;
    return true;
end $$;
revoke all on function public.sigma_live_toggle433(uuid,boolean,text) from public,adlog_storage_worker,adlog_semantic_worker;
grant execute on function public.sigma_live_toggle433(uuid,boolean,text) to adlog_user;

-- Scope-specific subscriptions use the existing risk path and its native
-- evidence checks. The worker can register only a pinned package policy.
create function public.ensure_sigma_starter_policy433(p_id text,p_document text) returns boolean
language plpgsql security definer set search_path=pg_catalog,public,pg_temp as $$
declare d jsonb:=p_document::jsonb; pin jsonb:=d#>'{source_selector,execution}';
    s jsonb:=pin->'scope'; r record; digest bytea:=sha256(convert_to(p_document,'UTF8'));
begin
    select * into r from public.sigma_starter433() where rule_id::text=pin->>'rule_id' and enabled;
    if not found or octet_length(p_document)>8192
       or p_id not like 'default:sigma:'||(pin->>'rule_id')||':%'
       or d->>'type' is distinct from 'scenario_policy'
       or d->>'title' is distinct from r.title
       or d->>'scenario_kind' is distinct from 'sigma.'||(pin->>'rule_id')
       or d#>>'{source_selector,rule_id}' is distinct from pin->>'rule_id'
       or pin->>'rule_sha256' is distinct from r.raw_sha256
       or pin->>'manifest_sha256' is distinct from r.manifest_sha256
       or pin->>'compiler_version' is distinct from 'sli.sigma.compiler.v1'
       or pin->>'mapping_version' is distinct from 'sli.sigma.windows-fields.v2'
       or s->>'plugin_id' is distinct from 'sli.windows.ad-dc'
       or s->>'collection_scope_id' is distinct from ''
       or public.finding_evidence_scope_allowed((s->>'installation_id')::uuid,s->>'plugin_id',
            s->>'source_instance_id',s->>'source_generation','','core_event') is not true then
        raise exception 'sigma_starter_policy_denied' using errcode='42501';
    end if;
    insert into public.semantic_risk_policies(policy_id,policy_version,source_kind,lifecycle_status,definition_json,definition_sha256)
        values(p_id,1,'detection_match','draft',d,digest) on conflict do nothing;
    perform 1 from public.semantic_risk_policies where policy_id=p_id and policy_version=1
        and definition_sha256=digest and definition_json=d for update;
    if not found then raise exception 'sigma_starter_policy_conflict'; end if;
    insert into public.semantic_risk_policy_subscriptions(policy_id,policy_version,source_kind,selector_value,definition_sha256)
        select p_id,1,'detection_match',r.rule_id::text,digest
        where not exists(select 1 from public.semantic_risk_policy_subscriptions where policy_id=p_id and policy_version=1);
    update public.semantic_risk_policies set lifecycle_status='shadow',updated_at=now()
        where policy_id=p_id and policy_version=1 and lifecycle_status='draft';
    insert into public.semantic_policy_admission(policy_id,policy_version,enabled,updated_by)
        values(p_id,1,true,'system:sigma-starter')
        on conflict(policy_id,policy_version) do update set enabled=true,
            updated_by='system:sigma-starter',updated_at=now()
        where semantic_policy_admission.updated_by='system:sigma-rollback';
    return exists(select 1 from public.semantic_risk_policies p join public.semantic_policy_admission a using(policy_id,policy_version)
        where p.policy_id=p_id and p.policy_version=1 and a.enabled
          and public.semantic_policy_mode_v160(p.policy_id,p.policy_version,p.lifecycle_status)='enabled');
end $$;
revoke all on function public.ensure_sigma_starter_policy433(text,text) from public,adlog_user,adlog_storage_worker;
grant execute on function public.ensure_sigma_starter_policy433(text,text) to adlog_semantic_worker;

-- Migration 301 renamed the function bound by the original policy.
-- Use the current, scope-checked resolver for new detection inputs.
alter policy detection_match_scope on public.semantic_detection_matches
with check (public.resolve_finding_evidence_ref(
    (document_json#>>'{evidence,scope,installation_id}')::uuid,
    document_json#>>'{evidence,scope,plugin_id}',document_json#>>'{evidence,scope,source_instance_id}',
    document_json#>>'{evidence,scope,source_generation}',document_json#>>'{evidence,scope,collection_scope_id}',
    document_json#>>'{evidence,storage_kind}',document_json#>>'{evidence,native_id}',
    document_json#>>'{evidence,sha256}'));

insert into public.schema_migrations(version,name) values(447,'sigma_live');
reset role;
commit;
