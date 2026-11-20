<#
Owned demo.example only. Five SMB fixtures; no audit policy/SACL writes or reboot.
Re-run restores fixture DACL/share grants, preserves existing seed bytes and SACLs.
-InspectOnly is read-only. Output: C:\SLI-Lab\file-audit-state.json (synthetic metadata).
#>
#Requires -Version 5.1
[CmdletBinding()]
param([switch]$InspectOnly)
. "$PSScriptRoot\lab-common.ps1"
$script:FsRoot = 'C:\SLI-Lab-Files'

function Get-LabFileShares {
    @(
        [pscustomobject]@{ Name='LAB-Finance'; Folder='Финансы'; Group='LAB-Department-03'; Rights='Modify' }
        [pscustomobject]@{ Name='LAB-HR'; Folder='Кадры'; Group='LAB-Department-07'; Rights='Modify' }
        [pscustomobject]@{ Name='LAB-Projects'; Folder='Проекты'; Group='LAB-Department-01'; Rights='Modify' }
        [pscustomobject]@{ Name='LAB-Common'; Folder='Общая'; Group='LAB-All'; Rights='ReadAndExecute' }
        [pscustomobject]@{ Name='LAB-Exchange'; Folder='Обмен'; Group='LAB-All'; Rights='Modify' }
    )
}

function Assert-LabFileRoot {
    $null = Assert-LabPath $script:FsRoot
    if (Test-Path -LiteralPath $script:FsRoot) {
        $marker = Join-Path $script:FsRoot '.sli-lab-owned'
        if (-not (Test-Path -LiteralPath $marker) -or [IO.File]::ReadAllText((Assert-LabPath $marker)).Trim() -cne $script:LabMarker) {
            throw 'lab_file_root_not_owned'
        }
        $pending = New-Object 'Collections.Generic.Queue[string]'
        $pending.Enqueue($script:FsRoot)
        while ($pending.Count -gt 0) {
            foreach ($item in Get-ChildItem -LiteralPath $pending.Dequeue() -Force) {
                $null = Assert-LabPath $item.FullName
                if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'lab_file_reparse_rejected' }
                if ($item.PSIsContainer) { $pending.Enqueue($item.FullName) }
            }
        }
    }
    foreach ($share in Get-LabFileShares) {
        $existing = Get-SmbShare -Name $share.Name -ErrorAction SilentlyContinue
        if ($existing -and ($existing.Path -cne (Join-Path $script:FsRoot $share.Folder) -or $existing.Description -cne $script:LabMarker)) {
            throw 'lab_file_share_collision'
        }
    }
}

function Add-LabFileRule($Acl, [string]$Sid, [string]$Rights, [bool]$Directory = $true) {
    $identity = New-Object Security.Principal.SecurityIdentifier($Sid)
    $inherit = if ($Directory) { 'ContainerInherit, ObjectInherit' } else { 'None' }
    $Acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($identity, $Rights, $inherit, 'None', 'Allow')))
}

function Set-LabFixtureDacl([string]$Path, $Share) {
    # Load existing descriptor and change Access only; never construct/set an Audit section.
    $acl = Get-Acl -LiteralPath (Assert-LabPath $Path)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) { $null = $acl.RemoveAccessRuleSpecific($rule) }
    Add-LabFileRule $acl 'S-1-5-18' 'FullControl'
    Add-LabFileRule $acl 'S-1-5-32-544' 'FullControl'
    Add-LabFileRule $acl (Get-ADGroup $Share.Group).SID.Value $Share.Rights
    if ($Share.Name -eq 'LAB-Exchange') { Add-LabFileRule $acl 'S-1-1-0' 'Modify' }
    if ($Share.Name -eq 'LAB-HR') { Add-LabFileRule $acl (Get-ADUser 'lab.u009').SID.Value 'ReadAndExecute' }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Get-LabFileState {
    $policies = foreach ($entry in @(
        @('File System','921d'), @('File Share','9224'), @('Detailed File Share','9244'))) {
        $guid = '{0cce' + $entry[1] + '-69ae-11d9-bed3-505054503030}'
        $result = Invoke-LabProcess "$env:WINDIR\System32\auditpol.exe" @('/get', "/subcategory:$guid", '/r')
        if ($result.ExitCode -ne 0) { throw 'lab_file_audit_read_failed' }
        [ordered]@{ name=$entry[0]; guid=$guid; auditpol_csv=$result.Stdout.Trim() }
    }
    $shares = foreach ($share in Get-LabFileShares) {
        $path = Assert-LabPath (Join-Path $script:FsRoot $share.Folder)
        $acl = Get-Acl -LiteralPath $path -Audit
        [ordered]@{
            name=$share.Name; path=$path; unc=('\\LAB-DC01.demo.example\' + $share.Name)
            share_access=@(Get-SmbShareAccess -Name $share.Name | Select-Object AccountName,AccessControlType,AccessRight)
            dacl_sddl=$acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
            ntfs_access=@($acl.Access | Select-Object IdentityReference,FileSystemRights,AccessControlType,IsInherited)
            sacl_sddl=$acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Audit)
            sacl_count=@($acl.Audit).Count; sacl_protected=$acl.AreAuditRulesProtected
            file_count=@(Get-ChildItem -LiteralPath $path -File -Recurse).Count
        }
    }
    $rootAcl = Get-Acl -LiteralPath $script:FsRoot -Audit
    [ordered]@{
        observed_at_utc=[datetime]::UtcNow.ToString('o'); host=$env:COMPUTERNAME
        root_sacl_sddl=$rootAcl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Audit)
        root_sacl_count=@($rootAcl.Audit).Count
        timezone=(Get-TimeZone).Id; features=@(Get-WindowsFeature FS-FileServer,FS-Resource-Manager | Select-Object Name,InstallState)
        audit_policy=@($policies); shares=@($shares)
        services=@(Get-Service NTDS,ADWS,LanmanServer | Select-Object Name,Status)
        boot_time=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
    }
}

function Invoke-LabFileServer {
    Assert-LabAdministrator
    $null = Assert-LabDomain
    if ($env:COMPUTERNAME -cne 'LAB-DC01') { throw 'lab_file_host_rejected' }
    Assert-LabFileRoot
    foreach ($name in @('LAB-Department-03','LAB-Department-07','LAB-Department-01','LAB-All')) {
        Assert-LabOwned (Get-ADGroup $name -Properties Description)
    }
    Assert-LabOwned (Get-ADUser 'lab.u009' -Properties Description)
    if ($InspectOnly) { Get-LabFileState | ConvertTo-Json -Depth 8; return }
    Initialize-LabDirectory
    $roleResults = foreach ($name in @('FS-FileServer','FS-Resource-Manager')) {
        if ((Get-WindowsFeature $name).Installed) {
            [ordered]@{ name=$name; success=$true; restart_needed='No'; result='already_installed' }
        } else {
            # No -Restart; a required restart is recorded for the owner, never executed.
            $result = Install-WindowsFeature -Name $name -IncludeManagementTools
            [ordered]@{ name=$name; success=$result.Success; restart_needed=[string]$result.RestartNeeded; result=[string]$result.ExitCode }
            if (-not $result.Success -and $name -eq 'FS-FileServer') { throw 'lab_file_role_failed' }
        }
    }
    if (-not (Test-Path -LiteralPath $script:FsRoot)) {
        Initialize-LabDirectory $script:FsRoot
        Write-LabSecret (Join-Path $script:FsRoot '.sli-lab-owned') $script:LabMarker
    }
    $admin = (New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([Security.Principal.NTAccount]).Value
    $everyone = (New-Object Security.Principal.SecurityIdentifier('S-1-1-0')).Translate([Security.Principal.NTAccount]).Value
    foreach ($share in Get-LabFileShares) {
        $path = Assert-LabPath (Join-Path $script:FsRoot $share.Folder)
        $null = [IO.Directory]::CreateDirectory($path)
        Set-LabFixtureDacl $path $share
        $grants = @(@($admin,'Full'), @(('DEMO\' + $share.Group),'Full'))
        if ($share.Name -eq 'LAB-Common') { $grants[1][1] = 'Read' }
        if ($share.Name -eq 'LAB-Exchange') { $grants += ,@($everyone,'Change') }
        if ($share.Name -eq 'LAB-HR') { $grants += ,@('DEMO\lab.u009','Read') }
        if (-not (Get-SmbShare -Name $share.Name -ErrorAction SilentlyContinue)) {
            New-SmbShare -Name $share.Name -Path $path -Description $script:LabMarker -FullAccess $admin -FolderEnumerationMode AccessBased | Out-Null
        }
        foreach ($ace in Get-SmbShareAccess -Name $share.Name) {
            if ($ace.AccessControlType -eq 'Deny') { Unblock-SmbShareAccess -Name $share.Name -AccountName $ace.AccountName -Force | Out-Null }
            else { Revoke-SmbShareAccess -Name $share.Name -AccountName $ace.AccountName -Force | Out-Null }
        }
        foreach ($grant in $grants) { Grant-SmbShareAccess -Name $share.Name -AccountName $grant[0] -AccessRight $grant[1] -Force | Out-Null }
        for ($i=1; $i -le 12; $i++) {
            $file = Assert-LabPath (Join-Path $path ('Сводка-{0:00}.csv' -f $i))
            if (-not (Test-Path -LiteralPath $file)) {
                [IO.File]::WriteAllText($file, "SLI-LAB-SYNTHETIC — только вымышленные данные`r`nПроект;Контрагент;План;Статус`r`nОблако-$i;ООО Лунолист-$i;$(12000+$i*700);Черновик`r`n", [Text.Encoding]::UTF8)
            }
        }
        $guide = Assert-LabPath (Join-Path $path 'Регламент.txt')
        if (-not (Test-Path -LiteralPath $guide)) {
            [IO.File]::WriteAllText($guide, "SLI-LAB-SYNTHETIC`r`nДемонстрационный отдел: $($share.Folder).`r`nСогласование учебных заявок: Вера Облаколистова, Артём Луноречев.`r`nВсе имена, организации и суммы вымышлены.`r`n", [Text.Encoding]::UTF8)
        }
        $document = switch ($share.Name) {
            'LAB-Finance' { @('Бюджет-демо.csv', "Месяц;Контрагент;План_руб;Оплачено_руб`r`n2026-10;ООО Лунолист;84000;42000`r`n2026-11;ООО Облакоречье;62000;0") }
            'LAB-HR' { @('Штат-демо.csv', "Сотрудник;Отдел;Дата_обучения;Статус`r`nВера Облаколистова;Кадры;2026-10-15;Запланировано`r`nАртём Луноречев;Финансы;2026-10-20;Согласовано") }
            'LAB-Projects' { @('План-проекта-Облако.csv', "Этап;Ответственный;Срок;Готовность`r`nМакет;Марк Снеголистов;2026-10-20;80%`r`nИспытания;Лада Ветросветова;2026-11-05;20%") }
            'LAB-Common' { @('Каталог-отделов.csv', "Отдел;Кабинет;День_приёма`r`nФинансы;Учебный-203;Понедельник`r`nКадры;Учебный-204;Среда") }
            'LAB-Exchange' { @('Заявки-на-обмен.csv', "Заявка;Проект;Документ;Статус`r`nLAB-42;Облако;Макет;Передан`r`nLAB-43;Лунолист;Учебная смета;Черновик") }
        }
        $documentPath = Assert-LabPath (Join-Path $path $document[0])
        if (-not (Test-Path -LiteralPath $documentPath)) {
            [IO.File]::WriteAllText($documentPath, "SLI-LAB-SYNTHETIC: все данные вымышлены`r`n" + $document[1] + "`r`n", [Text.Encoding]::UTF8)
        }
        if ($share.Name -eq 'LAB-Exchange') {
            for ($i=1; $i -le 20; $i++) {
                $file = Assert-LabPath (Join-Path $path ('batch-{0:00}.txt' -f $i))
                if (-not (Test-Path -LiteralPath $file)) {
                    [IO.File]::WriteAllText($file, "SLI-LAB-SYNTHETIC: fictional shipment $i; draft", [Text.Encoding]::UTF8)
                }
            }
        }
    }
    $state = Get-LabFileState
    $state['role_installation'] = @($roleResults)
    $state | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Assert-LabPath "$script:LabRoot\file-audit-state.json") -Encoding UTF8
    Write-Output 'lab_file_server_ready'
}

if ($MyInvocation.InvocationName -ne '.') {
    try { Invoke-LabFileServer } catch { Write-Output 'lab_file_server_failed'; exit 1 }
}
