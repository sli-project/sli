#requires -version 5.1
[CmdletBinding()]
param(
    [ValidateSet("Menu", "Export")]
    [string]$Mode = "Menu",

    [string]$StateRoot = ".\dc-audit-state"
)

$ErrorActionPreference = "Stop"

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-Timestamp {
    return (Get-Date -Format "yyyyMMdd-HHmmss")
}

function New-StateDirectory {
    $computer = $env:COMPUTERNAME
    $timestamp = Get-Timestamp
    $path = Join-Path -Path $StateRoot -ChildPath "$computer-$timestamp"
    New-Item -ItemType Directory -Force -Path $path | Out-Null
    return $path
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "==== $Title ===="
}

function Read-YesNo {
    param(
        [string]$QuestionRu,
        [string]$QuestionEn
    )

    while ($true) {
        Write-Host ""
        Write-Host "RU: $QuestionRu"
        Write-Host "EN: $QuestionEn"
        $answer = Read-Host "Y/N, default N"

        if ([string]::IsNullOrWhiteSpace($answer)) { return $false }

        switch -Regex ($answer.Trim()) {
            "^(y|yes|д|да)$" { return $true }
            "^(n|no|н|нет)$" { return $false }
            default { Write-Host "Please answer Y/N or Да/Нет." }
        }
    }
}

function Invoke-CommandLine {
    param(
        [string]$Description,
        [string]$FilePath,
        [string[]]$Arguments
    )

    Write-Host "Running: $FilePath $($Arguments -join ' ')"
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE"
    }
}

function Export-DcAuditState {
    $outDir = New-StateDirectory

    Write-Section "Export current audit state"
    Write-Host "Output: $outDir"

    Invoke-CommandLine -Description "auditpol backup" -FilePath "auditpol.exe" -Arguments @(
        "/backup",
        "/file:$(Join-Path $outDir 'auditpol-backup.csv')"
    )

    Invoke-CommandLine -Description "auditpol current policy" -FilePath "auditpol.exe" -Arguments @("/get", "/category:*", "/r") |
        Out-File -FilePath (Join-Path $outDir "auditpol-current.csv") -Encoding UTF8

    Invoke-CommandLine -Description "auditpol subcategory inventory" -FilePath "auditpol.exe" -Arguments @("/list", "/subcategory:*", "/v", "/r") |
        Out-File -FilePath (Join-Path $outDir "auditpol-subcategories.csv") -Encoding UTF8

    $channels = @(
        "Security",
        "System",
        "Application",
        "Directory Service",
        "DNS Server",
        "Windows PowerShell",
        "Microsoft-Windows-PowerShell/Operational",
        "Microsoft-Windows-TaskScheduler/Operational"
    )

    foreach ($channel in $channels) {
        $safeName = $channel -replace '[\\/:*?"<>| ]+', '_'
        $target = Join-Path $outDir "wevtutil-$safeName.txt"

        try {
            wevtutil gl $channel | Out-File -FilePath $target -Encoding UTF8
        }
        catch {
            "Channel not available or not readable: $channel`r`n$($_.Exception.Message)" |
                Out-File -FilePath $target -Encoding UTF8
        }
    }

    Get-ComputerInfo |
        Select-Object CsName, WindowsProductName, WindowsVersion, OsHardwareAbstractionLayer, OsArchitecture, OsLanguage, TimeZone |
        Format-List |
        Out-File -FilePath (Join-Path $outDir "computer-info.txt") -Encoding UTF8

    try {
        Get-CimInstance Win32_ComputerSystem |
            Select-Object Name, Domain, DomainRole, PartOfDomain |
            Format-List |
            Out-File -FilePath (Join-Path $outDir "computer-system.txt") -Encoding UTF8
    }
    catch {
        "Unable to query Win32_ComputerSystem: $($_.Exception.Message)" |
            Out-File -FilePath (Join-Path $outDir "computer-system.txt") -Encoding UTF8
    }

    Write-Host "Export completed."
    return $outDir
}

# GUIDs: Microsoft [MS-GPAC], Subcategory and SubcategoryGUID.
# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpac/77878370-0712-47cd-997d-b07053429f6d
function Get-MinimumAuditPolicySettings {
    return @(
        @{
            Name = "Credential Validation"; Guid = "{0cce923f-69ae-11d9-bed3-505054503030}"; Success = $true; Failure = $true
            Ru = "Проверка учетных данных. Нужна для событий проверки паролей доменных и локальных учетных записей."
            En = "Credential validation. Required for password validation events for domain and local accounts."
        };
        @{
            Name = "Security Group Management"; Guid = "{0cce9237-69ae-11d9-bed3-505054503030}"; Success = $true; Failure = $false
            Ru = "Управление группами безопасности. Фиксирует изменения групп, включая привилегированные группы."
            En = "Security group management. Records group changes, including privileged groups."
        };
        @{
            Name = "User Account Management"; Guid = "{0cce9235-69ae-11d9-bed3-505054503030}"; Success = $true; Failure = $true
            Ru = "Управление учетными записями пользователей. Фиксирует создание, изменение, включение, отключение и удаление."
            En = "User account management. Records user creation, modification, enable, disable, and deletion events."
        };
        @{
            Name = "Computer Account Management"; Guid = "{0cce9236-69ae-11d9-bed3-505054503030}"; Success = $true; Failure = $true
            Ru = "Управление учетными записями компьютеров. Важно для контроля добавления и изменения машин в домене."
            En = "Computer account management. Useful for tracking domain computer account creation and changes."
        };
        @{
            Name = "Other Account Management Events"; Guid = "{0cce923a-69ae-11d9-bed3-505054503030}"; Success = $true; Failure = $true
            Ru = "Прочие события управления учетными записями. Закрывает дополнительные сценарии изменений."
            En = "Other account management events. Covers additional account management scenarios."
        };
        @{
            Name = "Process Creation"; Guid = "{0cce922b-69ae-11d9-bed3-505054503030}"; Success = $true; Failure = $false
            Ru = "Создание процессов. Может увеличить объем логов, но полезно для расследований."
            En = "Process creation. Can increase event volume but is useful for investigations."
        };
        @{
            Name = "Process Termination"; Guid = "{0cce922c-69ae-11d9-bed3-505054503030}"; Success = $true; Failure = $false
            Ru = "Завершение процессов. Дополняет контроль жизненного цикла процессов."
            En = "Process termination. Complements process lifecycle visibility."
        };
        @{
            Name = "Logon"; Guid = "{0cce9215-69ae-11d9-bed3-505054503030}"; Success = $true; Failure = $true
            Ru = "Вход в систему. Ключевые события успешных и неуспешных входов."
            En = "Logon. Key successful and failed sign-in events."
        };
        @{
            Name = "Logoff"; Guid = "{0cce9216-69ae-11d9-bed3-505054503030}"; Success = $true; Failure = $false
            Ru = "Выход из системы. Позволяет видеть завершение сеансов."
            En = "Logoff. Provides visibility into session termination."
        };
        @{
            Name = "Other Logon/Logoff Events"; Guid = "{0cce921c-69ae-11d9-bed3-505054503030}"; Success = $true; Failure = $true
            Ru = "Прочие события входа и выхода. Дополняет картину аутентификации."
            En = "Other logon/logoff events. Adds authentication context."
        };
        @{
            Name = "Special Logon"; Guid = "{0cce921b-69ae-11d9-bed3-505054503030}"; Success = $true; Failure = $true
            Ru = "Специальный вход. Показывает входы с повышенными привилегиями."
            En = "Special logon. Shows sign-ins with elevated privileges."
        };
        @{
            Name = "Account Lockout"; Guid = "{0cce9217-69ae-11d9-bed3-505054503030}"; Success = $true; Failure = $false
            Ru = "Блокировка учетной записи. Важно для выявления перебора и проблем входа."
            En = "Account lockout. Important for detecting brute force and sign-in issues."
        };
        @{
            Name = "File Share"; Guid = "{0cce9224-69ae-11d9-bed3-505054503030}"; Success = $true; Failure = $false
            Ru = "Доступ к файловым шарам. Может быть шумным, но полезен для контроля доступа."
            En = "File share access. Can be noisy but useful for access monitoring."
        };
        @{
            Name = "Removable Storage"; Guid = "{0cce9245-69ae-11d9-bed3-505054503030}"; Success = $true; Failure = $false
            Ru = "Съемные носители. Помогает фиксировать доступ к removable storage."
            En = "Removable storage. Helps record access to removable storage."
        };
        @{
            Name = "Audit Policy Change"; Guid = "{0cce922f-69ae-11d9-bed3-505054503030}"; Success = $true; Failure = $true
            Ru = "Изменение политики аудита. Критично для контроля попыток скрыть активность."
            En = "Audit policy change. Critical for detecting attempts to hide activity."
        };
        @{
            Name = "MPSSVC Rule-Level Policy Change"; Guid = "{0cce9232-69ae-11d9-bed3-505054503030}"; Success = $true; Failure = $true
            Ru = "Изменения правил Windows Firewall. Полезно для контроля сетевых изменений."
            En = "Windows Firewall rule-level policy changes. Useful for network change monitoring."
        };
        @{
            Name = "Other Policy Change Events"; Guid = "{0cce9234-69ae-11d9-bed3-505054503030}"; Success = $true; Failure = $true
            Ru = "Прочие изменения политик. Дополнительный контроль изменений безопасности."
            En = "Other policy change events. Additional security change visibility."
        };
        @{
            Name = "Authentication Policy Change"; Guid = "{0cce9230-69ae-11d9-bed3-505054503030}"; Success = $true; Failure = $true
            Ru = "Изменение политик аутентификации. Важно для контроля доверий и Kerberos-настроек."
            En = "Authentication policy change. Important for trust and Kerberos-related changes."
        };
        @{
            Name = "Authorization Policy Change"; Guid = "{0cce9231-69ae-11d9-bed3-505054503030}"; Success = $true; Failure = $true
            Ru = "Изменение политик авторизации. Важно для контроля прав и разрешений."
            En = "Authorization policy change. Important for rights and permissions monitoring."
        };
        @{
            Name = "Security State Change"; Guid = "{0cce9210-69ae-11d9-bed3-505054503030}"; Success = $true; Failure = $true
            Ru = "Изменение состояния безопасности. Фиксирует важные системные изменения безопасности."
            En = "Security state change. Records important system security state changes."
        };
        @{
            Name = "Security System Extension"; Guid = "{0cce9211-69ae-11d9-bed3-505054503030}"; Success = $true; Failure = $true
            Ru = "Расширение системы безопасности. Важно для контроля компонентов безопасности."
            En = "Security system extension. Useful for monitoring security components."
        };
        @{
            Name = "System Integrity"; Guid = "{0cce9212-69ae-11d9-bed3-505054503030}"; Success = $true; Failure = $true
            Ru = "Целостность системы. Фиксирует нарушения и события контроля целостности."
            En = "System integrity. Records integrity and security enforcement events."
        }
    )
}

function Get-DcAdditionalAuditSettings {
    return @(
        @{
            Name = "Directory Service Access"; Guid = "{0cce923b-69ae-11d9-bed3-505054503030}"; Success = $true; Failure = $true
            Ru = "Доступ к службе каталогов. Может быть шумным; включать только при понимании объема."
            En = "Directory service access. Can be noisy; enable only after volume assessment."
        };
        @{
            Name = "Directory Service Changes"; Guid = "{0cce923c-69ae-11d9-bed3-505054503030}"; Success = $true; Failure = $true
            Ru = "Изменения службы каталогов. Полезно для контроля изменений объектов AD."
            En = "Directory service changes. Useful for tracking AD object changes."
        };
        @{
            Name = "Directory Service Replication"; Guid = "{0cce923d-69ae-11d9-bed3-505054503030}"; Success = $true; Failure = $true
            Ru = "Репликация службы каталогов. Включать осторожно, может увеличить объем событий."
            En = "Directory service replication. Enable carefully; can increase event volume."
        };
        @{
            Name = "Kerberos Authentication Service"; Guid = "{0cce9242-69ae-11d9-bed3-505054503030}"; Success = $true; Failure = $true
            Ru = "Служба аутентификации Kerberos. Важно для анализа TGT и доменной аутентификации."
            En = "Kerberos authentication service. Important for TGT and domain authentication analysis."
        };
        @{
            Name = "Kerberos Service Ticket Operations"; Guid = "{0cce9240-69ae-11d9-bed3-505054503030}"; Success = $true; Failure = $true
            Ru = "Операции service ticket Kerberos. Важно для анализа доступа к сервисам."
            En = "Kerberos service ticket operations. Important for service access analysis."
        }
    )
}

function Set-AuditPolicyItem {
    param([hashtable]$Setting)

    # Fail before mutation if a GUID is malformed or unavailable on this OS.
    $subcategory = ([guid]$Setting.Guid).ToString("B")
    if ([guid]$Setting.Guid -eq [guid]::Empty) { throw "Empty audit subcategory GUID" }
    Invoke-CommandLine -Description "Validate $($Setting.Name)" -FilePath "auditpol.exe" -Arguments @(
        "/get", "/subcategory:$subcategory", "/r"
    ) | Out-Null

    $success = if ($Setting.Success) { "enable" } else { "disable" }
    $failure = if ($Setting.Failure) { "enable" } else { "disable" }

    Invoke-CommandLine -Description $Setting.Name -FilePath "auditpol.exe" -Arguments @(
        "/set",
        "/subcategory:$subcategory",
        "/success:$success",
        "/failure:$failure"
    )
}

function Install-MinimumAuditPolicy {
    Write-Section "Install Microsoft minimum audit policy"
    Write-Host "RU: Перед изменениями будет создан бэкап текущей политики аудита."
    Write-Host "EN: The current audit policy will be backed up before any changes."

    if (-not (Read-YesNo -QuestionRu "Продолжить установку минимального набора аудита Microsoft?" -QuestionEn "Continue installing the Microsoft minimum audit baseline?")) {
        Write-Host "Canceled."
        return
    }

    $backupPath = Export-DcAuditState
    Write-Host "Backup saved to: $backupPath"

    foreach ($setting in Get-MinimumAuditPolicySettings) {
        Write-Section $setting.Name
        Write-Host "RU: $($setting.Ru)"
        Write-Host "EN: $($setting.En)"
        Write-Host "Setting: success=$($setting.Success), failure=$($setting.Failure), guid=$($setting.Guid)"

        if (Read-YesNo -QuestionRu "Применить этот пункт?" -QuestionEn "Apply this item?") {
            Set-AuditPolicyItem -Setting $setting
        }
        else {
            Write-Host "Skipped: $($setting.Name)"
        }
    }

    Write-Host "Installation menu completed. Exporting final state..."
    Export-DcAuditState | Out-Null
}

function Get-BackupFiles {
    if (-not (Test-Path $StateRoot)) { return @() }

    return @(Get-ChildItem -Path $StateRoot -Recurse -Filter "auditpol-backup.csv" -File |
        Sort-Object LastWriteTime -Descending)
}

function Restore-AuditPolicyFromBackup {
    Write-Section "Restore default / remove configured audit policy"
    Write-Host "RU: Безопасный откат выполняется через восстановление из ранее созданного бэкапа auditpol."
    Write-Host "EN: Safe rollback is performed by restoring a previously created auditpol backup."

    $backups = Get-BackupFiles
    if ($backups.Count -eq 0) {
        Write-Warning "No auditpol backup files found under $StateRoot. Nothing will be changed."
        return
    }

    for ($i = 0; $i -lt $backups.Count; $i++) {
        Write-Host ("{0}. {1} ({2})" -f ($i + 1), $backups[$i].FullName, $backups[$i].LastWriteTime)
    }

    $choice = Read-Host "Select backup number, default 1"
    if ([string]::IsNullOrWhiteSpace($choice)) { $choice = "1" }

    $index = 0
    if (-not [int]::TryParse($choice, [ref]$index) -or $index -lt 1 -or $index -gt $backups.Count) {
        Write-Warning "Invalid selection. Nothing will be changed."
        return
    }

    $selected = $backups[$index - 1].FullName
    Write-Host "Selected backup: $selected"

    if (Read-YesNo -QuestionRu "Восстановить политику аудита из выбранного бэкапа?" -QuestionEn "Restore audit policy from the selected backup?") {
        Export-DcAuditState | Out-Null
        Invoke-CommandLine -Description "auditpol restore" -FilePath "auditpol.exe" -Arguments @(
            "/restore",
            "/file:$selected"
        )
        Write-Host "Restore completed. Exporting final state..."
        Export-DcAuditState | Out-Null
    }
    else {
        Write-Host "Canceled."
    }
}

function Set-EventChannelMaxSize {
    param(
        [string]$Channel,
        [int64]$SizeBytes
    )

    Invoke-CommandLine -Description "Set $Channel max size" -FilePath "wevtutil.exe" -Arguments @(
        "sl",
        $Channel,
        "/ms:$SizeBytes"
    )
}

function Enable-EventChannel {
    param([string]$Channel)

    Invoke-CommandLine -Description "Enable $Channel" -FilePath "wevtutil.exe" -Arguments @(
        "sl",
        $Channel,
        "/e:true"
    )
}

function Configure-AdvancedOptions {
    Write-Section "Advanced settings"
    Write-Host "RU: Дополнительные параметры могут увеличить объем событий. Каждый пункт подтверждается отдельно."
    Write-Host "EN: Advanced settings can increase event volume. Each item is confirmed separately."

    Export-DcAuditState | Out-Null

    foreach ($setting in Get-DcAdditionalAuditSettings) {
        Write-Section $setting.Name
        Write-Host "RU: $($setting.Ru)"
        Write-Host "EN: $($setting.En)"
        Write-Host "Setting: success=$($setting.Success), failure=$($setting.Failure), guid=$($setting.Guid)"

        if (Read-YesNo -QuestionRu "Включить этот дополнительный аудит?" -QuestionEn "Enable this additional audit setting?") {
            Set-AuditPolicyItem -Setting $setting
        }
        else {
            Write-Host "Skipped: $($setting.Name)"
        }
    }

    $channelOptions = @(
        @{
            Name = "Security log max size 512 MB"; Channel = "Security"; Size = 536870912
            Ru = "Увеличить максимальный размер Security log до 512 MB."
            En = "Increase Security log maximum size to 512 MB."
        };
        @{
            Name = "System log max size 128 MB"; Channel = "System"; Size = 134217728
            Ru = "Увеличить максимальный размер System log до 128 MB."
            En = "Increase System log maximum size to 128 MB."
        };
        @{
            Name = "Directory Service log max size 128 MB"; Channel = "Directory Service"; Size = 134217728
            Ru = "Увеличить максимальный размер Directory Service log до 128 MB."
            En = "Increase Directory Service log maximum size to 128 MB."
        };
        @{
            Name = "DNS Server log max size 128 MB"; Channel = "DNS Server"; Size = 134217728
            Ru = "Увеличить максимальный размер DNS Server log до 128 MB."
            En = "Increase DNS Server log maximum size to 128 MB."
        }
    )

    foreach ($option in $channelOptions) {
        Write-Section $option.Name
        Write-Host "RU: $($option.Ru)"
        Write-Host "EN: $($option.En)"

        if (Read-YesNo -QuestionRu "Применить изменение размера журнала?" -QuestionEn "Apply this event log size change?") {
            Set-EventChannelMaxSize -Channel $option.Channel -SizeBytes $option.Size
        }
        else {
            Write-Host "Skipped: $($option.Name)"
        }
    }

    $enableChannels = @(
        @{
            Name = "PowerShell Operational"; Channel = "Microsoft-Windows-PowerShell/Operational"
            Ru = "Включить журнал PowerShell Operational для контроля PowerShell-активности."
            En = "Enable PowerShell Operational log for PowerShell activity monitoring."
        };
        @{
            Name = "Task Scheduler Operational"; Channel = "Microsoft-Windows-TaskScheduler/Operational"
            Ru = "Включить журнал Task Scheduler Operational для контроля задач планировщика."
            En = "Enable Task Scheduler Operational log for scheduled task monitoring."
        }
    )

    foreach ($option in $enableChannels) {
        Write-Section $option.Name
        Write-Host "RU: $($option.Ru)"
        Write-Host "EN: $($option.En)"

        if (Read-YesNo -QuestionRu "Включить этот журнал?" -QuestionEn "Enable this event channel?") {
            Enable-EventChannel -Channel $option.Channel
        }
        else {
            Write-Host "Skipped: $($option.Name)"
        }
    }

    Write-Host "Advanced menu completed. Exporting final state..."
    Export-DcAuditState | Out-Null
}

function Show-EnvironmentWarning {
    if (-not (Test-IsAdministrator)) {
        throw "Run this script from an elevated PowerShell session."
    }

    try {
        $computer = Get-CimInstance Win32_ComputerSystem
        if ($computer.DomainRole -notin 4, 5) {
            Write-Warning "This computer does not look like a domain controller. DomainRole=$($computer.DomainRole)."
        }
    }
    catch {
        Write-Warning "Unable to determine domain controller role: $($_.Exception.Message)"
    }
}

function Show-MainMenu {
    Show-EnvironmentWarning

    while ($true) {
        Write-Section "DC audit logging setup"
        Write-Host "RU: Единый ручной скрипт настройки аудита DC. По каждому изменению будет вопрос Да/Нет."
        Write-Host "EN: Unified manual DC audit setup script. Each change requires a Yes/No confirmation."
        Write-Host ""
        Write-Host "1. Установка / Install Microsoft minimum audit baseline"
        Write-Host "2. Удаление по умолчанию / Restore from backup"
        Write-Host "3. Настройка дополнительных параметров / Advanced settings"
        Write-Host "4. Экспорт текущего состояния / Export current state"
        Write-Host "5. Выход / Exit"

        $choice = Read-Host "Select 1-5"

        switch ($choice) {
            "1" { Install-MinimumAuditPolicy }
            "2" { Restore-AuditPolicyFromBackup }
            "3" { Configure-AdvancedOptions }
            "4" { Export-DcAuditState | Out-Null }
            "5" { return }
            default { Write-Host "Unknown option." }
        }
    }
}

if ($Mode -eq "Export") {
    Show-EnvironmentWarning
    Export-DcAuditState | Out-Null
}
else {
    Show-MainMenu
}

