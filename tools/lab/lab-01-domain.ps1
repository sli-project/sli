<#
VDS: powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\SLI-Lab\lab-01-domain.ps1
Clean standalone Windows Server 2019 ONLY, elevated SSH session. Creates demo.example/DEMO.
First run schedules SYSTEM continuation before promotion, then reboots. SSH reconnects
using the same administrator/key. Repeated runs validate the owned domain and return;
foreign domains are rejected. DSRM password exists only in a protected VDS file.
Continuation waits for AD, populates the domain and installs the simulation task.
#>
#Requires -Version 5.1
[CmdletBinding()]
param([switch]$Continue)
. "$PSScriptRoot\lab-common.ps1"

function Invoke-LabDomain {
    Assert-LabAdministrator
    Initialize-LabDirectory
    $system = Get-CimInstance Win32_ComputerSystem
    if ($system.PartOfDomain) {
        $null = Assert-LabDomain
        if ($system.DomainRole -notin @(4, 5)) { throw 'lab_dc_required' }
        if ($Continue -or -not (Test-Path -LiteralPath "$script:LabRoot\domain-ready")) {
            # A requested rerun must not leave prior readiness during readiness checks or after failure.
            if (Test-Path -LiteralPath "$script:LabRoot\domain-ready") {
                Remove-Item -LiteralPath (Assert-LabPath "$script:LabRoot\domain-ready") -Force
            }
            $ready = $false
            for ($i = 0; $i -lt 60; $i++) {
                try { $null = Get-ADDomainController -Discover -Service ADWS; $ready = $true; break }
                catch { Start-Sleep -Seconds 10 }
            }
            if (-not $ready) { throw 'lab_ad_not_ready' }
            # Script exit 1 is not a terminating exception. Clear stale native exits first.
            $global:LASTEXITCODE = 0
            & "$PSScriptRoot\lab-02-populate.ps1"
            if ($LASTEXITCODE -ne 0) { throw 'lab_population_failed' }
            $global:LASTEXITCODE = 0
            & "$PSScriptRoot\lab-03-simulate.ps1" -InstallTask
            if ($LASTEXITCODE -ne 0) { throw 'lab_simulation_install_failed' }
            'ready' | Set-Content -LiteralPath "$script:LabRoot\domain-ready" -Encoding UTF8
            Unregister-ScheduledTask -TaskName 'SLI Lab Domain Continue' -Confirm:$false -ErrorAction SilentlyContinue
        }
        Write-Output 'lab_domain_ready'
        return
    }
    if ($Continue -and -not (Test-Path -LiteralPath "$script:LabRoot\domain-owned")) { throw 'lab_promotion_not_owned' }
    if ($system.DomainRole -ne 2) { throw 'lab_standalone_server_required' }
    if ((Get-CimInstance Win32_OperatingSystem).BuildNumber -ne '17763') { throw 'lab_server_2019_required' }
    Set-Service -Name sshd -StartupType Automatic
    $feature = Install-WindowsFeature -Name @('AD-Domain-Services', 'GPMC') -IncludeManagementTools
    if (-not $feature.Success) { throw 'lab_feature_install_failed' }
    Import-Module ADDSDeployment
    $passwordPath = "$script:LabRoot\dsrm.secret"
    if (-not (Test-Path -LiteralPath $passwordPath)) { Write-LabSecret $passwordPath (New-LabPassword) }
    $password = ConvertTo-SecureString ([IO.File]::ReadAllText((Assert-LabPath $passwordPath))) -AsPlainText -Force
    $exe = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
    $action = New-ScheduledTaskAction -Execute $exe -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + $PSCommandPath + '" -Continue')
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 2)
    Register-ScheduledTask -TaskName 'SLI Lab Domain Continue' -Action $action -Trigger $trigger -Settings $settings -User SYSTEM -RunLevel Highest -Force | Out-Null
    'owned' | Set-Content -LiteralPath "$script:LabRoot\domain-owned" -Encoding UTF8
    if ($system.Name -cne 'LAB-DC01') {
        Rename-Computer -NewName 'LAB-DC01' -Force
        Write-Output 'lab_rebooting'
        Restart-Computer -Force
        return
    }
    Install-ADDSForest -DomainName 'demo.example' -DomainNetbiosName 'DEMO' -InstallDns `
        -ForestMode WinThreshold -DomainMode WinThreshold -SafeModeAdministratorPassword $password `
        -CreateDnsDelegation:$false -NoRebootOnCompletion -Force | Out-Null
    Write-Output 'lab_rebooting'
    Restart-Computer -Force
}

if ($MyInvocation.InvocationName -ne '.') {
    try { Invoke-LabDomain } catch { Write-Output 'lab_domain_failed'; exit 1 }
}
