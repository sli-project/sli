#Requires -Version 5.1
# Hermetic PS 5.1 parser, foreign-root/share guards, fixture DACL/SACL preservation.
$ErrorActionPreference = 'Stop'
$lab = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\tools\lab'))
function Assert-Test([bool]$Condition, [string]$Code) { if (-not $Condition) { throw ('lab_file_test_' + $Code) } }
Assert-Test ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -eq 1) 'ps51'
foreach ($name in @('lab-05-file-server.ps1','lab-06-file-simulate.ps1')) {
    $tokens=$null; $errors=$null
    $null = [Management.Automation.Language.Parser]::ParseFile((Join-Path $lab $name),[ref]$tokens,[ref]$errors)
    Assert-Test ($errors.Count -eq 0) ('parse_' + $name)
}
. "$lab\lab-06-file-simulate.ps1"
Initialize-LabFileClient
Assert-Test ($null -ne ('SliLabFileClient' -as [type])) 'csharp_compilation'
Assert-Test (@(Get-LabFileShares).Count -eq 5) 'five_shares'
function Get-ADGroup { [pscustomobject]@{ SID = [Security.Principal.SecurityIdentifier]'S-1-5-21-1-2-3-1103' } }
function Get-ADUser { [pscustomobject]@{ SID = [Security.Principal.SecurityIdentifier]'S-1-5-21-1-2-3-1109' } }
function Get-Acl { return $script:fixtureAcl }
function Set-Acl { param($LiteralPath,$AclObject); $script:fixtureAcl = $AclObject }
$script:fixtureAcl = New-Object Security.AccessControl.DirectorySecurity
$script:fixtureAcl.AddAuditRule((New-Object Security.AccessControl.FileSystemAuditRule(
    ([Security.Principal.SecurityIdentifier]'S-1-1-0'), 'ReadData', 'ContainerInherit, ObjectInherit', 'None', 'Success, Failure')))
$before = $script:fixtureAcl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Audit)
$share = @(Get-LabFileShares)[1]
Set-LabFixtureDacl 'C:\Synthetic-Lab-Test-Not-Created' $share
$first = $script:fixtureAcl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)
Set-LabFixtureDacl 'C:\Synthetic-Lab-Test-Not-Created' $share
Assert-Test ($first -ceq $script:fixtureAcl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)) 'dacl_rerun'
Assert-Test ($before -ceq $script:fixtureAcl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Audit)) 'sacl_preserved'
Assert-Test ($first.Contains('1109')) 'intentional_direct_grant'
Set-LabFixtureDacl 'C:\Synthetic-Lab-Test-Not-Created' (@(Get-LabFileShares)[4])
Assert-Test ($script:fixtureAcl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access).Contains('WD')) 'intentional_everyone'
function Test-Path { return $false }
function Get-SmbShare { return [pscustomobject]@{ Path='C:\Foreign'; Description='foreign' } }
$rejected=$false
try { Assert-LabFileRoot } catch { $rejected = $_.Exception.Message -eq 'lab_file_share_collision' }
Assert-Test $rejected 'foreign_share'
function Get-SmbShare { return $null }
function Test-Path { param($LiteralPath); return $LiteralPath -eq 'C:\SLI-Lab-Files' }
function Assert-LabPath { param($Path); return $Path }
$rejected=$false
try { Assert-LabFileRoot } catch { $rejected = $_.Exception.Message -eq 'lab_file_root_not_owned' }
Assert-Test $rejected 'foreign_root'
Write-Output 'lab_file_ps51_contracts_passed'