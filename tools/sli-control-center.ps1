[CmdletBinding()]
param(
    [switch]$ValidateOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$LifecycleScript = Join-Path $ProjectRoot "scripts\maintenance\control_center_lifecycle.py"
$InstructionsPath = Join-Path $PSScriptRoot "README.md"
$LifecycleTimeoutMilliseconds = 7000
$script:LastSummary = ""
$script:LastProjectSummary = ""
$script:LastWorkerSummary = ""

function Get-PythonExecutable {
    $venvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
    if (Test-Path -LiteralPath $venvPython) {
        return $venvPython
    }
    return "python.exe"
}

function ConvertTo-ProcessArgument {
    param([Parameter(Mandatory = $true)][string]$Value)

    if ($Value.Length -eq 0) {
        return '""'
    }
    $escaped = [regex]::Replace($Value, '(\\*)"', '$1$1\\"')
    $escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
    return '"' + $escaped + '"'
}

function New-LocalContractError {
    param([Parameter(Mandatory = $true)][string]$Code)

    return [pscustomobject]@{
        status = "local_error"
        error_code = $Code
        full_project_success = $false
    }
}

function Invoke-LifecycleJson {
    param([Parameter(Mandatory = $true)][string[]]$LifecycleArguments)

    $Python = Get-PythonExecutable
    $arguments = @($LifecycleScript, "--json") + $LifecycleArguments
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $Python
    $startInfo.Arguments = [string]::Join(" ", @($arguments | ForEach-Object { ConvertTo-ProcessArgument $_ }))
    $startInfo.WorkingDirectory = $ProjectRoot
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.StandardOutputEncoding = New-Object System.Text.UTF8Encoding($false)
    $startInfo.StandardErrorEncoding = New-Object System.Text.UTF8Encoding($false)

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    $failureCode = "local_contract_unavailable"
    try {
        [void]$process.Start()
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($LifecycleTimeoutMilliseconds)) {
            $failureCode = "local_contract_timeout"
            try { $process.Kill() } catch { }
            $process.WaitForExit()
            throw "Локальный контракт не ответил вовремя."
        }
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        [void]$stderrTask.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) {
            $failureCode = "local_contract_failed"
            throw "Локальный контракт завершился с ошибкой."
        }
        $result = $stdout | ConvertFrom-Json
        if ($null -eq $result) {
            $failureCode = "local_contract_invalid"
            throw "Локальный контракт вернул пустой результат."
        }
        return $result
    } catch {
        return New-LocalContractError $failureCode
    } finally {
        $process.Dispose()
    }
}

function ConvertTo-RussianState {
    param([AllowEmptyString()][string]$State)

    switch ($State) {
        "healthy" { return "исправен" }
        "unavailable" { return "недоступен" }
        "unknown" { return "неизвестно" }
        "pending" { return "ожидает подтверждения супервизора" }
        "requested" { return "запрос принят; ожидает подтверждения супервизора" }
        "requested_or_pending" { return "запрос принят; ожидает подтверждения супервизора" }
        "pending_supervisor" { return "ожидает подтверждения супервизора" }
        "stopping" { return "останавливается по наблюдению супервизора" }
        "stopped" { return "остановлен (есть подтверждённое наблюдение супервизора)" }
        "running" { return "запущен (есть подтверждённое наблюдение супервизора)" }
        "failed" { return "ошибка" }
        "blocked" { return "заблокировано" }
        "rejected" { return "отклонено" }
        "local_error" { return "локальный контракт недоступен" }
        default { return "неизвестно" }
    }
}

function ConvertTo-RussianReason {
    param([AllowEmptyString()][string]$Reason)

    switch ($Reason) {
        "exact_project_action_confirmation_required" { return "не получено точное подтверждение выбранного действия проекта" }
        "exact_action_and_worker_confirmation_required" { return "не получено точное подтверждение действия для выбранного обработчика" }
        "worker_not_supervised" { return "обработчик не входит в текущий управляемый состав" }
        "project_action_not_supported" { return "действие проекта не поддерживается локальным контрактом" }
        "worker_action_not_supported" { return "действие обработчика не поддерживается локальным контрактом" }
        "control_state_unreadable" { return "локальное состояние запросов невозможно прочитать" }
        "control_state_invalid" { return "локальное состояние запросов недействительно" }
        "control_state_write_failed" { return "локальный контракт не смог сохранить запрос" }
        "local_contract_timeout" { return "локальный контракт не ответил в отведённое время" }
        "local_contract_failed" { return "локальный контракт завершился с ошибкой" }
        "local_contract_invalid" { return "локальный контракт вернул недействительный результат" }
        "local_contract_unavailable" { return "локальный контракт недоступен" }
        default { return "локальный контракт не подтвердил результат" }
    }
}

function Set-CombinedSummary {
    $parts = @($script:LastProjectSummary, $script:LastWorkerSummary) | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_)
    }
    $script:LastSummary = $parts -join [Environment]::NewLine
}

function Get-WorkerLabel {
    $selected = $WorkerPicker.SelectedItem
    if ($null -eq $selected -or [string]::IsNullOrWhiteSpace([string]$selected.label_ru)) {
        return "выбранный обработчик"
    }
    return [string]$selected.label_ru
}

function Format-ProjectStatus {
    param([Parameter(Mandatory = $true)]$Result)

    if ($Result.status -eq "local_error") {
        return "Состояние проекта не получено: $(ConvertTo-RussianReason ([string]$Result.error_code))."
    }
    $web = $Result.web_runtime
    $supervision = $Result.worker_supervision
    $endpoint = if ($null -ne $web -and -not [string]::IsNullOrWhiteSpace([string]$web.endpoint)) {
        [string]$web.endpoint
    } else {
        "не указан"
    }
    $workerState = if ($null -ne $supervision) { ConvertTo-RussianState ([string]$supervision.state) } else { "неизвестно" }
    $workerCount = if ($null -ne $supervision -and $null -ne $supervision.workers) { @($supervision.workers.psobject.Properties).Count } else { 0 }
    return (@(
        "Состояние проекта",
        "Локальный веб-контур: $(ConvertTo-RussianState ([string]$web.state)). Адрес: $endpoint.",
        "Наблюдение $workerCount обработчиков: $workerState.",
        "Полный успех проекта: не подтверждён."
    ) -join [Environment]::NewLine)
}

function Format-WorkerStatus {
    param([Parameter(Mandatory = $true)]$Result)

    $label = Get-WorkerLabel
    if ($Result.status -eq "local_error") {
        return "Состояние обработчика «$label» не получено: $(ConvertTo-RussianReason ([string]$Result.error_code))."
    }
    if ($Result.status -eq "rejected") {
        return "Обработчик «$label»: $(ConvertTo-RussianReason ([string]$Result.reason))."
    }
    $effective = $Result.effective
    $effectiveState = if ($null -ne $effective) { ConvertTo-RussianState ([string]$effective.state) } else { "не подтверждено" }
    return "Обработчик «$label»: фактическое состояние — $effectiveState."
}

function Format-MutationResult {
    param(
        [Parameter(Mandatory = $true)]$Result,
        [Parameter(Mandatory = $true)][string]$Scope,
        [Parameter(Mandatory = $true)][string]$ActionText
    )

    switch ([string]$Result.status) {
        "requested" {
            return "${Scope}: запрос на действие «$ActionText» принят; ожидает подтверждения супервизора. Фактический результат ещё не подтверждён."
        }
        "pending" {
            return "${Scope}: запрос на действие «$ActionText» принят; ожидает подтверждения супервизора. Полный успех проекта не подтверждён."
        }
        "blocked" {
            return "${Scope}: запрос на действие «$ActionText» заблокирован: $(ConvertTo-RussianReason ([string]$Result.reason))."
        }
        "rejected" {
            return "${Scope}: запрос на действие «$ActionText» отклонён: $(ConvertTo-RussianReason ([string]$Result.reason))."
        }
        "failed" {
            return "${Scope}: запрос на действие «$ActionText» не выполнен. Фактический результат не подтверждён."
        }
        "local_error" {
            return "${Scope}: локальный контракт не выполнил действие «$ActionText»: $(ConvertTo-RussianReason ([string]$Result.error_code))."
        }
        default {
            return "${Scope}: локальный контракт не подтвердил действие «$ActionText»."
        }
    }
}

function Set-ProjectDisplay {
    param([Parameter(Mandatory = $true)]$Result)

    $script:LastProjectSummary = Format-ProjectStatus $Result
    Set-CombinedSummary
    $StatusBox.Text = $script:LastSummary
}

function Set-WorkerDisplay {
    param([Parameter(Mandatory = $true)]$Result)

    $script:LastWorkerSummary = Format-WorkerStatus $Result
    $WorkerStatusText.Text = $script:LastWorkerSummary
    Set-CombinedSummary
}

function Update-WorkerStatus {
    if ($null -eq $WorkerPicker.SelectedItem) {
        $script:LastWorkerSummary = "Обработчик не выбран."
        $WorkerStatusText.Text = $script:LastWorkerSummary
        Set-CombinedSummary
        return
    }
    $worker = [string]$WorkerPicker.SelectedItem.name
    $result = Invoke-LifecycleJson @("worker", "status", "--worker", $worker)
    Set-WorkerDisplay $result
}

function Refresh-ControlCenter {
    $workers = Invoke-LifecycleJson @("managed-workers")
    if ($workers.status -eq "ok" -and $workers.read_only -eq $true -and $null -ne $workers.workers) {
        $previousWorker = if ($null -ne $WorkerPicker.SelectedItem) { [string]$WorkerPicker.SelectedItem.name } else { "" }
        $WorkerPicker.ItemsSource = @($workers.workers)
        $selected = @($workers.workers | Where-Object { [string]$_.name -eq $previousWorker } | Select-Object -First 1)
        if ($selected.Count -gt 0) {
            $WorkerPicker.SelectedItem = $selected[0]
        } elseif (@($workers.workers).Count -gt 0) {
            $WorkerPicker.SelectedIndex = 0
        }
        Update-WorkerStatus
    } else {
        $WorkerPicker.ItemsSource = @()
        $script:LastWorkerSummary = "Список текущих управляемых обработчиков недоступен: $(ConvertTo-RussianReason ([string]$workers.error_code))."
        $WorkerStatusText.Text = $script:LastWorkerSummary
        Set-CombinedSummary
    }
    $project = Invoke-LifecycleJson @("project", "status")
    Set-ProjectDisplay $project
}

function Confirm-ProjectAction {
    param(
        [Parameter(Mandatory = $true)][string]$Action,
        [Parameter(Mandatory = $true)][string]$ActionText
    )

    $confirmation = "CONTROL-CENTER:project:$Action"
    $answer = [System.Windows.MessageBox]::Show(
        "Подтвердите действие «$ActionText» для проекта. Будет передан только локальный запрос с точным подтверждением. Результат не считается выполненным до подтверждённого наблюдения.",
        "Подтверждение действия проекта",
        [System.Windows.MessageBoxButton]::YesNo,
        [System.Windows.MessageBoxImage]::Warning
    )
    if ($answer -ne [System.Windows.MessageBoxResult]::Yes) {
        $StatusBox.Text = "Действие «$ActionText» отменено. Запрос не передан."
        return
    }
    $result = Invoke-LifecycleJson @("project", $Action, "--confirm", $confirmation)
    $script:LastProjectSummary = Format-MutationResult $result "Проект" $ActionText
    Set-CombinedSummary
    $StatusBox.Text = $script:LastSummary
}

function Confirm-WorkerAction {
    param(
        [Parameter(Mandatory = $true)][string]$Action,
        [Parameter(Mandatory = $true)][string]$ActionText
    )

    if ($null -eq $WorkerPicker.SelectedItem) {
        $StatusBox.Text = "Выберите текущий управляемый обработчик перед действием."
        return
    }
    $Worker = [string]$WorkerPicker.SelectedItem.name
    $label = Get-WorkerLabel
    $confirmation = "CONTROL-CENTER:worker:${Action}:${Worker}"
    $answer = [System.Windows.MessageBox]::Show(
        "Подтвердите действие «$ActionText» для обработчика «$label». Будет передан только локальный запрос с точным подтверждением. Результат не считается выполненным до подтверждённого наблюдения.",
        "Подтверждение действия обработчика",
        [System.Windows.MessageBoxButton]::YesNo,
        [System.Windows.MessageBoxImage]::Warning
    )
    if ($answer -ne [System.Windows.MessageBoxResult]::Yes) {
        $StatusBox.Text = "Действие «$ActionText» отменено. Запрос не передан."
        return
    }
    $result = Invoke-LifecycleJson @("worker", $Action, "--worker", $Worker, "--confirm", $confirmation)
    $script:LastWorkerSummary = Format-MutationResult $result "Обработчик «$label»" $ActionText
    $WorkerStatusText.Text = $script:LastWorkerSummary
    Set-CombinedSummary
    $StatusBox.Text = $script:LastSummary
}

function Get-CurrentSummary {
    if ([string]::IsNullOrWhiteSpace($script:LastSummary)) {
        Refresh-ControlCenter
    }
    return $script:LastSummary
}

if ($ValidateOnly) {
    if (-not (Test-Path -LiteralPath $LifecycleScript)) {
        throw "Локальный контракт жизненного цикла не найден."
    }
    exit 0
}

Add-Type -AssemblyName PresentationFramework
[xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" Title="Центр управления SLI" Height="720" Width="900" WindowStartupLocation="CenterScreen">
  <ScrollViewer VerticalScrollBarVisibility="Auto">
    <Grid Margin="16">
      <Grid.RowDefinitions>
        <RowDefinition Height="Auto" />
        <RowDefinition Height="Auto" />
        <RowDefinition Height="Auto" />
        <RowDefinition Height="*" />
        <RowDefinition Height="Auto" />
      </Grid.RowDefinitions>
      <TextBlock Grid.Row="0" Text="Локальная панель управления. Действия передаются только через защищённый локальный контракт; фактический результат требует отдельного подтверждённого наблюдения." TextWrapping="Wrap" Margin="0,0,0,12" />
      <GroupBox Grid.Row="1" Margin="0,0,0,12">
        <GroupBox.Header><TextBlock Text="Проект" /></GroupBox.Header>
        <WrapPanel Margin="8">
          <Button Name="ProjectStartButton" Content="Запустить проект" Margin="0,0,8,0" Padding="12,6" />
          <Button Name="ProjectRestartButton" Content="Перезапустить проект" Margin="0,0,8,0" Padding="12,6" />
          <Button Name="ProjectStopButton" Content="Остановить проект" Padding="12,6" />
        </WrapPanel>
      </GroupBox>
      <GroupBox Grid.Row="2" Margin="0,0,0,12">
        <GroupBox.Header><TextBlock Text="Выбранный обработчик" /></GroupBox.Header>
        <StackPanel Margin="8">
          <TextBlock Text="Доступны только обработчики, которые сейчас входят в состав, управляемый супервизором." TextWrapping="Wrap" Margin="0,0,0,6" />
          <ComboBox Name="WorkerPicker" DisplayMemberPath="label_ru" SelectedValuePath="name" MinWidth="360" HorizontalAlignment="Left" />
          <WrapPanel Margin="0,8,0,6">
            <Button Name="WorkerRestartButton" Content="Перезапустить выбранный обработчик" Margin="0,0,8,0" Padding="12,6" />
            <Button Name="WorkerStopButton" Content="Остановить выбранный обработчик" Padding="12,6" />
          </WrapPanel>
          <TextBlock Name="WorkerStatusText" Text="Состояние выбранного обработчика пока не получено." TextWrapping="Wrap" />
        </StackPanel>
      </GroupBox>
      <GroupBox Grid.Row="3">
        <GroupBox.Header><TextBlock Text="Состояние и результат" /></GroupBox.Header>
        <TextBox Name="StatusBox" Margin="8" IsReadOnly="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Auto" MinHeight="190" />
      </GroupBox>
      <WrapPanel Grid.Row="4" Margin="0,12,0,0">
        <Button Name="CheckButton" Content="Обновить состояние" Margin="0,0,8,0" Padding="12,6" />
        <Button Name="SaveButton" Content="Сохранить обезличенный отчёт" Margin="0,0,8,0" Padding="12,6" />
        <Button Name="CopyButton" Content="Копировать обезличенную сводку" Margin="0,0,8,0" Padding="12,6" />
        <Button Name="InstructionsButton" Content="Открыть локальную инструкцию" Padding="12,6" />
      </WrapPanel>
    </Grid>
  </ScrollViewer>
</Window>
'@

$reader = New-Object System.Xml.XmlNodeReader $xaml
$Window = [Windows.Markup.XamlReader]::Load($reader)
$StatusBox = $Window.FindName("StatusBox")
$WorkerStatusText = $Window.FindName("WorkerStatusText")
$WorkerPicker = $Window.FindName("WorkerPicker")
$ProjectStartButton = $Window.FindName("ProjectStartButton")
$ProjectRestartButton = $Window.FindName("ProjectRestartButton")
$ProjectStopButton = $Window.FindName("ProjectStopButton")
$WorkerRestartButton = $Window.FindName("WorkerRestartButton")
$WorkerStopButton = $Window.FindName("WorkerStopButton")
$CheckButton = $Window.FindName("CheckButton")
$SaveButton = $Window.FindName("SaveButton")
$CopyButton = $Window.FindName("CopyButton")
$InstructionsButton = $Window.FindName("InstructionsButton")

$WorkerPicker.Add_SelectionChanged({ Update-WorkerStatus })
$CheckButton.Add_Click({ Refresh-ControlCenter })
$ProjectStartButton.Add_Click({ Confirm-ProjectAction "start" "запуск" })
$ProjectRestartButton.Add_Click({ Confirm-ProjectAction "restart" "перезапуск" })
$ProjectStopButton.Add_Click({ Confirm-ProjectAction "stop" "остановка" })
$WorkerRestartButton.Add_Click({ Confirm-WorkerAction "restart" "перезапуск" })
$WorkerStopButton.Add_Click({ Confirm-WorkerAction "stop" "остановка" })
$SaveButton.Add_Click({
    $summary = Get-CurrentSummary
    $reportDirectory = Join-Path $ProjectRoot "data\control-center"
    [void][System.IO.Directory]::CreateDirectory($reportDirectory)
    $reportPath = Join-Path $reportDirectory ("status-{0}.txt" -f (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmss"))
    [System.IO.File]::WriteAllText($reportPath, $summary, (New-Object System.Text.UTF8Encoding($false)))
    $StatusBox.Text = "$($StatusBox.Text)$([Environment]::NewLine)$([Environment]::NewLine)Обезличенный отчёт сохранён: $reportPath"
})
$CopyButton.Add_Click({
    Set-Clipboard -Value (Get-CurrentSummary)
    $StatusBox.Text = "$($StatusBox.Text)$([Environment]::NewLine)$([Environment]::NewLine)Обезличенная сводка скопирована в буфер обмена."
})
$InstructionsButton.Add_Click({
    if (Test-Path -LiteralPath $InstructionsPath) {
        [void][System.Diagnostics.Process]::Start("notepad.exe", ('"{0}"' -f $InstructionsPath))
    } else {
        $StatusBox.Text = "Локальный файл инструкций недоступен."
    }
})

Refresh-ControlCenter
[void]$Window.ShowDialog()
