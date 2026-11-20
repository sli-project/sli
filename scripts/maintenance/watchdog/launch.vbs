Option Explicit
Dim shell, fs, bashPath, scriptPath, args, command, exitCode
Set args = WScript.Arguments
If args.Count <> 2 Then WScript.Quit 2
bashPath = args(0)
scriptPath = args(1)
Set fs = CreateObject("Scripting.FileSystemObject")
If Not fs.FileExists(bashPath) Or Not fs.FileExists(scriptPath) Then WScript.Quit 2
Set shell = CreateObject("WScript.Shell")
shell.CurrentDirectory = fs.GetParentFolderName(scriptPath)
command = Chr(34) & bashPath & Chr(34) & " --login " & Chr(34) & scriptPath & Chr(34)
' Hidden window; keep wscript alive so Scheduler observes Bash completion.
exitCode = shell.Run(command, 0, True)
WScript.Quit exitCode
