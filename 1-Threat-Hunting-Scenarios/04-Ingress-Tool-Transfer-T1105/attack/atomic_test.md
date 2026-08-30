# Atomic Test – Ingress Tool Transfer (T1105)

## Objective

Simulate an Ingress Tool Transfer activity by using PowerShell to download a remote file and save it locally on the Windows endpoint.

## Test Description

The test used PowerShell `Net.WebClient` and the `DownloadString()` method to retrieve the `LICENSE.txt` file from the Atomic Red Team GitHub repository.

The downloaded content was written to a local file and then opened using Windows Notepad.

## Command Executed

```powershell
powershell.exe & {
    (New-Object Net.WebClient).DownloadString(
        'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/4042cb3433bce024e304500dcfe3c5590571573a/LICENSE.txt'
    ) | Out-File LICENSE.txt;
    Invoke-Item LICENSE.txt
}