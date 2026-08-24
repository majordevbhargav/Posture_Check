<#
.SYNOPSIS
    Cisco ISE Posture Agent - Windows Firewall check, works against any
    Windows device (domain-joined or workgroup) with a single script.

.DESCRIPTION
    Tries CIM over DCOM first (no TrustedHosts / Enable-PSRemoting needed
    on either side). If that's blocked - some hardened domain machines
    disable DCOM - it automatically falls back to CIM over WSMan
    (Kerberos), which works cleanly on domain machines with no setup
    either. Either way, nothing needs to change on YOUR machine.

    What still can't be skipped, because it's the target's own security,
    not this script: the account you provide needs real admin rights on
    that machine. See the two common blockers explained in the error
    output if you hit Access Denied.

.EXAMPLE
    .\posture_agent.ps1
    (checks the local machine)

.EXAMPLE
    .\posture_agent.ps1 -ComputerName 10.66.1.12
    (prompts for plain Username + Password, auto-formats them)
#>

param(
    [string]$PostureServer = "http://127.0.0.1:8000/api/v1/posture",
    [string]$ComputerName,
    [string]$QueueFile = "pending_devices.txt",
    [string]$Username,
    [securestring]$Password,
    # Only for non-interactive callers (e.g. the web UI) that can't supply
    # a SecureString. Prefer -Password for interactive/manual use.
    [string]$PlainPassword,
    # The common stored credential from Save-PostureCredential.ps1. Used
    # automatically when none of Username/Password/PlainPassword are
    # given — pass any of those three to override it for one device.
    [string]$CommonCredPath = "$PSScriptRoot\posture_common_cred.xml"
)

$ErrorActionPreference = "Stop"

# Real cross-process file locking on pending_devices.txt, using the same
# underlying Win32 LockFile/UnlockFile API that Python's msvcrt.locking
# calls into on the watcher and posture_ui.py side. This is what actually
# makes it interoperate with THEIR locks — a PowerShell-only locking
# mechanism (e.g. a .lock sidecar file) would be invisible to those
# processes and wouldn't prevent the race it's meant to prevent. Guarded
# so re-running/dot-sourcing this script twice in one session doesn't
# throw on "type already exists".
if (-not ("Win32FileLock" -as [type])) {
    Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Win32FileLock {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool LockFile(IntPtr hFile, uint dwFileOffsetLow, uint dwFileOffsetHigh, uint nNumberOfBytesToLockLow, uint nNumberOfBytesToLockHigh);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool UnlockFile(IntPtr hFile, uint dwFileOffsetLow, uint dwFileOffsetHigh, uint nNumberOfBytesToUnlockLow, uint nNumberOfBytesToUnlockHigh);
}
"@
}

function Open-LockedQueueFile {
    param([string]$Path)
    if (-not (Test-Path $Path)) { New-Item -Path $Path -ItemType File -Force | Out-Null }
    $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::ReadWrite)
    $handle = $fs.SafeFileHandle.DangerousGetHandle()
    # Same byte-0, length-1 region Python locks - retry briefly since the
    # watcher or posture_ui.py may be holding it for a moment.
    $locked = $false
    for ($i = 0; $i -lt 50 -and -not $locked; $i++) {
        $locked = [Win32FileLock]::LockFile($handle, 0, 0, 1, 0)
        if (-not $locked) { Start-Sleep -Milliseconds 100 }
    }
    if (-not $locked) {
        $fs.Close()
        throw "Could not lock $Path (another process held it for 5s straight) - try again."
    }
    return $fs
}

function Close-LockedQueueFile {
    param([System.IO.FileStream]$FileStream)
    $handle = $FileStream.SafeFileHandle.DangerousGetHandle()
    [Win32FileLock]::UnlockFile($handle, 0, 0, 1, 0) | Out-Null
    $FileStream.Close()
}

# No -ComputerName given -> pull from the shared queue that
# ise_session_watcher.py writes to, asking Y/N before each one so you
# can skip devices you don't want to check right now. Skipped devices
# are removed from the queue (not re-asked); say Y to actually run it.
if (-not $ComputerName) {
    if (-not (Test-Path $QueueFile)) {
        Write-Host "No queue file found at $QueueFile - nothing pending. (Is the watcher running?)"
        exit 0
    }

    while (-not $ComputerName) {
        $Fs = Open-LockedQueueFile -Path $QueueFile
        $Candidate = $null
        $RemainingCount = 0
        try {
            $Reader = New-Object System.IO.StreamReader($Fs, [System.Text.Encoding]::UTF8, $true, 1024, $true)
            $Content = $Reader.ReadToEnd()
            $Reader.Dispose()

            $Pending = @($Content -split "`r?`n" | Where-Object { $_.Trim() -ne "" })
            if ($Pending.Count -eq 0) {
                Write-Host "Queue is empty - no pending devices to check."
                Close-LockedQueueFile -FileStream $Fs
                exit 0
            }

            $Candidate = $Pending[0].Trim()
            $Remaining = if ($Pending.Count -gt 1) { $Pending[1..($Pending.Count - 1)] } else { @() }
            $RemainingCount = $Remaining.Count
            $NewContent = if ($Remaining.Count -gt 0) { ($Remaining -join "`n") + "`n" } else { "" }

            $Fs.Position = 0
            $Fs.SetLength(0)
            $Writer = New-Object System.IO.StreamWriter($Fs, [System.Text.Encoding]::UTF8, 1024, $true)
            $Writer.Write($NewContent)
            $Writer.Flush()
            $Writer.Dispose()
        } finally {
            Close-LockedQueueFile -FileStream $Fs
        }

        $Answer = Read-Host "Run posture check on $Candidate`? (Y/N)"
        if ($Answer -match '^[Yy]') {
            $ComputerName = $Candidate
        } else {
            Write-Host "Skipped $Candidate. ($RemainingCount remaining in queue)"
        }
    }
}

$IsRemote = $ComputerName -ne $env:COMPUTERNAME
$CimParams = @{}
$Session = $null
$Cred = $null

function Get-PostureCred {
    # Any explicit credential info passed in is an override — use it
    # instead of the common stored one, no matter what.
    $HasExplicitOverride = [bool]($Username -or $Password -or $PlainPassword)

    if (-not $HasExplicitOverride -and (Test-Path $CommonCredPath)) {
        try {
            $Stored = Import-Clixml -Path $CommonCredPath
            $StoredUser = $Stored.UserName

            # The manual-entry path below always qualifies the username as
            # ComputerName\User before using it - that's what lets Windows
            # correctly resolve it as a LOCAL account ON THE TARGET, rather
            # than an ambiguous or (worse) wrongly-scoped one. A stored
            # credential can be wrongly-scoped in FOUR ways, all needing
            # re-qualification to the CURRENT target here:
            #   - no prefix at all:      "Administrator"
            #   - ".\" (means THIS machine, wherever the script is
            #     currently running - your laptop, not the target):
            #                            ".\Administrator"
            #   - your own machine's literal name (same meaning as ".\"):
            #                            "YOUR-LAPTOP\Administrator"
            #   - a DIFFERENT device's IP baked in at save time (e.g. it
            #     was saved as "10.66.1.11\Administrator" instead of the
            #     recommended ".\Administrator" or "DOMAIN\svc" pattern) -
            #     that only ever worked against that one IP and silently
            #     fails Access Denied against every other device.
            $BareUser = $StoredUser
            $Prefix = $null
            if ($StoredUser -match '\\') {
                $Parts = $StoredUser -split '\\', 2
                $Prefix = $Parts[0]
                $BareUser = $Parts[1]
            }
            $PrefixIsIp = $Prefix -and ($Prefix -match '^\d{1,3}(\.\d{1,3}){3}$')
            $NeedsRequalify = (-not $Prefix) -or
                              ($Prefix -eq '.') -or
                              ($Prefix -ieq $env:COMPUTERNAME) -or
                              ($PrefixIsIp -and $Prefix -ne $ComputerName)

            if ($NeedsRequalify) {
                if ($PrefixIsIp -and $Prefix -ne $ComputerName) {
                    Write-Host "Stored credential was saved scoped to $Prefix, not $ComputerName - re-qualifying for this target." -ForegroundColor DarkYellow
                }
                $QualifiedStoredUser = "$ComputerName\$BareUser"
                $Stored = New-Object System.Management.Automation.PSCredential($QualifiedStoredUser, $Stored.Password)
            }

            Write-Host "Using stored common credential ($($Stored.UserName)) for $ComputerName" -ForegroundColor DarkGray
            return $Stored
        } catch {
            $ImportErr = $_.Exception.Message
            if ($ImportErr -match 'Key not valid|invalid in the current context|padding is invalid|Cryptographic') {
                $script:CredLoadWarning = "Could not decrypt the stored credential at $CommonCredPath. This almost always means it was saved under a DIFFERENT Windows user account or session than the one running this check right now - DPAPI-encrypted credentials only decrypt for the exact user+machine that created them. Re-run Save-PostureCredential.ps1 under the SAME account/session that runs posture_agent.ps1 (e.g. whatever Windows account posture_ui.py's Flask process itself runs as, if that's what's calling this)."
            } else {
                $script:CredLoadWarning = "Could not load stored credential from $CommonCredPath : $ImportErr"
            }
            Write-Host $script:CredLoadWarning -ForegroundColor Yellow
        }
    }

    if (-not $Username) {
        try {
            $script:Username = Read-Host "Username on $ComputerName (e.g. Administrator)"
        } catch {
            # Read-Host throws under -NonInteractive (always true for the
            # web UI's subprocess calls) - without this catch, that raw
            # PowerShell error is all that surfaces, which doesn't point
            # at the actual root cause. Surface whatever we already know.
            $Reason = if ($script:CredLoadWarning) { $script:CredLoadWarning } else { "No credential available, and this session can't prompt interactively (running non-interactively)." }
            throw $Reason
        }
    }
    if ($PlainPassword) {
        # Built directly via the .NET class instead of ConvertTo-SecureString,
        # so this doesn't depend on the Microsoft.PowerShell.Security module
        # being able to auto-load (blocked on some locked-down machines).
        $SecurePwd = New-Object System.Security.SecureString
        foreach ($ch in $PlainPassword.ToCharArray()) { $SecurePwd.AppendChar($ch) }
        $SecurePwd.MakeReadOnly()
    } elseif ($Password) {
        $SecurePwd = $Password
    } else {
        $SecurePwd = Read-Host "Password for $Username" -AsSecureString
    }
    $QualifiedUser = if ($Username -match '\\') { $Username } else { "$ComputerName\$Username" }
    return New-Object System.Management.Automation.PSCredential($QualifiedUser, $SecurePwd)
}

try {
    if ($IsRemote) {
        try {
            $Cred = Get-PostureCred
        } catch {
            Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
            $FailResult = [ordered]@{
                computer  = $ComputerName
                compliant = $null
                status    = "ERROR"
                detail    = $_.Exception.Message
                submitted = $false
            }
            Write-Output ("RESULT_JSON:" + ($FailResult | ConvertTo-Json -Compress))
            exit 1
        }

        # Try DCOM first - no TrustedHosts/PSRemoting needed anywhere.
        try {
            $Session = New-CimSession -ComputerName $ComputerName -Credential $Cred `
                       -SessionOption (New-CimSessionOption -Protocol Dcom) -ErrorAction Stop
        } catch {
            $DcomError = $_.Exception.Message
            Write-Host "DCOM connection failed ($DcomError), trying WSMan/Kerberos instead..." -ForegroundColor Yellow
            try {
                $Session = New-CimSession -ComputerName $ComputerName -Credential $Cred -ErrorAction Stop
            } catch {
                Write-Host ""
                Write-Host "ERROR: Could not connect to $ComputerName via DCOM or WSMan." -ForegroundColor Red
                Write-Host "Most likely cause (in order of likelihood):" -ForegroundColor Red
                Write-Host "  1. The account doesn't have real admin rights on $ComputerName." -ForegroundColor Red
                Write-Host "     - Built-in 'Administrator' must be active: net user administrator  (on the target)" -ForegroundColor Red
                Write-Host "     - Any OTHER local admin account needs, once on the target:" -ForegroundColor Red
                Write-Host "       New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System ``" -ForegroundColor Red
                Write-Host "         -Name LocalAccountTokenFilterPolicy -Value 1 -PropertyType DWord -Force" -ForegroundColor Red
                Write-Host "  2. Wrong password, or account locked out." -ForegroundColor Red
                Write-Host "  3. WMI firewall rule blocked on target: Set-NetFirewallRule -DisplayGroup 'Windows Management Instrumentation (WMI)' -Enabled True" -ForegroundColor Red
                Write-Host ""
                Write-Host "WSMan error detail: $($_.Exception.Message)" -ForegroundColor DarkGray
                $FailResult = [ordered]@{
                    computer  = $ComputerName
                    compliant = $null
                    status    = "ERROR"
                    detail    = "Could not connect via DCOM or WSMan: $($_.Exception.Message)"
                    submitted = $false
                }
                Write-Output ("RESULT_JSON:" + ($FailResult | ConvertTo-Json -Compress))
                exit 1
            }
        }
        $CimParams = @{ CimSession = $Session }
    }

    try {
        $OS = Get-CimInstance @CimParams -ClassName Win32_OperatingSystem
        $Nic = Get-CimInstance @CimParams -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" |
               Where-Object { $_.DefaultIPGateway } | Select-Object -First 1
        if (-not $Nic) {
            $Nic = Get-CimInstance @CimParams -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" | Select-Object -First 1
        }

        $FwDisabled = Get-CimInstance @CimParams -Namespace ROOT\StandardCimv2 -ClassName MSFT_NetFirewallProfile |
                      Where-Object { -not $_.Enabled }
        $Compliant = $FwDisabled.Count -eq 0
        $Status = if ($Compliant) { "COMPLIANT" } else { "NON-COMPLIANT" }
        $Detail = if ($Compliant) {
            "All firewall profiles enabled"
        } else {
            "Disabled: " + (($FwDisabled | Select-Object -ExpandProperty Name) -join ", ")
        }
    } catch {
        # Connected fine, but the actual query failed (e.g. some machines
        # don't expose MSFT_NetFirewallProfile cleanly over a DCOM
        # CimSession even though the connection itself succeeded). Without
        # this catch, the script used to die here with no RESULT_JSON line
        # at all, which just meant an endless silent requeue loop.
        Write-Host "ERROR querying $ComputerName after connecting: $($_.Exception.Message)" -ForegroundColor Red
        $FailResult = [ordered]@{
            computer  = $ComputerName
            compliant = $null
            status    = "ERROR"
            detail    = "Connected, but the posture query itself failed: $($_.Exception.Message)"
            submitted = $false
        }
        Write-Output ("RESULT_JSON:" + ($FailResult | ConvertTo-Json -Compress))
        exit 1
    }
}
finally {
    if ($Session) { Remove-CimSession $Session }
}

Write-Host "Host: $($OS.CSName)  MAC: $($Nic.MACAddress)  Overall: $Status" -ForegroundColor $(if ($Compliant) { "Green" } else { "Red" })

$Payload = @{
    endpoint = @{ hostname = $OS.CSName; mac = $Nic.MACAddress; operating_system = $OS.Caption; os_version = $OS.Version }
    posture  = @{ status = $Status; timestamp = (Get-Date).ToUniversalTime().ToString("o"); checks = @(@{ Check = "Windows Firewall"; Status = $Status; Details = $Detail }) }
} | ConvertTo-Json -Depth 10

try {
    $Response = Invoke-RestMethod -Uri $PostureServer -Method Post -Body $Payload -ContentType "application/json" -TimeoutSec 15
    Write-Host "Submitted OK:" ($Response | ConvertTo-Json -Depth 10)
    $SubmitOk = $true
    $SubmitError = $null
} catch {
    Write-Host "ERROR submitting to $PostureServer : $($_.Exception.Message)" -ForegroundColor Red
    $SubmitOk = $false
    $SubmitError = $_.Exception.Message
}

$FinalResult = [ordered]@{
    computer   = $OS.CSName
    mac        = $Nic.MACAddress
    os         = $OS.Caption
    osVersion  = $OS.Version
    compliant  = $Compliant
    status     = $Status
    detail     = $Detail
    submitted  = $SubmitOk
    submitError = $SubmitError
}
Write-Output ("RESULT_JSON:" + ($FinalResult | ConvertTo-Json -Compress))