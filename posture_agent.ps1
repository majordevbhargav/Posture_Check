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
    [string]$PlainPassword
)

$ErrorActionPreference = "Stop"

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
        $Pending = @(Get-Content $QueueFile | Where-Object { $_.Trim() -ne "" })
        if ($Pending.Count -eq 0) {
            Write-Host "Queue is empty - no pending devices to check."
            exit 0
        }

        $Candidate = $Pending[0].Trim()
        if ($Pending.Count -gt 1) {
            Set-Content -Path $QueueFile -Value $Pending[1..($Pending.Count - 1)]
        } else {
            Clear-Content -Path $QueueFile
        }

        $Answer = Read-Host "Run posture check on $Candidate`? (Y/N)"
        if ($Answer -match '^[Yy]') {
            $ComputerName = $Candidate
        } else {
            Write-Host "Skipped $Candidate. ($($Pending.Count - 1) remaining in queue)"
        }
    }
}

$IsRemote = $ComputerName -ne $env:COMPUTERNAME
$CimParams = @{}
$Session = $null
$Cred = $null

function Get-PostureCred {
    if (-not $Username) { $script:Username = Read-Host "Username on $ComputerName (e.g. Administrator)" }
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
        $Cred = Get-PostureCred

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