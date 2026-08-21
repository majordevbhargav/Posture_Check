<#
.SYNOPSIS
    One-time setup: stores a single admin credential, encrypted, for
    posture_agent.ps1 to use automatically instead of prompting every
    time you check a device.

.DESCRIPTION
    Uses Windows DPAPI (Export-Clixml under the hood) — the resulting
    file can only be decrypted by YOUR Windows account, on THIS machine.
    Copying it to another machine, or another user account on this one,
    produces an unreadable file, not a security hole. Nobody, including
    us in this chat, ever sees the actual password — it goes straight
    from the secure prompt below into the encrypted file.

.EXAMPLE
    .\Save-PostureCredential.ps1
    (prompts once, saves to posture_common_cred.xml next to this script)
#>

param(
    [string]$Path = "$PSScriptRoot\posture_common_cred.xml"
)

Write-Host "This stores ONE credential, used automatically for every device" -ForegroundColor Cyan
Write-Host "you check — unless you explicitly override it per-device later." -ForegroundColor Cyan
Write-Host ""

$cred = Get-Credential -Message "Common admin credential for posture checks (e.g. .\Administrator, or a domain service account like CORP\svc-posture)"

if (-not $cred) {
    Write-Host "Cancelled — nothing saved." -ForegroundColor Yellow
    exit 0
}

$cred | Export-Clixml -Path $Path

Write-Host ""
Write-Host "Saved to: $Path" -ForegroundColor Green
Write-Host "posture_agent.ps1 will now use this automatically." -ForegroundColor Green
Write-Host "Re-run this script any time to change it." -ForegroundColor DarkGray
