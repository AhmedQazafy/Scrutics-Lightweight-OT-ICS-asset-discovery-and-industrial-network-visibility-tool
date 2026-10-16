# Scrutics AI setup: store an API key as a per-user Windows environment variable.
# Called by scrutics_ai_setup.bat with the variable name. The key is typed into a hidden prompt here,
# so it never appears on screen, on a command line or in another program's arguments.
# Exit codes: 0 stored, 2 no key entered, 3 an existing value was kept, 1 error.
param([Parameter(Mandatory = $true)][string]$Name)

$allowed = @("GEMINI_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY")
if ($allowed -notcontains $Name) {
    Write-Host " Unknown key variable: $Name"
    exit 1
}

$secure = Read-Host -AsSecureString "  Paste API key (hidden)"
$pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try {
    $key = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
}
$key = $key.Trim()
if ([string]::IsNullOrEmpty($key)) {
    Write-Host ""
    Write-Host " No key entered. Nothing was changed."
    exit 2
}
if ($key -match "[\x00-\x1f\x7f]") {
    Write-Host ""
    Write-Host " The key contains a line break or another control character. Nothing was changed."
    exit 1
}

# A per-user variable lives in this account's registry (HKCU\Environment), which other standard users
# cannot read. A value that is already there may have been set by someone else, so ask first.
$existing = [Environment]::GetEnvironmentVariable($Name, "User")
if (-not [string]::IsNullOrEmpty($existing)) {
    Write-Host ""
    $answer = Read-Host "  $Name is already set for your Windows account. Replace it? [y/N]"
    if ($answer -notmatch "^[yY]") {
        Write-Host " Kept the existing value of $Name."
        exit 3
    }
}

try {
    [Environment]::SetEnvironmentVariable($Name, $key, "User")
} catch {
    Write-Host " Could not save $Name for your Windows account: $($_.Exception.Message)"
    exit 1
}
Write-Host ""
Write-Host " Saved $Name for your Windows account. New terminals and programs will see it."
exit 0
