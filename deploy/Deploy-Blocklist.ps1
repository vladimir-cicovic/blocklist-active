<#
.SYNOPSIS
  Installs blocklist-active on a remote Linux server over SSH, from Windows.

.DESCRIPTION
  Uses the built-in Windows OpenSSH client (ssh.exe, scp.exe) and tar.exe
  (Windows 10 1803+ / Windows 11 / Windows Server 2019+). No bash required.

  Flow:
    1. connection probe; the address the server sees (SSH_CONNECTION) becomes --hold-ip
    2. the kit and the config are copied to a temporary directory on the server
    3. install.sh: your address passes every block while it runs + Hold seconds
    4. waits for the hold to expire, then opens a NEW SSH connection; if it gets
       through, it confirms the installation (blocklist confirm). If not, the
       rollback timer on the server disables the blocks after Rollback seconds.

.PARAMETER Target
  user@server (root, or a user with passwordless sudo)

.PARAMETER Config
  blocklist.conf for this server (required for the first installation)

.PARAMETER InstallArgs
  extra arguments for install.sh, for example @('--no-bootstrap')

.EXAMPLE
  .\deploy\Deploy-Blocklist.ps1 -Target root@server.example.com -Config .\configs\server.conf

.EXAMPLE
  .\deploy\Deploy-Blocklist.ps1 -Target admin@10.0.0.5 -Port 2222 -Config .\blocklist.conf -Hold 30 -Rollback 900
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Target,
    [int]$Port = 22,
    [string]$Config,
    [string]$Identity,
    [int]$Hold = 30,
    [int]$Rollback = 600,
    [switch]$NoConfirm,
    [string[]]$InstallArgs = @(),
    [ValidateSet('accept-new', 'yes', 'no')][string]$StrictHostKeyChecking = 'accept-new'
)

$ErrorActionPreference = 'Stop'
$Kit = Split-Path -Parent $PSScriptRoot

function Say([string]$Text) { Write-Host ""; Write-Host "== $Text" -ForegroundColor White }
function Fail([string]$Text) { Write-Host ""; Write-Host "ERROR: $Text" -ForegroundColor Red; exit 1 }

foreach ($exe in 'ssh.exe', 'scp.exe', 'tar.exe') {
    if (-not (Get-Command $exe -ErrorAction SilentlyContinue)) {
        Fail "$exe not found. Enable 'OpenSSH Client' (Settings > Apps > Optional features)."
    }
}
if ($Config -and -not (Test-Path -LiteralPath $Config)) { Fail "config $Config does not exist" }
$installSh = Join-Path $Kit 'install.sh'
if ([IO.File]::ReadAllText($installSh).Contains("`r`n")) {
    Fail "the scripts have Windows line endings (CRLF). Clone again with .gitattributes or: git config core.autocrlf false"
}

$sshOpts = @('-p', "$Port", '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=15',
             '-o', 'ServerAliveInterval=15', '-o', "StrictHostKeyChecking=$StrictHostKeyChecking")
$scpOpts = @('-q', '-P', "$Port", '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=15',
             '-o', "StrictHostKeyChecking=$StrictHostKeyChecking")
if ($Identity) { $sshOpts += @('-i', $Identity); $scpOpts += @('-i', $Identity) }

# Native commands: output goes to the console (Out-Host), success comes from $LASTEXITCODE.
# Without Out-Host the ssh output would become the function's return value along with the code.
function Invoke-Ssh([string]$Command) {
    $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    & ssh.exe @sshOpts $Target $Command 2>&1 | ForEach-Object { "$_" } | Out-Host
    $code = $LASTEXITCODE
    $ErrorActionPreference = $old
    return $code
}

# ---------- 1. connection probe ----------
Say "Connecting to ${Target}:$Port"
$ErrorActionPreference = 'Continue'
$probe = & ssh.exe @sshOpts $Target 'echo $SSH_CONNECTION; id -u; command -v systemctl || echo no-systemd'
$probeCode = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
if ($probeCode -ne 0 -or -not $probe) { Fail "SSH connection failed (code $probeCode)" }
$lines = @($probe)
$client = ($lines[0] -split ' ')[0]
$uid = $lines[1].Trim()
if ($lines -contains 'no-systemd') { Fail "the target has no systemd" }
$sudo = ''
if ($uid -ne '0') { $sudo = 'sudo -n' }
Write-Host "   the server sees you as: $client   user uid: $uid"

# ---------- 2. kit ----------
Say "Uploading the kit"
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("blocklist-deploy-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    $items = @('install.sh', 'uninstall.sh', 'VERSION', 'blocklist.conf.example', 'files')
    if (Test-Path (Join-Path $Kit 'seed\seed.tar.gz')) { $items += 'seed' }
    & tar.exe -czf (Join-Path $tmp 'kit.tgz') -C $Kit @items
    if ($LASTEXITCODE -ne 0) { Fail "tar.exe could not create the kit archive" }
    $upload = @('kit.tgz')
    $cfgArg = ''
    $rd = "/tmp/blocklist-deploy-" + (Get-Random -Minimum 100000 -Maximum 999999)
    if ($Config) {
        Copy-Item -LiteralPath $Config -Destination (Join-Path $tmp 'blocklist.conf')
        $upload += 'blocklist.conf'
        $cfgArg = "--config $rd/blocklist.conf"
    }
    if ((Invoke-Ssh "mkdir -m 700 $rd") -ne 0) { Fail "cannot create $rd on the server" }
    Push-Location $tmp
    try {
        $ErrorActionPreference = 'Continue'
        & scp.exe @scpOpts @upload "${Target}:$rd/"
        $scpCode = $LASTEXITCODE
        $ErrorActionPreference = 'Stop'
    } finally { Pop-Location }
    if ($scpCode -ne 0) { Fail "upload failed (scp code $scpCode)" }
    Write-Host "   uploaded to $rd"
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

# ---------- 3. installation ----------
Say "Installing"
$holdArg = ''
if ($client) { $holdArg = "--hold-ip $client" }
$extra = ($InstallArgs -join ' ')
$cmd = "cd $rd && tar xzf kit.tgz && $sudo bash ./install.sh $cfgArg $holdArg --hold $Hold --rollback $Rollback $extra; rc=`$?; cd /; $sudo rm -rf $rd; exit `$rc"
$rc = Invoke-Ssh $cmd
if ($rc -ne 0) { Fail "install.sh exited with code $rc (if the rollback is armed, the blocks disable themselves within ${Rollback}s)" }

# ---------- 4. confirmation from a new connection ----------
if ($Rollback -gt 0 -and -not $NoConfirm) {
    Say "Confirming access"
    Write-Host "   waiting $($Hold + 2)s for the hold to expire, then opening a NEW SSH connection..."
    Start-Sleep -Seconds ($Hold + 2)
    $confirmed = $false
    foreach ($i in 1..3) {
        if ((Invoke-Ssh "$sudo /usr/local/sbin/blocklist confirm") -eq 0) { $confirmed = $true; break }
        Write-Host "   attempt $i failed, retrying in 5s"
        Start-Sleep -Seconds 5
    }
    if (-not $confirmed) {
        Fail ("A NEW SSH CONNECTION DOES NOT GET THROUGH - your address ($client) is probably blocked.`n" +
              "   The rollback disables the blocks at most ${Rollback}s after the installation.`n" +
              "   Then: add the address to OWNER_IPS, run 'blocklist update rebuild' and 'blocklist enable'.")
    }
} elseif ($Rollback -gt 0) {
    Write-Host ""
    Write-Host "   The rollback waits ${Rollback}s for a confirmation. Confirm from a NEW connection:"
    Write-Host "     ssh -p $Port $Target '$sudo blocklist confirm'"
}

Say "Status"
[void](Invoke-Ssh "$sudo /usr/local/sbin/blocklist status")
exit 0
