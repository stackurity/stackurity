# Install or upgrade the Stackurity agent on a Windows host.
#
# In PowerShell opened with "Run as administrator":
#
#   $env:STACKURITY_ENROLL_CODE = 'enr_...'; irm __SERVER__/install/agent.ps1 | iex
#
# It downloads the agent from your Stackurity server and checks its SHA-256,
# installs it to Program Files, exchanges the one-time enrollment code for a
# collector token, and registers the StackurityAgent service. The service
# runs as its own virtual account (NT SERVICE\StackurityAgent): no password,
# no interactive logon, no privileges beyond reading, and a write-restricted
# token. It starts at boot and reports every 6 hours. Only that account and
# Administrators can read the token. Run the script again (without a code)
# to upgrade the agent. To remove the agent:
#
#   $env:STACKURITY_UNINSTALL = '1'; irm __SERVER__/install/agent.ps1 | iex
#
# The agent only reads: it never installs or changes software. Written for
# Windows PowerShell 5.1 and PowerShell 7; it stops on the first error
# without closing the window it runs in.

& {
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
# Invoke-WebRequest's progress bar makes downloads in Windows PowerShell 5.1 very slow.
$ProgressPreference = 'SilentlyContinue'

$Server = $env:STACKURITY_SERVER
if (-not $Server) { $Server = '__SERVER__' }
$Code = $env:STACKURITY_ENROLL_CODE
$ServiceName = 'StackurityAgent'
$Account = "NT SERVICE\$ServiceName"
# BUILTIN\Administrators by SID: the group's name is translated on non-English Windows.
$Admins = '*S-1-5-32-544'
$InstallDir = Join-Path $env:ProgramFiles 'Stackurity'
$Bin = Join-Path $InstallDir 'stackurity.exe'
$Conf = Join-Path $env:ProgramData 'Stackurity'
$Token = Join-Path $Conf 'token'
$EnvFile = Join-Path $Conf 'agent.env'
$ServiceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
$EventSource = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\$ServiceName"

function Say([string]$Message) { Write-Host "stackurity: $Message" }
function Die([string]$Message) { throw "stackurity: error: $Message" }

# Exec runs a Windows command and stops the script if it fails.
function Exec([string]$What, [string]$File, [string[]]$Arguments) {
  $ErrorActionPreference = 'Continue'
  $out = & $File @Arguments 2>&1 | Out-String
  if ($LASTEXITCODE -ne 0) { Die "$What failed (exit code $LASTEXITCODE): $($out.Trim())" }
}

function Stop-Agent {
  $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
  if ($svc -and $svc.Status -ne 'Stopped') {
    Stop-Service -Name $ServiceName -Force
    $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
  }
}

# Checks before anything changes.
if ([Environment]::OSVersion.Platform -ne 'Win32NT') { Die 'this installer is for Windows; on Linux use /install/agent.sh' }
if (-not [Environment]::Is64BitOperatingSystem) { Die 'the Windows agent needs 64-bit Windows (x64)' }
if (-not [Environment]::Is64BitProcess) { Die 'this is the 32-bit PowerShell; run the script in the 64-bit Windows PowerShell' }
if ($env:PROCESSOR_ARCHITECTURE -ne 'AMD64') { Die "unsupported architecture $($env:PROCESSOR_ARCHITECTURE): the Windows agent is built for x64 (AMD64)" }
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Die 'run PowerShell as Administrator (right-click PowerShell, Run as administrator), then run the command again'
}

if ($env:STACKURITY_UNINSTALL -eq '1') {
  Stop-Agent
  if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) { Exec 'removing the service' 'sc.exe' @('delete', $ServiceName) }
  if (Test-Path -LiteralPath $EventSource) { Remove-Item -LiteralPath $EventSource -Recurse -Force }
  foreach ($dir in @($InstallDir, $Conf)) {
    if (Test-Path -LiteralPath $dir) { Remove-Item -LiteralPath $dir -Recurse -Force }
  }
  Remove-Item Env:STACKURITY_UNINSTALL -ErrorAction SilentlyContinue
  Say 'removed the agent, its service and its token from this host'
  Say 'the host stays in Stackurity until you delete it under Assets; its collector token stays valid until you revoke it under Integrations > API tokens'
  return
}

$Server = $Server.TrimEnd('/')
if ($Server -match '[\s"''`$]') { Die 'the server URL must not contain spaces or quotes' }
if ($Server -notmatch '^https://' -and $Server -notmatch '^http://(127\.0\.0\.1|localhost|\[::1\])(:[0-9]+)?(/|$)') {
  # A local port, e.g. an SSH tunnel, may use plain HTTP.
  if ($env:STACKURITY_ALLOW_HTTP -ne '1') { Die 'the server URL must use https (set $env:STACKURITY_ALLOW_HTTP = ''1'' to override)' }
}
$enrolled = (Test-Path -LiteralPath $Token -PathType Leaf) -and ((Get-Item -LiteralPath $Token).Length -gt 0)
if (-not $enrolled -and -not $Code) {
  Die 'no enrollment code: create one under Assets > Add server and set $env:STACKURITY_ENROLL_CODE'
}
# Windows PowerShell 5.1 on Windows Server 2016 and older offers TLS 1.0 only unless told otherwise.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$Tmp = Join-Path ([IO.Path]::GetTempPath()) ('stackurity-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $Tmp | Out-Null
try {
  # Download and verify.
  $tmpExe = Join-Path $Tmp 'stackurity.exe'
  $tmpSum = Join-Path $Tmp 'stackurity.exe.sha256'
  Say "downloading the agent for windows/amd64 from $Server"
  try {
    Invoke-WebRequest -UseBasicParsing -Uri "$Server/download/agent/windows-amd64" -OutFile $tmpExe
    Invoke-WebRequest -UseBasicParsing -Uri "$Server/download/agent/windows-amd64.sha256" -OutFile $tmpSum
  } catch {
    Die "download failed: $($_.Exception.Message)"
  }
  $sum = Get-Content -LiteralPath $tmpSum -Raw
  if (-not $sum) { $sum = 'none' }
  $want = ($sum.Trim() -split '\s+')[0].ToLowerInvariant()
  $got = (Get-FileHash -LiteralPath $tmpExe -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($want -notmatch '^[0-9a-f]{64}$' -or $want -ne $got) { Die 'checksum mismatch: refusing to install' }

  # Install. A running copy (a scheduled task from a manual install) keeps
  # its file open, but Windows lets it be renamed out of the way.
  Stop-Agent
  New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
  if (Test-Path -LiteralPath $Bin) { Move-Item -LiteralPath $Bin -Destination "$Bin.old" -Force }
  Copy-Item -LiteralPath $tmpExe -Destination $Bin
  Remove-Item -LiteralPath "$Bin.old" -Force -ErrorAction SilentlyContinue
  $installed = (& $Bin --version | Out-String).Trim()
  if ($LASTEXITCODE -ne 0) { Die "the downloaded agent does not run: $installed" }
  Say "installed $installed"
} finally {
  Remove-Item -LiteralPath $Tmp -Recurse -Force -ErrorAction SilentlyContinue
}

if ($enrolled -and -not (Test-Path -LiteralPath $EnvFile)) {
  # Installed by hand: its scheduled task holds settings this script cannot
  # know, so leave it alone.
  Say 'the agent was installed by hand; replaced the binary only (restart its scheduled task to use it)'
  return
}

# The settings directory: owned by Administrators and readable by them
# alone (until the service account is added below). ProgramData lets any
# user create folders and read what they hold, so its ACL is not inherited.
# Before enrollment there is nothing secret in it, and a folder someone
# created beforehand is reset; an enrolled one must already be ours.
New-Item -ItemType Directory -Force -Path $Conf | Out-Null
if ($enrolled) {
  $owner = (Get-Acl -LiteralPath $Conf).GetOwner([Security.Principal.SecurityIdentifier]).Value
  if ($owner -ne 'S-1-5-32-544' -and $owner -ne 'S-1-5-18') {
    Die "$Conf is not owned by Administrators, so its settings cannot be trusted; remove the folder and run the command again with a new code"
  }
} else {
  Exec 'setting the owner of the settings folder' 'icacls.exe' @($Conf, '/setowner', $Admins, '/T', '/Q')
  Exec 'resetting the settings folder' 'icacls.exe' @($Conf, '/reset', '/T', '/Q')
}
Exec 'restricting the settings folder' 'icacls.exe' @($Conf, '/inheritance:r', '/grant:r', "${Admins}:(OI)(CI)F", '/Q')

if ($enrolled) {
  Say 'already enrolled; upgrading the agent only'
} else {
  try {
    $enrollArgs = @('enroll', '--server', $Server, '--dir', $Conf)
    # An empty token file is a failed earlier attempt.
    if (Test-Path -LiteralPath $Token) { $enrollArgs += '--force' }
    & $Bin @enrollArgs
    if ($LASTEXITCODE -ne 0) { Die 'enrollment failed (see the message above)' }
  } finally {
    # The code is used up; keep it out of later commands in this window.
    Remove-Item Env:STACKURITY_ENROLL_CODE -ErrorAction SilentlyContinue
  }
}

# The service's environment, from agent.env. Application directories are
# not scanned on Windows yet, so those settings are left out (the agent
# would refuse to start with them).
$environment = @()
foreach ($line in Get-Content -LiteralPath $EnvFile) {
  if ($line -notmatch '^(STACKURITY_[A-Z0-9_]+)=(.*)$') { continue }
  $name = $Matches[1]
  $value = $Matches[2]
  if ($name -eq 'STACKURITY_APP_DIRS' -or $name -eq 'STACKURITY_DISCOVER_APPS') {
    if ($value -and $value -ne 'false') { Say "note: $name=$value is ignored; Windows hosts report the OS and installed programs only" }
    continue
  }
  $environment += "$name=$value"
}

# The service. It runs as a virtual account that Windows creates for it
# and that cannot log on interactively, with only the privilege of passing
# through folders and a write-restricted token (it may write only where its
# own account or write-restricted services may: nowhere on disk, and the
# Application event log). It starts shortly after boot and is restarted a
# minute after a failure.
if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
  New-Service -Name $ServiceName -BinaryPathName ('"' + $Bin + '" agent --interval 6h') -DisplayName 'Stackurity agent' `
    -Description 'Reports this host''s OS build and installed programs to Stackurity. Read-only.' -StartupType Automatic | Out-Null
}
Exec 'setting the service account' 'sc.exe' @('config', $ServiceName, 'obj=', $Account, 'start=', 'delayed-auto')
Exec 'restricting the service token' 'sc.exe' @('sidtype', $ServiceName, 'restricted')
Exec 'limiting the service privileges' 'sc.exe' @('privs', $ServiceName, 'SeChangeNotifyPrivilege')
Exec 'setting restart on failure' 'sc.exe' @('failure', $ServiceName, 'reset=', '86400', 'actions=', 'restart/60000/restart/60000/restart/60000')
Exec 'setting restart on failure' 'sc.exe' @('failureflag', $ServiceName, '1')
New-ItemProperty -Path $ServiceKey -Name Environment -PropertyType MultiString -Value ([string[]]$environment) -Force | Out-Null

# The agent's output goes to the Application event log under this source.
if (-not (Test-Path -LiteralPath $EventSource)) { New-Item -Path $EventSource | Out-Null }
New-ItemProperty -Path $EventSource -Name EventMessageFile -PropertyType ExpandString -Value '%SystemRoot%\System32\EventCreate.exe' -Force | Out-Null
New-ItemProperty -Path $EventSource -Name TypesSupported -PropertyType DWord -Value 7 -Force | Out-Null

# The service account may read the settings; the token and agent.env are
# readable by it and Administrators only.
Exec 'giving the service read access' 'icacls.exe' @($Conf, '/grant:r', "${Account}:(OI)(CI)RX", '/Q')
foreach ($file in @($Token, $EnvFile)) {
  Exec "resetting $file" 'icacls.exe' @($file, '/reset', '/Q')
  Exec "restricting $file" 'icacls.exe' @($file, '/inheritance:r', '/grant:r', "${Admins}:F", "${Account}:R", '/Q')
}

Start-Service -Name $ServiceName
(Get-Service -Name $ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
Say 'the agent is running; it reports now and every 6 hours'
Say "logs: Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='$ServiceName'} -MaxEvents 20"
}
