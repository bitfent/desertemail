# DesertEmail Windows installer (generated from installers/install-windows.ps1).
# One-liner:  irm https://<site>/install-windows.ps1 | iex
# Or:         powershell -ExecutionPolicy Bypass -c "irm https://<site>/install-windows.ps1 | iex"
# Optional env:
#   DESERTEMAIL_PREFIX, DESERTEMAIL_NONINTERACTIVE=1
#   DESERTEMAIL_DOMAIN, DESERTEMAIL_ADMIN_USER, DESERTEMAIL_ADMIN_PASSWORD
#   DESERTEMAIL_DATA_DIR, DESERTEMAIL_WEBMAIL=1|0, DESERTEMAIL_PORTS=high|privileged
#   DESERTEMAIL_DKIM=1|0
#
# Placeholders substituted by site-build.sh:
#   __TARGET__   rust triple (x86_64-pc-windows-msvc)
#   __BASE_URL__ site origin (e.g. https://example.onrender.com)

$ErrorActionPreference = "Stop"

$AppName = "desertemail"
# Substituted at site-build time — do not edit by hand in generated files.
$Target = "__TARGET__"
$BaseUrl = "__BASE_URL__"
$DefaultPrefix = Join-Path $env:USERPROFILE ".desertemail"
if ($env:DESERTEMAIL_PREFIX) {
    $Prefix = $env:DESERTEMAIL_PREFIX
} else {
    $Prefix = $DefaultPrefix
}
$BinDir = Join-Path $Prefix "bin"
$ConfigPath = Join-Path $Prefix "config.toml"
$DestExe = Join-Path $BinDir "desertemail.exe"

# Script-scoped wizard results (shared across functions)
$script:Domain = ""
$script:AdminUser = ""
$script:AdminPassword = ""
$script:DataDir = ""
$script:WebListen = ""
$script:SmtpListen = ""
$script:SubListen = ""
$script:ImapListen = ""
$script:DkimKey = ""
$script:SkipConfig = $false

function Write-Info {
    param([string]$Message)
    Write-Host $Message
}

function Write-Warn {
    param([string]$Message)
    Write-Warning $Message
}

function Die {
    param([string]$Message)
    Write-Host "error: $Message" -ForegroundColor Red
    exit 1
}

function Test-IsInteractive {
    if ($env:DESERTEMAIL_NONINTERACTIVE -eq "1") {
        return $false
    }
    try {
        $null = $Host.UI.RawUI
        if ([Console]::IsOutputRedirected) {
            return $false
        }
        return $true
    } catch {
        return $false
    }
}

$script:Interactive = Test-IsInteractive

function Read-Prompt {
    param(
        [string]$Question,
        [string]$Default
    )
    if (-not $script:Interactive) {
        return $Default
    }
    if ($Default) {
        $reply = Read-Host "$Question [$Default]"
    } else {
        $reply = Read-Host $Question
    }
    if ([string]::IsNullOrEmpty($reply)) {
        return $Default
    }
    return $reply
}

function Read-Secret {
    param(
        [string]$Question,
        [string]$DefaultIfEmpty
    )
    if (-not $script:Interactive) {
        return $DefaultIfEmpty
    }
    $sec = Read-Host "$Question [hidden, Enter=generate]" -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
    try {
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) | Out-Null
    }
    if ([string]::IsNullOrEmpty($plain)) {
        return $DefaultIfEmpty
    }
    return $plain
}

function Read-YesNo {
    param(
        [string]$Question,
        [string]$Default
    )
    if (-not $script:Interactive) {
        if ($Default -match '^(Y|y|yes|YES)$') { return "y" }
        return "n"
    }
    $reply = Read-Host "$Question [$Default]"
    if ([string]::IsNullOrEmpty($reply)) {
        $reply = $Default
    }
    if ($reply -match '^(Y|y|yes|YES)$') { return "y" }
    return "n"
}

function Get-RandomPassword {
    # ~16 chars from RNG; avoid ambiguous base64 padding chars
    $bytes = New-Object byte[] 12
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    } finally {
        $rng.Dispose()
    }
    $b64 = [Convert]::ToBase64String($bytes)
    $clean = ($b64 -replace '[^A-Za-z0-9]', '')
    if ($clean.Length -ge 16) {
        return $clean.Substring(0, 16)
    }
    return ("change-me-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
}

function Escape-Toml {
    param([string]$Value)
    if ($null -eq $Value) { return "" }
    # Double backslashes first (Windows paths), then quotes — TOML double-quoted strings.
    $s = $Value -replace '\\', '\\\\'
    $s = $s -replace '"', '\"'
    return $s
}

function Install-Binary {
    $base = $BaseUrl.TrimEnd('/')
    if ([string]::IsNullOrEmpty($base)) {
        Die "installer BASE_URL is empty; rebuild the site with SITE_BASE_URL or RENDER_EXTERNAL_URL set"
    }

    $asset = "$AppName-$Target.exe"
    $url = "$base/bin/$asset"
    $sumsUrl = "$base/bin/SHA256SUMS"

    $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("desertemail-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null
    $binTmp = Join-Path $tmpDir $asset
    $sumsTmp = Join-Path $tmpDir "SHA256SUMS"

    try {
        Write-Info "Downloading $asset from $url ..."
        try {
            Invoke-WebRequest -Uri $url -OutFile $binTmp -UseBasicParsing
        } catch {
            Die "no prebuilt binary for $Target published yet — see the build-from-source installer (download failed: $url)"
        }
        if (-not (Test-Path $binTmp) -or ((Get-Item $binTmp).Length -eq 0)) {
            Die "no prebuilt binary for $Target published yet — see the build-from-source installer"
        }

        Write-Info "Downloading SHA256SUMS ..."
        $sumsOk = $false
        try {
            Invoke-WebRequest -Uri $sumsUrl -OutFile $sumsTmp -UseBasicParsing
            if ((Test-Path $sumsTmp) -and ((Get-Item $sumsTmp).Length -gt 0)) {
                $sumsOk = $true
            }
        } catch {
            $sumsOk = $false
        }

        if ($sumsOk) {
            $got = (Get-FileHash -Path $binTmp -Algorithm SHA256).Hash.ToLowerInvariant()
            $want = $null
            Get-Content $sumsTmp | ForEach-Object {
                $line = $_.Trim()
                if ([string]::IsNullOrEmpty($line)) { return }
                $parts = $line -split '\s+', 2
                if ($parts.Count -lt 2) { return }
                $name = $parts[1].Trim().TrimStart('*')
                $baseName = Split-Path $name -Leaf
                if ($name -eq $asset -or $baseName -eq $asset) {
                    $want = $parts[0].ToLowerInvariant()
                }
            }
            if (-not $want) {
                Write-Warn "SHA256SUMS has no entry for $asset; continuing without verify"
            } elseif ($got -ne $want) {
                Die "SHA256 mismatch for ${asset}: expected $want, got $got"
            } else {
                Write-Info "SHA256 verified."
            }
        } else {
            Write-Warn "could not download SHA256SUMS; continuing without verify"
        }

        if (-not (Test-Path $BinDir)) {
            New-Item -ItemType Directory -Path $BinDir -Force | Out-Null
        }
        Copy-Item -Path $binTmp -Destination $DestExe -Force
        Write-Info "Installed binary -> $DestExe"
    } finally {
        if (Test-Path $tmpDir) {
            Remove-Item -Recurse -Force $tmpDir -ErrorAction SilentlyContinue
        }
    }
}

function Ensure-UserPath {
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($null -eq $userPath) { $userPath = "" }
    $parts = $userPath -split ';' | Where-Object { $_ -ne "" }
    $already = $false
    foreach ($p in $parts) {
        if ($p -eq $BinDir) { $already = $true; break }
    }
    if ($already) {
        Write-Info "PATH already includes $BinDir"
        return
    }
    if ($userPath -and -not $userPath.EndsWith(';')) {
        $newPath = $userPath + ";" + $BinDir
    } elseif ($userPath) {
        $newPath = $userPath + $BinDir
    } else {
        $newPath = $BinDir
    }
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    $env:Path = $BinDir + ";" + $env:Path
    Write-Info "Added $BinDir to user PATH"
}

function Write-ConfigFile {
    param(
        [string]$Domain,
        [string]$Admin,
        [string]$Password,
        [string]$DataDir,
        [string]$WebListen,
        [string]$Smtp,
        [string]$Sub,
        [string]$Imap,
        [string]$DkimKey
    )

    $escPw = Escape-Toml $Password
    $escAdmin = Escape-Toml $Admin
    $escDomain = Escape-Toml $Domain
    $escData = Escape-Toml $DataDir
    $escWeb = Escape-Toml $WebListen
    $escSmtp = Escape-Toml $Smtp
    $escSub = Escape-Toml $Sub
    $escImap = Escape-Toml $Imap

    $lines = @()
    $lines += "# Generated by desertemail installer — edit as needed"
    $lines += "domains = [`"$escDomain`"]"
    $lines += "data_dir = `"$escData`""
    $lines += "smtp_listen = `"$escSmtp`""
    $lines += "submission_listen = `"$escSub`""
    $lines += "imap_listen = `"$escImap`""
    $lines += "web_listen = `"$escWeb`""
    $lines += "admin_user = `"$escAdmin`""
    $lines += "catch_all = true"
    $lines += "default_password = `"$escPw`""
    if ($DkimKey) {
        $escDkim = Escape-Toml $DkimKey
        $lines += 'dkim_selector = "mail"'
        $lines += "dkim_key_file = `"$escDkim`""
    }
    $lines += ""
    $lines += "[users]"
    $lines += "`"$escAdmin`" = `"$escPw`""

    $dir = Split-Path $ConfigPath -Parent
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    # UTF-8 without BOM so the Rust TOML parser sees plain ASCII/UTF-8
    $utf8 = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllLines($ConfigPath, $lines, $utf8)
}

function Invoke-Configure {
    Write-Info ""
    Write-Info "=== DesertEmail setup ==="
    Write-Info ""

    $defDomain = if ($env:DESERTEMAIL_DOMAIN) { $env:DESERTEMAIL_DOMAIN } else { "localhost" }
    $defAdmin = if ($env:DESERTEMAIL_ADMIN_USER) { $env:DESERTEMAIL_ADMIN_USER } else { "admin" }
    $defData = if ($env:DESERTEMAIL_DATA_DIR) { $env:DESERTEMAIL_DATA_DIR } else { (Join-Path $Prefix "data") }
    $genPw = Get-RandomPassword
    $defPw = if ($env:DESERTEMAIL_ADMIN_PASSWORD) { $env:DESERTEMAIL_ADMIN_PASSWORD } else { $genPw }

    if ($script:Interactive) {
        $script:Domain = Read-Prompt "Primary domain" $defDomain
        $script:AdminUser = Read-Prompt "Admin username" $defAdmin
        $script:AdminPassword = Read-Secret "Admin password" $defPw
        $script:DataDir = Read-Prompt "Data directory" $defData

        $web = Read-YesNo "Enable webmail?" "Y"
        if ($web -eq "y") {
            $script:WebListen = "0.0.0.0:8080"
        } else {
            $script:WebListen = ""
        }

        Write-Info "Ports:"
        Write-Info "  1) high (2525/2587/2143) — no admin required [default]"
        Write-Info "  2) privileged (25/587/143) — may need elevated privileges"
        $portSet = Read-Prompt "Port set (high/privileged)" "high"

        $enableDkim = Read-YesNo "Enable DKIM signing?" "N"
    } else {
        $script:Domain = $defDomain
        $script:AdminUser = $defAdmin
        $script:AdminPassword = $defPw
        $script:DataDir = $defData
        $wm = if ($env:DESERTEMAIL_WEBMAIL) { $env:DESERTEMAIL_WEBMAIL } else { "1" }
        if ($wm -match '^(0|n|N|false|FALSE|no|NO)$') {
            $script:WebListen = ""
        } else {
            $script:WebListen = "0.0.0.0:8080"
        }
        $portSet = if ($env:DESERTEMAIL_PORTS) { $env:DESERTEMAIL_PORTS } else { "high" }
        $dk = if ($env:DESERTEMAIL_DKIM) { $env:DESERTEMAIL_DKIM } else { "0" }
        if ($dk -match '^(1|y|Y|true|TRUE|yes|YES)$') {
            $enableDkim = "y"
        } else {
            $enableDkim = "n"
        }
    }

    if ($portSet -match '^(privileged|priv|2)$') {
        $script:SmtpListen = "0.0.0.0:25"
        $script:SubListen = "0.0.0.0:587"
        $script:ImapListen = "0.0.0.0:143"
    } else {
        $script:SmtpListen = "0.0.0.0:2525"
        $script:SubListen = "0.0.0.0:2587"
        $script:ImapListen = "0.0.0.0:2143"
    }

    $script:DkimKey = ""
    if ($enableDkim -eq "y") {
        $openssl = Get-Command openssl.exe -ErrorAction SilentlyContinue
        if ($openssl) {
            $script:DkimKey = Join-Path $Prefix "dkim.pem"
            if (-not (Test-Path $script:DkimKey)) {
                Write-Info "Generating DKIM key at $($script:DkimKey) ..."
                $p = Start-Process -FilePath $openssl.Source -ArgumentList @("genrsa", "-out", $script:DkimKey, "2048") -Wait -PassThru -NoNewWindow
                if ($p.ExitCode -ne 0) {
                    Die "openssl genrsa failed"
                }
            } else {
                Write-Info "Using existing DKIM key $($script:DkimKey)"
            }
        } else {
            Write-Warn "openssl.exe not found in PATH; skipping DKIM key generation"
            Write-Warn "later: install openssl, then run: desertemail setup dkim --config `"$ConfigPath`""
            Write-Warn "(no openssl possible? opt in to the unaudited built-in keygen with DESERTEMAIL_ALLOW_UNAUDITED_KEYGEN=1)"
            $script:DkimKey = ""
        }
    }

    if (-not (Test-Path $Prefix)) {
        New-Item -ItemType Directory -Path $Prefix -Force | Out-Null
    }
    if (-not (Test-Path $script:DataDir)) {
        New-Item -ItemType Directory -Path $script:DataDir -Force | Out-Null
    }

    $script:SkipConfig = $false
    if (Test-Path $ConfigPath) {
        if ($script:Interactive) {
            $ow = Read-YesNo "Config already exists at $ConfigPath. Overwrite?" "N"
            if ($ow -ne "y") {
                Write-Info "Keeping existing config."
                $script:SkipConfig = $true
            }
        } else {
            Write-Info "Config already exists; keeping it (non-interactive)."
            $script:SkipConfig = $true
        }
    }

    if (-not $script:SkipConfig) {
        Write-ConfigFile `
            -Domain $script:Domain `
            -Admin $script:AdminUser `
            -Password $script:AdminPassword `
            -DataDir $script:DataDir `
            -WebListen $script:WebListen `
            -Smtp $script:SmtpListen `
            -Sub $script:SubListen `
            -Imap $script:ImapListen `
            -DkimKey $script:DkimKey
        Write-Info "Wrote config -> $ConfigPath"
    }
}

function Show-Summary {
    Write-Info ""
    Write-Info "========================================"
    Write-Info " DesertEmail install complete"
    Write-Info "========================================"
    Write-Info " Binary : $DestExe"
    Write-Info " Config : $ConfigPath"
    Write-Info " Prefix : $Prefix"
    Write-Info (" Ports  : SMTP {0} | submission {1} | IMAP {2}" -f $script:SmtpListen, $script:SubListen, $script:ImapListen)
    if ($script:WebListen) {
        Write-Info " Webmail: http://127.0.0.1:8080  (listen $($script:WebListen))"
    } else {
        Write-Info " Webmail: disabled"
    }
    Write-Info ""
    Write-Info "Start manually:"
    Write-Info "  & `"$DestExe`" --config `"$ConfigPath`""
    Write-Info ""
    Write-Info "To run at login, create a Task Scheduler task that runs the command above."
    Write-Info "(This installer does not register a Windows service.)"
    Write-Info ""
    Write-Info "If PATH was updated, open a new PowerShell window."
    Write-Info ""

    if ($script:DkimKey -and (Test-Path $script:DkimKey)) {
        Write-Info "DNS records to publish for domain '$($script:Domain)':"
        Write-Info "  MX  $($script:Domain).  10  <your-server-hostname>."
        Write-Info "  A   <your-server-hostname>.  <your-public-ip>"
        Write-Info "  TXT $($script:Domain).  `"v=spf1 mx ~all`""
        Write-Info ""
        Write-Info "DKIM TXT (from binary --dkim-dns):"
        try {
            & $DestExe --dkim-dns $script:Domain --config $ConfigPath
        } catch {
            try {
                & $DestExe --config $ConfigPath --dkim-dns $script:Domain
            } catch {
                Write-Warn "could not run --dkim-dns; run: & `"$DestExe`" --dkim-dns $($script:Domain) --config `"$ConfigPath`""
            }
        }
    } else {
        Write-Info "DNS (when going public): MX + A/AAAA + SPF TXT for your domain."
    }
    Write-Info ""
    Write-Info "Admin password is stored in $ConfigPath (not shown here)."
    Write-Info "========================================"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

Write-Info "DesertEmail installer"
Write-Info "Target: $Target"

Install-Binary
Ensure-UserPath
Invoke-Configure
Show-Summary
