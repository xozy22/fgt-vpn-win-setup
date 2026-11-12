<#
.SYNOPSIS
    FGT-VPN Setup: IKEv2-Always-On-VPN von Windows 11 zur FortiGate (FortiOS 7.6).

.DESCRIPTION
    Menue (interaktiv):
      A  Assistent (gefuehrtes Setup)          4  Status und Verbindungstest
      1  Windows-Client einrichten              5  Deinstallieren (optional FortiGate)
      2  FortiGate konfigurieren (SSH)          P  Client-Paket fuer einen anderen PC
      3  Zertifikate erzeugen                   K  Clients verwalten / sperren
      X  FortiGate-Konfiguration entfernen      S  Einstellungen anzeigen
      E  Einstellungen aendern     H  Kurzanleitung     Q  Beenden

    Krypto: IKE AES256/SHA384/DH20 (ECP384), ESP AES256-GCM, PFS DH20.
    Wichtig: Mit ECP384 verlangt Windows ein ECDSA-P384-Maschinenzertifikat.
    Das Skript erzeugt Client-Zertifikate deshalb als ECDSA P-384.

    Nicht-interaktiv (Tests/Rollout):
      .\FGT-VPN-Setup.ps1 -Action "Purge,Certs,Fgt,Client" -Auto -PfxPassword "..." -LogFile C:\temp\vpn.log
      Aktionen: Menu, Wizard, Help, Settings, Certs, Fgt, FgtRemove, Client, Package,
                Clients, Peers, Revoke, Status, Uninstall, Purge

    Rollen:
      Admin-PC   (Zugriff auf die FortiGate): 3 Zertifikate, 2 FortiGate, P Client-Paket
      VPN-Client (beliebiger PC):             Paket entpacken, Installieren.cmd starten
      EAP im Auto-Modus: zusaetzlich -VpnUser und -VpnPassword.
      -MovePolicies verschiebt im Auto-Modus eigene Policies vor eine Deny-Policy.
      -Auto beantwortet Rueckfragen mit dem Standardwert. Das FortiGate-Passwort
      fragt ssh.exe weiterhin selbst ab.

.NOTES
    Starten:  Rechtsklick > "Mit PowerShell ausfuehren"
    oder:     Set-ExecutionPolicy -Scope Process Bypass -Force; .\FGT-VPN-Setup.ps1
    Administratorrechte werden bei Bedarf automatisch angefordert.
#>
param(
    [string]$Action = 'Menu',
    [switch]$Auto,
    [string]$PfxPassword,
    [string]$VpnUser,
    [string]$VpnPassword,
    [string]$ClientName,
    [switch]$NewCa,
    [switch]$MovePolicies,
    [string]$LogFile,
    [switch]$Elevated
)

$ErrorActionPreference = 'Stop'
$Script:Version = '3.1'
$Script:Actions = @($Action -split '[,; ]+' | Where-Object { $_ })
$valid = 'Menu','Wizard','Help','Settings','Certs','Fgt','FgtRemove','Client','Package','Clients','Peers','Revoke','Status','Uninstall','Purge'
foreach ($a in $Script:Actions) { if ($valid -notcontains $a) { Write-Host "Unbekannte Aktion: $a (erlaubt: $($valid -join ', '))" -ForegroundColor Red; exit 2 } }

# ---------------------------------------------------------------------------
# Administratorrechte: bei Bedarf automatisch anfordern (UAC)
# ---------------------------------------------------------------------------
$curPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $curPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    if (-not $PSCommandPath) { Write-Host 'Bitte das Skript als Datei speichern und starten.' -ForegroundColor Red; return }
    Write-Host '  Administratorrechte werden benoetigt, fordere sie an ...' -ForegroundColor Yellow
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $PSCommandPath), '-Elevated',
                 '-Action', ('"{0}"' -f ($Script:Actions -join ',')))
    if ($Auto)        { $argList += '-Auto' }
    if ($PfxPassword) { $argList += @('-PfxPassword', ('"{0}"' -f $PfxPassword)) }
    if ($VpnUser)     { $argList += @('-VpnUser', ('"{0}"' -f $VpnUser)) }
    if ($VpnPassword) { $argList += @('-VpnPassword', ('"{0}"' -f $VpnPassword)) }
    if ($ClientName)  { $argList += @('-ClientName', ('"{0}"' -f $ClientName)) }
    if ($NewCa)       { $argList += '-NewCa' }
    if ($MovePolicies) { $argList += '-MovePolicies' }
    if ($LogFile)     { $argList += @('-LogFile', ('"{0}"' -f $LogFile)) }
    try { Start-Process -FilePath (Get-Process -Id $PID).Path -Verb RunAs -ArgumentList $argList }
    catch { Write-Host '  Erhoehung abgebrochen. Ohne Administratorrechte ist das Setup nicht moeglich.' -ForegroundColor Red }
    return
}

# ---------------------------------------------------------------------------
# Globale Werte
# ---------------------------------------------------------------------------
$Script:Auto         = [bool]$Auto
$Script:Root         = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$Script:SettingsFile = Join-Path $Script:Root 'fgt-vpn-settings.json'
$Script:CertDir      = Join-Path $Script:Root 'vpn-certs'
$Script:BaseDir      = 'C:\ProgramData\FGT-VPN'
$Script:TaskName     = 'FGT-VPN Watchdog'
$Script:CaSubject    = 'CN=FGT-VPN Root CA v2'
$Script:CaFamily     = 'CN=FGT-VPN Root CA*'
$Script:EkuClient    = '1.3.6.1.5.5.7.3.2'
$Script:EkuServer    = '1.3.6.1.5.5.7.3.1'
$Script:EkuIke       = '1.3.6.1.5.5.8.2.2'
$Script:Settings     = $null
# Gueltigkeits-Obergrenzen: CA 20 Jahre, Serverzertifikat 825 Tage (Obergrenze fuer TLS-Serverzertifikate
# privater CAs, z. B. Apple), Client 5 Jahre - Zertifikate nie laenger als die ausstellende CA.
$Script:MaxCaYears    = 20
$Script:MaxServerDays = 825
$Script:MaxClientDays = 1825

if ($LogFile) { try { Start-Transcript -Path $LogFile -Force | Out-Null } catch {} }
try { $Host.UI.RawUI.WindowTitle = "FGT-VPN Setup $Script:Version" } catch {}

# ---------------------------------------------------------------------------
# Oberflaeche
# ---------------------------------------------------------------------------
$Script:W = 80

function Write-Line([string]$Char = '-', [string]$Color = 'DarkCyan') {
    Write-Host ('  +' + ($Char * ($Script:W - 2)) + '+') -ForegroundColor $Color
}

function Write-BoxText([string]$Text, [string]$Color = 'Gray', [string]$Frame = 'DarkCyan') {
    $t = $Text
    if ($t.Length -gt $Script:W - 4) { $t = $t.Substring(0, $Script:W - 4) }
    Write-Host '  | ' -ForegroundColor $Frame -NoNewline
    Write-Host $t.PadRight($Script:W - 4) -ForegroundColor $Color -NoNewline
    Write-Host ' |' -ForegroundColor $Frame
}

function Show-Banner {
    if (-not $Script:Auto) { try { Clear-Host } catch {} }
    $logo = @(
        '   _____ ____ _____     __     ______  _   _ ',
        '  |  ___/ ___|_   _|    \ \   / /  _ \| \ | |',
        '  | |_ | |  _  | |  _____\ \ / /| |_) |  \| |',
        '  |  _|| |_| | | | |_____|\ V / |  __/| |\  |',
        '  |_|   \____| |_|         \_/  |_|   |_| \_|'
    )
    $colors = @('Cyan', 'Cyan', 'DarkCyan', 'DarkCyan', 'Blue')
    Write-Host ''
    for ($i = 0; $i -lt $logo.Count; $i++) { Write-Host ('  ' + $logo[$i]) -ForegroundColor $colors[$i] }
    Write-Host ''
    Write-Host '     ' -NoNewline
    Write-Host ' IKEv2 ' -ForegroundColor Black -BackgroundColor Cyan -NoNewline
    Write-Host ' ALWAYS-ON ' -ForegroundColor Black -BackgroundColor DarkCyan -NoNewline
    Write-Host ' ECP384 / AES-GCM ' -ForegroundColor White -BackgroundColor DarkBlue -NoNewline
    Write-Host "  Windows 11 <==> FortiGate  v$Script:Version" -ForegroundColor DarkGray
    Write-Host ''
}

function Write-Section([string]$Title, [string]$Step = '') {
    Write-Host ''
    Write-Line '='
    $label = if ($Step) { "[$Step]  $Title" } else { $Title }
    Write-BoxText $label 'White'
    Write-Line '='
}

function Write-Badge([string]$Badge, [string]$Fg, [string]$Bg, [string]$Text, [string]$TextColor = 'Gray') {
    Write-Host '   ' -NoNewline
    Write-Host " $Badge " -ForegroundColor $Fg -BackgroundColor $Bg -NoNewline
    Write-Host " $Text" -ForegroundColor $TextColor
}
function Write-Ok([string]$Text)    { Write-Badge ' OK ' 'Black' 'Green'    $Text }
function Write-Warn2([string]$Text) { Write-Badge ' !! ' 'Black' 'Yellow'   $Text 'Yellow' }
function Write-Err2([string]$Text)  { Write-Badge 'FAIL' 'White' 'DarkRed'  $Text 'Red' }
function Write-Info([string]$Text)  { Write-Badge ' .. ' 'White' 'DarkGray' $Text 'DarkGray' }
function Write-Step([string]$Text)  { Write-Host ''; Write-Host "   >> $Text" -ForegroundColor Cyan }

function Wait-Until {
    # Wartet mit Spinner, bis $Condition $true liefert oder die Zeit ablaeuft
    param([scriptblock]$Condition, [int]$Seconds, [string]$Text)
    $spin = '|/-\'
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $i = 0
    while ($sw.Elapsed.TotalSeconds -lt $Seconds) {
        if (& $Condition) { Write-Host ("`r" + (' ' * ($Script:W + 4)) + "`r") -NoNewline; return $true }
        if (-not $LogFile) { Write-Host ("`r   [{0}] {1} ({2}s)  " -f $spin[$i % 4], $Text, [int]$sw.Elapsed.TotalSeconds) -NoNewline -ForegroundColor DarkCyan }
        Start-Sleep -Milliseconds 500
        $i++
    }
    Write-Host ''
    return $false
}

# ---------------------------------------------------------------------------
# Eingabe
# ---------------------------------------------------------------------------
function Read-Default {
    param([string]$Prompt, [string]$Default = '')
    if ($Script:Auto) { return $Default }
    $suffix = if ($Default) { " [$Default]" } else { '' }
    Write-Host '   ? ' -ForegroundColor Cyan -NoNewline
    $v = Read-Host "$Prompt$suffix"
    if ([string]::IsNullOrWhiteSpace($v)) { return $Default }
    return $v.Trim()
}

function Read-YesNo {
    param([string]$Prompt, [bool]$Default = $true)
    if ($Script:Auto) { return $Default }
    $hint = if ($Default) { 'J/n' } else { 'j/N' }
    while ($true) {
        Write-Host '   ? ' -ForegroundColor Cyan -NoNewline
        $v = Read-Host "$Prompt ($hint)"
        if ([string]::IsNullOrWhiteSpace($v)) { return $Default }
        switch -Regex ($v.Trim()) {
            '^(j|ja|y|yes)$' { return $true }
            '^(n|nein|no)$'  { return $false }
        }
    }
}

function Read-Choice {
    param([string]$Prompt, [string[]]$Options, [string]$Default)
    while ($true) {
        $v = Read-Default $Prompt $Default
        if ($Options -contains $v) { return $v }
        Write-Warn2 "Bitte eine der Optionen waehlen: $($Options -join ', ')"
    }
}

function ConvertTo-Plain([Security.SecureString]$Secure) {
    return (New-Object System.Net.NetworkCredential('', $Secure)).Password
}

function Read-Secret {
    param([string]$Prompt, [switch]$Confirm)
    while ($true) {
        Write-Host '   ? ' -ForegroundColor Cyan -NoNewline
        $a = Read-Host $Prompt -AsSecureString
        $pa = ConvertTo-Plain $a
        if ([string]::IsNullOrEmpty($pa)) { Write-Warn2 'Leere Eingabe ist nicht erlaubt.'; continue }
        if ($pa.Contains('"')) { Write-Warn2 'Bitte kein Anfuehrungszeichen (") verwenden.'; continue }
        if (-not $Confirm) { return $a }
        Write-Host '   ? ' -ForegroundColor Cyan -NoNewline
        $b = Read-Host 'Wiederholen' -AsSecureString
        if ($pa -ceq (ConvertTo-Plain $b)) { return $a }
        Write-Warn2 'Eingaben stimmen nicht ueberein.'
    }
}

function Get-PfxPassword {
    if ($PfxPassword) { return (ConvertTo-SecureString $PfxPassword -AsPlainText -Force) }
    if ($Script:Auto) { throw 'Im Auto-Modus wird -PfxPassword benoetigt.' }
    return (Read-Secret 'Passwort fuer die PFX-Dateien' -Confirm)
}

function Wait-Enter([string]$Text = 'Weiter mit Enter') {
    if ($Script:Auto) { return }
    Write-Host "   $Text " -ForegroundColor DarkGray -NoNewline
    $null = Read-Host
}

# ---------------------------------------------------------------------------
# Hilfsfunktionen
# ---------------------------------------------------------------------------
function Test-IPv4([string]$Ip) {
    $parsed = $null
    return ([Net.IPAddress]::TryParse($Ip, [ref]$parsed) -and $parsed.AddressFamily -eq 'InterNetwork' -and $Ip -match '^(\d{1,3}\.){3}\d{1,3}$')
}

function ConvertTo-Mask([int]$Prefix) {
    $mask = ([uint64]4294967295 -shl (32 - $Prefix)) -band [uint64]4294967295
    return '{0}.{1}.{2}.{3}' -f (($mask -shr 24) -band 255), (($mask -shr 16) -band 255), (($mask -shr 8) -band 255), ($mask -band 255)
}

function ConvertTo-IpNum([string]$Ip) {
    $b = ([Net.IPAddress]::Parse($Ip)).GetAddressBytes()
    return ([uint64]$b[0] * 16777216) + ([uint64]$b[1] * 65536) + ([uint64]$b[2] * 256) + [uint64]$b[3]
}

function ConvertFrom-IpNum([uint64]$N) {
    $a = [math]::Floor($N / 16777216) % 256
    $b = [math]::Floor($N / 65536) % 256
    $c = [math]::Floor($N / 256) % 256
    $d = $N % 256
    return "$a.$b.$c.$d"
}

function Get-LanNets {
    $result = @()
    foreach ($n in ($Script:Settings.LanNets -split ',')) {
        $n = $n.Trim()
        if (-not $n) { continue }
        if ($n -notmatch '^((\d{1,3}\.){3}\d{1,3})/(\d{1,2})$' -or -not (Test-IPv4 $Matches[1]) -or [int]$Matches[3] -gt 32) { throw "Ungueltiges Netz: $n (Format a.b.c.d/nn)" }
        $ip = $Matches[1]; $prefix = [int]$Matches[3]
        $size = [uint64][math]::Pow(2, 32 - $prefix)
        $netNum = [uint64]([math]::Floor((ConvertTo-IpNum $ip) / $size) * $size)
        $net = ConvertFrom-IpNum $netNum
        if ($net -ne $ip) { throw "Netz $n hat gesetzte Host-Bits - gemeint ist vermutlich $net/$prefix" }
        $result += [pscustomobject]@{ Cidr = $n; Net = $net; Prefix = $prefix; Mask = (ConvertTo-Mask $prefix); First = $netNum; Size = $size }
    }
    if ($result.Count -eq 0) { throw 'Keine internen Netze konfiguriert.' }
    return $result
}

function Test-IpInLanNets([string]$Ip) {
    if (-not (Test-IPv4 $Ip)) { return $false }
    $x = ConvertTo-IpNum $Ip
    foreach ($n in (Get-LanNets)) { if ($x -ge $n.First -and $x -lt ($n.First + $n.Size)) { return $true } }
    return $false
}

function Test-DnsRouted {
    $s = $Script:Settings
    return ($s.DnsViaTunnel -eq 'Yes' -and -not (Test-IpInLanNets $s.DnsServer))
}

function Get-RouteNets {
    # Interne Netze plus (optional) DNS-Server als /32
    $r = @((Get-LanNets) | ForEach-Object { $_.Cidr })
    if (Test-DnsRouted) { $r += "$($Script:Settings.DnsServer)/32" }
    return $r
}

function Write-DnsHint {
    $s = $Script:Settings
    if (-not (Test-IpInLanNets $s.DnsServer) -and $s.DnsViaTunnel -ne 'Yes') {
        Write-Warn2 "DNS-Server $($s.DnsServer) liegt ausserhalb der internen Netze und wird NICHT ueber den Tunnel erreicht (Einstellung E)."
    }
}

function Protect-Folder([string]$Path) {
    # Nur SYSTEM, Administratoren und der aktuelle Benutzer
    & icacls.exe $Path /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' "$($env:USERDOMAIN)\$($env:USERNAME):(OI)(CI)F" | Out-Null
}

function Read-Number {
    param([string]$Prompt, [int]$Default, [int]$Min, [int]$Max)
    if ($Default -gt $Max) { $Default = $Max }
    if ($Default -lt $Min) { $Default = $Min }
    while ($true) {
        $v = Read-Default "$Prompt ($Min-$Max)" "$Default"
        $n = 0
        if ([int]::TryParse($v, [ref]$n) -and $n -ge $Min -and $n -le $Max) { return $n }
        Write-Warn2 "Bitte eine Zahl von $Min bis $Max eingeben."
    }
}

function New-RandomPassword([int]$Length = 16) {
    $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789'
    $bytes = New-Object byte[] $Length
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    return -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })
}

function Format-FgtList([string]$Csv) {
    return (($Csv -split ',') | Where-Object { $_.Trim() } | ForEach-Object { '"' + $_.Trim() + '"' }) -join ' '
}

function Get-ShortId($Cert) { return $Cert.Thumbprint.Substring(0, 6).ToLower() }

# ---------------------------------------------------------------------------
# Einstellungen
# ---------------------------------------------------------------------------
function Get-DefaultSettings {
    return [pscustomobject]@{
        Fqdn           = 'vpn.example.de'
        ConnName       = 'FGT-VPN'
        AuthMode       = 'Cert'          # Cert | EAP
        LanNets        = '192.168.10.0/24'
        TestIp         = ''
        TunnelMode     = 'Split'         # Split | Full
        PolicyBoth     = 'No'            # Yes = zusaetzlich Policy LAN -> VPN-Clients
        DnsServer      = '192.168.10.1'
        DnsSuffix      = ''
        DnsViaTunnel   = 'No'            # Yes = DNS-Server ausserhalb der internen Netze ueber den Tunnel
        CaYears        = '10'
        ServerDays     = '825'
        ClientDays     = '825'
        PoolStart      = '10.10.50.10'
        PoolEnd        = '10.10.50.50'
        PoolMask       = '255.255.255.0'
        P1Name         = 'WIN-IKEv2'
        WanIf          = 'wan1'
        LanIf          = 'internal'
        Vdom           = ''
        ServerCertMode = 'Own'           # Own | Existing
        ServerCertName = 'FGT-VPN-Server'
        CaName         = 'FGT-VPN-CA'
        UserGroup      = 'VPN-Users'
        FgtHost        = ''
        FgtPort        = '22'
        FgtUser        = 'admin'
    }
}

function Import-Settings {
    $s = Get-DefaultSettings
    $found = $false
    if (Test-Path $Script:SettingsFile) {
        $saved = Get-Content $Script:SettingsFile -Raw | ConvertFrom-Json
        foreach ($p in $saved.PSObject.Properties) {
            if ($s.PSObject.Properties.Name -contains $p.Name) { $s.($p.Name) = $p.Value }
        }
        $found = $true
    }
    $Script:Settings = $s
    return $found
}

function Save-Settings {
    $Script:Settings | ConvertTo-Json | Set-Content -Path $Script:SettingsFile -Encoding UTF8
}

function Get-TestIp {
    $s = $Script:Settings
    if ($s.TestIp) { return $s.TestIp }
    $o = (Get-LanNets)[0].Net.Split('.')
    return '{0}.{1}.{2}.{3}' -f $o[0], $o[1], $o[2], ([int]$o[3] + 1)
}

function Edit-Settings {
    $s = $Script:Settings
    Write-Section 'Einstellungen' 'E'
    Write-Info 'Enter uebernimmt den Wert in eckigen Klammern.'

    Write-Step 'Allgemein'
    do { $s.Fqdn = Read-Default 'FQDN oder IP der FortiGate (WAN)' $s.Fqdn } until ($s.Fqdn -match '^[A-Za-z0-9.-]+$')
    do { $s.ConnName = Read-Default 'Name der VPN-Verbindung in Windows' $s.ConnName } until ($s.ConnName -match '^[A-Za-z0-9 _.-]+$')
    $cur = if ($s.AuthMode -eq 'EAP') { '2' } else { '1' }
    $a = Read-Choice 'Anmeldung: 1 = Maschinenzertifikat (empfohlen), 2 = EAP Benutzer/Passwort' @('1','2') $cur
    $s.AuthMode = if ($a -eq '2') { 'EAP' } else { 'Cert' }
    $cur = if ($s.ServerCertMode -eq 'Existing') { '2' } else { '1' }
    $a = Read-Choice 'FortiGate-Zertifikat: 1 = vom Skript erzeugen, 2 = vorhandenes (z. B. Let''s Encrypt)' @('1','2') $cur
    if ($a -eq '2') {
        $s.ServerCertMode = 'Existing'
        $s.ServerCertName = Read-Default 'Name des vorhandenen Zertifikats auf der FortiGate' $s.ServerCertName
        Write-Warn2 "SAN muss $($s.Fqdn) enthalten, EKU Server Authentication, CA muss Windows bekannt sein."
    } else {
        $s.ServerCertMode = 'Own'
        $s.ServerCertName = Read-Default 'Namenspraefix fuer das Serverzertifikat auf der FortiGate' $s.ServerCertName
    }

    Write-Step 'Netze'
    while ($true) {
        $s.LanNets = Read-Default 'Interne Netze hinter der FortiGate (kommagetrennt, a.b.c.d/nn)' $s.LanNets
        try { $null = Get-LanNets; break } catch { Write-Warn2 $_.Exception.Message }
    }
    $s.TestIp = Read-Default 'IP fuer den Ping-Test durch den Tunnel (leer = erste IP im Netz)' $s.TestIp
    $cur = if ($s.TunnelMode -eq 'Full') { '2' } else { '1' }
    $a = Read-Choice 'Tunnel: 1 = Split (nur interne Netze ueber VPN), 2 = Full (gesamter Verkehr inkl. Internet)' @('1','2') $cur
    $s.TunnelMode = if ($a -eq '2') { 'Full' } else { 'Split' }
    $s.PolicyBoth = if (Read-YesNo 'Policies in beide Richtungen anlegen (auch LAN -> VPN-Clients, z. B. fuer RDP/Fernwartung)?' ($s.PolicyBoth -eq 'Yes')) { 'Yes' } else { 'No' }
    do { $s.PoolStart = Read-Default 'IP-Pool Start' $s.PoolStart } until ((Test-IPv4 $s.PoolStart) -and -not (Test-IpInLanNets $s.PoolStart))
    do { $s.PoolEnd   = Read-Default 'IP-Pool Ende'  $s.PoolEnd }   until ((Test-IPv4 $s.PoolEnd) -and -not (Test-IpInLanNets $s.PoolEnd) -and (ConvertTo-IpNum $s.PoolEnd) -ge (ConvertTo-IpNum $s.PoolStart))
    do { $s.PoolMask  = Read-Default 'IP-Pool Netzmaske' $s.PoolMask } until (Test-IPv4 $s.PoolMask)
    do { $s.DnsServer = Read-Default 'DNS-Server fuer VPN-Clients' $s.DnsServer } until (Test-IPv4 $s.DnsServer)
    if (Test-IpInLanNets $s.DnsServer) { $s.DnsViaTunnel = 'No' }
    else {
        Write-Warn2 "DNS-Server $($s.DnsServer) liegt nicht in den internen Netzen."
        $s.DnsViaTunnel = if (Read-YesNo 'DNS-Server ueber den Tunnel erreichbar machen (Route + Policy-Ziel, er muss hinter den Ziel-Interfaces liegen)?' $true) { 'Yes' } else { 'No' }
    }
    $s.DnsSuffix = Read-Default 'DNS-Suffix (leer = keins)' $s.DnsSuffix

    Write-Step 'FortiGate'
    do { $s.P1Name = Read-Default 'Name Phase1 (max. 13 Zeichen)' $s.P1Name } until ($s.P1Name -match '^[A-Za-z0-9_-]{1,13}$')
    $s.Vdom  = Read-Default 'VDOM (leer = VDOMs nicht aktiv)' $s.Vdom
    if ($s.AuthMode -eq 'Cert') { $s.CaName = Read-Default 'Namenspraefix der CA auf der FortiGate' $s.CaName }
    else { $s.UserGroup = Read-Default 'Benutzergruppe auf der FortiGate' $s.UserGroup }
    $s.FgtHost = Read-Default 'Management-IP der FortiGate fuer SSH' $(if ($s.FgtHost) { $s.FgtHost } else { $s.Fqdn })
    $s.FgtPort = Read-Default 'SSH-Port' $s.FgtPort
    $s.FgtUser = Read-Default 'Admin-Benutzer' $s.FgtUser

    Write-Step 'Interfaces'
    $ifs = $null
    if ($s.FgtHost -and -not $Script:Auto -and (Read-YesNo 'Interfaces per SSH von der FortiGate lesen (nur lesend)?' $true)) {
        $ifs = Get-FgtInterfaces
        if ($ifs -and -not $ifs.Count) { Write-Warn2 'Keine passenden Interfaces gefunden.'; $ifs = $null }
    }
    if ($ifs) {
        Show-FgtInterfaces $ifs
        $names = @($ifs | ForEach-Object { $_.Name })
        $defWan = if ($names -contains $s.WanIf) { $s.WanIf } else { (@($ifs | Where-Object { $_.Role -eq 'wan' -and -not $_.Down }) + @($ifs | Where-Object { $_.Role -eq 'wan' }) + @([pscustomobject]@{ Name = $s.WanIf }))[0].Name }
        $s.WanIf = Select-FgtInterface -List $ifs -Prompt 'WAN-Interface (Nummer oder Name)' -Default $defWan
        $curLan = @(($s.LanIf -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        $defLan = if ($curLan.Count -and -not @($curLan | Where-Object { $names -notcontains $_ }).Count) { $curLan -join ',' }
                  else { $l = @($ifs | Where-Object { $_.Role -eq 'lan' -and -not $_.Down } | ForEach-Object { $_.Name }); if ($l.Count) { $l -join ',' } else { $s.LanIf } }
        $s.LanIf = Select-FgtInterface -List $ifs -Prompt 'Ziel-Interface(s) fuer die Policy (Nummern oder Namen, kommagetrennt)' -Default $defLan -Multi
        if (@($s.LanIf -split ',') -contains $s.WanIf) { Write-Warn2 'WAN-Interface ist auch als Ziel-Interface gewaehlt - bitte pruefen.' }
    } else {
        $s.WanIf = Read-Default 'WAN-Interface' $s.WanIf
        $s.LanIf = Read-Default 'Ziel-Interface(s) fuer die Policy (kommagetrennt)' $s.LanIf
    }

    Save-Settings
    Write-Ok "Gespeichert: $Script:SettingsFile"
}

function Show-Settings {
    Initialize-Settings
    $s = $Script:Settings
    Write-Section 'Einstellungen anzeigen' 'S'
    $yn = { param($v) if ($v -eq 'Yes') { 'ja' } else { 'nein' } }
    $p1 = $s.P1Name
    $groups = [ordered]@{
        'ALLGEMEIN' = @(
            @('FortiGate (VPN-Ziel)', $s.Fqdn),
            @('VPN-Verbindung', $s.ConnName),
            @('Anmeldung', $(if ($s.AuthMode -eq 'EAP') { "EAP (Gruppe $($s.UserGroup)) - kein Always-On" } else { 'Maschinenzertifikat (ECDSA P-384)' })),
            @('Serverzertifikat', $(if ($s.ServerCertMode -eq 'Own') { "vom Skript erzeugt, Praefix $($s.ServerCertName)" } else { "vorhanden: $($s.ServerCertName)" })))
        'NETZ UND TUNNEL' = @(
            @('Tunnel', $(if ($s.TunnelMode -eq 'Full') { 'Full (gesamter Verkehr)' } else { 'Split (nur interne Netze)' })),
            @('Interne Netze', $s.LanNets),
            @('Ping-Test', (Get-TestIp)),
            @('IP-Pool', "$($s.PoolStart) - $($s.PoolEnd) / $($s.PoolMask)"),
            @('DNS', ("{0}{1}{2}" -f $s.DnsServer, $(if ($s.DnsSuffix) { " (Suffix $($s.DnsSuffix))" } else { '' }), $(if (Test-IpInLanNets $s.DnsServer) { ', im internen Netz' } elseif ($s.DnsViaTunnel -eq 'Yes') { ', ueber den Tunnel' } else { ', NICHT ueber den Tunnel' }))),
            @('Routen ueber VPN', ((Get-RouteNets) -join ', ')))
        'FORTIGATE' = @(
            @('Phase1 / Phase2', "$p1 / $p1-p2"),
            @('WAN / Ziel-Interface', "$($s.WanIf) / $($s.LanIf)"),
            @('VDOM', $(if ($s.Vdom) { $s.Vdom } else { '(keine)' })),
            @('Policies', ((Get-WantedPolicies | ForEach-Object { $_.Name }) -join ', ')),
            @('Beide Richtungen', (& $yn $s.PolicyBoth)),
            @('Logging', 'alle Sitzungen (logtraffic all)'),
            @('CA-Praefix', $s.CaName),
            @('Clients (Peer-Gruppe)', $(if ($s.AuthMode -eq 'Cert') { $a = @(Get-ActiveClients); "$p1-clients: $(if ($a.Count) { ($a | ForEach-Object { $_.Name }) -join ', ' } else { '(keine)' })" } else { '-' })),
            @('SSH-Zugang', "$($s.FgtUser)@$(if ($s.FgtHost) { $s.FgtHost } else { $s.Fqdn }):$($s.FgtPort)"))
        'GUELTIGKEIT' = @(
            @('CA (neu)', "$($s.CaYears) Jahre (max. $Script:MaxCaYears)"),
            @('Serverzertifikat', "$($s.ServerDays) Tage (max. $Script:MaxServerDays)"),
            @('Client-Zertifikate', "$($s.ClientDays) Tage (max. $Script:MaxClientDays, nie laenger als die CA)"))
        'KRYPTO' = @(
            @('IKE (Phase1)', 'AES256 / SHA384 / DH20 (ECP384)'),
            @('ESP (Phase2)', 'AES256-GCM / PFS DH20'))
        'DATEIEN' = @(
            @('Einstellungen', $Script:SettingsFile),
            @('Zertifikate', $Script:CertDir),
            @('Watchdog', "$Script:BaseDir (Aufgabe '$Script:TaskName')"))
    }
    Write-Line
    $first = $true
    foreach ($g in $groups.Keys) {
        if (-not $first) { Write-BoxText '' }
        $first = $false
        Write-BoxText $g 'Cyan'
        foreach ($row in $groups[$g]) { Write-BoxText ('  {0,-22}{1}' -f $row[0], $row[1]) 'Gray' }
    }
    Write-Line
    Write-Info 'Aendern: Menuepunkt E'
}

function Initialize-Settings {
    if (-not $Script:Settings) { $null = Import-Settings }
    if (-not (Test-Path $Script:SettingsFile)) {
        if ($Script:Auto) { throw "Keine Einstellungen gefunden ($Script:SettingsFile)." }
        Write-Warn2 'Noch keine Einstellungen vorhanden.'
        Edit-Settings
    }
}

# ---------------------------------------------------------------------------
# Zertifikate
# ---------------------------------------------------------------------------
function ConvertTo-Pem([byte[]]$Der, [string]$Label) {
    $b64 = [Convert]::ToBase64String($Der)
    $lines = for ($i = 0; $i -lt $b64.Length; $i += 64) { $b64.Substring($i, [Math]::Min(64, $b64.Length - $i)) }
    return "-----BEGIN $Label-----`n" + ($lines -join "`n") + "`n-----END $Label-----"
}

function Get-DerLength([int]$Len) {
    if ($Len -lt 128) { return ,([byte[]]@($Len)) }
    $bytes = New-Object System.Collections.Generic.List[byte]
    while ($Len -gt 0) { $bytes.Insert(0, [byte]($Len -band 0xFF)); $Len = $Len -shr 8 }
    $bytes.Insert(0, [byte](0x80 -bor $bytes.Count))
    return ,($bytes.ToArray())
}

function Get-DerInteger([byte[]]$Value) {
    $i = 0
    while ($i -lt $Value.Length - 1 -and $Value[$i] -eq 0) { $i++ }
    $v = New-Object System.Collections.Generic.List[byte]
    for ($j = $i; $j -lt $Value.Length; $j++) { $v.Add($Value[$j]) }
    if ($v[0] -ge 0x80) { $v.Insert(0, [byte]0) }
    $out = New-Object System.Collections.Generic.List[byte]
    $out.Add([byte]0x02)
    [byte[]]$len = Get-DerLength $v.Count
    $out.AddRange($len)
    $out.AddRange($v)
    return ,($out.ToArray())
}

function ConvertTo-Pkcs1([Security.Cryptography.RSAParameters]$P) {
    $body = New-Object System.Collections.Generic.List[byte]
    $parts = @(, ([byte[]]@(0))) + @(, $P.Modulus) + @(, $P.Exponent) + @(, $P.D) + @(, $P.P) + @(, $P.Q) + @(, $P.DP) + @(, $P.DQ) + @(, $P.InverseQ)
    foreach ($part in $parts) {
        [byte[]]$enc = Get-DerInteger ([byte[]]$part)
        $body.AddRange($enc)
    }
    $out = New-Object System.Collections.Generic.List[byte]
    $out.Add([byte]0x30)
    [byte[]]$len = Get-DerLength $body.Count
    $out.AddRange($len)
    $out.AddRange($body)
    return ,($out.ToArray())
}

function Export-RsaKeyPem($Cert) {
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Cert)
    $p = $rsa.ExportParameters($true)
    [byte[]]$der = ConvertTo-Pkcs1 $p
    return (ConvertTo-Pem $der 'RSA PRIVATE KEY')
}

function Read-CertFile([string]$Path) {
    return New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (Resolve-Path $Path).Path
}

function Backup-CaFiles([string]$Reason) {
    # Alte CA-Dateien archivieren und die alte CA samt ihrer Zertifikate aus dem Computer-Speicher nehmen
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $arch = Join-Path $Script:CertDir "archiv-$stamp"
    $files = @(Get-ChildItem $Script:CertDir -File -ErrorAction SilentlyContinue |
               Where-Object { $_.Name -match '^(ca\.(pfx|pem|cer)|fgt-server\..*|client-.*\.pfx|clients\.json)$' })
    if ($files.Count) {
        $null = New-Item -ItemType Directory -Path $arch -Force
        $files | Move-Item -Destination $arch
        Write-Ok "Alte CA-Dateien archiviert: $(Split-Path $arch -Leaf)"
    }
    $old = @(Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Issuer -like $Script:CaFamily -or $_.Subject -like $Script:CaFamily })
    foreach ($c in $old) { Remove-Item -Path "Cert:\LocalMachine\My\$($c.Thumbprint)" -DeleteKey }
    $oldRoot = @(Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -like $Script:CaFamily })
    foreach ($c in $oldRoot) { Remove-Item -Path "Cert:\LocalMachine\Root\$($c.Thumbprint)" }
    if ($old.Count + $oldRoot.Count) { Write-Ok "Alte CA und $($old.Count) Zertifikat(e) aus dem Computer-Speicher entfernt" }
    Write-Warn2 "$Reason Bereits ausgerollte Clients brauchen danach ein neues Paket (Menuepunkt P)."
}

function New-RootCa([Security.SecureString]$PfxPw, [int]$Years = 10) {
    Write-Info "Erzeuge neue Root-CA (RSA 4096, $Years Jahre, ohne EKU-Einschraenkung) ..."
    $ca = New-SelfSignedCertificate -Type Custom -Subject $Script:CaSubject -FriendlyName 'FGT-VPN Root CA v2' `
        -CertStoreLocation Cert:\LocalMachine\My -KeyAlgorithm RSA -KeyLength 4096 -HashAlgorithm SHA256 `
        -KeyExportPolicy Exportable -KeyUsage CertSign, CRLSign, DigitalSignature -KeyUsageProperty Sign `
        -TextExtension @('2.5.29.19={critical}{text}ca=1&pathlength=0') -NotAfter (Get-Date).AddYears($Years)
    $null = Export-PfxCertificate -Cert $ca -FilePath (Join-Path $Script:CertDir 'ca.pfx') -Password $PfxPw
    Write-Ok "CA erzeugt und als ca.pfx gesichert ($(Get-ShortId $ca))"
    return $ca
}

function Get-OrCreateCa([Security.SecureString]$PfxPw, [switch]$ForceNew, [int]$Years = 10) {
    $caPfx = Join-Path $Script:CertDir 'ca.pfx'
    $caPem = Join-Path $Script:CertDir 'ca.pem'
    if ($ForceNew) { Backup-CaFiles 'Neue CA angefordert.'; return (New-RootCa $PfxPw $Years) }

    $ca = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq $Script:CaSubject -and $_.HasPrivateKey } |
          Sort-Object NotAfter -Descending | Select-Object -First 1
    if ($ca) { Write-Ok "CA im Zertifikatsspeicher gefunden ($(Get-ShortId $ca))"; return $ca }

    if ((Test-Path $caPfx) -and (Test-Path $caPem) -and (Read-CertFile $caPem).Subject -ne $Script:CaSubject) {
        Backup-CaFiles 'Alte CA aus Version 1 (mit EKU-Einschraenkung) wird ersetzt.'
    }
    if (-not (Test-Path $caPfx)) { return (New-RootCa $PfxPw $Years) }

    Write-Info 'Vorhandene ca.pfx gefunden, wird importiert.'
    $pw = $PfxPw
    for ($try = 1; $try -le 4; $try++) {
        try {
            $imp = Import-PfxCertificate -FilePath $caPfx -CertStoreLocation Cert:\LocalMachine\My -Password $pw -Exportable -ErrorAction Stop
            $ca = $imp | Where-Object { $_.Subject -eq $Script:CaSubject } | Select-Object -First 1
            if (-not $ca) { throw 'ca.pfx enthaelt nicht die erwartete CA.' }
            Write-Ok 'CA aus ca.pfx importiert'
            return $ca
        } catch {
            if ($Script:Auto) { throw 'ca.pfx laesst sich mit dem angegebenen Passwort nicht oeffnen (fuer eine neue CA: -NewCa).' }
            Write-Warn2 'Das Passwort passt nicht zur vorhandenen ca.pfx.'
            $a = Read-Choice '1 = anderes Passwort versuchen, 2 = NEUE CA erzeugen (alte wird archiviert), 3 = Abbrechen' @('1','2','3') '1'
            if ($a -eq '3') { throw 'Abgebrochen.' }
            if ($a -eq '2') { Backup-CaFiles 'Neue CA, weil das Passwort der alten ca.pfx unbekannt ist.'; return (New-RootCa $PfxPw $Years) }
            $pw = Read-Secret 'Passwort der vorhandenen ca.pfx'
        }
    }
    throw 'Zu viele Fehlversuche.'
}

function Export-CaPublic($Ca) {
    $cer = Join-Path $Script:CertDir 'ca.cer'
    [IO.File]::WriteAllBytes($cer, $Ca.RawData)
    Set-Content -Path (Join-Path $Script:CertDir 'ca.pem') -Value (ConvertTo-Pem $Ca.RawData 'CERTIFICATE') -Encoding ASCII
    if (-not (Get-ChildItem Cert:\LocalMachine\Root | Where-Object Thumbprint -eq $Ca.Thumbprint)) {
        $null = Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\Root
        Write-Ok 'CA als vertrauenswuerdige Stammzertifizierungsstelle (Computer) importiert'
    }
}

function New-ClientCert($Ca, [string]$Name, [switch]$Exportable, [int]$Days = 825) {
    # ECDSA P-384: Windows verlangt bei DH-Gruppe ECP384 ein ECDSA-P384-Zertifikat (sonst Fehler 13806)
    $policy = if ($Exportable) { 'Exportable' } else { 'NonExportable' }
    return New-SelfSignedCertificate -Type Custom -Subject "CN=$Name" -Signer $Ca `
        -CertStoreLocation Cert:\LocalMachine\My -KeyAlgorithm ECDSA_nistP384 -HashAlgorithm SHA384 `
        -Provider 'Microsoft Software Key Storage Provider' -KeyExportPolicy $policy -KeyUsage DigitalSignature `
        -TextExtension @("2.5.29.37={text}$($Script:EkuClient),$($Script:EkuIke)", "2.5.29.17={text}DNS=$Name") `
        -NotAfter (Get-Date).AddDays($Days)
}

function Get-CurrentCa {
    # Massgeblich ist die CA aus vpn-certs\ca.cer (Fingerabdruck), sonst die neueste gleichnamige Stamm-CA
    $cer = Join-Path $Script:CertDir 'ca.cer'
    if (Test-Path $cer) { return (Read-CertFile $cer) }
    return Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -eq $Script:CaSubject } |
           Sort-Object NotAfter -Descending | Select-Object -First 1
}

function Read-DerElement([byte[]]$Data, [int]$Pos) {
    # Liefert @(Start, Laenge des Inhalts, Gesamtlaenge) eines DER-Elements ab Position $Pos
    $len = [int]$Data[$Pos + 1]; $hdr = 2
    if ($len -ge 0x80) {
        $n = $len -band 0x7F; $len = 0
        for ($k = 0; $k -lt $n; $k++) { $len = ($len * 256) + $Data[$Pos + 2 + $k] }
        $hdr = 2 + $n
    }
    return @(($Pos + $hdr), $len, ($hdr + $len))
}

function Test-SignedByCa($Cert, $Ca) {
    # Prueft die Signatur des Zertifikats direkt mit dem oeffentlichen Schluessel der CA.
    # (Kettenbildung waere unzuverlaessig, wenn mehrere CAs denselben Namen tragen.)
    if (-not $Cert -or -not $Ca) { return $false }
    if ($Cert.Issuer -ne $Ca.Subject) { return $false }
    try {
        [byte[]]$raw = $Cert.RawData
        $outer = Read-DerElement $raw 0
        $tbs   = Read-DerElement $raw $outer[0]
        $tbsBytes = New-Object byte[] $tbs[2]
        [Array]::Copy($raw, $outer[0], $tbsBytes, 0, $tbs[2])
        $algPos = $outer[0] + $tbs[2]
        $alg = Read-DerElement $raw $algPos
        $sigPos = $algPos + $alg[2]
        $sig = Read-DerElement $raw $sigPos
        $sigBytes = New-Object byte[] ($sig[1] - 1)
        [Array]::Copy($raw, $sig[0] + 1, $sigBytes, 0, $sig[1] - 1)
        $hash = switch -Regex ($Cert.SignatureAlgorithm.FriendlyName) { '512' { 'SHA512' } '384' { 'SHA384' } '256' { 'SHA256' } default { 'SHA1' } }
        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($Ca)
        if (-not $rsa) { return $false }
        return $rsa.VerifyData($tbsBytes, $sigBytes, [System.Security.Cryptography.HashAlgorithmName]::$hash, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    } catch { return $false }
}

function Get-LeafMaxDays($Ca, [int]$Cap) {
    $left = [int][math]::Floor(($Ca.NotAfter - (Get-Date)).TotalDays) - 1
    return [math]::Max(1, [math]::Min($Cap, $left))
}

function Read-ClientDays($Ca) {
    $s = $Script:Settings
    $max = Get-LeafMaxDays $Ca $Script:MaxClientDays
    $d = Read-Number 'Gueltigkeit Client-Zertifikat in Tagen (max. 5 Jahre, nie laenger als die CA)' ([int]$s.ClientDays) 1 $max
    $s.ClientDays = [string]$d
    return $d
}

function Get-ServerCertState($Ca) {
    $s = $Script:Settings
    $fc = Join-Path $Script:CertDir 'fgt-server.crt.pem'
    $fk = Join-Path $Script:CertDir 'fgt-server.key.pem'
    if (-not (Test-Path $fc) -or -not (Test-Path $fk)) { return @{ Ok = $false; Reason = 'nicht vorhanden' } }
    $c = Read-CertFile $fc
    if (-not (Test-SignedByCa $c $Ca)) { return @{ Ok = $false; Reason = 'von einer anderen CA ausgestellt' } }
    $san = ($c.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' } | ForEach-Object { $_.Format($false) }) -join ' '
    if ($san -notmatch "(^|[=\s,])$([regex]::Escape($s.Fqdn))($|[\s,])") { return @{ Ok = $false; Reason = "SAN passt nicht zu $($s.Fqdn)" } }
    if ($c.NotAfter -lt (Get-Date).AddDays(30)) { return @{ Ok = $false; Reason = "laeuft am $($c.NotAfter.ToString('d')) ab" } }
    return @{ Ok = $true; NotAfter = $c.NotAfter }
}

# --- Client-Verzeichnis (welche PCs auf der FortiGate freigeschaltet sind) ---
function Get-ClientRegistry {
    $p = Join-Path $Script:CertDir 'clients.json'
    if (-not (Test-Path $p)) { return @() }
    $raw = Get-Content $p -Raw
    if (-not $raw -or -not $raw.Trim()) { return @() }
    return @(($raw | ConvertFrom-Json) | ForEach-Object { $_ })
}

function Save-ClientRegistry($List) {
    $null = New-Item -ItemType Directory -Path $Script:CertDir -Force
    ConvertTo-Json -InputObject @($List) -Depth 3 | Set-Content -Path (Join-Path $Script:CertDir 'clients.json') -Encoding UTF8
}

function Register-Client($Cert) {
    $name = $Cert.Subject -replace '^CN=', ''
    $list = @(Get-ClientRegistry | Where-Object { $_.Name -ne $name })
    $list += [pscustomobject]@{ Name = $name; Thumbprint = $Cert.Thumbprint; Created = (Get-Date -Format 'yyyy-MM-dd')
                                Expires = $Cert.NotAfter.ToString('yyyy-MM-dd'); Status = 'aktiv'; Revoked = '' }
    Save-ClientRegistry $list
    Write-Ok "Client '$name' im Client-Verzeichnis registriert"
}

function Get-ActiveClients {
    return @(Get-ClientRegistry | Where-Object { $_.Status -eq 'aktiv' -and [datetime]$_.Expires -gt (Get-Date) })
}

function Sync-LocalClient {
    # Uebernahme: Client-Zertifikat dieses PCs automatisch registrieren
    $mine = Get-OurClientCerts | Where-Object { $_.Subject -eq "CN=$env:COMPUTERNAME" } | Sort-Object NotAfter -Descending | Select-Object -First 1
    if ($mine -and -not (Get-ClientRegistry | Where-Object { $_.Thumbprint -eq $mine.Thumbprint })) { Register-Client $mine }
}

function Get-PeerName([string]$Client) {
    $n = "$($Script:Settings.P1Name)-c-$Client"
    if ($n.Length -gt 35) { $n = $n.Substring(0, 35) }
    return $n
}

function Show-ClientTable {
    $list = @(Get-ClientRegistry)
    Write-Line
    Write-BoxText ('{0,-20}{1,-12}{2,-14}{3}' -f 'CLIENT', 'STATUS', 'GUELTIG BIS', 'ERSTELLT') 'Cyan'
    if (-not $list.Count) { Write-BoxText 'Noch keine Clients registriert (Menuepunkt 3 oder P).' 'DarkGray' }
    foreach ($c in ($list | Sort-Object Name)) {
        $st = $c.Status
        if ($st -eq 'aktiv' -and [datetime]$c.Expires -lt (Get-Date)) { $st = 'abgelaufen' }
        elseif ($st -eq 'aktiv' -and [datetime]$c.Expires -lt (Get-Date).AddDays(30)) { $st = 'laeuft ab' }
        $color = switch ($st) { 'aktiv' { 'Green' } 'laeuft ab' { 'Yellow' } default { 'Red' } }
        Write-BoxText ('{0,-20}{1,-12}{2,-14}{3}' -f $c.Name, $st, $c.Expires, $c.Created) $color
    }
    Write-Line
}

function Get-OurClientCerts {
    # ECDSA-Client-Zertifikate, die nachweislich von der aktuellen CA (Fingerabdruck) stammen
    $ca = Get-CurrentCa
    return @(Get-ChildItem Cert:\LocalMachine\My | Where-Object {
        $_.Issuer -eq $Script:CaSubject -and $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date) -and
        ($_.EnhancedKeyUsageList.ObjectId -contains $Script:EkuClient) -and
        $_.PublicKey.Oid.Value -eq '1.2.840.10045.2.1' -and (Test-SignedByCa $_ $ca)
    })
}

function Invoke-Certs {
    Initialize-Settings
    $s = $Script:Settings
    Write-Section 'Zertifikate erzeugen' '3'
    $null = New-Item -ItemType Directory -Path $Script:CertDir -Force
    Protect-Folder $Script:CertDir
    $forceNew = [bool]$NewCa
    $hasCa = Test-Path (Join-Path $Script:CertDir 'ca.pfx')
    if (-not $forceNew -and -not $Script:Auto -and $hasCa) {
        Write-Info 'Es gibt bereits eine CA (vpn-certs\ca.pfx).'
        $a = Read-Choice '1 = vorhandene CA weiterverwenden, 2 = NEUE CA erzeugen (alte wird archiviert)' @('1','2') '1'
        $forceNew = ($a -eq '2')
    }
    if ($forceNew -or -not $hasCa) {
        $s.CaYears = [string](Read-Number 'Gueltigkeit der neuen CA in Jahren' ([int]$s.CaYears) 1 $Script:MaxCaYears)
    }
    $pfxPw = Get-PfxPassword

    $ca = Get-OrCreateCa $pfxPw -ForceNew:$forceNew -Years ([int]$s.CaYears)
    Export-CaPublic $ca
    Write-Info "CA gueltig bis $($ca.NotAfter.ToString('d'))"

    if ($s.ServerCertMode -eq 'Own') {
        $state = Get-ServerCertState $ca
        if ($state.Ok) { Write-Ok "Vorhandenes Serverzertifikat passt (SAN $($s.Fqdn), gueltig bis $($state.NotAfter.ToString('d')))" }
        else { Write-Warn2 "Serverzertifikat: $($state.Reason)" }
        if (Read-YesNo "Neues FortiGate-Serverzertifikat fuer $($s.Fqdn) erzeugen?" (-not $state.Ok)) {
            $max = Get-LeafMaxDays $ca $Script:MaxServerDays
            $days = Read-Number 'Gueltigkeit Serverzertifikat in Tagen (max. 825, nie laenger als die CA)' ([int]$s.ServerDays) 1 $max
            $s.ServerDays = [string]$days
            $san = if (Test-IPv4 $s.Fqdn) { "2.5.29.17={text}IPAddress=$($s.Fqdn)&DNS=$($s.Fqdn)" } else { "2.5.29.17={text}DNS=$($s.Fqdn)" }
            $srv = New-SelfSignedCertificate -Type Custom -Subject "CN=$($s.Fqdn)" -Signer $ca `
                -CertStoreLocation Cert:\LocalMachine\My -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 `
                -Provider 'Microsoft Enhanced RSA and AES Cryptographic Provider' -KeySpec KeyExchange `
                -KeyExportPolicy Exportable -KeyUsage DigitalSignature, KeyEncipherment `
                -TextExtension @("2.5.29.37={text}$($Script:EkuServer),$($Script:EkuIke)", $san) -NotAfter (Get-Date).AddDays($days)
            $null = Export-PfxCertificate -Cert $srv -FilePath (Join-Path $Script:CertDir 'fgt-server.pfx') -Password $pfxPw
            Set-Content -Path (Join-Path $Script:CertDir 'fgt-server.crt.pem') -Value (ConvertTo-Pem $srv.RawData 'CERTIFICATE') -Encoding ASCII
            Set-Content -Path (Join-Path $Script:CertDir 'fgt-server.key.pem') -Value (Export-RsaKeyPem $srv) -Encoding ASCII
            Remove-Item -Path "Cert:\LocalMachine\My\$($srv.Thumbprint)" -DeleteKey
            Write-Ok "Serverzertifikat (RSA 2048, SAN $($s.Fqdn), $days Tage) erzeugt"
        }
    }

    if ($s.AuthMode -eq 'Cert') {
        $mine = @(Get-OurClientCerts | Where-Object { $_.Subject -eq "CN=$env:COMPUTERNAME" -and $_.NotAfter -gt (Get-Date).AddDays(30) })
        if ($mine.Count) { Write-Ok "Client-Zertifikat dieses PCs vorhanden (gueltig bis $($mine[0].NotAfter.ToString('d')))" }
        if (Read-YesNo "Maschinenzertifikat fuer diesen PC ($env:COMPUTERNAME) erzeugen?" ($mine.Count -eq 0)) {
            $days = Read-ClientDays $ca
            Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Issuer -like $Script:CaFamily -and $_.Subject -eq "CN=$env:COMPUTERNAME" } |
                ForEach-Object { Remove-Item -Path "Cert:\LocalMachine\My\$($_.Thumbprint)" -DeleteKey }
            $c = New-ClientCert $ca $env:COMPUTERNAME -Days $days
            Write-Ok "Client-Zertifikat CN=$env:COMPUTERNAME (ECDSA P-384, $days Tage) installiert"
            Register-Client $c
        } elseif ($mine.Count) { Sync-LocalClient }
        Write-Info 'Weitere PCs: Menuepunkt P (Client-Paket). Freischalten auf der FortiGate: Menuepunkt 2 oder K.'
    }
    Save-Settings

    if (Read-YesNo 'Privaten CA-Schluessel aus dem Speicher entfernen (bleibt in ca.pfx)?' $true) {
        Remove-Item -Path "Cert:\LocalMachine\My\$($ca.Thumbprint)" -DeleteKey -ErrorAction SilentlyContinue
        Write-Ok 'CA-Schluessel entfernt. ca.pfx und fgt-server.key.pem sicher verwahren!'
    }
    Write-Info "Dateien: $Script:CertDir"
}

function Invoke-Package {
    # Client-Paket fuer einen anderen PC: Skript, Einstellungen, CA und (bei Zertifikat) dessen PFX
    Initialize-Settings
    $s = $Script:Settings
    Write-Section 'Client-Paket fuer einen anderen PC erzeugen' 'P'
    Write-Info 'Der VPN-Client braucht keinen Zugriff auf die FortiGate - nur dieses Paket.'
    $name = if ($ClientName) { $ClientName } else { Read-Default 'Rechnername des VPN-Clients (wie in "hostname")' '' }
    if ($name -notmatch '^[A-Za-z0-9-]{1,63}$') { throw "Ungueltiger Rechnername: '$name'" }
    $name = $name.ToUpper()

    $caCer = Join-Path $Script:CertDir 'ca.cer'
    if (($s.AuthMode -eq 'Cert' -or $s.ServerCertMode -eq 'Own') -and -not (Test-Path $caCer)) { throw 'ca.cer fehlt. Zuerst Menuepunkt 3 ausfuehren.' }

    $pkgDir = Join-Path $Script:Root "vpn-client-$name"
    if (Test-Path $pkgDir) { Remove-Item $pkgDir -Recurse -Force }
    $pkgCerts = Join-Path $pkgDir 'vpn-certs'
    $null = New-Item -ItemType Directory -Path $pkgCerts -Force

    $pkgPw = $null
    if ($s.AuthMode -eq 'Cert') {
        $ca = Get-OrCreateCa (Get-PfxPassword)
        $days = Read-ClientDays $ca
        $c = New-ClientCert $ca $name -Exportable -Days $days
        # Eigenes Zufallspasswort je Paket - niemals das CA-Passwort weitergeben
        $pkgPw = New-RandomPassword 16
        $null = Export-PfxCertificate -Cert $c -FilePath (Join-Path $pkgCerts "client-$name.pfx") -Password (ConvertTo-SecureString $pkgPw -AsPlainText -Force)
        Remove-Item -Path "Cert:\LocalMachine\My\$($c.Thumbprint)" -DeleteKey
        Remove-Item -Path "Cert:\LocalMachine\My\$($ca.Thumbprint)" -DeleteKey -ErrorAction SilentlyContinue
        Write-Ok "Client-Zertifikat CN=$name (ECDSA P-384, $days Tage) erzeugt"
        Register-Client $c
        Save-Settings
    }
    if (Test-Path $caCer) { Copy-Item $caCer $pkgCerts }
    Copy-Item $PSCommandPath (Join-Path $pkgDir 'FGT-VPN-Setup.ps1')
    $Script:Settings | ConvertTo-Json | Set-Content -Path (Join-Path $pkgDir 'fgt-vpn-settings.json') -Encoding UTF8
    $cmd = "@echo off`r`ntitle FGT-VPN Client-Installation`r`npowershell.exe -NoProfile -ExecutionPolicy Bypass -File `"%~dp0FGT-VPN-Setup.ps1`" -Action Client`r`n"
    [IO.File]::WriteAllText((Join-Path $pkgDir 'Installieren.cmd'), $cmd)
    $readme = @(
        "FGT-VPN Client-Paket fuer $name",
        '',
        '1. Ordner auf den PC kopieren (lokal, nicht im Netzlaufwerk starten).',
        '2. Installieren.cmd doppelklicken und die UAC-Abfrage bestaetigen.',
        $(if ($s.AuthMode -eq 'Cert') { '3. Das PFX-Passwort eingeben (bekommst du vom Admin auf separatem Weg).' } else { '3. Danach einmal ueber das Netzwerk-Symbol verbinden und Benutzer/Passwort eingeben.' }),
        '',
        'Danach den Ordner loeschen.'
    )
    Set-Content -Path (Join-Path $pkgDir 'LIESMICH.txt') -Value $readme -Encoding ASCII
    $zip = "$pkgDir.zip"
    if (Test-Path $zip) { Remove-Item $zip -Force }
    Compress-Archive -Path (Join-Path $pkgDir '*') -DestinationPath $zip
    Write-Ok "Paket: $zip"
    if ($pkgPw) {
        Write-Host ''
        Write-Host '   ' -NoNewline
        Write-Host ' PFX-PASSWORT ' -ForegroundColor Black -BackgroundColor Yellow -NoNewline
        Write-Host "  $name :  " -ForegroundColor Yellow -NoNewline
        Write-Host $pkgPw -ForegroundColor White
        Write-Warn2 'Nur fuer dieses Paket gueltig. Getrennt vom Paket weitergeben - es wird nirgends gespeichert.'
        if (-not $Script:Auto -and (Read-YesNo "Client '$name' jetzt auf der FortiGate freischalten (SSH)?" $true)) { Invoke-FgtPeers }
        else { Write-Info 'Freischalten auf der FortiGate: Menuepunkt K > 2 (oder Menuepunkt 2).' }
    }
}

# ---------------------------------------------------------------------------
# FortiGate
# ---------------------------------------------------------------------------
function Read-PemText([string]$Path) { return ((Get-Content $Path -Raw).Trim() -replace "`r", '') }

function Test-SshClient {
    $ssh = Get-Command ssh.exe -ErrorAction SilentlyContinue
    if ($ssh) { return $ssh.Source }
    Write-Warn2 'Der Windows-OpenSSH-Client (ssh.exe) ist nicht aktiviert.'
    if (-not (Read-YesNo 'Windows-Feature "OpenSSH-Client" jetzt aktivieren?' $true)) { return $null }
    $null = Add-WindowsCapability -Online -Name 'OpenSSH.Client~~~~0.0.1.0'
    $ssh = Get-Command "$env:SystemRoot\System32\OpenSSH\ssh.exe" -ErrorAction SilentlyContinue
    if (-not $ssh) { throw 'ssh.exe nach der Aktivierung nicht gefunden.' }
    return $ssh.Source
}

function Confirm-SshHostKey([string]$SshExe, [string]$HostName, [int]$Port) {
    $dir    = Split-Path $SshExe
    $scan   = Join-Path $dir 'ssh-keyscan.exe'
    $keygen = Join-Path $dir 'ssh-keygen.exe'
    $sshDir = Join-Path $HOME '.ssh'
    $known  = Join-Path $sshDir 'known_hosts'
    $spec   = if ($Port -eq 22) { $HostName } else { "[$HostName]:$Port" }
    # Windows PowerShell 5.1 wertet jede stderr-Zeile nativer Programme als Fehler; mit 'Stop'
    # bricht dann z. B. ssh-keyscan ab (es schreibt "# host:22 SSH-2.0-..." auf stderr).
    $ErrorActionPreference = 'Continue'
    foreach ($exe in @($scan, $keygen)) {
        if (-not (Test-Path $exe)) { Write-Err2 "$(Split-Path $exe -Leaf) fehlt neben ssh.exe ($dir)."; return $false }
    }

    if (Test-Path $known) {
        $null = & $keygen -F $spec -f $known 2>$null
        if ($LASTEXITCODE -eq 0) { Write-Ok 'Host-Key der FortiGate ist bekannt.'; return $true }
    }
    if ($Script:Auto) { Write-Err2 'Host-Key unbekannt - im Auto-Modus wird kein neuer Key akzeptiert.'; return $false }

    Write-Info 'Lese Host-Key der FortiGate ...'
    $keys = @()
    try { $keys = @(& $scan -T 10 -p $Port $HostName 2>$null | ForEach-Object { "$_" } | Where-Object { $_ -match '^\S+ (ssh-|ecdsa-)\S+ \S+' }) }
    catch { Write-Err2 ("ssh-keyscan: " + ($_.Exception.Message -replace '[\r\n]+', ' ')); return $false }
    if (-not $keys) { Write-Err2 "Kein Host-Key von ${HostName}:$Port erhalten (SSH erreichbar und erlaubt?)."; return $false }
    $tmpKeys = Join-Path $env:TEMP ("fgtvpn-keys-{0}.txt" -f [guid]::NewGuid().ToString('N'))
    try {
        Set-Content -Path $tmpKeys -Value $keys -Encoding ASCII
        Write-Info 'Fingerprints des Host-Keys:'
        & $keygen -l -f $tmpKeys 2>$null | ForEach-Object { Write-Host "      $_" -ForegroundColor White }
        if (-not (Read-YesNo 'Diesem Host-Key vertrauen und speichern?' $false)) { return $false }
        $null = New-Item -ItemType Directory -Path $sshDir -Force -ErrorAction Stop
        Add-Content -Path $known -Value $keys -Encoding ASCII -ErrorAction Stop
        Write-Ok "Host-Key gespeichert ($known)"
        return $true
    } finally { Remove-Item $tmpKeys -Force -ErrorAction SilentlyContinue }
}

function Initialize-FgtSsh {
    # ssh.exe pruefen und Host-Key bestaetigen. Rueckgabe: Pfad zu ssh.exe, oder $null = Rueckfall (CLI-Datei bzw. manuell).
    param([string]$Fallback = 'stattdessen CLI-Datei speichern')
    $s = $Script:Settings
    while ($true) {
        $ssh = $null; $ok = $false
        try {
            $ssh = Test-SshClient
            if ($ssh) { $ok = Confirm-SshHostKey -SshExe $ssh -HostName $s.FgtHost -Port ([int]$s.FgtPort) }
        } catch { Write-Err2 ($_.Exception.Message -replace '[\r\n]+', ' ') }
        if ($ok) { return $ssh }
        if ($Script:Auto) { throw 'SSH-Vorbereitung fehlgeschlagen (Auto-Modus).' }
        Write-Warn2 'Die SSH-Verbindung kann nicht sicher vorbereitet werden.'
        $a = Read-Choice "1 = erneut versuchen, 2 = $Fallback, 3 = Abbrechen" @('1','2','3') '2'
        if ($a -eq '2') { return $null }
        if ($a -eq '3') { throw 'Abbruch durch Benutzer.' }
    }
}

function Split-FgtSegments([string]$Raw) {
    # CLI-Ausgabe an den Prompts ("HOST # ", "HOST (global) # ") in Abschnitte je Befehl zerlegen
    $pm = [regex]::Matches($Raw, '(?m)^[A-Za-z0-9._-]+ (?:\([^)]*\) )?# ?')
    $segs = @()
    for ($i = 0; $i -lt $pm.Count; $i++) {
        $st = $pm[$i].Index + $pm[$i].Length
        $en = if ($i + 1 -lt $pm.Count) { $pm[$i + 1].Index } else { $Raw.Length }
        $segs += $Raw.Substring($st, $en - $st)
    }
    return ,$segs
}

function ConvertFrom-FgtEditBlocks([string]$Text, [int]$Indent = 4) {
    # "edit <name>" auf Ebene $Indent mit ihren "set"-Zeilen eine Ebene tiefer -> Liste von Hashtables
    $res = New-Object System.Collections.Generic.List[object]
    $cur = $null
    $eRx = '^' + (' ' * $Indent) + 'edit "?([^"]+)"?\s*$'
    $sRx = '^' + (' ' * ($Indent + 4)) + 'set (\S+) ?(.*)$'
    $nRx = '^' + (' ' * $Indent) + 'next\s*$'
    foreach ($l in ($Text -split "`n")) {
        if ($l -match $eRx) { $cur = @{ '_name' = $Matches[1] }; $res.Add($cur); continue }
        if ($cur -and $l -match $sRx) { $cur[$Matches[1]] = $Matches[2].Trim(); continue }
        if ($l -match $nRx) { $cur = $null }
    }
    return ,$res
}

function Get-FgtInterfaces {
    # Liest Interfaces, Zonen und SD-WAN-Zonen per SSH. Rueckgabe: Liste oder $null (Rueckfall auf manuelle Eingabe).
    $s = $Script:Settings
    $ssh = Initialize-FgtSsh -Fallback 'Interfaces manuell eingeben'
    if (-not $ssh) { return $null }
    $lines = @()
    if ($s.Vdom) { $lines += @('config global', 'show system interface', 'end', 'config vdom', "edit `"$($s.Vdom)`"", 'show system zone', 'show system sdwan', 'end') }
    else         { $lines += @('show system interface', 'show system zone', 'show system sdwan') }
    try { $raw = Invoke-FgtCli -SshExe $ssh -Lines $lines -Purpose 'Interfaces lesen (nur lesend)' }
    catch { Write-Err2 ($_.Exception.Message -replace '[\r\n]+', ' '); return $null }

    $segs = @(Split-FgtSegments $raw)
    $find = { param($head) ($segs | Where-Object { $_ -match "(?m)^config $head\s*$" } | Select-Object -First 1) }
    $ifText = & $find 'system interface'
    if (-not $ifText) { Write-Err2 'Die Interface-Liste konnte nicht gelesen werden (Rechte des Admin-Profils?).'; return $null }
    $zoneText = & $find 'system zone'
    $sdText   = & $find 'system sdwan'

    $list = New-Object System.Collections.Generic.List[object]
    $members = @{}
    foreach ($z in (ConvertFrom-FgtEditBlocks "$zoneText")) {
        foreach ($m in ([regex]::Matches("$($z['interface'])", '"([^"]+)"'))) { $members[$m.Groups[1].Value] = "Zone $($z._name)" }
        $list.Add([pscustomobject]@{ Name = $z._name; Type = 'zone'; Role = ''; Ip = ''; Alias = "$($z['description'])".Trim('"'); Down = $false })
    }
    if ("$sdText" -match '(?m)^    set status enable') {
        $zm = [regex]::Match("$sdText", '(?ms)^    config zone\s*$(.*?)^    end\s*$')
        if ($zm.Success) {
            foreach ($z in (ConvertFrom-FgtEditBlocks $zm.Groups[1].Value 8)) {
                $list.Add([pscustomobject]@{ Name = $z._name; Type = 'sdwan-zone'; Role = 'wan'; Ip = ''; Alias = ''; Down = $false })
            }
        }
        $mm = [regex]::Match("$sdText", '(?ms)^    config members\s*$(.*?)^    end\s*$')
        if ($mm.Success) {
            foreach ($m in (ConvertFrom-FgtEditBlocks $mm.Groups[1].Value 8)) { if ($m['interface']) { $members[$m['interface'].Trim('"')] = 'SD-WAN' } }
        }
    }
    foreach ($i in (ConvertFrom-FgtEditBlocks "$ifText")) {
        $n = $i._name
        if ($s.Vdom -and "$($i['vdom'])".Trim('"') -ne $s.Vdom) { continue }
        if ($n -match '^(ssl|naf|l2t)\.' -or $n -eq $s.P1Name -or $members.ContainsKey($n)) { continue }
        $ip = ''
        if ($i['ip'] -match '^(\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+)$') { $ip = "$($Matches[1])/$(ConvertTo-PrefixLength $Matches[2])" }
        elseif ($i['mode'] -in @('dhcp', 'pppoe')) { $ip = $i['mode'] }
        $list.Add([pscustomobject]@{ Name = $n; Type = "$(if ($i['type']) { $i['type'] } else { 'physical' })"; Role = "$($i['role'])"
                                     Ip = $ip; Alias = "$($i['alias'])".Trim('"'); Down = ($i['status'] -eq 'down') })
    }
    if ($members.Count) { Write-Info ("Nicht waehlbar (Mitglied einer Zone/SD-WAN): {0}" -f (($members.Keys | Sort-Object) -join ', ')) }
    return ,$list
}

function ConvertTo-PrefixLength([string]$Mask) {
    $bits = 0
    foreach ($o in $Mask.Split('.')) { $bits += ([Convert]::ToString([int]$o, 2) -replace '0', '').Length }
    return $bits
}

function Show-FgtInterfaces($List) {
    Write-Line
    Write-BoxText ('{0,-4}{1,-18}{2,-12}{3,-6}{4,-20}{5}' -f 'NR', 'NAME', 'TYP', 'ROLLE', 'IP', 'ALIAS') 'Cyan'
    for ($k = 0; $k -lt $List.Count; $k++) {
        $i = $List[$k]
        $alias = if ($i.Down) { ("$($i.Alias) (down)").Trim() } else { $i.Alias }
        $line = '{0,-4}{1,-18}{2,-12}{3,-6}{4,-20}{5}' -f ($k + 1), $i.Name, $i.Type, $i.Role, $i.Ip, $alias
        if ($line.Length -gt $Script:W - 4) { $line = $line.Substring(0, $Script:W - 4) }
        Write-BoxText $line $(if ($i.Down) { 'DarkGray' } elseif ($i.Role -eq 'wan') { 'Yellow' } else { 'White' })
    }
    Write-Line
}

function Select-FgtInterface {
    # Auswahl per Nummer oder Name, mehrere kommagetrennt (-Multi). Unbekannte Namen nur nach Rueckfrage.
    param($List, [string]$Prompt, [string]$Default, [switch]$Multi)
    $names = @($List | ForEach-Object { $_.Name })
    while ($true) {
        $v = Read-Default $Prompt $Default
        $parts = @(($v -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        if (-not $parts.Count) { Write-Warn2 'Bitte mindestens ein Interface waehlen.'; continue }
        if (-not $Multi -and $parts.Count -gt 1) { Write-Warn2 'Bitte genau ein Interface waehlen.'; continue }
        $sel = @(); $bad = @()
        foreach ($p in $parts) {
            if ($p -match '^\d+$' -and [int]$p -ge 1 -and [int]$p -le $names.Count) { $sel += $names[[int]$p - 1] }
            elseif ($names -contains $p) { $sel += $p }
            else { $bad += $p; $sel += $p }
        }
        if ($bad.Count -and -not (Read-YesNo "Nicht in der Liste: $($bad -join ', ') - trotzdem verwenden?" $false)) { continue }
        return (($sel | Select-Object -Unique) -join ',')
    }
}

function Invoke-FgtCli {
    # Fuehrt CLI-Zeilen mit dem integrierten ssh.exe aus (Konfiguration per Standardeingabe)
    param([string]$SshExe, [string[]]$Lines, [string]$Purpose)
    $s = $Script:Settings
    $tmp = Join-Path $env:TEMP ("fgtvpn-{0}.txt" -f [guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType File -Path $tmp -Force
    & icacls.exe $tmp /inheritance:r /grant:r "$($env:USERDOMAIN)\$($env:USERNAME):F" '*S-1-5-18:F' | Out-Null
    [IO.File]::WriteAllText($tmp, ((@($Lines) + 'exit') -join "`n") + "`n", (New-Object System.Text.UTF8Encoding($false)))
    try {
        Write-Host ''
        Write-Host '   ' -NoNewline
        Write-Host ' SSH ' -ForegroundColor Black -BackgroundColor Yellow -NoNewline
        Write-Host " $Purpose - Passwort fuer $($s.FgtUser)@$($s.FgtHost) (unsichtbar, dann Enter):" -ForegroundColor Yellow
        $sshArgs = @('-T', '-p', $s.FgtPort, '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=15',
                     '-o', 'LogLevel=ERROR', '-o', 'NumberOfPasswordPrompts=2', "$($s.FgtUser)@$($s.FgtHost)")
        $cmdLine = '"{0}" {1} < "{2}" 2>&1' -f $SshExe, ($sshArgs -join ' '), $tmp
        $out = (& cmd.exe /d /c $cmdLine) -join "`n"
        if ($LASTEXITCODE -eq 255) { throw "SSH-Verbindung fehlgeschlagen: $((($out -split "`n") | Select-Object -Last 2) -join ' ')" }
        return ($out -replace "`r", '')
    } finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
}

function Get-WantedPolicies {
    # Policies, die das Skript anlegt (alle mit vollem Logging)
    $s = $Script:Settings; $p1 = $s.P1Name
    $list = @([ordered]@{ Name = "$p1-to-LAN"; Src = "`"$p1`""; Dst = (Format-FgtList $s.LanIf); SrcAddr = "`"$p1-pool`""; DstAddr = "`"$p1-lan`""; Nat = $false })
    if ($s.PolicyBoth -eq 'Yes') {
        $list += [ordered]@{ Name = "$p1-from-LAN"; Src = (Format-FgtList $s.LanIf); Dst = "`"$p1`""; SrcAddr = "`"$p1-lan`""; DstAddr = "`"$p1-pool`""; Nat = $false }
    }
    if ($s.TunnelMode -eq 'Full') {
        $list += [ordered]@{ Name = "$p1-to-Internet"; Src = "`"$p1`""; Dst = (Format-FgtList $s.WanIf); SrcAddr = "`"$p1-pool`""; DstAddr = '"all"'; Nat = $true }
    }
    return $list
}

function Get-OurPolicyNames { $p1 = $Script:Settings.P1Name; return @("$p1-to-LAN", "$p1-from-LAN", "$p1-to-Internet") }

function Get-FgtPolicyMap([string]$Out) {
    # "edit <id>" gefolgt von "set name" -> Name = ID
    $map = @{}
    foreach ($m in [regex]::Matches($Out, '(?m)^\s*edit (\d+)\s*\r?\n\s*set name "([^"]+)"')) { $map[$m.Groups[2].Value] = $m.Groups[1].Value }
    return $map
}

function Invoke-FgtQuery {
    # Liest den Bestand in EINER SSH-Sitzung, sichert ihn lokal (fgt-backups) und wertet ihn aus
    param([string]$SshExe, [string]$Purpose, [switch]$WithGateways)
    $s = $Script:Settings; $p1 = $s.P1Name
    $cmds = @(
        "show firewall policy | grep -f `"$p1-`"",          # 0 unsere Policies
        'show firewall policy | grep edit',                  # 1 Reihenfolge aller Policies
        'show firewall policy',                              # 2 alle Policies (Deny erkennen)
        "show vpn ipsec phase1-interface `"$p1`"",           # 3
        "show vpn ipsec phase2-interface `"$p1-p2`"",        # 4
        "show firewall address | grep -f `"$p1-`"",          # 5
        "show firewall addrgrp | grep -f `"$p1-`"",          # 6
        "show user peer | grep -f `"$p1-`"",                 # 7
        "show user peergrp | grep -f `"$p1-`"",              # 8
        'show vpn certificate local | grep edit',            # 9
        'show vpn certificate ca | grep edit')               # 10
    if ($WithGateways) { $cmds += 'diagnose vpn ike gateway list | grep name' }   # 11
    $lines = @(); $off = 0
    if ($s.Vdom) { $lines += @('config vdom', "edit `"$($s.Vdom)`""); $off = 2 }
    $lines += $cmds
    if ($s.Vdom) { $lines += 'end' }
    $raw = Invoke-FgtCli -SshExe $SshExe -Lines $lines -Purpose $Purpose

    # Ausgabe an den Prompts ("HOST # ") in Abschnitte je Befehl zerlegen
    $pm = [regex]::Matches($raw, '(?m)^[A-Za-z0-9._-]+ (?:\([^)]*\) )?# ?')
    $segs = @()
    for ($i = 0; $i -lt $pm.Count; $i++) {
        $st = $pm[$i].Index + $pm[$i].Length
        $en = if ($i + 1 -lt $pm.Count) { $pm[$i + 1].Index } else { $raw.Length }
        $segs += $raw.Substring($st, $en - $st)
    }
    $aligned = ($segs.Count -ge $cmds.Count + $off)
    $seg = @(for ($k = 0; $k -lt $cmds.Count; $k++) { if ($aligned) { $segs[$k + $off] } else { '' } })
    $text = if ($segs.Count) { $segs -join "`n" } else { $raw }

    $bdir = Join-Path $Script:Root 'fgt-backups'
    if (-not (Test-Path $bdir)) { $null = New-Item -ItemType Directory -Path $bdir -Force; Protect-Folder $bdir }
    $bfile = Join-Path $bdir ('{0}-{1}.txt' -f (Get-Date -Format 'yyyyMMdd-HHmmss'), $p1)
    $head = "# FortiGate-Stand vor der Aenderung ($Purpose), $(Get-Date -Format s)`r`n# Befehle:`r`n# " + ($cmds -join "`r`n# ")
    Set-Content -Path $bfile -Value ($head + "`r`n`r`n" + ($raw -replace "`n", "`r`n")) -Encoding UTF8
    Write-Ok "Bisheriger Stand gesichert: fgt-backups\$(Split-Path $bfile -Leaf)"

    $polMap = Get-FgtPolicyMap $(if ($aligned) { $seg[0] } else { $text })
    $seq  = @(if ($aligned) { [regex]::Matches($seg[1], '(?m)^\s*edit (\d+)') | ForEach-Object { [int]$_.Groups[1].Value } })
    # Deny-Policies: "deny" ist Standard und erscheint in "show" nicht - also alles ohne
    # "set action accept/ipsec"; deaktivierte Policies zaehlen nicht
    $deny = @(if ($aligned) {
        foreach ($blk in [regex]::Split($seg[2], '(?m)^(?=\s*edit \d+\s*$)')) {
            $m = [regex]::Match($blk, '^\s*edit (\d+)')
            if ($m.Success -and $blk -notmatch 'set action (accept|ipsec)' -and $blk -notmatch 'set status disable') { [int]$m.Groups[1].Value }
        } })
    $names = @([regex]::Matches($text, '(?m)^\s*edit "([^"]+)"') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
    $gws = @()
    if ($WithGateways) {
        $src = if ($aligned) { $seg[11] } else { $text }
        $gws = @([regex]::Matches($src, "name:\s*($([regex]::Escape($p1))_\d+)") | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
    }
    if (-not $aligned) { Write-Warn2 'Ausgabe der FortiGate nicht eindeutig zuordenbar - Pruefung der Policy-Reihenfolge entfaellt.' }
    return [pscustomobject]@{ Raw = $raw; PolicyMap = $polMap; Seq = $seq; Deny = $deny; Names = $names; Gateways = $gws; Aligned = $aligned }
}

function Get-PolicyPlan($Query, [string[]]$Wanted) {
    # IDs fuer neue Policies festlegen und pruefen, ob eine Deny-Policy darueber steht
    $map = $Query.PolicyMap
    $newIds = @{}
    $plan = @{ NewIds = $newIds; MoveBefore = 0 }
    if (-not $Query.Aligned) { return $plan }
    $next = if ($Query.Seq.Count) { ($Query.Seq | Measure-Object -Maximum).Maximum + 1 } else { 1 }
    foreach ($w in $Wanted) { if (-not $map.ContainsKey($w)) { $newIds[$w] = [string]$next; $next++ } }
    $ourExisting = @($Wanted | Where-Object { $map.ContainsKey($_) } | ForEach-Object { [int]$map[$_] })
    $firstDeny = $Query.Seq | Where-Object { $Query.Deny -contains $_ -and $ourExisting -notcontains $_ } | Select-Object -First 1
    if (-not $firstDeny) { Write-Ok 'Policy-Reihenfolge: keine Deny-Policy vor unseren Policies'; return $plan }
    $idxDeny = [array]::IndexOf($Query.Seq, $firstDeny)
    $behind = @($ourExisting | Where-Object { [array]::IndexOf($Query.Seq, $_) -gt $idxDeny }) + @($newIds.Values)
    if (-not $behind.Count) { Write-Ok 'Policy-Reihenfolge: unsere Policies stehen vor der ersten Deny-Policy'; return $plan }
    Write-Warn2 "Deny-Policy ID $firstDeny steht ueber unseren Policies - VPN-Verkehr koennte dort blockiert werden."
    if ($MovePolicies -or (Read-YesNo "Unsere Policies vor Policy ID $firstDeny verschieben?" (-not $Script:Auto))) { $plan.MoveBefore = [int]$firstDeny }
    else { Write-Info 'Reihenfolge bitte auf der FortiGate pruefen (Policy & Objects).' }
    return $plan
}

function New-FgtPeerLines {
    # Je Client ein Peer (CN = Rechnername), alle in einer Peer-Gruppe -> einzeln sperrbar
    param([string]$CaName, [string[]]$Existing = @(), [switch]$KnowExisting)
    $p1 = $Script:Settings.P1Name
    $grp = "$p1-clients"
    $peers = @()
    $pre = New-Object System.Collections.Generic.List[string]
    $pre.Add('config user peer')
    foreach ($cl in (Get-ActiveClients)) {
        $pn = Get-PeerName $cl.Name
        $peers += $pn
        $pre.AddRange([string[]]@("edit `"$pn`"", "set ca `"$CaName`"", "set cn `"$($cl.Name)`"", 'next'))
    }
    $pre.Add('end')
    $pre.AddRange([string[]]@('config user peergrp', "edit `"$grp`""))
    if ($peers.Count) { $pre.Add('set member ' + (($peers | ForEach-Object { "`"$_`"" }) -join ' ')) } else { $pre.Add('unset member') }
    $pre.AddRange([string[]]@('next', 'end'))
    $stale = @()
    $del = New-Object System.Collections.Generic.List[string]
    if ($KnowExisting) {
        $stale = @($Existing | Where-Object { $_ -eq "$p1-peer" -or ($_ -like "$p1-c-*" -and $peers -notcontains $_) })
        if ($stale.Count) { $del.Add('config user peer'); foreach ($n in $stale) { $del.Add("delete `"$n`"") }; $del.Add('end') }
    }
    return @{ Pre = $pre; Del = $del; Peers = $peers; Stale = $stale; Group = $grp }
}

function New-FgtConfig {
    param([string]$CaName, [string]$CaPem, [string]$SrvName, [string]$SrvCertPem, [string]$SrvKeyPem,
          [string]$EapUser, [string]$EapPass, [hashtable]$PolicyIds = @{}, [string[]]$DeletePolicyIds = @(),
          [hashtable]$NewPolicyIds = @{}, [int]$MoveBefore = 0, [string[]]$Existing = @(), [switch]$KnowExisting)
    $s = $Script:Settings
    $nets = Get-LanNets
    $p1 = $s.P1Name
    $p1e = [regex]::Escape($p1)
    $c = New-Object System.Collections.Generic.List[string]
    if ($s.Vdom) { $c.Add('config vdom'); $c.Add("edit `"$($s.Vdom)`"") }

    if ($CaPem) { $c.AddRange([string[]]@('config vpn certificate ca', "edit `"$CaName`"", "set ca `"$CaPem`"", 'next', 'end')) }
    if ($SrvCertPem -and $SrvKeyPem) {
        $c.AddRange([string[]]@('config vpn certificate local', "edit `"$SrvName`"",
            "set private-key `"$SrvKeyPem`"", "set certificate `"$SrvCertPem`"", 'next', 'end'))
    }
    $peer = $null
    if ($s.AuthMode -eq 'Cert') {
        $peer = New-FgtPeerLines -CaName $CaName -Existing $Existing -KnowExisting:$KnowExisting
        $c.AddRange([string[]]$peer.Pre)
    } else {
        if ($EapUser) { $c.AddRange([string[]]@('config user local', "edit `"$EapUser`"", 'set type password', "set passwd `"$EapPass`"", 'next', 'end')) }
        $c.AddRange([string[]]@('config user group', "edit `"$($s.UserGroup)`""))
        if ($EapUser) { $c.Add("append member `"$EapUser`"") }
        $c.AddRange([string[]]@('next', 'end'))
    }

    # Adressen: Pool, interne Netze, optional DNS-Server
    $c.AddRange([string[]]@('config firewall address', "edit `"$p1-pool`"", 'set type iprange',
        "set start-ip $($s.PoolStart)", "set end-ip $($s.PoolEnd)", 'next'))
    $i = 0; $members = @(); $wantAddr = @("$p1-pool")
    foreach ($n in $nets) {
        $i++
        $c.AddRange([string[]]@("edit `"$p1-lan$i`"", "set subnet $($n.Net) $($n.Mask)", 'next'))
        $members += "`"$p1-lan$i`""; $wantAddr += "$p1-lan$i"
    }
    if (Test-DnsRouted) {
        $c.AddRange([string[]]@("edit `"$p1-dns`"", "set subnet $($s.DnsServer) 255.255.255.255", 'next'))
        $members += "`"$p1-dns`""; $wantAddr += "$p1-dns"
    }
    $c.Add('end')
    $c.AddRange([string[]]@('config firewall addrgrp', "edit `"$p1-lan`"", "set member $($members -join ' ')", 'next', 'end'))

    $c.AddRange([string[]]@('config vpn ipsec phase1-interface', "edit `"$p1`"",
        'set type dynamic', "set interface `"$($s.WanIf)`"", 'set ike-version 2',
        'set authmethod signature', "set certificate `"$SrvName`""))
    if ($s.AuthMode -eq 'Cert') { $c.AddRange([string[]]@('set eap disable', 'set peertype peergrp', "set peergrp `"$($peer.Group)`"")) }
    else { $c.AddRange([string[]]@('set peertype any', 'set eap enable', 'set eap-identity send-request', "set authusrgrp `"$($s.UserGroup)`"")) }
    $c.AddRange([string[]]@('set net-device disable', 'set mode-cfg enable', 'set assign-ip-from range',
        "set ipv4-start-ip $($s.PoolStart)", "set ipv4-end-ip $($s.PoolEnd)", "set ipv4-netmask $($s.PoolMask)",
        'set dns-mode manual', "set ipv4-dns-server1 $($s.DnsServer)",
        'set proposal aes256-sha384', 'set dhgrp 20', 'set keylife 28800',
        'set dpd on-idle', 'set dpd-retryinterval 20', 'next', 'end'))
    $c.AddRange([string[]]@('config vpn ipsec phase2-interface', "edit `"$p1-p2`"", "set phase1name `"$p1`"",
        'set proposal aes256gcm', 'set pfs enable', 'set dhgrp 20', 'set keylifeseconds 3600', 'next', 'end'))

    # Policies (vorhandene aktualisieren, neue mit fester ID, Logging komplett)
    $c.Add('config firewall policy')
    foreach ($id in $DeletePolicyIds) { $c.Add("delete $id") }
    $ids = @()
    foreach ($pol in (Get-WantedPolicies)) {
        $isNew = -not $PolicyIds.ContainsKey($pol.Name)
        $id = if (-not $isNew) { $PolicyIds[$pol.Name] } elseif ($NewPolicyIds.ContainsKey($pol.Name)) { $NewPolicyIds[$pol.Name] } else { '0' }
        $ids += $id
        $c.Add("edit $id")
        if ($isNew) { $c.Add("set name `"$($pol.Name)`"") }
        $c.AddRange([string[]]@("set srcintf $($pol.Src)", "set dstintf $($pol.Dst)",
            "set srcaddr $($pol.SrcAddr)", "set dstaddr $($pol.DstAddr)",
            'set action accept', 'set schedule "always"', 'set service "ALL"',
            'set logtraffic all', 'set logtraffic-start enable',
            $(if ($pol.Nat) { 'set nat enable' } else { 'set nat disable' }), 'next'))
    }
    if ($MoveBefore) { foreach ($id in $ids) { if ($id -ne '0') { $c.Add("move $id before $MoveBefore") } } }
    $c.Add('end')

    # Aufraeumen: nicht mehr benoetigte eigene Objekte (nur wenn der Bestand bekannt ist)
    if ($KnowExisting) {
        if ($peer) { $c.AddRange([string[]]$peer.Del) }
        $orphan = @($Existing | Where-Object { $_ -match "^$p1e-(lan\d+|dns)$" -and $wantAddr -notcontains $_ })
        if ($orphan.Count) { $c.Add('config firewall address'); foreach ($n in $orphan) { $c.Add("delete `"$n`"") }; $c.Add('end') }
        if ($s.ServerCertMode -eq 'Own') {
            $oldSrv = @($Existing | Where-Object { $_ -like "$($s.ServerCertName)*" -and $_ -ne $SrvName })
            if ($oldSrv.Count) { $c.Add('config vpn certificate local'); foreach ($n in $oldSrv) { $c.Add("delete `"$n`"") }; $c.Add('end') }
        }
        if ($s.AuthMode -eq 'Cert' -and $CaName) {
            $oldCa = @($Existing | Where-Object { $_ -like "$($s.CaName)*" -and $_ -ne $CaName })
            if ($oldCa.Count) { $c.Add('config vpn certificate ca'); foreach ($n in $oldCa) { $c.Add("delete `"$n`"") }; $c.Add('end') }
        }
    }
    if ($s.Vdom) { $c.Add('end') }
    return $c
}

function Assert-FgtOutput([string]$Out) {
    $lines = $Out -split "`n"
    $pattern = 'Command fail|parse error|node_check_object fail|entry not found|Unknown action|value parse error|Return code -|is used|in use'
    $errIdx = @(for ($k = 0; $k -lt $lines.Count; $k++) { if ($lines[$k] -match $pattern) { $k } })
    if ($errIdx.Count) {
        Write-Err2 'Die FortiGate hat Fehler gemeldet:'
        foreach ($k in $errIdx) {
            $from = [Math]::Max(0, $k - 2)
            $lines[$from..$k] | Where-Object { $_ -notmatch 'BEGIN|END|PRIVATE|passwd|^[A-Za-z0-9+/=]{40,}$' -and $_.Length -lt 200 } |
                ForEach-Object { Write-Host "         $_" -ForegroundColor Red }
            Write-Host '         ---' -ForegroundColor DarkGray
        }
        throw 'FortiGate meldet Fehler.'
    }
}

function Invoke-FgtRemove {
    # Entfernt alles, was das Skript auf der FortiGate angelegt hat
    Initialize-Settings
    $s = $Script:Settings
    $p1 = $s.P1Name
    $p1e = [regex]::Escape($p1)
    Write-Section "FortiGate aufraeumen (Phase1 $p1)" 'X'
    if (-not $s.FgtHost) { $s.FgtHost = Read-Default 'Management-IP der FortiGate' $s.Fqdn; Save-Settings }

    $mode = Read-Choice '1 = per SSH, 2 = nur als CLI-Datei speichern' @('1','2') '1'
    $ssh = $null; $names = @(); $polMap = @{}
    if ($mode -eq '1') { $ssh = Initialize-FgtSsh; if (-not $ssh) { $mode = '2' } }
    if ($mode -eq '1') {
        $q = Invoke-FgtQuery -SshExe $ssh -Purpose '1/2 Bestand abfragen und sichern'
        $polMap = $q.PolicyMap; $names = $q.Names
    } else {
        $names = @($p1, "$p1-p2", "$p1-clients", "$p1-lan", "$p1-pool", "$p1-dns", "$p1-peer") +
                 @((Get-LanNets) | ForEach-Object -Begin { $i = 0 } -Process { $i++; "$p1-lan$i" }) +
                 @(Get-ClientRegistry | ForEach-Object { Get-PeerName $_.Name })
    }
    $has = { param($n) $names -contains $n }
    $addr  = @($names | Where-Object { $_ -match "^$p1e-(pool|lan\d+|dns)$" })
    $peers = @($names | Where-Object { $_ -match "^$p1e-(peer|c-.+)$" })
    $cas   = if ($mode -eq '1') { @($names | Where-Object { $_ -like "$($s.CaName)*" }) } else { @() }
    $srvs  = if ($mode -eq '1' -and $s.ServerCertMode -eq 'Own') { @($names | Where-Object { $_ -like "$($s.ServerCertName)*" }) } else { @() }

    $c = New-Object System.Collections.Generic.List[string]
    if ($s.Vdom) { $c.Add('config vdom'); $c.Add("edit `"$($s.Vdom)`"") }
    $polDel = @((Get-OurPolicyNames) | Where-Object { $polMap.ContainsKey($_) })
    if ($polDel.Count) { $c.Add('config firewall policy'); foreach ($n in $polDel) { $c.Add("delete $($polMap[$n])") }; $c.Add('end') }
    elseif ($mode -eq '2') { $c.Add("# Policies $((Get-OurPolicyNames) -join ', ') bitte per ID loeschen: config firewall policy / delete <ID> / end") }
    if (& $has "$p1-p2")      { $c.AddRange([string[]]@('config vpn ipsec phase2-interface', "delete `"$p1-p2`"", 'end')) }
    if (& $has $p1)           { $c.AddRange([string[]]@('config vpn ipsec phase1-interface', "delete `"$p1`"", 'end')) }
    if (& $has "$p1-clients") { $c.AddRange([string[]]@('config user peergrp', "delete `"$p1-clients`"", 'end')) }
    if (& $has "$p1-lan")     { $c.AddRange([string[]]@('config firewall addrgrp', "delete `"$p1-lan`"", 'end')) }
    if ($addr.Count)  { $c.Add('config firewall address'); foreach ($a in $addr) { $c.Add("delete `"$a`"") }; $c.Add('end') }
    if ($peers.Count) { $c.Add('config user peer'); foreach ($n in $peers) { $c.Add("delete `"$n`"") }; $c.Add('end') }
    if ($srvs.Count)  { $c.Add('config vpn certificate local'); foreach ($n in $srvs) { $c.Add("delete `"$n`"") }; $c.Add('end') }
    if ($cas.Count)   { $c.Add('config vpn certificate ca');    foreach ($n in $cas)  { $c.Add("delete `"$n`"") }; $c.Add('end') }
    if ($s.Vdom) { $c.Add('end') }

    $todo = @($c | Where-Object { $_ -match '^delete ' })
    if ($mode -eq '1' -and -not $todo.Count) { Write-Ok 'Nichts zu entfernen - die FortiGate ist bereits sauber.'; return }
    Write-Info 'Wird entfernt:'
    foreach ($n in $polDel) { Write-Host "      Policy ID $($polMap[$n]) ($n)" -ForegroundColor White }
    foreach ($n in @($c | Where-Object { $_ -match '^delete "' })) { Write-Host ("      " + ($n -replace '^delete ', '')) -ForegroundColor White }
    if ($s.AuthMode -eq 'EAP') { Write-Info "Benutzergruppe '$($s.UserGroup)' und lokale Benutzer bleiben erhalten (evtl. anderweitig genutzt)." }
    if ($s.ServerCertMode -ne 'Own') { Write-Info "Vorhandenes Serverzertifikat '$($s.ServerCertName)' bleibt erhalten." }

    if ($mode -eq '2') {
        $file = Join-Path $Script:Root "fgt-remove-$p1.txt"
        Set-Content -Path $file -Value ($c -join "`r`n") -Encoding ASCII
        Write-Ok "CLI-Datei: $file (Eintraege, die es nicht gibt, meldet die FortiGate als Fehler - unkritisch)"
        return
    }
    if (-not (Read-YesNo 'Jetzt von der FortiGate loeschen?' $true)) { return }
    $out = Invoke-FgtCli -SshExe $ssh -Lines $c -Purpose '2/2 Loeschen'
    Assert-FgtOutput $out
    Write-Ok 'FortiGate aufgeraeumt.'
}

function Get-CurrentCaName {
    $f = Join-Path $Script:CertDir 'ca.pem'
    if (-not (Test-Path $f)) { throw "ca.pem fehlt ($f). Zuerst Menuepunkt 3 ausfuehren." }
    return "$($Script:Settings.CaName)-$(Get-ShortId (Read-CertFile $f))"
}

function Invoke-FgtPeers {
    # Nur die Client-Freischaltungen (Peers + Peer-Gruppe) abgleichen, optional Tunnel neu aufbauen lassen
    param([switch]$Flush)
    Initialize-Settings
    $s = $Script:Settings
    $p1 = $s.P1Name
    Write-Section 'Clients auf der FortiGate abgleichen' 'K'
    if ($s.AuthMode -ne 'Cert') { Write-Info 'Nur bei Anmeldung per Zertifikat noetig.'; return }
    $caName = Get-CurrentCaName
    Sync-LocalClient
    $active = @(Get-ActiveClients)
    Write-Info ("Freizuschalten: {0}" -f $(if ($active.Count) { ($active | ForEach-Object { $_.Name }) -join ', ' } else { '(keine)' }))

    $mode = Read-Choice '1 = per SSH, 2 = nur als CLI-Datei speichern' @('1','2') '1'
    $ssh = $null
    if ($mode -eq '1') { $ssh = Initialize-FgtSsh; if (-not $ssh) { $mode = '2' } }
    $c = New-Object System.Collections.Generic.List[string]
    if ($s.Vdom) { $c.Add('config vdom'); $c.Add("edit `"$($s.Vdom)`"") }
    if ($mode -eq '2') {
        $peer = New-FgtPeerLines -CaName $caName
        $c.AddRange([string[]]$peer.Pre)
        $c.AddRange([string[]]@('config vpn ipsec phase1-interface', "edit `"$p1`"", 'set peertype peergrp', "set peergrp `"$($peer.Group)`"", 'next', 'end'))
        if ($s.Vdom) { $c.Add('end') }
        $file = Join-Path $Script:Root "fgt-peers-$p1.txt"
        Set-Content -Path $file -Value ($c -join "`r`n") -Encoding ASCII
        Write-Ok "CLI-Datei: $file (gesperrte Peers bitte zusaetzlich unter config user peer loeschen)"
        return
    }
    $q = Invoke-FgtQuery -SshExe $ssh -Purpose '1/2 Bestand abfragen und sichern' -WithGateways:$Flush
    if ($q.Names -notcontains $p1) { throw "Phase1 '$p1' gibt es auf der FortiGate nicht - zuerst Menuepunkt 2 ausfuehren." }
    $peer = New-FgtPeerLines -CaName $caName -Existing $q.Names -KnowExisting
    $c.AddRange([string[]]$peer.Pre)
    $c.AddRange([string[]]@('config vpn ipsec phase1-interface', "edit `"$p1`"", 'set peertype peergrp', "set peergrp `"$($peer.Group)`"", 'next', 'end'))
    $c.AddRange([string[]]$peer.Del)
    if ($Flush) { foreach ($gw in $q.Gateways) { $c.Add("diagnose vpn ike gateway clear name $gw") } }
    if ($s.Vdom) { $c.Add('end') }
    $out = Invoke-FgtCli -SshExe $ssh -Lines $c -Purpose '2/2 Abgleich'
    Assert-FgtOutput $out
    Write-Ok ("Freigeschaltet: {0}" -f $(if ($peer.Peers.Count) { $peer.Peers -join ', ' } else { '(keine)' }))
    foreach ($n in $peer.Stale) { Write-Ok "Entfernt: Peer $n" }
    if ($Flush -and $q.Gateways.Count) { Write-Ok "Bestehende VPN-Verbindungen getrennt ($($q.Gateways -join ', ')) - berechtigte Clients verbinden sich neu." }
}

function Invoke-ClientRevoke {
    Initialize-Settings
    $s = $Script:Settings
    Write-Section 'Client sperren' 'K'
    if ($s.AuthMode -ne 'Cert') { throw 'Sperren gibt es nur bei Anmeldung per Zertifikat (bei EAP den Benutzer auf der FortiGate deaktivieren).' }
    $list = @(Get-ClientRegistry)
    if (-not $ClientName) { Show-ClientTable }
    $name = if ($ClientName) { $ClientName } else { Read-Default 'Welchen Client sperren? (Name, leer = abbrechen)' '' }
    if (-not $name) { return }
    $name = $name.ToUpper()
    $e = $list | Where-Object { $_.Name -eq $name } | Select-Object -First 1
    if (-not $e) { throw "Client '$name' ist nicht im Client-Verzeichnis." }
    if ($name -eq $env:COMPUTERNAME) { Write-Warn2 'Das ist DIESER PC - er verliert danach seine VPN-Verbindung.' }
    if (-not (Read-YesNo "Client '$name' sperren? Er kann sich danach nicht mehr verbinden." $true)) { return }
    $e.Status = 'gesperrt'
    $e | Add-Member -NotePropertyName Revoked -NotePropertyValue (Get-Date -Format 'yyyy-MM-dd') -Force
    Save-ClientRegistry $list
    foreach ($f in @((Join-Path $Script:CertDir "client-$name.pfx"), (Join-Path $Script:Root "vpn-client-$name"), (Join-Path $Script:Root "vpn-client-$name.zip"))) {
        if (Test-Path $f) { Remove-Item $f -Recurse -Force; Write-Ok "Geloescht: $(Split-Path $f -Leaf)" }
    }
    Write-Ok "Client '$name' im Client-Verzeichnis gesperrt"
    Invoke-FgtPeers -Flush

    $vpn = Get-VpnConnection -Name $s.ConnName -AllUserConnection -ErrorAction SilentlyContinue
    if ($vpn -and $name -ne $env:COMPUTERNAME -and (Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue)) {
        $cn = $s.ConnName
        $up = Wait-Until -Seconds 90 -Text 'Dieser PC verbindet sich neu' -Condition {
            (Get-VpnConnection -Name $cn -AllUserConnection -ErrorAction SilentlyContinue).ConnectionStatus -eq 'Connected' }
        if ($up) { Write-Ok 'Dieser PC ist wieder verbunden' } else { Write-Warn2 'Dieser PC ist noch nicht wieder verbunden (Status pruefen)' }
    }
}

function Invoke-ClientMenu {
    Initialize-Settings
    Write-Section 'Clients verwalten' 'K'
    Show-ClientTable
    $a = Read-Choice '1 = Client sperren, 2 = FortiGate abgleichen, 0 = zurueck' @('0','1','2') '0'
    switch ($a) { '1' { Invoke-ClientRevoke } '2' { Invoke-FgtPeers } }
}

function Invoke-Fgt {
    Initialize-Settings
    $s = $Script:Settings
    Write-Section "FortiGate konfigurieren (Phase1 $($s.P1Name), $($s.AuthMode))" '2'

    if (-not $s.FgtHost) { $s.FgtHost = Read-Default 'Management-IP der FortiGate' $s.Fqdn; Save-Settings }

    $caName = $null; $caPem = $null; $srvName = $s.ServerCertName; $srvCert = $null; $srvKey = $null
    $eapUser = $null; $eapPass = $null

    if ($s.AuthMode -eq 'Cert') {
        $caName = Get-CurrentCaName
        $caPem = Read-PemText (Join-Path $Script:CertDir 'ca.pem')
        Write-Ok "CA wird als '$caName' uebertragen"
        Sync-LocalClient
        $active = @(Get-ActiveClients)
        if (-not $active.Count) {
            Write-Warn2 'Kein Client registriert - mit der Peer-Gruppe koennte sich dann niemand verbinden.'
            if ($Script:Auto -or -not (Read-YesNo 'Trotzdem fortfahren?' $false)) { throw 'Abgebrochen: zuerst ein Client-Zertifikat erzeugen (3) oder ein Client-Paket (P).' }
        } else { Write-Ok "Freigeschaltete Clients: $(($active | ForEach-Object { $_.Name }) -join ', ')" }
    }
    Write-DnsHint
    if ($s.ServerCertMode -eq 'Own') {
        $fc = Join-Path $Script:CertDir 'fgt-server.crt.pem'
        $fk = Join-Path $Script:CertDir 'fgt-server.key.pem'
        if (-not (Test-Path $fc) -or -not (Test-Path $fk)) { throw 'fgt-server.crt.pem/.key.pem fehlen. Zuerst Menuepunkt 3 ausfuehren.' }
        $srvName = "$($s.ServerCertName)-$(Get-ShortId (Read-CertFile $fc))"
        $srvCert = Read-PemText $fc
        $srvKey  = Read-PemText $fk
        Write-Ok "Serverzertifikat wird als '$srvName' uebertragen"
    } else {
        Write-Info "Verwende vorhandenes Zertifikat '$srvName' auf der FortiGate."
    }
    if ($s.AuthMode -eq 'EAP' -and $VpnUser -and $VpnPassword) {
        $eapUser = $VpnUser; $eapPass = $VpnPassword
        Write-Ok "Lokaler VPN-Benutzer '$eapUser' wird angelegt/aktualisiert"
    } elseif ($s.AuthMode -eq 'EAP' -and -not $Script:Auto) {
        if (Read-YesNo "Lokalen VPN-Benutzer anlegen (Gruppe $($s.UserGroup))?" $true) {
            do { Write-Host '   ? ' -ForegroundColor Cyan -NoNewline; $eapUser = Read-Host 'VPN-Benutzername' } until ($eapUser -match '^[A-Za-z0-9._@-]+$')
            $eapPass = ConvertTo-Plain (Read-Secret 'VPN-Passwort' -Confirm)
        }
    }

    $mode = Read-Choice '1 = per SSH uebertragen, 2 = nur als CLI-Datei speichern' @('1','2') '1'
    $ssh = $null
    if ($mode -eq '1') { $ssh = Initialize-FgtSsh; if (-not $ssh) { $mode = '2' } }
    if ($mode -eq '2') {
        $cfg = New-FgtConfig -CaName $caName -CaPem $caPem -SrvName $srvName -SrvCertPem $srvCert -SrvKeyPem $srvKey -EapUser $eapUser -EapPass $eapPass
        $file = Join-Path $Script:Root "fgt-config-$($s.P1Name).txt"
        Set-Content -Path $file -Value ($cfg -join "`r`n") -Encoding ASCII
        Write-Ok "CLI-Datei: $file"
        Write-Warn2 'Enthaelt den privaten Schluessel - nach dem Einfuegen loeschen!'
        return
    }

    # 1/2: Bestand abfragen und lokal sichern (vorhandene Policies, Reihenfolge, eigene Objekte)
    $q = Invoke-FgtQuery -SshExe $ssh -Purpose '1/2 Bestand abfragen und sichern'
    $map = $q.PolicyMap
    $wanted = @((Get-WantedPolicies) | ForEach-Object { $_.Name })
    foreach ($n in $wanted) {
        if ($map.ContainsKey($n)) { Write-Ok "Policy '$n' gefunden (ID $($map[$n])) - wird aktualisiert" }
        else { Write-Info "Policy '$n' wird neu angelegt" }
    }
    $obsolete = @((Get-OurPolicyNames) | Where-Object { $map.ContainsKey($_) -and $wanted -notcontains $_ })
    foreach ($n in $obsolete) { Write-Warn2 "Policy '$n' (ID $($map[$n])) wird nicht mehr benoetigt und geloescht" }
    $delIds = @($obsolete | ForEach-Object { $map[$_] })
    $plan = Get-PolicyPlan $q $wanted

    # 2/2: Konfiguration uebertragen (inkl. Aufraeumen nicht mehr benoetigter eigener Objekte)
    $cfg = New-FgtConfig -CaName $caName -CaPem $caPem -SrvName $srvName -SrvCertPem $srvCert -SrvKeyPem $srvKey -EapUser $eapUser -EapPass $eapPass `
               -PolicyIds $map -DeletePolicyIds $delIds -NewPolicyIds $plan.NewIds -MoveBefore $plan.MoveBefore -Existing $q.Names -KnowExisting
    $out = Invoke-FgtCli -SshExe $ssh -Lines $cfg -Purpose '2/2 Konfiguration'

    Assert-FgtOutput $out
    Write-Ok 'Konfiguration ohne Fehlermeldung uebernommen.'
    $removed = @($cfg | Where-Object { $_ -match '^delete "' } | ForEach-Object { $_ -replace '^delete ', '' })
    if ($removed.Count) { Write-Ok "Nicht mehr benoetigt und entfernt: $($removed -join ', ')" }
    if ($plan.MoveBefore) { Write-Ok "Policies vor Policy ID $($plan.MoveBefore) verschoben" }
    if ($s.AuthMode -eq 'EAP' -and $eapUser) { Write-Info "Benutzer '$eapUser' bei der Client-Einrichtung verwenden." }
}

# ---------------------------------------------------------------------------
# Windows-Client
# ---------------------------------------------------------------------------
$Script:WatchdogTemplate = @'
# FGT-VPN Watchdog - erzeugt vom FGT-VPN-Setup
$Name     = '__NAME__'
$Routes   = @(__ROUTES__)
$Base     = 'C:\ProgramData\FGT-VPN'
$Log      = Join-Path $Base 'watchdog.log'
$CredFile = Join-Path $Base 'cred.bin'
$Interval = 30
Add-Type -AssemblyName System.Security

function Write-Log([string]$Msg) {
    try {
        if ((Test-Path $Log) -and ((Get-Item $Log).Length -gt 1MB)) { Move-Item $Log "$Log.old" -Force }
        Add-Content -Path $Log -Value ('{0}  {1}' -f (Get-Date -Format s), $Msg)
    } catch {}
}

function Set-VpnRoutes {
    # rasdial wendet die Profil-Routen nicht an - deshalb setzt der Watchdog sie selbst
    $if = Get-NetIPInterface -InterfaceAlias $Name -AddressFamily IPv4 -ErrorAction SilentlyContinue
    if (-not $if) { return }
    foreach ($r in $Routes) {
        if (-not (Get-NetRoute -InterfaceIndex $if.ifIndex -DestinationPrefix $r -ErrorAction SilentlyContinue)) {
            try { New-NetRoute -DestinationPrefix $r -InterfaceIndex $if.ifIndex -NextHop 0.0.0.0 -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null; Write-Log "Route $r gesetzt" }
            catch { Write-Log "Route $r fehlgeschlagen: $($_.Exception.Message)" }
        }
    }
}

function Get-VpnCred {
    if (-not (Test-Path $CredFile)) { return $null }
    $bytes = [IO.File]::ReadAllBytes($CredFile)
    $plain = [Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine))
    return ,($plain -split "`n", 2)
}

Write-Log 'Watchdog gestartet'
$last = ''
while ($true) {
    try {
        $vpn = Get-VpnConnection -Name $Name -AllUserConnection -ErrorAction SilentlyContinue
        if (-not $vpn) {
            if ($last -ne 'missing') { Write-Log "VPN-Verbindung '$Name' nicht gefunden"; $last = 'missing' }
        } elseif ($vpn.ConnectionStatus -eq 'Connected') {
            if ($last -ne 'up') { Write-Log 'Tunnel verbunden'; $last = 'up' }
            Set-VpnRoutes
        } else {
            $cred = Get-VpnCred
            if ($cred) { $out = & rasdial.exe $Name $cred[0] $cred[1] 2>&1 }
            else       { $out = & rasdial.exe $Name 2>&1 }
            Write-Log ('Verbindungsaufbau: ' + (($out | Where-Object { $_ }) -join ' | '))
            $last = 'dial'
            if ((Get-VpnConnection -Name $Name -AllUserConnection -ErrorAction SilentlyContinue).ConnectionStatus -eq 'Connected') { Set-VpnRoutes }
        }
    } catch { Write-Log ('Fehler: ' + $_.Exception.Message) }
    Start-Sleep -Seconds $Interval
}
'@

function Get-RootCa {
    $cur = Get-CurrentCa
    if (-not $cur) { return $null }
    return Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Thumbprint -eq $cur.Thumbprint } | Select-Object -First 1
}

function Confirm-ClientCert {
    $ca = Get-CurrentCa
    # Client-Zertifikate frueherer CAs entfernen (gleicher Name, anderer Fingerabdruck)
    $stale = @(if ($ca) { Get-ChildItem Cert:\LocalMachine\My | Where-Object {
        $_.Issuer -like $Script:CaFamily -and $_.Subject -notlike $Script:CaFamily -and
        ($_.EnhancedKeyUsageList.ObjectId -contains $Script:EkuClient) -and -not (Test-SignedByCa $_ $ca) } })
    foreach ($c in $stale) { Remove-Item -Path "Cert:\LocalMachine\My\$($c.Thumbprint)" -DeleteKey; Write-Ok "Altes Client-Zertifikat entfernt ($($c.Subject), andere CA)" }

    $certs = Get-OurClientCerts
    if ($certs.Count -gt 0) {
        foreach ($c in $certs) {
            Write-Ok "Client-Zertifikat $($c.Subject) (ECDSA P-384), gueltig bis $($c.NotAfter.ToString('d'))"
            if ($c.NotAfter -lt (Get-Date).AddDays(30)) { Write-Warn2 'Das Zertifikat laeuft in weniger als 30 Tagen ab - neues Paket anfordern.' }
        }
        return
    }
    Write-Warn2 'Kein ECDSA-P384-Maschinenzertifikat der aktuellen CA vorhanden.'
    $pfx = Join-Path $Script:CertDir "client-$env:COMPUTERNAME.pfx"
    if (-not (Test-Path $pfx)) { $pfx = Read-Default 'Pfad zur Client-PFX (leer = abbrechen)' '' }
    if (-not $pfx -or -not (Test-Path $pfx)) { throw 'Ohne Client-Zertifikat keine Verbindung moeglich (Menuepunkt 3 oder Client-Paket P).' }
    for ($try = 1; $try -le 3; $try++) {
        $pw = if ($PfxPassword) { ConvertTo-SecureString $PfxPassword -AsPlainText -Force } else { Read-Secret 'PFX-Passwort' }
        try { $null = Import-PfxCertificate -FilePath $pfx -CertStoreLocation Cert:\LocalMachine\My -Password $pw -ErrorAction Stop; break }
        catch { if ($PfxPassword -or $try -eq 3) { throw 'PFX-Passwort falsch.' }; Write-Warn2 'Passwort falsch, bitte erneut.' }
    }
    if (-not (Get-OurClientCerts).Count) { throw 'Das importierte Zertifikat stammt nicht von der CA in vpn-certs\ca.cer.' }
    Write-Ok "Client-Zertifikat aus $(Split-Path $pfx -Leaf) importiert"
}

function Confirm-CaTrust {
    $cer = Join-Path $Script:CertDir 'ca.cer'
    if (Test-Path $cer) {
        $cur = Read-CertFile $cer
        # Fruehere CAs mit gleichem Namen entfernen, damit Windows nicht die falsche verwendet
        foreach ($old in @(Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -like $Script:CaFamily -and $_.Thumbprint -ne $cur.Thumbprint })) {
            Remove-Item -Path "Cert:\LocalMachine\Root\$($old.Thumbprint)"
            Write-Ok "Fruehere Stamm-CA entfernt ($(Get-ShortId $old))"
        }
        if (Get-ChildItem Cert:\LocalMachine\Root | Where-Object Thumbprint -eq $cur.Thumbprint) { Write-Ok "CA vertrauenswuerdig: $($cur.Subject) ($(Get-ShortId $cur))" }
        else { $null = Import-Certificate -FilePath $cer -CertStoreLocation Cert:\LocalMachine\Root; Write-Ok "CA importiert ($(Get-ShortId $cur))" }
        return
    }
    if (Get-RootCa) { Write-Ok "CA vertrauenswuerdig: $Script:CaSubject"; return }
    $alt = Read-Default 'Pfad zum CA-Zertifikat (ca.cer/ca.pem, leer = ueberspringen)' ''
    if (-not $alt) { Write-Warn2 'CA nicht importiert - Windows muss dem FortiGate-Zertifikat vertrauen (sonst 13801).'; return }
    $null = Import-Certificate -FilePath $alt -CertStoreLocation Cert:\LocalMachine\Root
    Write-Ok 'CA importiert'
}

function Test-Tunnel {
    $ip = Get-TestIp
    $ok = Test-Connection -ComputerName $ip -Count 2 -Quiet -ErrorAction SilentlyContinue
    if ($ok) { Write-Ok "Ping durch den Tunnel zu $ip erfolgreich" }
    else     { Write-Warn2 "Ping zu $ip ohne Antwort (Policy/ICMP auf dem Ziel pruefen)" }
    $dnsName = if (Test-IPv4 $Script:Settings.Fqdn) { 'www.fortinet.com' } else { $Script:Settings.Fqdn }
    try { $null = Resolve-DnsName -Name $dnsName -Server $Script:Settings.DnsServer -DnsOnly -QuickTimeout -ErrorAction Stop; Write-Ok "DNS-Server $($Script:Settings.DnsServer) antwortet" }
    catch { Write-Warn2 "DNS-Server $($Script:Settings.DnsServer) antwortet nicht ($dnsName)" }
    $inet = (Find-NetRoute -RemoteIPAddress 1.1.1.1 -ErrorAction SilentlyContinue | Select-Object -Last 1).InterfaceAlias
    if ($Script:Settings.TunnelMode -eq 'Full') {
        if ($inet -eq $Script:Settings.ConnName) {
            if (Test-Connection 1.1.1.1 -Count 2 -Quiet -ErrorAction SilentlyContinue) { Write-Ok 'Internet laeuft ueber den Tunnel (1.1.1.1 erreichbar)' }
            else { Write-Warn2 'Internet-Route zeigt auf den Tunnel, 1.1.1.1 aber nicht erreichbar (Policy/NAT pruefen)' }
        } else { Write-Warn2 "Full Tunnel, aber Internet geht ueber '$inet'" }
    } else { Write-Info "Internet geht direkt ueber '$inet' (Split Tunnel)" }
    return $ok
}

function Install-Client {
    Initialize-Settings
    $s = $Script:Settings
    Write-Section "Windows-Client einrichten: $($s.ConnName) -> $($s.Fqdn)" '1'

    if ($s.ServerCertMode -eq 'Own' -or $s.AuthMode -eq 'Cert') { Confirm-CaTrust }
    if ($s.AuthMode -eq 'Cert') { Confirm-ClientCert }

    $eapUser = $null; $eapPass = $null

    if (Get-VpnConnection -Name $s.ConnName -AllUserConnection -ErrorAction SilentlyContinue) {
        if (-not (Read-YesNo "Verbindung '$($s.ConnName)' existiert bereits. Ersetzen?" $true)) { return }
        Stop-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
        & rasdial.exe $s.ConnName /disconnect | Out-Null
        Remove-VpnConnection -Name $s.ConnName -AllUserConnection -Force
    }

    $params = @{
        Name = $s.ConnName; ServerAddress = $s.Fqdn; TunnelType = 'Ikev2'
        AuthenticationMethod = $(if ($s.AuthMode -eq 'EAP') { 'Eap' } else { 'MachineCertificate' })
        EncryptionLevel = 'Required'; SplitTunneling = ($s.TunnelMode -ne 'Full'); AllUserConnection = $true; Force = $true
    }
    if ($s.DnsSuffix) { $params.DnsSuffix = $s.DnsSuffix }
    if ($s.AuthMode -eq 'Cert') {
        $rootCa = Get-RootCa
        if ($rootCa) {
            $params.MachineCertificateIssuerFilter = $rootCa
            $params.MachineCertificateEKUFilter = @($Script:EkuClient)
        }
    }
    Add-VpnConnection @params
    Write-Ok $(if ($s.AuthMode -eq 'Cert') { 'VPN-Verbindung angelegt (alle Benutzer, Zertifikatsfilter auf unsere CA)' } else { 'VPN-Verbindung angelegt (alle Benutzer, EAP-MSCHAPv2)' })

    Set-VpnConnectionIPsecConfiguration -ConnectionName $s.ConnName -AllUserConnection `
        -EncryptionMethod AES256 -IntegrityCheckMethod SHA384 -DHGroup ECP384 `
        -CipherTransformConstants GCMAES256 -AuthenticationTransformConstants GCMAES256 `
        -PfsGroup ECP384 -Force
    Write-Ok 'Krypto: IKE AES256/SHA384/ECP384  |  ESP AES256-GCM  |  PFS ECP384'
    Write-Ok $(if ($s.TunnelMode -eq 'Full') { 'Full Tunnel: gesamter Verkehr laeuft ueber das VPN' } else { 'Split Tunnel: nur die internen Netze laufen ueber das VPN' })

    foreach ($r in (Get-RouteNets)) {
        $null = Add-VpnConnectionRoute -ConnectionName $s.ConnName -AllUserConnection -DestinationPrefix $r
        Write-Ok "Route $r ueber den Tunnel"
    }
    Write-DnsHint

    if ($s.AuthMode -eq 'EAP') {
        # Getestet: Windows reicht EAP-Zugangsdaten bei rasdial nicht durch (Fehler 703).
        # EAP ist daher ein Benutzer-VPN: einmal interaktiv verbinden, Windows merkt sich die Daten.
        Set-VpnConnection -Name $s.ConnName -AllUserConnection -RememberCredential $true -Force
        if (Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue) {
            Stop-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $Script:TaskName -Confirm:$false
        }
        if (Test-Path $Script:BaseDir) { Remove-Item $Script:BaseDir -Recurse -Force }
        Write-Ok 'EAP-Verbindung eingerichtet (Benutzer-VPN, Zugangsdaten werden gemerkt)'
        Write-Warn2 'EAP startet NICHT vor der Anmeldung - fuer Always-On bitte Zertifikat verwenden.'
        Write-Info "Verbinden: Netzwerk-Symbol > VPN > $($s.ConnName) > Verbinden, Benutzer/Passwort eingeben."
        return
    }

    $null = New-Item -ItemType Directory -Path $Script:BaseDir -Force
    & icacls.exe $Script:BaseDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null

    $wd = Join-Path $Script:BaseDir 'watchdog.ps1'
    $routeList = ((Get-RouteNets) | ForEach-Object { "'$_'" }) -join ', '
    Set-Content -Path $wd -Value ($Script:WatchdogTemplate.Replace('__NAME__', $s.ConnName.Replace("'", "''")).Replace('__ROUTES__', $routeList)) -Encoding UTF8
    $action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$wd`""
    $trigger   = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
                    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew
    $null = Register-ScheduledTask -TaskName $Script:TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
                -Description 'Haelt den FortiGate-IKEv2-Tunnel dauerhaft aufrecht.' -Force
    Write-Ok "Watchdog '$Script:TaskName' (SYSTEM, beim Start) eingerichtet"

    if (Read-YesNo 'Watchdog jetzt starten und Verbindung testen?' $true) {
        Start-ScheduledTask -TaskName $Script:TaskName
        $name = $s.ConnName
        $firstNet = (Get-LanNets)[0].Cidr
        $up = Wait-Until -Seconds 90 -Text 'Warte auf Tunnel und Routen' -Condition {
            ((Get-VpnConnection -Name $name -AllUserConnection -ErrorAction SilentlyContinue).ConnectionStatus -eq 'Connected') -and
            (Get-NetRoute -InterfaceAlias $name -DestinationPrefix $firstNet -ErrorAction SilentlyContinue)
        }
        if ($up) { Write-Ok 'Tunnel verbunden'; $null = Test-Tunnel }
        else { Write-Err2 'Tunnel nicht verbunden - Details unter Status (Menuepunkt 4)' }
        Show-Status -NoHeader
        if (-not $up) { throw 'Verbindungstest fehlgeschlagen.' }
    }
}

function Show-Status {
    param([switch]$NoHeader)
    Initialize-Settings
    $s = $Script:Settings
    if (-not $NoHeader) { Write-Section 'Status' '4' }
    $vpn = Get-VpnConnection -Name $s.ConnName -AllUserConnection -ErrorAction SilentlyContinue
    Write-Host ''
    if ($vpn) {
        $up = $vpn.ConnectionStatus -eq 'Connected'
        Write-Host '   Tunnel      ' -NoNewline -ForegroundColor DarkGray
        if ($up) { Write-Host ' VERBUNDEN ' -ForegroundColor Black -BackgroundColor Green -NoNewline }
        else     { Write-Host ' GETRENNT ' -ForegroundColor White -BackgroundColor DarkRed -NoNewline }
        Write-Host ("  {0} -> {1}" -f $vpn.Name, $vpn.ServerAddress)
        if ($up) {
            $ip = Get-NetIPAddress -InterfaceAlias $s.ConnName -AddressFamily IPv4 -ErrorAction SilentlyContinue
            if ($ip) { Write-Host "   Tunnel-IP   $($ip.IPAddress)" -ForegroundColor Gray }
            Write-Host ("   Modus       {0}" -f $(if ($s.TunnelMode -eq 'Full') { 'Full Tunnel (alles ueber VPN)' } else { 'Split Tunnel (nur interne Netze)' })) -ForegroundColor Gray
            $want = @(Get-RouteNets)
            $rt = @(Get-NetRoute -InterfaceAlias $s.ConnName -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $want -contains $_.DestinationPrefix })
            Write-Host ("   Routen      {0}" -f $(if ($rt.Count) { ($rt.DestinationPrefix -join ', ') } else { 'keine (Watchdog setzt sie in max. 30 s)' })) -ForegroundColor Gray
        }
    } else { Write-Warn2 "Verbindung '$($s.ConnName)' nicht vorhanden." }
    $task = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
    if ($task) {
        $info = $task | Get-ScheduledTaskInfo
        Write-Host ("   Watchdog    {0}, letzter Start {1}" -f $task.State, $info.LastRunTime) -ForegroundColor Gray
    } else { Write-Warn2 'Watchdog nicht eingerichtet.' }
    $certs = Get-OurClientCerts
    $certText = if ($certs.Count) { "$($certs[0].Subject) (ECDSA P-384, bis $($certs[0].NotAfter.ToString('d')))" } else { 'kein Client-Zertifikat der aktuellen CA' }
    Write-Host "   Zertifikat  $certText" -ForegroundColor Gray
    if ($certs.Count -and $certs[0].NotAfter -lt (Get-Date).AddDays(30)) { Write-Warn2 "Client-Zertifikat laeuft am $($certs[0].NotAfter.ToString('d')) ab" }
    if ($vpn -and $vpn.ConnectionStatus -eq 'Connected' -and -not $NoHeader) { $null = Test-Tunnel }

    $log = Join-Path $Script:BaseDir 'watchdog.log'
    if (Test-Path $log) {
        Write-Host ''
        Write-Host '   Watchdog-Log (letzte Eintraege)' -ForegroundColor DarkCyan
        Get-Content $log -Tail 5 | ForEach-Object { Write-Host "     $_" -ForegroundColor DarkGray }
    }
    $ev = Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'RasClient'; Id = 20227; StartTime = (Get-Date).AddMinutes(-30) } -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($ev -and -not ($vpn -and $vpn.ConnectionStatus -eq 'Connected')) {
        $code = [regex]::Match($ev.Message, '(\d{3,5})\.?\s*$').Groups[1].Value
        $hint = switch ($code) {
            '809'   { 'keine Antwort: UDP 500/4500, FQDN/IP pruefen' }
            '13801' { 'Serverzertifikat: SAN/EKU/CA pruefen' }
            '13806' { 'kein passendes Client-Zertifikat (ECDSA P-384 unserer CA?)' }
            '13868' { 'Krypto-Proposals passen nicht' }
            default { '' }
        }
        Write-Host ''
        Write-Warn2 ("Letzter Einwahlfehler {0} um {1} {2}" -f $code, $ev.TimeCreated.ToString('HH:mm'), $(if ($hint) { "- $hint" } else { '' }))
    }
}

function Uninstall-Client {
    param([switch]$Purge)
    Initialize-Settings
    $s = $Script:Settings
    Write-Section 'Deinstallieren' '5'
    if (-not (Read-YesNo "Watchdog, Verbindung '$($s.ConnName)' und $Script:BaseDir entfernen?" $true)) { return }
    if (Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $Script:TaskName -Confirm:$false
        Write-Ok 'Watchdog entfernt'
    }
    & rasdial.exe $s.ConnName /disconnect | Out-Null
    if (Get-VpnConnection -Name $s.ConnName -AllUserConnection -ErrorAction SilentlyContinue) {
        Remove-VpnConnection -Name $s.ConnName -AllUserConnection -Force
        Write-Ok 'VPN-Verbindung entfernt'
    }
    if (Test-Path $Script:BaseDir) { Remove-Item $Script:BaseDir -Recurse -Force; Write-Ok "$Script:BaseDir geloescht" }

    if (-not $Script:Auto -and (Read-YesNo 'Auch die Konfiguration auf der FortiGate entfernen (SSH oder CLI-Datei)?' $false)) {
        try { Invoke-FgtRemove } catch { Write-Err2 "FortiGate: $($_.Exception.Message)" }
    }

    $doPurge = $Purge -or (Read-YesNo 'Auch alle FGT-VPN-Zertifikate (Client und CA) aus dem Computer-Speicher entfernen?' $false)
    if ($doPurge) {
        $mine = @(Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Issuer -like $Script:CaFamily -or $_.Subject -like $Script:CaFamily })
        foreach ($c in $mine) { Remove-Item -Path "Cert:\LocalMachine\My\$($c.Thumbprint)" -DeleteKey; Write-Ok "Entfernt: $($c.Subject)  [Eigene, von $($c.Issuer)]" }
        $roots = @(Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -like $Script:CaFamily })
        foreach ($c in $roots) { Remove-Item -Path "Cert:\LocalMachine\Root\$($c.Thumbprint)"; Write-Ok "Entfernt: $($c.Subject)  [Stamm]" }
        if (-not ($mine.Count + $roots.Count)) { Write-Info 'Keine FGT-VPN-Zertifikate gefunden.' }
        Write-Info "Ordner $Script:CertDir bleibt erhalten (ca.pfx fuer weitere Clients)."
    }
}

# ---------------------------------------------------------------------------
# Kurzanleitung und Assistent
# ---------------------------------------------------------------------------
function Show-Help {
    Write-Section 'Kurzanleitung' 'H'
    $txt = @(
        'WAS GEBAUT WIRD',
        '  Windows 11 baut mit dem eingebauten VPN-Client einen IKEv2-Tunnel',
        '  zur FortiGate. Ein Watchdog (geplante Aufgabe als SYSTEM) haelt ihn',
        '  ab dem Booten dauerhaft aufrecht - auch ohne Anmeldung.',
        '',
        'VORAUSSETZUNGEN',
        '  - FQDN/IP der FortiGate ist erreichbar (UDP 500/4500)',
        '  - SSH ist auf dem Management-Interface der FortiGate erlaubt',
        '  - Der VPN-IP-Pool ueberschneidet sich nicht mit anderen Netzen',
        '',
        'TUNNEL UND POLICIES',
        '  Split   nur interne Netze ueber VPN     Full  alles inkl. Internet',
        '  Policies VPN->LAN (optional auch LAN->VPN), Full: VPN->Internet',
        '  mit NAT. Alle Policies loggen komplett (logtraffic all).',
        '',
        'ANMELDUNG',
        '  Zertifikat  ECDSA-P384-Maschinenzertifikat je PC (empfohlen)',
        '  EAP         Benutzer/Passwort einer FortiGate-Gruppe (kein Always-On)',
        '',
        'REIHENFOLGE (alles auf einem PC)',
        '  3 Zertifikate  ->  2 FortiGate  ->  1 Client   (oder A Assistent)',
        '',
        'ADMIN-PC UND VPN-CLIENT GETRENNT',
        '  Admin-PC:  3 Zertifikate -> 2 FortiGate -> P Client-Paket je PC',
        '  Client:    Paket kopieren, Installieren.cmd starten (keine',
        '             FortiGate-Verbindung noetig). Ohne SSH vom Admin-PC:',
        '             unter 2 "CLI-Datei" waehlen und in PuTTY/GUI einfuegen.',
        '',
        'CLIENTS UND SPERREN',
        '  Jeder PC hat einen eigenen Peer (CN = Rechnername) in der Gruppe',
        '  <Phase1>-clients. K > 1 sperrt einen PC: Peer weg, Tunnel getrennt.',
        '  Paket-Passwoerter sind zufaellig und je Paket verschieden.',
        '',
        'SICHERUNG',
        '  Vor jeder Aenderung wird der betroffene FortiGate-Stand unter',
        '  fgt-backups\ gesichert.',
        '',
        'EAP-HINWEIS',
        '  EAP ist ein Benutzer-VPN (Anmeldedialog). Nur das Zertifikat',
        '  startet den Tunnel vor der Anmeldung (Always-On).',
        '',
        'FEHLERCODES',
        '  809    keine Antwort (Ports/FQDN)    13801  Serverzertifikat',
        '  13806  kein passendes Client-Zert.   13868  Krypto passt nicht'
    )
    Write-Line
    foreach ($l in $txt) {
        $color = if ($l -cmatch '^[A-Z]{3}') { 'Cyan' } else { 'Gray' }
        Write-BoxText $l $color
    }
    Write-Line
}

function Invoke-Wizard {
    Write-Section 'Assistent' 'A'
    Write-Info 'In 4 Schritten zum Always-On-VPN. Jeder Schritt laesst sich ueberspringen.'
    Show-Help
    Wait-Enter

    Write-Section 'Einstellungen' '1/4'
    if (-not (Test-Path $Script:SettingsFile) -or (Read-YesNo 'Einstellungen jetzt (erneut) bearbeiten?' $false)) { Edit-Settings }
    else { Write-Ok 'Vorhandene Einstellungen werden verwendet.' }

    Write-Section 'Zertifikate' '2/4'
    Write-Info 'Eigene CA, Serverzertifikat fuer die FortiGate, ECDSA-Zertifikat fuer diesen PC.'
    if (Read-YesNo 'Schritt ausfuehren?' $true) { Invoke-Certs }

    Write-Section 'FortiGate' '3/4'
    Write-Info 'Uebertraegt CA, Serverzertifikat, Peer, Adressen, Phase1/2 und Policy per SSH.'
    if (Read-YesNo 'Schritt ausfuehren?' $true) { Invoke-Fgt }

    Write-Section 'Windows-Client' '4/4'
    Write-Info 'VPN-Verbindung, Krypto, Routen und Watchdog fuer den Dauerbetrieb.'
    if (Read-YesNo 'Schritt ausfuehren?' $true) { Install-Client }

    Write-Section 'Fertig'
    Write-Ok 'Nach einem Neustart steht der Tunnel ohne Anmeldung innerhalb ca. 1 Minute.'
}

# ---------------------------------------------------------------------------
# Ablauf
# ---------------------------------------------------------------------------
function Show-Menu {
    $s = $Script:Settings
    Show-Banner
    $vpn = Get-VpnConnection -Name $s.ConnName -AllUserConnection -ErrorAction SilentlyContinue
    $state = if (-not $vpn) { 'nicht eingerichtet' } elseif ($vpn.ConnectionStatus -eq 'Connected') { 'VERBUNDEN' } else { 'getrennt' }
    $stateColor = if ($state -eq 'VERBUNDEN') { 'Green' } elseif ($state -eq 'getrennt') { 'Yellow' } else { 'DarkGray' }
    Write-Line
    Write-BoxText ("Ziel  {0,-24} Anmeldung  {1}" -f $s.Fqdn, $(if ($s.AuthMode -eq 'EAP') { 'EAP' } else { 'Zertifikat' })) 'Gray'
    Write-BoxText ("VPN   {0,-24} Status     {1}" -f $s.ConnName, $state) $stateColor
    Write-Line
    $items = @(
        @('A', 'Assistent - gefuehrtes Setup Schritt fuer Schritt', 'Cyan'),
        @('1', 'Windows-Client einrichten (VPN + Watchdog)', 'Gray'),
        @('2', 'FortiGate konfigurieren (SSH)', 'Gray'),
        @('3', 'Zertifikate erzeugen', 'Gray'),
        @('4', 'Status und Verbindungstest', 'Gray'),
        @('5', 'Deinstallieren (Client, optional FortiGate)', 'Gray'),
        @('X', 'FortiGate-Konfiguration entfernen', 'Gray'),
        @('K', 'Clients verwalten (Liste, sperren, FortiGate abgleichen)', 'Gray'),
        @('P', 'Client-Paket fuer einen anderen PC (Admin-PC)', 'Gray'),
        @('S', 'Einstellungen anzeigen', 'Gray'),
        @('E', 'Einstellungen aendern    H  Kurzanleitung    Q  Beenden', 'DarkGray')
    )
    foreach ($it in $items) {
        Write-Host '  | ' -ForegroundColor DarkCyan -NoNewline
        Write-Host " $($it[0]) " -ForegroundColor Black -BackgroundColor DarkCyan -NoNewline
        Write-Host ('  ' + $it[1]).PadRight($Script:W - 7) -ForegroundColor $it[2] -NoNewline
        Write-Host ' |' -ForegroundColor DarkCyan
    }
    Write-Line
}

function Invoke-Action([string]$Name) {
    switch ($Name) {
        'Wizard'    { Invoke-Wizard }
        'Settings'  { Show-Settings }
        'Help'      { Show-Help }
        'Certs'     { Invoke-Certs }
        'Fgt'       { Invoke-Fgt }
        'FgtRemove' { Invoke-FgtRemove }
        'Clients'   { Show-ClientTable }
        'Peers'     { Invoke-FgtPeers }
        'Revoke'    { Invoke-ClientRevoke }
        'Client'    { Install-Client }
        'Package'   { Invoke-Package }
        'Status'    { Show-Status }
        'Uninstall' { Uninstall-Client }
        'Purge'     { Uninstall-Client -Purge }
    }
}

$hasSettings = Import-Settings
if ($Script:Actions -notcontains 'Menu') {
    $exitCode = 0
    Show-Banner
    foreach ($a in $Script:Actions) {
        try { Invoke-Action $a }
        catch { Write-Err2 "$a fehlgeschlagen: $($_.Exception.Message)"; $exitCode = 1; break }
    }
    Write-Host ''
    if ($exitCode -eq 0) { Write-Ok "Fertig: $($Script:Actions -join ' > ')" } else { Write-Err2 'Abgebrochen.' }
    if ($LogFile) { try { Stop-Transcript | Out-Null } catch {} }
    if ($Elevated -and $Script:Auto) { Write-Host '   Fenster schliesst in 10 s ...' -ForegroundColor DarkGray; Start-Sleep 10 }
    elseif ($Elevated) { Write-Host '   Enter zum Schliessen ' -ForegroundColor DarkGray -NoNewline; $null = Read-Host }
    exit $exitCode
}

if (-not $hasSettings) {
    Show-Banner
    Write-Host '   Willkommen! Es sind noch keine Einstellungen vorhanden.' -ForegroundColor White
    Write-Host ''
    if (Read-YesNo 'Assistent starten?' $true) {
        try { Invoke-Wizard } catch { Write-Err2 $_.Exception.Message }
        Wait-Enter
    }
}
while ($true) {
    Show-Menu
    Write-Host '   Auswahl: ' -ForegroundColor Cyan -NoNewline
    $choice = ("$(Read-Host)").Trim().ToUpper()
    if ($choice -eq 'Q') { break }
    try {
        switch ($choice) {
            'A' { Invoke-Wizard }
            '1' { Install-Client }
            '2' { Invoke-Fgt }
            '3' { Invoke-Certs }
            '4' { Show-Status }
            '5' { Uninstall-Client }
            'P' { Invoke-Package }
            'X' { Invoke-FgtRemove }
            'K' { Invoke-ClientMenu }
            'S' { Show-Settings }
            'E' { Edit-Settings }
            'H' { Show-Help }
            default { Write-Warn2 'Ungueltige Auswahl.' }
        }
    } catch {
        Write-Err2 ($_.Exception.Message -replace '[\r\n]+', ' ')
        if ($_.InvocationInfo) { Write-Host "         ($($_.InvocationInfo.PositionMessage.Split("`n")[0]))" -ForegroundColor DarkGray }
    }
    Wait-Enter
}
if ($LogFile) { try { Stop-Transcript | Out-Null } catch {} }
