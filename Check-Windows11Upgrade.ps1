#requires -version 5.1

<#
.SYNOPSIS
    KissLabs - Windows 11 Upgrade Readiness Check

.DESCRIPTION
    Vérifie si la machine est prête pour une mise à niveau vers Windows 11 25H2.

    Contrôles principaux :
      - Version Windows actuelle (25H2 ou plus récent = déjà à jour, LTSC)
      - Prérequis Microsoft Windows 11 via HardwareReadiness.ps1
      - CPU / RAM / TPM 2.0 / Secure Boot / stockage
      - DirectX 12 / WDDM 2.0
      - Espace disque libre
      - Redémarrage en attente
      - Service Windows Update
      - Verrouillage de version GPO / Intune (TargetReleaseVersion / ProductVersion)
      - WSUS
      - Safeguard Hold Microsoft (Appraiser, clé GE25H2)
      - Nettoyage automatique du dossier temporaire

    Le script HardwareReadiness.ps1 de Microsoft n'est exécuté que si sa
    signature Authenticode est valide et émise pour Microsoft Corporation, ou
    si son empreinte SHA-256 correspond à une version officielle connue.

    Lancé depuis un hôte PowerShell 32 bits sur un Windows 64 bits (Intune
    par défaut), le script se relance automatiquement en PowerShell 64 bits
    afin de lire les bonnes clés de registre.

    Chaque exécution est journalisée (horodatage, niveau) dans un fichier
    dédié, par défaut %SystemRoot%\Logs\KissLabs (écriture réservée à SYSTEM
    et aux administrateurs).

.PARAMETER RecommendedFreeSpaceGB
    Espace libre recommandé sur le disque système, en Go. En dessous, un
    avertissement est affiché (non bloquant). Défaut : 30.

.PARAMETER KeepTemp
    Conserve le dossier temporaire (HardwareReadiness.ps1, DxDiag.xml) pour
    analyse au lieu de le supprimer en fin d'exécution.

.PARAMETER HardwareScriptPath
    Chemin d'une copie locale de HardwareReadiness.ps1, pour les machines sans
    accès Internet. Si absent, le script est téléchargé depuis
    https://aka.ms/HWReadinessScript. La signature est contrôlée dans les deux cas.

.PARAMETER LogDirectory
    Dossier du fichier journal. Défaut : %SystemRoot%\Logs\KissLabs.

.EXAMPLE
    .\Check-Windows11Upgrade.ps1

.EXAMPLE
    .\Check-Windows11Upgrade.ps1 -HardwareScriptPath "\\serveur\partage\HardwareReadiness.ps1" -KeepTemp

.NOTES
    Version              : 1.2.0
    Cible de déploiement : Windows 11 25H2 (build 26200)
    Compatible Windows PowerShell 5.1, droits administrateur requis.

    Codes de sortie :
      0 = READY / ALREADY_CURRENT
      1 = NOT_CAPABLE
      2 = UNDETERMINED / ALREADY_CURRENT_CHECK_INCOMPLETE / ERROR
          (y compris exécution sans droits administrateur)
      3 = CAPABLE_BUT_BLOCKED (stratégie GPO / Intune, Safeguard Hold, édition LTSC)
      4 = ALREADY_CURRENT_NOT_COMPLIANT
#>

[CmdletBinding()]
param(
    [int]$RecommendedFreeSpaceGB = 30,
    [switch]$KeepTemp,
    [string]$HardwareScriptPath,
    [string]$LogDirectory
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$ScriptVersion = "1.2.0"
$TargetVersion = "25H2"
$TargetBuild = 26200
$TargetIndicatorKey = "GE25H2"

# Empreintes SHA-256 de versions officielles connues de HardwareReadiness.ps1
# (version signée le 2021-11-29), acceptées si la chaîne de certificats ne
# peut pas être validée localement.
$KnownHardwareScriptHashes = @(
    "3F21C32818BFC3A20293317FF91A62ADB349B5A0D468A6DDDEA752F68365C24A"
)
$ExitCode = 2
$FinalResult = "UNDETERMINED"
$TranscriptStarted = $false

function Write-Title {
    param([string]$Text)

    Write-Host ""
    Write-Host ("=" * 78) -ForegroundColor Cyan
    Write-Host (" " + $Text) -ForegroundColor Cyan
    Write-Host ("=" * 78) -ForegroundColor Cyan
}

function Write-Check {
    param(
        [string]$Name,
        [ValidateSet("OK", "WARN", "FAIL", "INFO", "ERROR")]
        [string]$State,
        [string]$Detail
    )

    $Color = switch ($State) {
        "OK"   { "Green" }
        "WARN" { "Yellow" }
        "FAIL" { "Red" }
        "ERROR" { "Red" }
        "INFO" { "Cyan" }
        default { "White" }
    }

    Write-Host ("{0} [{1,-5}] {2,-28} {3}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $State, $Name, $Detail) -ForegroundColor $Color
}

function Exit-Script {
    param(
        [string]$Result,
        [int]$Code
    )

    # Résumé toujours en dernières lignes de la sortie et du journal.
    Write-Host ""
    Write-Host ("FinalResult : {0}" -f $Result)
    Write-Host ("ExitCode    : {0}" -f $Code)

    if ($script:TranscriptStarted) {
        try {
            Stop-Transcript | Out-Null
        }
        catch {
            Write-Verbose ("Arrêt du journal impossible : {0}" -f $_.Exception.Message)
        }
    }

    exit $Code
}

function Get-PropertyValue {
    param(
        [object]$Object,
        [string]$Name,
        $Default = $null
    )

    if ($null -eq $Object) {
        return $Default
    }

    $Property = $Object.PSObject.Properties[$Name]

    if ($null -ne $Property) {
        return $Property.Value
    }

    return $Default
}

function Invoke-RobustDownload {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $true)]
        [string]$Destination,

        [int]$MaxAttempts = 3
    )

    for ($Attempt = 1; $Attempt -le $MaxAttempts; $Attempt++) {
        try {
            Write-Check "Téléchargement Microsoft" "INFO" ("Tentative {0}/{1}" -f $Attempt, $MaxAttempts)

            $IwrParams = @{
                Uri                = $Uri
                OutFile            = $Destination
                UseBasicParsing    = $true
                MaximumRedirection = 10
                ErrorAction        = "Stop"
            }

            Invoke-WebRequest @IwrParams

            if ((Test-Path $Destination) -and ((Get-Item $Destination).Length -gt 1000)) {
                return
            }

            throw "Le fichier téléchargé est vide ou invalide."
        }
        catch {
            if ($Attempt -eq $MaxAttempts) {
                throw
            }

            Start-Sleep -Seconds (2 * $Attempt)
        }
    }
}

function Test-PendingReboot {
    $Pending = $false
    $Reasons = New-Object System.Collections.Generic.List[string]

    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
        $Pending = $true
        $Reasons.Add("Component Based Servicing")
    }

    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
        $Pending = $true
        $Reasons.Add("Windows Update")
    }

    try {
        $SessionManager = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -ErrorAction SilentlyContinue
        $PendingRename = Get-PropertyValue $SessionManager "PendingFileRenameOperations"

        if ($null -ne $PendingRename) {
            $Pending = $true
            $Reasons.Add("PendingFileRenameOperations")
        }
    }
    catch {
        Write-Verbose ("PendingFileRenameOperations illisible : {0}" -f $_.Exception.Message)
    }

    [PSCustomObject]@{
        Pending = $Pending
        Reasons = $Reasons
    }
}

function Get-GraphicsReadiness {
    param(
        [string]$OutputFile
    )

    try {
        $DxDiag = Join-Path $env:SystemRoot "System32\dxdiag.exe"

        if (-not (Test-Path $DxDiag)) {
            throw "dxdiag.exe introuvable."
        }

        $Process = Start-Process -FilePath $DxDiag -ArgumentList ("/whql:off /x `"{0}`"" -f $OutputFile) -WindowStyle Hidden -PassThru

        if (-not $Process.WaitForExit(30000)) {
            Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
            throw "Timeout lors de l'exécution de DxDiag."
        }

        if (-not (Test-Path $OutputFile)) {
            throw "DxDiag n'a pas généré de fichier XML."
        }

        [xml]$DxDiagXml = Get-Content -Path $OutputFile -Raw -ErrorAction Stop
        $Devices = @($DxDiagXml.DxDiag.DisplayDevices.DisplayDevice)

        if ($Devices.Count -eq 0) {
            throw "Aucun périphérique graphique détecté."
        }

        $Results = @()
        $AtLeastOneCompatible = $false
        $AtLeastOneKnown = $false

        foreach ($Device in $Devices) {
            if ($null -eq $Device) {
                continue
            }

            $CardName = [string]$Device.CardName
            $DDIText = [string]$Device.DDIVersion
            $DriverModelText = [string]$Device.DriverModel

            $DDIVersion = $null
            $WDDMVersion = $null

            if ($DDIText -match '(\d+(?:\.\d+)?)') {
                $DDIVersion = [double]::Parse($Matches[1], [Globalization.CultureInfo]::InvariantCulture)
            }

            if ($DriverModelText -match 'WDDM\s+(\d+(?:\.\d+)?)') {
                $WDDMVersion = [double]::Parse($Matches[1], [Globalization.CultureInfo]::InvariantCulture)
            }

            if (($null -ne $DDIVersion) -and ($null -ne $WDDMVersion)) {
                $AtLeastOneKnown = $true

                if (($DDIVersion -ge 12) -and ($WDDMVersion -ge 2.0)) {
                    $AtLeastOneCompatible = $true
                }
            }

            $Results += [PSCustomObject]@{
                CardName    = $CardName
                DDIVersion  = $DDIVersion
                WDDMVersion = $WDDMVersion
                DriverModel = $DriverModelText
            }
        }

        if (-not $AtLeastOneKnown) {
            return [PSCustomObject]@{
                State   = "WARN"
                Capable = $null
                Detail  = "Version DirectX/WDDM non déterminée."
                Devices = $Results
            }
        }

        if ($AtLeastOneCompatible) {
            return [PSCustomObject]@{
                State   = "OK"
                Capable = $true
                Detail  = "DirectX 12 / WDDM 2.0 ou supérieur détecté."
                Devices = $Results
            }
        }

        [PSCustomObject]@{
            State   = "FAIL"
            Capable = $false
            Detail  = "Aucun GPU DirectX 12 + WDDM 2.0 compatible détecté."
            Devices = $Results
        }
    }
    catch {
        [PSCustomObject]@{
            State   = "WARN"
            Capable = $null
            Detail  = $_.Exception.Message
            Devices = @()
        }
    }
}

function ConvertTo-ReleaseNumber {
    param([string]$Release)

    # "25H2" -> 252 : permet de comparer deux versions Windows "YYHn".
    if ($Release.Trim() -match '^(\d{2})H([12])$') {
        return ([int]$Matches[1] * 10) + [int]$Matches[2]
    }

    return $null
}

function ConvertTo-StringList {
    param($Value)

    # Valeurs REG_MULTI_SZ de l'Appraiser : "None" signifie liste vide.
    @(@($Value) | ForEach-Object { ([string]$_).Trim() } | Where-Object {
        (-not [string]::IsNullOrWhiteSpace($_)) -and ($_ -ne "None")
    })
}

function ConvertTo-NullableInt {
    param($Value)

    # Attention : "" -as [int] vaut 0, d'où le contrôle explicite.
    $Text = ([string]$Value).Trim()

    if ($Text -match '^-?\d+$') {
        return [int]$Text
    }

    return $null
}

function Get-SafeguardStatus {
    param(
        [string]$IndicatorKeyName
    )

    $Known = $false
    $GStatus = $null
    $BlockIDs = @()
    $Reasons = @()
    $FailedPrereqs = @()
    $UpgEx = ""
    $RedReasons = @()
    $EvaluatedOn = $null
    $GWXStatus = $null

    # Seule la sous-clé de la version cible fait foi (GE25H2 pour 25H2) : les
    # autres sous-clés peuvent conserver d'anciens blocages sur d'autres versions.
    $IndicatorKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TargetVersionUpgradeExperienceIndicators\{0}" -f $IndicatorKeyName
    $Values = Get-ItemProperty -Path $IndicatorKey -ErrorAction SilentlyContinue

    if ($null -ne $Values) {
        $Known = $true
        $GStatus = ConvertTo-NullableInt (Get-PropertyValue $Values "GStatus")
        $BlockIDs = @(ConvertTo-StringList (Get-PropertyValue $Values "GatedBlockId"))
        $Reasons = @(ConvertTo-StringList (Get-PropertyValue $Values "GatedBlockReason"))
        $FailedPrereqs = @(ConvertTo-StringList (Get-PropertyValue $Values "FailedPrereqs"))
        $UpgEx = ([string](Get-PropertyValue $Values "UpgEx" "")).Trim()
        $RedReasons = @(ConvertTo-StringList (Get-PropertyValue $Values "RedReason"))

        # Date de la dernière évaluation (format non documenté : contrôle de plage).
        $EpochSeconds = 0L
        $Timestamp = 0L

        if ([long]::TryParse(([string](Get-PropertyValue $Values "TimestampEpochString" "")).Trim(), [ref]$EpochSeconds) -and ($EpochSeconds -gt 0)) {
            if ($EpochSeconds -gt 100000000000) {
                $EpochSeconds = [long]($EpochSeconds / 1000)
            }

            $EvaluatedOn = (New-Object DateTime 1970, 1, 1, 0, 0, 0, ([DateTimeKind]::Utc)).AddSeconds($EpochSeconds)
        }
        elseif ([long]::TryParse([string](Get-PropertyValue $Values "Timestamp" ""), [ref]$Timestamp) -and ($Timestamp -gt 100000000000000000)) {
            $EvaluatedOn = [DateTime]::FromFileTimeUtc($Timestamp)
        }

        if (($null -ne $EvaluatedOn) -and (($EvaluatedOn.Year -lt 2015) -or ($EvaluatedOn -gt [DateTime]::UtcNow.AddDays(1)))) {
            $EvaluatedOn = $null
        }
    }

    # Appraiser\GWX n'est pas propre à une version cible : simple indice,
    # utilisé uniquement en l'absence de la sous-clé de la version cible.
    $GWX = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Appraiser\GWX" -ErrorAction SilentlyContinue

    if ($null -ne $GWX) {
        $GWXStatus = ConvertTo-NullableInt (Get-PropertyValue $GWX "GStatus")
    }

    [PSCustomObject]@{
        Known         = $Known
        GStatus       = $GStatus
        BlockIDs      = $BlockIDs
        Reasons       = $Reasons
        FailedPrereqs = $FailedPrereqs
        UpgEx         = $UpgEx
        RedReasons    = $RedReasons
        EvaluatedOn   = $EvaluatedOn
        GWXStatus     = $GWXStatus
    }
}

# ----------------------------------------------------------------------------
# Relance en PowerShell 64 bits
# ----------------------------------------------------------------------------

# Chemins absolus : le processus relancé ne partage pas l'emplacement
# PowerShell courant. Un lecteur absent (session SYSTEM, élévation UAC) laisse
# la valeur telle quelle : les contrôles suivants renverront ERROR (2).
foreach ($PathParameter in @("HardwareScriptPath", "LogDirectory")) {
    $PathValue = Get-Variable -Name $PathParameter -ValueOnly

    if (-not [string]::IsNullOrWhiteSpace($PathValue)) {
        try {
            Set-Variable -Name $PathParameter -Value $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($PathValue)
        }
        catch {
            Write-Verbose ("Chemin non résolu ({0}) : {1}" -f $PathParameter, $_.Exception.Message)
        }
    }
}

# Un hôte 32 bits (Intune par défaut, certains RMM) voit le registre via
# WOW6432Node : les clés Appraiser / Component Based Servicing seraient
# introuvables et les contrôles concluraient à tort que tout va bien.
$Is32BitHostOn64BitOS = [Environment]::Is64BitOperatingSystem -and (-not [Environment]::Is64BitProcess)

# Avertissements affichés une fois le journal ouvert, pour y figurer aussi.
$HostWarnings = New-Object System.Collections.Generic.List[string]

if ($Is32BitHostOn64BitOS) {
    $SysNativePowerShell = Join-Path $env:SystemRoot "SysNative\WindowsPowerShell\v1.0\powershell.exe"

    # La variable d'environnement empêche une relance en boucle (ex. Windows
    # ARM64 dont le PowerShell natif ne serait pas 64 bits).
    if ((-not [string]::IsNullOrEmpty($PSCommandPath)) -and (Test-Path $SysNativePowerShell) -and ($env:KISSLABS_W11CHECK_RELAUNCHED -ne "1")) {
        $RelaunchArguments = @(
            "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-File", $PSCommandPath,
            "-RecommendedFreeSpaceGB", $RecommendedFreeSpaceGB
        )

        if ($KeepTemp) {
            $RelaunchArguments += "-KeepTemp"
        }

        if (-not [string]::IsNullOrWhiteSpace($HardwareScriptPath)) {
            $RelaunchArguments += @("-HardwareScriptPath", $HardwareScriptPath)
        }

        if (-not [string]::IsNullOrWhiteSpace($LogDirectory)) {
            # Windows PowerShell 5.1 n'échappe pas un "\" final dans un argument
            # entre guillemets : le retirer (sauf racine de lecteur).
            $RelaunchArguments += @("-LogDirectory", ($LogDirectory -replace '(?<=[^\\:])\\+$', ''))
        }

        Write-Host "[INFO] Hôte PowerShell 32 bits détecté : relance en PowerShell 64 bits." -ForegroundColor Cyan

        # La sortie d'erreur du processus enfant ne doit pas interrompre le relais.
        $ErrorActionPreference = "Continue"
        $env:KISSLABS_W11CHECK_RELAUNCHED = "1"
        $RelaunchCompleted = $false

        try {
            & $SysNativePowerShell @RelaunchArguments
            $RelaunchExitCode = $LASTEXITCODE
            $RelaunchCompleted = $true
        }
        catch {
            $HostWarnings.Add(("Relance 64 bits impossible : {0}" -f $_.Exception.Message))
        }
        finally {
            # Le marqueur ne vaut que pour le processus relancé : une nouvelle
            # exécution dans le même hôte 32 bits doit pouvoir relancer.
            Remove-Item -Path "Env:\KISSLABS_W11CHECK_RELAUNCHED" -ErrorAction SilentlyContinue
        }

        if ($RelaunchCompleted) {
            if ($null -eq $RelaunchExitCode) {
                exit 2
            }

            exit $RelaunchExitCode
        }

        $ErrorActionPreference = "Stop"
    }

    $HostWarnings.Add("Hôte 32 bits : certains contrôles du registre peuvent être incomplets.")
}

# ----------------------------------------------------------------------------
# Vérification des droits administrateur
# ----------------------------------------------------------------------------

$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object Security.Principal.WindowsPrincipal($Identity)
$IsAdministrator = $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdministrator) {
    Write-Host ""
    Write-Check "Droits" "ERROR" "Le script doit être exécuté en administrateur."
    Exit-Script -Result "ERROR" -Code 2
}

# ----------------------------------------------------------------------------
# Journal (fichier dédié, une exécution par fichier)
# ----------------------------------------------------------------------------

$LogFile = $null

try {
    # Défaut sous %SystemRoot%\Logs : un utilisateur standard ne peut pas y
    # créer de dossier à l'avance (contrairement à %ProgramData%).
    if ([string]::IsNullOrWhiteSpace($LogDirectory)) {
        $LogDirectory = Join-Path $env:SystemRoot "Logs\KissLabs"
    }

    if (-not (Test-Path -LiteralPath $LogDirectory -PathType Container)) {
        New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
    }

    # Le journal est écrit en administrateur / SYSTEM : refuser un dossier
    # (ou son parent) redirigé par une jonction ou un lien symbolique.
    foreach ($LogPathToCheck in @($LogDirectory, (Split-Path -Path $LogDirectory -Parent))) {
        if ([string]::IsNullOrWhiteSpace($LogPathToCheck)) {
            continue
        }

        $LogPathItem = Get-Item -LiteralPath $LogPathToCheck -Force -ErrorAction SilentlyContinue

        if (($null -ne $LogPathItem) -and ($LogPathItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
            throw ("dossier redirigé (jonction / lien symbolique) : {0}" -f $LogPathToCheck)
        }
    }

    $LogFile = Join-Path $LogDirectory ("Check-Windows11Upgrade_{0}_{1}_{2}.log" -f $env:COMPUTERNAME, (Get-Date -Format "yyyyMMdd-HHmmss"), $PID)
    Start-Transcript -LiteralPath $LogFile -Force | Out-Null
    $TranscriptStarted = $true
}
catch {
    $LogFile = $null
    $HostWarnings.Add(("Journal impossible à créer : {0}" -f $_.Exception.Message))
}

# ----------------------------------------------------------------------------
# Dossier temporaire unique
# ----------------------------------------------------------------------------

$TempFolder = Join-Path ([System.IO.Path]::GetTempPath()) ("TempW11UpgradeCheck_" + [guid]::NewGuid().ToString("N"))
$HardwareScript = Join-Path $TempFolder "HardwareReadiness.ps1"
$DxDiagFile = Join-Path $TempFolder "DxDiag.xml"

try {
    Write-Title ("WINDOWS 11 {0} - UPGRADE READINESS CHECK" -f $TargetVersion)

    Write-Check "Machine" "INFO" $env:COMPUTERNAME
    Write-Check "Utilisateur" "INFO" $Identity.Name

    if ($null -ne $LogFile) {
        Write-Check "Journal" "INFO" $LogFile
    }

    foreach ($HostWarning in $HostWarnings) {
        Write-Check "Avertissement" "WARN" $HostWarning
    }

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }
    catch {
        Write-Verbose ("Activation TLS 1.2 impossible : {0}" -f $_.Exception.Message)
    }

    New-Item -Path $TempFolder -ItemType Directory -Force | Out-Null

    # ------------------------------------------------------------------------
    # 1. Système d'exploitation
    # ------------------------------------------------------------------------

    Write-Title "1. SYSTEME D'EXPLOITATION"

    $CurrentVersion = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    $OS = Get-CimInstance Win32_OperatingSystem

    $ProductName = [string](Get-PropertyValue $CurrentVersion "ProductName" "Windows")
    $DisplayVersion = [string](Get-PropertyValue $CurrentVersion "DisplayVersion" (Get-PropertyValue $CurrentVersion "ReleaseId" "Unknown"))
    $EditionID = [string](Get-PropertyValue $CurrentVersion "EditionID" "Unknown")
    $IsLTSC = ($EditionID -like "*EnterpriseS*")
    $Build = [int](Get-PropertyValue $CurrentVersion "CurrentBuildNumber" 0)
    $UBR = [int](Get-PropertyValue $CurrentVersion "UBR" 0)
    $FullBuild = "{0}.{1}" -f $Build, $UBR
    # Windows Enterprise multi-session (AVD, EditionID ServerRdsh) est une
    # édition client qui annonce pourtant ProductType 3, comme un serveur.
    $IsClientOS = ($OS.ProductType -eq 1) -or ($EditionID -eq "ServerRdsh")
    $IsWindows11 = $IsClientOS -and ($Build -ge 22000)

    # Le registre peut encore exposer "Windows 10" sur certaines installations
    # Windows 11. Le numéro de build reste la référence la plus fiable ici
    # (Windows Server 2025 partage toutefois le build 26100 : d'où ProductType).
    if ($IsWindows11) {
        $FriendlyProductName = "Windows 11"
    }
    else {
        $FriendlyProductName = $ProductName
    }

    Write-Check "Script" "INFO" ("Version {0}" -f $ScriptVersion)
    Write-Check "Windows actuel" "INFO" ("{0} {1} - Build {2} - {3}" -f $FriendlyProductName, $DisplayVersion, $FullBuild, $EditionID)

    # Détection VM / hyperviseur. Le contrôle GPU DirectX est moins pertinent
    # comme blocage absolu dans une VM car le guest voit un adaptateur virtuel.
    $ComputerSystem = Get-CimInstance Win32_ComputerSystem
    $VirtualizationText = ("{0} {1}" -f $ComputerSystem.Manufacturer, $ComputerSystem.Model).Trim()
    $IsVirtualMachine = $false

    if (
        $VirtualizationText -match '(?i)VMware' -or
        $VirtualizationText -match '(?i)Virtual Machine' -or
        $VirtualizationText -match '(?i)VirtualBox' -or
        $VirtualizationText -match '(?i)KVM' -or
        $VirtualizationText -match '(?i)QEMU' -or
        $VirtualizationText -match '(?i)HVM domU' -or
        $VirtualizationText -match '(?i)Parallels'
    ) {
        $IsVirtualMachine = $true
        Write-Check "Environnement" "INFO" ("Machine virtuelle détectée : {0}" -f $VirtualizationText)
    }
    else {
        Write-Check "Environnement" "INFO" ("Machine physique / non identifiée comme VM : {0}" -f $VirtualizationText)
    }

    $OSBlockers = New-Object System.Collections.Generic.List[string]

    if (-not $IsClientOS) {
        $OSBlockers.Add("Windows Server détecté : ce contrôle concerne Windows Client.")
    }

    if (-not $IsWindows11) {
        if ($Build -lt 19041) {
            $OSBlockers.Add("Windows 10 version 2004 ou supérieure requise.")
        }
        elseif (($Build -ge 19041) -and ($Build -le 19045) -and ($UBR -lt 1237)) {
            $OSBlockers.Add("La mise à jour de sécurité du 14 septembre 2021 ou une version ultérieure est requise.")
        }
    }

    if ($OSBlockers.Count -eq 0) {
        Write-Check "OS source" "OK" "Version source compatible avec un upgrade Windows 11."
    }
    else {
        foreach ($Blocker in $OSBlockers) {
            Write-Check "OS source" "FAIL" $Blocker
        }
    }

    # Comparaison sur le build et non sur DisplayVersion : une version plus
    # récente que la cible (26H2, 26H1...) doit aussi être considérée comme à jour.
    $AlreadyTarget = $IsWindows11 -and ($Build -ge $TargetBuild)

    # Les éditions LTSC ne reçoivent pas de mise à jour de fonctionnalités.
    $EditionBlock = $IsLTSC -and $IsClientOS -and (-not $AlreadyTarget)

    if ($AlreadyTarget) {
        if ($DisplayVersion -eq $TargetVersion) {
            Write-Check "Version cible" "OK" ("Windows 11 {0} est déjà installé." -f $TargetVersion)
        }
        else {
            Write-Check "Version cible" "OK" ("Windows 11 {0} (build {1}) installé : plus récent que la cible {2}." -f $DisplayVersion, $Build, $TargetVersion)
        }
    }
    else {
        Write-Check "Version cible" "INFO" ("Cible de mise à niveau : Windows 11 {0}" -f $TargetVersion)
    }

    if ($EditionBlock) {
        Write-Check "Edition LTSC" "WARN" ("{0} : pas de mise à jour de fonctionnalités vers {1} via Windows Update." -f $EditionID, $TargetVersion)
    }

    # ------------------------------------------------------------------------
    # Espace disque
    # ------------------------------------------------------------------------

    $SystemDisk = Get-CimInstance Win32_LogicalDisk | Where-Object {
        $_.DeviceID -eq $env:SystemDrive
    } | Select-Object -First 1

    if ($null -ne $SystemDisk) {
        $FreeGB = [Math]::Round($SystemDisk.FreeSpace / 1GB, 1)

        if ($FreeGB -ge $RecommendedFreeSpaceGB) {
            Write-Check "Espace disque libre" "OK" ("{0} Go disponibles" -f $FreeGB)
        }
        else {
            Write-Check "Espace disque libre" "WARN" ("{0} Go disponibles ; {1} Go recommandés avant upgrade." -f $FreeGB, $RecommendedFreeSpaceGB)
        }
    }

    # ------------------------------------------------------------------------
    # 2. Microsoft Hardware Readiness
    # ------------------------------------------------------------------------

    Write-Title "2. MICROSOFT WINDOWS 11 HARDWARE READINESS"

    if ([string]::IsNullOrWhiteSpace($HardwareScriptPath)) {
        $Url = "https://aka.ms/HWReadinessScript"
        Invoke-RobustDownload -Uri $Url -Destination $HardwareScript

        Write-Check "HardwareReadiness.ps1" "OK" "Script Microsoft téléchargé."
    }
    else {
        if (-not (Test-Path -LiteralPath $HardwareScriptPath -PathType Leaf)) {
            throw ("Copie locale de HardwareReadiness.ps1 introuvable : {0}" -f $HardwareScriptPath)
        }

        # Copie dans le dossier temporaire : le fichier contrôlé est celui exécuté.
        Copy-Item -LiteralPath $HardwareScriptPath -Destination $HardwareScript -Force
        Write-Check "HardwareReadiness.ps1" "OK" ("Copie locale utilisée : {0}" -f $HardwareScriptPath)
    }

    # Le script est exécuté en administrateur : il doit être signé par Microsoft.
    $Signature = Get-AuthenticodeSignature -FilePath $HardwareScript
    $SignerSubject = ""

    if ($null -ne $Signature.SignerCertificate) {
        $SignerSubject = [string]$Signature.SignerCertificate.Subject
    }

    $HardwareScriptHash = (Get-FileHash -LiteralPath $HardwareScript -Algorithm SHA256).Hash
    $SignatureValid = ($Signature.Status -eq [System.Management.Automation.SignatureStatus]::Valid) -and
        ($SignerSubject -like "CN=Microsoft Corporation, O=Microsoft Corporation,*")

    if ($SignatureValid) {
        Write-Check "Signature script" "OK" "Signature Microsoft Corporation valide."
    }
    elseif ($KnownHardwareScriptHashes -contains $HardwareScriptHash) {
        Write-Check "Signature script" "WARN" ("Etat Authenticode : {0} ; empreinte identique à la version Microsoft connue." -f $Signature.Status)
    }
    else {
        Write-Check "Signature script" "FAIL" ("Etat Authenticode : {0} ; signataire : {1}" -f $Signature.Status, $SignerSubject)

        if (-not [string]::IsNullOrWhiteSpace($Signature.StatusMessage)) {
            Write-Check "Détail signature" "FAIL" $Signature.StatusMessage
        }

        throw "HardwareReadiness.ps1 n'a pas de signature Microsoft valide : exécution refusée."
    }

    Write-Check "SHA-256 script" "INFO" $HardwareScriptHash

    $WindowsPowerShell = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"

    # Hôte 32 bits non relancé : passer quand même par le PowerShell 64 bits.
    if ($Is32BitHostOn64BitOS) {
        $SysNativeHardwarePowerShell = Join-Path $env:SystemRoot "SysNative\WindowsPowerShell\v1.0\powershell.exe"

        if (Test-Path $SysNativeHardwarePowerShell) {
            $WindowsPowerShell = $SysNativeHardwarePowerShell
        }
    }

    if (-not (Test-Path $WindowsPowerShell)) {
        throw "Windows PowerShell 5.1 introuvable."
    }

    # Sous Windows PowerShell 5.1, avec ErrorActionPreference = Stop, la
    # première ligne écrite sur stderr par le processus enfant deviendrait une
    # erreur bloquante : elle doit au contraire être lue comme le reste.
    $PreviousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"

    try {
        $ChildOutput = @(
            & $WindowsPowerShell -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $HardwareScript 2>&1
        )
    }
    finally {
        $ErrorActionPreference = $PreviousErrorActionPreference
    }

    # stdout porte le JSON ; stderr ne contient que des erreurs non bloquantes
    # du script Microsoft (typiquement des échecs WMI).
    $RawOutput = @($ChildOutput | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] } | ForEach-Object { [string]$_ })
    $ChildErrors = @($ChildOutput | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] } | ForEach-Object { ([string]$_).Trim() } | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_)
    })

    $HardwareResult = $null

    for ($Index = $RawOutput.Count - 1; $Index -ge 0; $Index--) {
        $Line = $RawOutput[$Index].Trim()

        if ($Line.StartsWith("{") -and $Line.EndsWith("}")) {
            try {
                $HardwareResult = $Line | ConvertFrom-Json -ErrorAction Stop
                break
            }
            catch {
                Write-Verbose ("Ligne non JSON ignorée : {0}" -f $Line)
            }
        }
    }

    if ($null -eq $HardwareResult) {
        Write-Host ""
        Write-Host "Sortie brute HardwareReadiness :" -ForegroundColor Yellow
        $ChildOutput | ForEach-Object { Write-Host ([string]$_) }
        throw "Impossible d'analyser le résultat JSON HardwareReadiness."
    }

    $HardwareLogging = [string](Get-PropertyValue $HardwareResult "logging" "")

    $FailEntries = New-Object System.Collections.Generic.List[string]

    # Les ";" entre accolades (détail du processeur) ne séparent pas les entrées.
    # Chaque entrée se termine par PASS / FAIL / UNDETERMINED ; les autres
    # fragments sont le détail d'une exception (texte localisé).
    foreach ($RawEntry in ($HardwareLogging -split ';\s*(?![^{]*\})')) {
        $Entry = $RawEntry.Trim()

        if ([string]::IsNullOrWhiteSpace($Entry)) {
            continue
        }

        if ($Entry -cmatch '\bFAIL$') {
            $FailEntries.Add($Entry)
            Write-Check "Microsoft HW" "FAIL" $Entry
        }
        elseif ($Entry -cmatch '\bUNDETERMINED$') {
            Write-Check "Microsoft HW" "WARN" $Entry
        }
        elseif ($Entry -cmatch '\bPASS$') {
            Write-Check "Microsoft HW" "OK" $Entry
        }
        else {
            Write-Check "Microsoft HW" "INFO" $Entry
        }
    }

    if ($ChildErrors.Count -gt 0) {
        $MaxErrorLines = 10

        foreach ($ErrorLine in ($ChildErrors | Select-Object -First $MaxErrorLines)) {
            Write-Check "Erreur HW script" "WARN" $ErrorLine
        }

        if ($ChildErrors.Count -gt $MaxErrorLines) {
            Write-Check "Erreur HW script" "WARN" ("... {0} ligne(s) supplémentaire(s)." -f ($ChildErrors.Count - $MaxErrorLines))
        }
    }

    $HWReturnCode = [int](Get-PropertyValue $HardwareResult "returnCode" -2)
    $HWReturnResult = [string](Get-PropertyValue $HardwareResult "returnResult" "UNKNOWN")
    $HWReason = [string](Get-PropertyValue $HardwareResult "returnReason" "")

    $HardwareNotCapable = $false
    $HardwareUndetermined = $false

    $CleanReason = $HWReason.Trim().TrimEnd(",")

    # Un FAIL dû uniquement à une requête WMI en échec ("... is null") ne
    # prouve pas une incompatibilité matérielle : résultat indéterminé.
    $WmiOnlyFailure = ($HWReturnCode -eq 1) -and ($ChildErrors.Count -gt 0) -and ($FailEntries.Count -gt 0) -and
        (@($FailEntries | Where-Object { $_ -notmatch '(is null|=null)\.\s*FAIL$' }).Count -eq 0)

    switch ($HWReturnCode) {
        0 {
            Write-Check "Résultat matériel" "OK" "CAPABLE"

            # Le script Microsoft force CAPABLE pour certains modèles (i7-7820HQ).
            if (-not [string]::IsNullOrWhiteSpace($CleanReason)) {
                Write-Check "Exception Microsoft" "WARN" ("CAPABLE malgré : {0}" -f $CleanReason)
            }
        }

        1 {
            if ($WmiOnlyFailure) {
                $HardwareUndetermined = $true
                Write-Check "Résultat matériel" "WARN" "NOT CAPABLE dû à une erreur WMI : contrôle indéterminé."
            }
            else {
                $HardwareNotCapable = $true
                Write-Check "Résultat matériel" "FAIL" "NOT CAPABLE"
            }

            if (-not [string]::IsNullOrWhiteSpace($CleanReason)) {
                if ($WmiOnlyFailure) {
                    Write-Check "Blocage matériel" "WARN" $CleanReason
                }
                else {
                    Write-Check "Blocage matériel" "FAIL" $CleanReason
                }
            }
        }

        default {
            $HardwareUndetermined = $true
            Write-Check "Résultat matériel" "WARN" ("{0} - contrôle indéterminé." -f $HWReturnResult)
        }
    }

    # ------------------------------------------------------------------------
    # 3. DirectX / WDDM
    # ------------------------------------------------------------------------

    Write-Title "3. DIRECTX / WDDM"

    $Graphics = Get-GraphicsReadiness -OutputFile $DxDiagFile
    $GraphicsBlocking = $false
    $VirtualGraphicsWarning = $false

    if ($Graphics.Capable -eq $false) {
        if ($IsVirtualMachine) {
            $VirtualGraphicsWarning = $true
            Write-Check "Carte graphique" "WARN" ("{0} VM détectée : le GPU virtuel est traité comme avertissement non bloquant." -f $Graphics.Detail)
        }
        else {
            $GraphicsBlocking = $true
            Write-Check "Carte graphique" "FAIL" $Graphics.Detail
        }
    }
    elseif ($Graphics.Capable -eq $true) {
        Write-Check "Carte graphique" "OK" $Graphics.Detail
    }
    else {
        Write-Check "Carte graphique" "WARN" $Graphics.Detail
    }

    foreach ($GPU in $Graphics.Devices) {
        Write-Check "GPU" "INFO" ("{0} | DDI={1} | WDDM={2}" -f $GPU.CardName, $GPU.DDIVersion, $GPU.WDDMVersion)
    }

    if ($VirtualGraphicsWarning) {
        Write-Check "GPU virtuel" "WARN" "DirectX 12 non détecté dans le guest, mais ce point ne bloque pas à lui seul le résultat sur une VM."
    }

    # ------------------------------------------------------------------------
    # 4. Etat Windows
    # ------------------------------------------------------------------------

    Write-Title "4. ETAT WINDOWS"

    $PendingReboot = Test-PendingReboot

    if ($PendingReboot.Pending) {
        Write-Check "Redémarrage en attente" "WARN" ($PendingReboot.Reasons -join ", ")
    }
    else {
        Write-Check "Redémarrage en attente" "OK" "Aucun redémarrage en attente détecté."
    }

    try {
        $WindowsUpdateService = Get-CimInstance Win32_Service -Filter "Name='wuauserv'"

        if ($WindowsUpdateService.StartMode -eq "Disabled") {
            Write-Check "Windows Update" "WARN" "Service wuauserv désactivé."
        }
        else {
            Write-Check "Windows Update" "OK" ("Service disponible - StartMode={0}" -f $WindowsUpdateService.StartMode)
        }
    }
    catch {
        Write-Check "Windows Update" "WARN" "Impossible de contrôler le service."
    }

    # ------------------------------------------------------------------------
    # GPO Windows Update / Target Release
    # ------------------------------------------------------------------------

    $PolicyBlock = $false
    $WUPolicy = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ErrorAction SilentlyContinue
    $MdmUpdatePolicy = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update" -ErrorAction SilentlyContinue

    # Verrouillage de version : GPO (TargetReleaseVersion = 1) ou Intune / MDM
    # (TargetReleaseVersion non vide, sans indicateur d'activation séparé).
    $ReleasePins = @()

    if ((ConvertTo-NullableInt (Get-PropertyValue $WUPolicy "TargetReleaseVersion")) -eq 1) {
        $ReleasePins += [PSCustomObject]@{
            Source  = "GPO"
            Release = ([string](Get-PropertyValue $WUPolicy "TargetReleaseVersionInfo" "")).Trim()
            Product = ([string](Get-PropertyValue $WUPolicy "ProductVersion" "")).Trim()
        }
    }

    $MdmRelease = ([string](Get-PropertyValue $MdmUpdatePolicy "TargetReleaseVersion" "")).Trim()

    if (-not [string]::IsNullOrWhiteSpace($MdmRelease)) {
        $ReleasePins += [PSCustomObject]@{
            Source  = "MDM"
            Release = $MdmRelease
            Product = ([string](Get-PropertyValue $MdmUpdatePolicy "ProductVersion" "")).Trim()
        }
    }

    foreach ($Pin in $ReleasePins) {
        $PinName = "TargetRelease {0}" -f $Pin.Source

        if (-not [string]::IsNullOrWhiteSpace($Pin.Release)) {
            $PolicyRelease = ConvertTo-ReleaseNumber $Pin.Release
            $ExpectedRelease = ConvertTo-ReleaseNumber $TargetVersion

            if ($Pin.Release -eq $TargetVersion) {
                Write-Check $PinName "OK" ("Stratégie autorise {0}." -f $TargetVersion)
            }
            elseif (($null -ne $PolicyRelease) -and ($null -ne $ExpectedRelease) -and ($PolicyRelease -gt $ExpectedRelease)) {
                Write-Check $PinName "INFO" ("Stratégie cible {0}, plus récent que {1}." -f $Pin.Release, $TargetVersion)
            }
            else {
                $PolicyBlock = $true
                Write-Check $PinName "WARN" ("Stratégie verrouillée sur {0} ; cible attendue {1}." -f $Pin.Release, $TargetVersion)
            }
        }

        # Sans ProductVersion = Windows 11, Windows Update reste sur le produit
        # installé : une machine Windows 10 n'est jamais mise à niveau.
        if ((-not $IsWindows11) -and ($Pin.Product -notmatch '^(Windows\s*)?11$')) {
            $PolicyBlock = $true

            if ([string]::IsNullOrWhiteSpace($Pin.Product)) {
                Write-Check ("ProductVersion {0}" -f $Pin.Source) "WARN" "Non définie : la stratégie maintient la machine sur Windows 10."
            }
            else {
                Write-Check ("ProductVersion {0}" -f $Pin.Source) "WARN" ("{0} : la stratégie maintient la machine sur Windows 10." -f $Pin.Product)
            }
        }
    }

    $FeatureDeferral = Get-PropertyValue $WUPolicy "DeferFeatureUpdatesPeriodInDays"

    if ($null -ne $FeatureDeferral) {
        Write-Check "Feature Update Deferral" "INFO" ("{0} jour(s)" -f $FeatureDeferral)
    }

    # Contournement des safeguard holds par stratégie (GPO ou MDM / Intune).
    $SafeguardsBypassed = ([string](Get-PropertyValue $WUPolicy "DisableWUfBSafeguards" "")).Trim() -eq "1"

    if (([string](Get-PropertyValue $MdmUpdatePolicy "DisableWUfBSafeguards" "")).Trim() -eq "1") {
        $SafeguardsBypassed = $true
    }

    # ------------------------------------------------------------------------
    # WSUS
    # ------------------------------------------------------------------------

    $AUPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    $AUPolicy = Get-ItemProperty $AUPath -ErrorAction SilentlyContinue
    $UseWUServer = ConvertTo-NullableInt (Get-PropertyValue $AUPolicy "UseWUServer")

    if ($UseWUServer -eq 1) {
        $WUServer = [string](Get-PropertyValue $WUPolicy "WUServer" "WSUS configuré")
        Write-Check "WSUS" "INFO" ("Machine gérée par WSUS : {0}" -f $WUServer)
    }
    else {
        Write-Check "WSUS" "INFO" "Windows Update Microsoft / WUfB."
    }

    # ------------------------------------------------------------------------
    # 5. Safeguard Hold
    # ------------------------------------------------------------------------

    Write-Title "5. MICROSOFT SAFEGUARD HOLD"

    $Safeguard = Get-SafeguardStatus -IndicatorKeyName $TargetIndicatorKey
    $SafeguardHold = $false
    $SafeguardBlocking = $false

    if (-not $Safeguard.Known) {
        Write-Check "Safeguard Hold" "INFO" ("Aucune évaluation Appraiser pour {0} (clé {1} absente)." -f $TargetVersion, $TargetIndicatorKey)

        if ($Safeguard.GWXStatus -eq 0) {
            Write-Check "Safeguard (GWX)" "WARN" "Indice de safeguard hold non spécifique à la version cible (Appraiser\GWX GStatus=0)."
        }
    }
    else {
        if ($Safeguard.BlockIDs.Count -gt 0) {
            $SafeguardHold = $true
            Write-Check "Safeguard Hold" "WARN" "Microsoft bloque actuellement l'upgrade sur cette machine."
            Write-Check "Safeguard ID" "WARN" ($Safeguard.BlockIDs -join ", ")

            if ($Safeguard.Reasons.Count -gt 0) {
                Write-Check "Safeguard Reason" "WARN" ($Safeguard.Reasons -join ", ")
            }
        }
        elseif ($Safeguard.GStatus -eq 0) {
            $SafeguardHold = $true
            Write-Check "Safeguard Hold" "WARN" "Safeguard hold signalé par l'Appraiser (GStatus=0), sans identifiant."
        }
        elseif ($Safeguard.GStatus -eq 1) {
            Write-Check "Safeguard Hold" "WARN" "Avertissement de compatibilité Appraiser (GStatus=1), non bloquant."
        }
        elseif ($Safeguard.GStatus -eq 2) {
            Write-Check "Safeguard Hold" "OK" "Aucun safeguard hold détecté."
        }
        else {
            Write-Check "Safeguard Hold" "INFO" ("Données Appraiser incomplètes pour {0} (GStatus absent)." -f $TargetVersion)
        }

        # Blocages matériels vus par l'Appraiser : à recouper avec HardwareReadiness.
        if ($Safeguard.RedReasons.Count -gt 0) {
            Write-Check "Appraiser" "INFO" ("Blocage matériel signalé ({0}) : {1}" -f $Safeguard.UpgEx, ($Safeguard.RedReasons -join ", "))
        }

        if ($Safeguard.FailedPrereqs.Count -gt 0) {
            Write-Check "Appraiser" "INFO" ("Evaluation incomplète : {0}" -f ($Safeguard.FailedPrereqs -join ", "))
        }

        if ($null -ne $Safeguard.EvaluatedOn) {
            $AppraiserAgeDays = [Math]::Floor(([DateTime]::UtcNow - $Safeguard.EvaluatedOn).TotalDays)

            if ($AppraiserAgeDays -gt 30) {
                Write-Check "Evaluation Appraiser" "WARN" ("{0:yyyy-MM-dd} ({1} jours) : données potentiellement obsolètes." -f $Safeguard.EvaluatedOn.ToLocalTime(), $AppraiserAgeDays)
            }
            else {
                Write-Check "Evaluation Appraiser" "INFO" ("{0:yyyy-MM-dd} ({1} jour(s))" -f $Safeguard.EvaluatedOn.ToLocalTime(), $AppraiserAgeDays)
            }
        }
    }

    if ($SafeguardHold) {
        if ($SafeguardsBypassed) {
            Write-Check "DisableWUfBSafeguards" "WARN" "Stratégie active : les safeguard holds sont ignorés sur cette machine."
        }
        else {
            $SafeguardBlocking = $true
        }
    }

    # ------------------------------------------------------------------------
    # Résultat final
    # ------------------------------------------------------------------------

    Write-Title "RESULTAT FINAL"

    # Le script Microsoft reste l'autorité principale pour CPU / RAM / TPM /
    # Secure Boot / stockage. Le GPU devient bloquant uniquement sur une
    # machine physique. Sur une VM, un GPU virtuel insuffisant est un WARN.
    # Un blocage avéré l'emporte sur un contrôle matériel indéterminé.
    $PermanentBlock = ($OSBlockers.Count -gt 0) -or $HardwareNotCapable -or $GraphicsBlocking

    if ($AlreadyTarget) {
        if ($PermanentBlock) {
            $FinalResult = "ALREADY_CURRENT_NOT_COMPLIANT"

            Write-Host ""
            Write-Host ("WINDOWS 11 {0} EST DEJA INSTALLE" -f $DisplayVersion) -ForegroundColor Green
            Write-Host "ATTENTION : la configuration matérielle actuelle ne respecte pas tous les prérequis contrôlés pour Windows 11." -ForegroundColor Yellow

            if ($HardwareNotCapable) {
                Write-Host "Le contrôle Microsoft HardwareReadiness retourne NOT CAPABLE." -ForegroundColor Red
            }

            if ($GraphicsBlocking) {
                Write-Host "Le contrôle DirectX / WDDM est bloquant sur cette machine physique." -ForegroundColor Red
            }

            if ($HardwareUndetermined) {
                Write-Host "Le contrôle matériel Microsoft n'a pas pu être déterminé complètement." -ForegroundColor Yellow
            }

            $ExitCode = 4
        }
        elseif ($HardwareUndetermined) {
            $FinalResult = "ALREADY_CURRENT_CHECK_INCOMPLETE"

            Write-Host ""
            Write-Host ("WINDOWS 11 {0} EST DEJA INSTALLE" -f $DisplayVersion) -ForegroundColor Green
            Write-Host "Le contrôle matériel Microsoft n'a pas pu être déterminé complètement." -ForegroundColor Yellow

            $ExitCode = 2
        }
        else {
            $FinalResult = "ALREADY_CURRENT"

            Write-Host ""
            Write-Host ("WINDOWS 11 {0} EST DEJA INSTALLE" -f $DisplayVersion) -ForegroundColor Green
            Write-Host "Les prérequis matériels principaux contrôlés sont conformes." -ForegroundColor Green

            if ($VirtualGraphicsWarning) {
                Write-Host "Avertissement : GPU virtuel sans DirectX 12 détecté ; non bloquant pour le résultat de cette VM." -ForegroundColor Yellow
            }

            if ($PendingReboot.Pending) {
                Write-Host "ATTENTION : un redémarrage Windows est actuellement en attente." -ForegroundColor Yellow
            }

            $ExitCode = 0
        }
    }
    elseif ($PermanentBlock) {
        $FinalResult = "NOT_CAPABLE"

        Write-Host ""
        Write-Host ("UPGRADE WINDOWS 11 {0} : NOT CAPABLE" -f $TargetVersion) -ForegroundColor Red
        Write-Host "Au moins un prérequis obligatoire n'est pas respecté." -ForegroundColor Red

        foreach ($Blocker in $OSBlockers) {
            Write-Host ("- {0}" -f $Blocker) -ForegroundColor Red
        }

        if ($HardwareNotCapable) {
            Write-Host "- Le contrôle Microsoft HardwareReadiness retourne NOT CAPABLE." -ForegroundColor Red
        }

        if ($GraphicsBlocking) {
            Write-Host "- Le contrôle DirectX / WDDM est bloquant sur cette machine physique." -ForegroundColor Red
        }

        if ($HardwareUndetermined) {
            Write-Host "Le contrôle matériel Microsoft n'a par ailleurs pas pu être déterminé complètement." -ForegroundColor Yellow
        }

        $ExitCode = 1
    }
    elseif ($HardwareUndetermined) {
        $FinalResult = "UNDETERMINED"

        Write-Host ""
        Write-Host ("UPGRADE WINDOWS 11 {0} : RESULTAT INDETERMINE" -f $TargetVersion) -ForegroundColor Yellow
        Write-Host "Le contrôle matériel Microsoft n'a pas pu être validé." -ForegroundColor Yellow

        $ExitCode = 2
    }
    elseif ($SafeguardBlocking -or $PolicyBlock -or $EditionBlock) {
        $FinalResult = "CAPABLE_BUT_BLOCKED"

        Write-Host ""
        Write-Host ("UPGRADE WINDOWS 11 {0} : CAPABLE MAIS BLOQUE" -f $TargetVersion) -ForegroundColor Yellow
        Write-Host "Le matériel est compatible, mais le déploiement est actuellement bloqué :" -ForegroundColor Yellow

        if ($SafeguardBlocking) {
            Write-Host "- Safeguard Hold Microsoft." -ForegroundColor Yellow
        }

        if ($PolicyBlock) {
            Write-Host "- Stratégie Windows Update GPO / Intune (TargetReleaseVersion / ProductVersion)." -ForegroundColor Yellow
        }

        if ($EditionBlock) {
            Write-Host ("- Edition LTSC ({0}) : pas de mise à jour de fonctionnalités." -f $EditionID) -ForegroundColor Yellow
        }

        $ExitCode = 3
    }
    else {
        $FinalResult = "READY"

        Write-Host ""
        Write-Host ("WINDOWS 11 {0} UPGRADE IS OK ON THIS COMPUTER" -f $TargetVersion) -ForegroundColor Green
        Write-Host ""
        Write-Host ("La machine satisfait les prérequis détectables pour Windows 11 {0}." -f $TargetVersion) -ForegroundColor Green

        if ($VirtualGraphicsWarning) {
            Write-Host "Avertissement : GPU virtuel sans DirectX 12 détecté ; non bloquant pour le résultat de cette VM." -ForegroundColor Yellow
        }

        if ($PendingReboot.Pending) {
            Write-Host "ATTENTION : redémarrer Windows avant de lancer l'upgrade." -ForegroundColor Yellow
        }

        $ExitCode = 0
    }
}
catch {
    $FinalResult = "ERROR"
    $ExitCode = 2

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Red
    Write-Host " ERREUR WINDOWS 11 UPGRADE CHECK" -ForegroundColor Red
    Write-Host "============================================================" -ForegroundColor Red
    Write-Host ""
    Write-Check "Erreur" "ERROR" $_.Exception.Message
}
finally {
    Write-Host ""

    if ($KeepTemp) {
        Write-Check "Nettoyage" "INFO" ("Dossier conservé : {0}" -f $TempFolder)
    }
    else {
        if (Test-Path $TempFolder) {
            try {
                Remove-Item -Path $TempFolder -Recurse -Force -ErrorAction Stop
                Write-Check "Nettoyage" "OK" "Dossier temporaire supprimé."
            }
            catch {
                Write-Check "Nettoyage" "WARN" ("Impossible de supprimer {0} : {1}" -f $TempFolder, $_.Exception.Message)
            }
        }
    }
}

Exit-Script -Result $FinalResult -Code $ExitCode
