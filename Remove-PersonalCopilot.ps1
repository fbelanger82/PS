#requires -Version 5.1


[CmdletBinding()]
param()

# ============================================================
# CONFIGURATION
# ============================================================

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$ConfirmPreference = "None"

$CopilotPackage = "Microsoft.Copilot"

$LogDirectory = "C:\ProgramData\VilleDeMagog\Logs"
$LogFile = Join-Path $LogDirectory "Remove-PersonalCopilot.log"

$TempDirectory = "C:\ProgramData\VilleDeMagog\Temp"
$PolicyFile = Join-Path $TempDirectory "Block-PersonalCopilot.xml"

# Codes de retour
$EXIT_SUCCESS = 0
$EXIT_NOT_ADMIN = 10
$EXIT_APPLOCKER_FAILED = 20
$EXIT_REMOVAL_FAILED = 30
$EXIT_VERIFICATION_FAILED = 40
$EXIT_UNEXPECTED = 99

# ============================================================
# JOURNALISATION
# ============================================================

function Initialize-Environment {

    foreach ($Directory in @($LogDirectory, $TempDirectory)) {

        if (-not (Test-Path -LiteralPath $Directory)) {

            New-Item `
                -Path $Directory `
                -ItemType Directory `
                -Force `
                -ErrorAction Stop |
                Out-Null
        }
    }
}

function Write-Log {

    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [ValidateSet("INFO", "SUCCESS", "WARNING", "ERROR")]
        [string]$Level = "INFO"
    )

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    $Entry = "{0} [{1}] [{2}] {3}" -f `
        $Timestamp,
        $env:COMPUTERNAME,
        $Level,
        $Message

    Add-Content `
        -LiteralPath $LogFile `
        -Value $Entry `
        -Encoding UTF8 `
        -ErrorAction SilentlyContinue
}

# ============================================================
# VERIFICATION ADMIN / SYSTEM
# ============================================================

function Test-IsAdministrator {

    try {

        $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()

        $Principal = New-Object `
            Security.Principal.WindowsPrincipal($Identity)

        return $Principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator
        )
    }
    catch {
        return $false
    }
}

# ============================================================
# APPLICATION IDENTITY
# ============================================================

function Enable-ApplicationIdentity {

    Write-Log `
        -Message "Configuration du service Application Identity."

    try {

        $ServiceOutput = & "$env:SystemRoot\System32\sc.exe" `
            config AppIDSvc start= auto 2>&1

        $ServiceExitCode = $LASTEXITCODE
        $ServiceOutputText = $ServiceOutput -join " "

        Write-Log `
            -Message "SC.EXE : $ServiceOutputText"

        if ($ServiceExitCode -ne 0) {

            throw "SC.EXE a retourne le code $ServiceExitCode."
        }

        $Service = Get-Service `
            -Name "AppIDSvc" `
            -ErrorAction Stop

        if ($Service.Status -ne "Running") {

            Write-Log `
                -Message "Demarrage du service Application Identity."

            Start-Service `
                -Name "AppIDSvc" `
                -ErrorAction Stop
        }

        Start-Sleep -Seconds 1

        $Service = Get-Service `
            -Name "AppIDSvc" `
            -ErrorAction Stop

        if ($Service.Status -ne "Running") {

            throw "AppIDSvc n'est pas en cours d'execution."
        }

        Write-Log `
            -Message "Application Identity est actif." `
            -Level "SUCCESS"

        return $true
    }
    catch {

        Write-Log `
            -Message "Erreur Application Identity : $($_.Exception.Message)" `
            -Level "ERROR"

        return $false
    }
}

# ============================================================
# CREATION DE LA POLITIQUE APPLOCKER
# ============================================================

function Install-CopilotAppLockerPolicy {

    Write-Log `
        -Message "Creation de la politique AppLocker Copilot."

    $PolicyXml = @'
<AppLockerPolicy Version="1">
  <RuleCollection Type="Appx" EnforcementMode="Enabled">

    <FilePublisherRule
      Id="B872227C-A7CC-4EB8-AC32-9AFF823615CB"
      Name="Ville de Magog - Allow signed packaged apps"
      Description="Autorise les autres applications empaquetees signees."
      UserOrGroupSid="S-1-1-0"
      Action="Allow">

      <Conditions>

        <FilePublisherCondition
          PublisherName="*"
          ProductName="*"
          BinaryName="*">

          <BinaryVersionRange
            LowSection="0.0.0.0"
            HighSection="*" />

        </FilePublisherCondition>

      </Conditions>

    </FilePublisherRule>

    <FilePublisherRule
      Id="319F84DB-8A7B-42B0-A596-C7293984621F"
      Name="Ville de Magog - Block Microsoft Copilot Personal"
      Description="Bloque Microsoft Copilot personnel."
      UserOrGroupSid="S-1-1-0"
      Action="Deny">

      <Conditions>

        <FilePublisherCondition
          PublisherName="CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
          ProductName="Microsoft.Copilot"
          BinaryName="*">

          <BinaryVersionRange
            LowSection="0.0.0.0"
            HighSection="*" />

        </FilePublisherCondition>

      </Conditions>

    </FilePublisherRule>

  </RuleCollection>
</AppLockerPolicy>
'@

    try {

        $PolicyXml |
            Set-Content `
                -LiteralPath $PolicyFile `
                -Encoding UTF8 `
                -Force `
                -ErrorAction Stop

        Write-Log `
            -Message "Fichier XML AppLocker cree."

        Set-AppLockerPolicy `
            -XmlPolicy $PolicyFile `
            -Merge `
            -ErrorAction Stop

        Write-Log `
            -Message "Politique AppLocker appliquee." `
            -Level "SUCCESS"

        return $true
    }
    catch {

        Write-Log `
            -Message "Erreur lors de l'application AppLocker : $($_.Exception.Message)" `
            -Level "ERROR"

        return $false
    }
}

# ============================================================
# VERIFICATION DE LA REGLE APPLOCKER
# =================function Test-CopilotAppLockerRule {

    try {

        $PolicyXml = Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop

        if ([string]::IsNullOrWhiteSpace($PolicyXml)) {

            Write-Log `
                -Message "La politique AppLocker effective est vide." `
                -Level "ERROR"

            return $false
        }

        # Verification de la collection Appx
        if ($PolicyXml -notmatch 'RuleCollection Type="Appx" EnforcementMode="Enabled"') {

            Write-Log `
                -Message "La collection Appx AppLocker n'est pas active." `
                -Level "ERROR"

            return $false
        }

        # Verification du nom de la regle
        if ($PolicyXml -notmatch 'Ville de Magog - Block Microsoft Copilot Personal') {

            Write-Log `
                -Message "La regle AppLocker Copilot est absente." `
                -Level "ERROR"

            return $false
        }

        # Verification du package cible
        if ($PolicyXml -notmatch 'ProductName="Microsoft\.Copilot"') {

            Write-Log `
                -Message "La regle AppLocker ne cible pas Microsoft.Copilot." `
                -Level "ERROR"

            return $false
        }

        # Verification du mode Deny
        if ($PolicyXml -notmatch 'Action="Deny"') {

            Write-Log `
                -Message "Aucune regle AppLocker Deny detectee." `
                -Level "ERROR"

            return $false
        }

        Write-Log `
            -Message "Regle AppLocker Microsoft.Copilot validee dans la politique effective." `
            -Level "SUCCESS"

        return $true
    }
    catch {

        Write-Log `
            -Message "Impossible de verifier AppLocker : $($_.Exception.Message)" `
            -Level "ERROR"

        return $false
    }
===========================================

function Test-CopilotAppLockerRule {

    try {

        $PolicyXml = Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop

        if ([string]::IsNullOrWhiteSpace($PolicyXml)) {

            Write-Log `
                -Message "La politique AppLocker effective est vide." `
                -Level "ERROR"

            return $false
        }

        # Verification de la collection Appx
        if ($PolicyXml -notmatch 'RuleCollection Type="Appx" EnforcementMode="Enabled"') {

            Write-Log `
                -Message "La collection Appx AppLocker n'est pas active." `
                -Level "ERROR"

            return $false
        }

        # Verification du nom de la regle
        if ($PolicyXml -notmatch 'Ville de Magog - Block Microsoft Copilot Personal') {

            Write-Log `
                -Message "La regle AppLocker Copilot est absente." `
                -Level "ERROR"

            return $false
        }

        # Verification du package cible
        if ($PolicyXml -notmatch 'ProductName="Microsoft\.Copilot"') {

            Write-Log `
                -Message "La regle AppLocker ne cible pas Microsoft.Copilot." `
                -Level "ERROR"

            return $false
        }

        # Verification du mode Deny
        if ($PolicyXml -notmatch 'Action="Deny"') {

            Write-Log `
                -Message "Aucune regle AppLocker Deny detectee." `
                -Level "ERROR"

            return $false
        }

        Write-Log `
            -Message "Regle AppLocker Microsoft.Copilot validee dans la politique effective." `
            -Level "SUCCESS"

        return $true

        }
    catch {

        Write-Log `
            -Message "Impossible de verifier AppLocker : $($_.Exception.Message)" `
            -Level "ERROR"

        return $false
    }
}
    

# ============================================================
# SUPPRESSION DU PACKAGE APPX
# ============================================================

function Remove-CopilotInstalledPackage {

    $Success = $true

    Write-Log `
        -Message "Recherche des packages Microsoft.Copilot installes."

    $Packages = @(
        Get-AppxPackage `
            -AllUsers `
            -Name $CopilotPackage `
            -ErrorAction SilentlyContinue
    )

    if ($Packages.Count -eq 0) {

        Write-Log `
            -Message "Microsoft.Copilot n'est pas actuellement installe."

        return $true
    }

    foreach ($Package in $Packages) {

        try {

            Write-Log `
                -Message "Suppression de $($Package.PackageFullName)."

            Remove-AppxPackage `
                -Package $Package.PackageFullName `
                -AllUsers `
                -Confirm:$false `
                -ErrorAction Stop

            Write-Log `
                -Message "Package supprime : $($Package.PackageFullName)." `
                -Level "SUCCESS"
        }
        catch {

            Write-Log `
                -Message "Echec de suppression de $($Package.PackageFullName) : $($_.Exception.Message)" `
                -Level "ERROR"

            $Success = $false
        }
    }

    return $Success
}

# ============================================================
# SUPPRESSION DU PACKAGE PROVISIONNE
# ============================================================

function Remove-CopilotProvisionedPackage {

    $Success = $true

    Write-Log `
        -Message "Recherche du package Microsoft.Copilot provisionne."

    $ProvisionedPackages = @(
        Get-AppxProvisionedPackage `
            -Online `
            -ErrorAction SilentlyContinue |
        Where-Object {
            $_.DisplayName -eq $CopilotPackage -or
            $_.PackageName -like "Microsoft.Copilot*"
        }
    )

    if ($ProvisionedPackages.Count -eq 0) {

        Write-Log `
            -Message "Aucun package Microsoft.Copilot provisionne."

        return $true
    }

    foreach ($Package in $ProvisionedPackages) {

        try {

            Write-Log `
                -Message "Suppression du provisionnement $($Package.PackageName)."

            Remove-AppxProvisionedPackage `
                -Online `
                -PackageName $Package.PackageName `
                -AllUsers `
                -ErrorAction Stop |
                Out-Null

            Write-Log `
                -Message "Package provisionne supprime : $($Package.PackageName)." `
                -Level "SUCCESS"
        }
        catch {

            Write-Log `
                -Message "Echec de suppression du provisionnement $($Package.PackageName) : $($_.Exception.Message)" `
                -Level "ERROR"

            $Success = $false
        }
    }

    return $Success
}

# ============================================================
# VERIFICATION DE LA SUPPRESSION
# ============================================================

function Test-CopilotRemoved {

    try {

        $Installed = @(
            Get-AppxPackage `
                -AllUsers `
                -Name $CopilotPackage `
                -ErrorAction SilentlyContinue
        )

        $Provisioned = @(
            Get-AppxProvisionedPackage `
                -Online `
                -ErrorAction SilentlyContinue |
            Where-Object {
                $_.DisplayName -eq $CopilotPackage -or
                $_.PackageName -like "Microsoft.Copilot*"
            }
        )

        if ($Installed.Count -gt 0) {

            Write-Log `
                -Message "Microsoft.Copilot est encore installe." `
                -Level "ERROR"

            return $false
        }

        if ($Provisioned.Count -gt 0) {

            Write-Log `
                -Message "Microsoft.Copilot est encore provisionne." `
                -Level "ERROR"

            return $false
        }

        Write-Log `
            -Message "Microsoft.Copilot n'est plus installe ou provisionne." `
            -Level "SUCCESS"

        return $true
    }
    catch {

        Write-Log `
            -Message "Erreur pendant la verification de Copilot : $($_.Exception.Message)" `
            -Level "ERROR"

        return $false
    }
}

# ============================================================
# NETTOYAGE
# ============================================================

function Remove-TemporaryFiles {

    Remove-Item `
        -LiteralPath $PolicyFile `
        -Force `
        -ErrorAction SilentlyContinue
}

# ============================================================
# EXECUTION PRINCIPALE
# ============================================================

try {

    Initialize-Environment

    Write-Log `
        -Message "============================================================"

    Write-Log `
        -Message "Debut Remove-PersonalCopilot."

    $CurrentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent().Name

    Write-Log `
        -Message "Compte d'execution : $CurrentIdentity"

    Write-Log `
        -Message "Version PowerShell : $($PSVersionTable.PSVersion)"

    # --------------------------------------------------------
    # 1. Verification des privileges
    # --------------------------------------------------------

    if (-not (Test-IsAdministrator)) {

        Write-Log `
            -Message "Privileges administratifs ou SYSTEM requis." `
            -Level "ERROR"

        exit $EXIT_NOT_ADMIN
    }

    # --------------------------------------------------------
    # 2. Application Identity
    # --------------------------------------------------------

    if (-not (Enable-ApplicationIdentity)) {

        Write-Log `
            -Message "Impossible d'activer Application Identity." `
            -Level "ERROR"

        exit $EXIT_APPLOCKER_FAILED
    }

    # --------------------------------------------------------
    # 3. AppLocker
    # --------------------------------------------------------

    if (-not (Install-CopilotAppLockerPolicy)) {

        Write-Log `
            -Message "Impossible d'appliquer la politique AppLocker." `
            -Level "ERROR"

        exit $EXIT_APPLOCKER_FAILED
    }

    Start-Sleep -Seconds 2

    if (-not (Test-CopilotAppLockerRule)) {

        Write-Log `
            -Message "La verification de la regle AppLocker a echoue." `
            -Level "ERROR"

        exit $EXIT_APPLOCKER_FAILED
    }

    # --------------------------------------------------------
    # 4. Suppression de Copilot
    # --------------------------------------------------------

    $InstalledRemoval = Remove-CopilotInstalledPackage
    $ProvisionedRemoval = Remove-CopilotProvisionedPackage

    if (-not $InstalledRemoval) {

        Write-Log `
            -Message "Une erreur s'est produite pendant la suppression du package installe." `
            -Level "WARNING"
    }

    if (-not $ProvisionedRemoval) {

        Write-Log `
            -Message "Une erreur s'est produite pendant la suppression du package provisionne." `
            -Level "WARNING"
    }

    # --------------------------------------------------------
    # 5. Verification finale
    # --------------------------------------------------------

    if (-not (Test-CopilotRemoved)) {

        Write-Log `
            -Message "Copilot reste present. La regle AppLocker demeure toutefois active." `
            -Level "ERROR"

        Remove-TemporaryFiles

        exit $EXIT_VERIFICATION_FAILED
    }

    # --------------------------------------------------------
    # 6. Nettoyage
    # --------------------------------------------------------

    Remove-TemporaryFiles

    Write-Log `
        -Message "Microsoft.Copilot a ete supprime et bloque par AppLocker." `
        -Level "SUCCESS"

    Write-Log `
        -Message "Fin Remove-PersonalCopilot."

    exit $EXIT_SUCCESS
}
catch {
    try {
        Initialize-Environment

        $ErrorMessage = $_.Exception.Message
        $ErrorLine = $_.InvocationInfo.ScriptLineNumber
        $ErrorPosition = $_.InvocationInfo.PositionMessage

        Write-Log `
            -Message "Erreur inattendue : $ErrorMessage" `
            -Level "ERROR"

        Write-Log `
            -Message "Ligne du script : $ErrorLine" `
            -Level "ERROR"

        if (-not [string]::IsNullOrWhiteSpace($ErrorPosition)) {
            Write-Log `
                -Message "Position : $ErrorPosition" `
                -Level "ERROR"
        }
    }
    catch {
        # Aucun affichage
    }

    exit $EXIT_UNEXPECTED
}
