#requires -Version 7.0
<#
.SYNOPSIS
    Unified Microsoft 365 Tenant Setup Utility - PowerShell 7 Self-Contained
.DESCRIPTION
    Complete Microsoft 365 tenant setup automation in a single file that downloads 
    specialized modules as needed. Enhanced for PowerShell 7 with automatic module management.
.NOTES
    Version: 2.0
    Requirements: PowerShell 7.0 or later
    Author: 365 Engineer
    Last Modified: $(Get-Date)
    
    Features:
    - Single file deployment (no dependencies)
    - Automatic module management with version checking
    - Force authentication (no token caching)
    - GitHub module downloading as needed
    - Comprehensive logging and error handling
    - PowerShell 7 optimizations
#>

# ===================================================================
# CONFIGURATION SECTION
# ===================================================================

$script:config = @{
    # Logging configuration
    LogFile = "$env:TEMP\M365TenantSetup_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    
    # Required modules with automatic dependency handling
    RequiredModules = @(
        @{
            Name = 'Microsoft.Graph.Authentication'
            MinVersion = '2.0.0'
            Scope = 'CurrentUser'
        }
    )
   
    # Microsoft Graph scopes
    GraphScopes = @(
        "User.ReadWrite.All"
        "Group.ReadWrite.All"
        "Directory.ReadWrite.All"
        "Policy.ReadWrite.ConditionalAccess"
        "DeviceManagementConfiguration.ReadWrite.All"
        "DeviceManagementManagedDevices.ReadWrite.All"
        "DeviceManagementApps.ReadWrite.All"
        "RoleManagement.ReadWrite.Directory"
    )
    
    # Default resource configurations
    DefaultGroups = @{
        Security = @("BITS Admin", "SSPR Enabled", "NoMFA Exemption")
        License = @("BusinessBasic", "BusinessStandard", "BusinessPremium", "ExchangeOnline1", "ExchangeOnline2")
    }
    
    SharePoint = @{
        StorageQuota = 1024
        SiteTemplate = "STS#3"
    }
}

# GitHub Module Loading Configuration
$script:GitHubConfig = @{
    BaseUrl = "https://raw.githubusercontent.com/cbro09/Powershell7_365TenantGraph/main"
    CacheDirectory = "$env:TEMP\M365TenantSetup\Modules"
    ModuleFiles = @{
        "Groups" = "Groups-Module-PS7.ps1"
        "AdminAccounts" = "Admin-Accounts-Module-PS7.ps1"
        "ConditionalAccess" = "Conditional-Access-Module-PS7.ps1"
        "SharePoint" = "SharePoint-Module-PS7.ps1"
        "Intune" = "Intune-Module-PS7.ps1"
        "Users" = "User-Module-PS7.ps1"
        "Documentation" = "Documentation-Module-PS7.ps1"
        "AdminCreation" = "Admin-HD-Role-Creation-PS7.ps1"
    }
}

# Global Script Variables
$script:TenantState = $null
$script:LogInitialized = $false

# ===================================================================
# EMBEDDED CORE FUNCTIONS
# ===================================================================

# === Logging Functions ===
function Initialize-Logging {
    <#
    .SYNOPSIS
        Initializes logging system with PowerShell 7 enhancements
    #>
    [CmdletBinding()]
    param()
    
    try {
        $logDirectory = Split-Path -Path $script:config.LogFile -Parent
        if (-not (Test-Path -Path $logDirectory)) {
            New-Item -Path $logDirectory -ItemType Directory -Force | Out-Null
        }
        
        $logHeader = @"
=================================================================
Microsoft 365 Tenant Setup Utility Log
PowerShell Version: $($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))
Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
User: $($env:USERNAME)
Computer: $($env:COMPUTERNAME)
Script: Unified Self-Contained Version 2.0
=================================================================

"@
        
        $logHeader | Out-File -FilePath $script:config.LogFile -Encoding UTF8
        $script:LogInitialized = $true
        
        Write-Host "Logging initialized: $($script:config.LogFile)" -ForegroundColor Green
    }
    catch {
        Write-Warning "Failed to initialize logging: $($_.Exception.Message)"
        $script:LogInitialized = $false
    }
}

function Write-LogMessage {
    <#
    .SYNOPSIS
        Enhanced logging function with PowerShell 7 optimizations
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Warning", "Error", "Success")]
        [string]$Type = "Info",
        
        [Parameter(Mandatory = $false)]
        [switch]$LogOnly
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "$timestamp [$Type] $Message"
    
    # Write to log file if initialized
    if ($script:LogInitialized) {
        try {
            $logEntry | Out-File -FilePath $script:config.LogFile -Append -Encoding UTF8
        }
        catch {
            # Silently continue if logging fails to avoid disrupting main flow
        }
    }
    
    # Display to console unless LogOnly is specified
    if (-not $LogOnly) {
        switch ($Type) {
            "Info"    { Write-Host $Message -ForegroundColor Cyan }
            "Warning" { Write-Host $Message -ForegroundColor Yellow }
            "Error"   { Write-Host $Message -ForegroundColor Red }
            "Success" { Write-Host $Message -ForegroundColor Green }
        }
    }
}

# === Progress Display Functions ===
function Show-Progress {
    <#
    .SYNOPSIS
        Enhanced progress display with PowerShell 7 improvements
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [int]$Current,
        
        [Parameter(Mandatory = $true)]
        [int]$Total,
        
        [Parameter(Mandatory = $true)]
        [string]$Status,
        
        [Parameter(Mandatory = $false)]
        [string]$Activity = "Processing"
    )
    
    $percentComplete = [math]::Round(($Current / $Total) * 100, 1)
    
    Write-Progress -Activity $Activity -Status $Status -PercentComplete $percentComplete
    
    # Also show inline progress for better visibility
    Write-Host "[$Current/$Total] $Status" -ForegroundColor Gray
}

# === Utility Functions ===
function Test-NotEmpty {
    <#
    .SYNOPSIS
        Enhanced null/empty checking with PowerShell 7 features
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [AllowNull()]
        [AllowEmptyString()]
        $InputObject
    )
    
    return -not [string]::IsNullOrWhiteSpace($InputObject)
}

function New-ProgressBar {
    <#
    .SYNOPSIS
        Creates a simple text-based progress bar for visual feedback
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [int]$Current,
        
        [Parameter(Mandatory = $true)]
        [int]$Total,
        
        [Parameter(Mandatory = $false)]
        [int]$Width = 50
    )
    
    $percent = $Current / $Total
    $filledWidth = [math]::Floor($percent * $Width)
    $emptyWidth = $Width - $filledWidth
    
    $filled = "█" * $filledWidth
    $empty = "░" * $emptyWidth
    $percentText = "{0:P0}" -f $percent
    
    return "[$filled$empty] $percentText ($Current/$Total)"
}

# === PowerShell 7 Feature Detection ===
function Test-PowerShell7Features {
    <#
    .SYNOPSIS
        Tests for PowerShell 7 specific features and reports availability
    #>
    [CmdletBinding()]
    param()
    
    $features = @{
        'Null-Coalescing Operators (??, ??=)' = $PSVersionTable.PSVersion -ge [Version]"7.0"
        'Ternary Operator (? :)' = $PSVersionTable.PSVersion -ge [Version]"7.0"
        'Pipeline Chain Operators (&&, ||)' = $PSVersionTable.PSVersion -ge [Version]"7.0"
        'ForEach-Object -Parallel' = $PSVersionTable.PSVersion -ge [Version]"7.0"
        'Cross-Platform Support' = $PSVersionTable.PSEdition -eq 'Core'
    }
    
    Write-Host "=== PowerShell 7 Features Check ===" -ForegroundColor Cyan
    foreach ($feature in $features.GetEnumerator()) {
        $status = if ($feature.Value) { "✓ Available" } else { "✗ Not Available" }
        $color = if ($feature.Value) { "Green" } else { "Red" }
        Write-Host "$($feature.Key): " -ForegroundColor Gray -NoNewline
        Write-Host $status -ForegroundColor $color
    }
    Write-Host ""
    
    return $features
}

# ===================================================================
# MENU DISPLAY AND NAVIGATION
# ===================================================================

function Show-Banner {
    <#
    .SYNOPSIS
        Displays the application banner with PowerShell 7 styling
    #>
    Write-Host ""
    Write-Host "+--------------------------------------------------+" -ForegroundColor Blue
    Write-Host "|   Unified Microsoft 365 Tenant Setup (PS7)      |" -ForegroundColor Magenta
    Write-Host "|           Single File Self-Contained            |" -ForegroundColor Magenta
    Write-Host "+--------------------------------------------------+" -ForegroundColor Blue
    Write-Host ""
    Write-Host "PowerShell Version: " -ForegroundColor Cyan -NoNewline
    Write-Host "$($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))" -ForegroundColor White
    Write-Host ""
    Write-Host "IMPORTANT: Ensure you have Global Administrator" -ForegroundColor Red
    Write-Host "credentials for the target Microsoft 365 tenant" -ForegroundColor Red
    Write-Host "before proceeding with this script." -ForegroundColor Red
    Write-Host ""
}

function Show-Menu {
    <#
    .SYNOPSIS
        Displays the main menu with enhanced PowerShell 7 features and conditional options
    #>
    [CmdletBinding()]
    param (
        [string]$Title = 'Menu',
        [array]$Options
    )
    
    Clear-Host
    Show-Banner
    Write-Host "== $Title ==" -ForegroundColor Yellow
    
    # Show authentication status message if needed
    if ($Title -like "*Authentication Required*") {
        Write-Host ""
        Write-Host "⚠️  Please connect to Microsoft Graph to access all features" -ForegroundColor Yellow
        Write-Host "   Only basic options are available until authentication is complete" -ForegroundColor Gray
    }
    
    Write-Host ""
    
    for ($i = 0; $i -lt $Options.Count; $i++) {
        Write-Host " [$($i + 1)] " -ForegroundColor Yellow -NoNewline
        Write-Host $Options[$i] -ForegroundColor White
    }
    
    Write-Host ""
    $selection = Read-Host "Enter your choice (1-$($Options.Count))"
    
    # Validate input is a number within range using simple type conversion
    $selectionNumber = $selection -as [int]
    if ($selectionNumber -and $selectionNumber -ge 1 -and $selectionNumber -le $Options.Count) {
        return $selectionNumber
    }
    else {
        Write-Host "Invalid selection. Please try again." -ForegroundColor Red
        Start-Sleep -Seconds 2
        return $null
    }
}

# ===================================================================
# MODULE MANAGEMENT AND DEPENDENCY HANDLING
# ===================================================================

function Install-RequiredModulesWithDependencies {
    <#
    .SYNOPSIS
        Enhanced module installation with dependency resolution and version checking
    #>
    [CmdletBinding()]
    param()
    
    Write-LogMessage -Message "Checking and installing required PowerShell modules..." -Type Info
    
    $moduleInstallationResults = @()
    $totalModules = $script:config.RequiredModules.Count
    $currentModule = 0
    
    foreach ($moduleConfig in $script:config.RequiredModules) {
        $currentModule++
        $moduleName = $moduleConfig.Name
        
        
        try {
            # Check if module is already installed
            $installedModule = Get-Module -ListAvailable -Name $moduleName | 
                Where-Object { $_.Version -ge [Version]$moduleConfig.MinVersion } | 
                Sort-Object Version -Descending | 
                Select-Object -First 1
            
            if ($installedModule) {
                Write-LogMessage -Message "Module $moduleName (v$($installedModule.Version)) is already installed and meets requirements" -Type Success -LogOnly
                $moduleInstallationResults += @{
                    Module = $moduleName
                    Status = "Already Installed"
                    Version = $installedModule.Version
                    Success = $true
                }
                continue
            }
            
            # Install module if not present or version is too old
            Write-LogMessage -Message "Installing module: $moduleName (minimum version: $($moduleConfig.MinVersion))" -Type Info
            
            $installParams = @{
                Name = $moduleName
                MinimumVersion = $moduleConfig.MinVersion
                Scope = $moduleConfig.Scope
                Force = $true
                AllowClobber = $true
                SkipPublisherCheck = $true
                ErrorAction = 'Stop'
            }
            
            Install-Module @installParams
            
            # Verify installation
            $verifyModule = Get-Module -ListAvailable -Name $moduleName | 
                Where-Object { $_.Version -ge [Version]$moduleConfig.MinVersion } | 
                Sort-Object Version -Descending | 
                Select-Object -First 1
                
            if ($verifyModule) {
                Write-LogMessage -Message "Successfully installed $moduleName (v$($verifyModule.Version))" -Type Success
                $moduleInstallationResults += @{
                    Module = $moduleName
                    Status = "Newly Installed"
                    Version = $verifyModule.Version
                    Success = $true
                }
            }
            else {
                throw "Module installation verification failed"
            }
        }
        catch {
            Write-LogMessage -Message "Failed to install $moduleName - $($_.Exception.Message)" -Type Error
            $moduleInstallationResults += @{
                Module = $moduleName
                Status = "Installation Failed"
                Version = $null
                Success = $false
                Error = $_.Exception.Message
            }
        }
    }
    
    # Display installation summary
    Write-Host ""
    Write-Host "=== Module Installation Summary ===" -ForegroundColor Cyan
    
    $successCount = $script:config.RequiredModules.Count
    $totalCount = $script:config.RequiredModules.Count
    
    Write-Host "Successfully processed: $successCount/$totalCount modules" -ForegroundColor Green
    
    foreach ($result in $moduleInstallationResults) {
        $statusColor = if ($result.Success) { "Green" } else { "Red" }
        $statusText = if ($result.Success) { "✓" } else { "✗" }
        
        Write-Host "$statusText $($result.Module) " -ForegroundColor $statusColor -NoNewline
        if ($result.Success -and $result.Version) {
            Write-Host "(v$($result.Version)) " -ForegroundColor Gray -NoNewline
        }
        Write-Host "- $($result.Status)" -ForegroundColor Gray
        
        if (-not $result.Success -and $result.Error) {
            Write-Host "   Error: $($result.Error)" -ForegroundColor Red
        }
    }
    
    Write-Host ""
    
    # Return true if authentication module is available
return $successCount -gt 0
}

# ===================================================================
# GRAPH AUTHENTICATION WITH FORCE LOGIN
# ===================================================================

function Connect-ToGraphWithForceAuth {
    <#
    .SYNOPSIS
        Connects to Microsoft Graph with forced authentication and tenant verification
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-LogMessage -Message "Initializing Microsoft Graph connection..." -Type Info
        
        # Disconnect any existing sessions to force fresh authentication
        $existingContext = Get-MgContext -ErrorAction SilentlyContinue
        if ($existingContext) {
            Write-LogMessage -Message "Disconnecting existing Microsoft Graph session..." -Type Info
            Disconnect-MgGraph | Out-Null
        }
        
        # Force authentication with device code flow (works reliably across environments)
        Write-LogMessage -Message "Connecting to Microsoft Graph with forced authentication..." -Type Info
        Write-Host ""
        Write-Host "You will be prompted to sign in to Microsoft Graph." -ForegroundColor Yellow
        Write-Host "Please use Global Administrator credentials for your Microsoft 365 tenant." -ForegroundColor Yellow
        Write-Host ""
        
        # Connect with comprehensive scopes for all tenant operations
        Connect-MgGraph -Scopes $script:config.GraphScopes -NoWelcome
        
        # Verify connection and get context
        $mgContext = Get-MgContext
        if (-not $mgContext) {
            throw "Failed to establish Microsoft Graph connection"
        }
        
        Write-LogMessage -Message "Successfully connected to Microsoft Graph" -Type Success
        Write-LogMessage -Message "Connected as: $($mgContext.Account)" -Type Info
        Write-LogMessage -Message "Tenant ID: $($mgContext.TenantId)" -Type Info
        
        # Get and verify tenant information
        return Confirm-TenantDomain
        
    }
    catch {
        Write-LogMessage -Message "Microsoft Graph connection failed - $($_.Exception.Message)" -Type Error
        return $false
    }
}

function Confirm-TenantDomain {
    <#
    .SYNOPSIS
        Verifies tenant domain and stores tenant information for use throughout the script
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-LogMessage -Message "Retrieving tenant domain information..." -Type Info
        
        # Get organization information
        $organization = Get-MgOrganization
        if (-not $organization) {
            throw "Failed to retrieve organization information"
        }
        
        # Get primary domain
        $domains = Get-MgDomain
        $defaultDomain = $domains | Where-Object { $_.IsDefault -eq $true }
        
        if (-not $defaultDomain) {
            throw "Failed to identify default domain"
        }
        
        Write-Host ""
        Write-Host "=== Tenant Information ===" -ForegroundColor Cyan
        Write-Host "Organization: " -ForegroundColor Gray -NoNewline
        Write-Host "$($organization.DisplayName)" -ForegroundColor White
        Write-Host "Default Domain: " -ForegroundColor Gray -NoNewline
        Write-Host "$($defaultDomain.Id)" -ForegroundColor White
        Write-Host "Tenant ID: " -ForegroundColor Gray -NoNewline
        Write-Host "$($organization.Id)" -ForegroundColor White
        Write-Host ""
        
        $confirmation = Read-Host "Continue with this tenant configuration? (Y/N)"
        if ($confirmation -ne 'Y' -and $confirmation -ne 'y') {
            return $false
        }
        
        # Save tenant state information
        $script:TenantState = @{
            DefaultDomain = $defaultDomain.Id
            TenantName = $organization.DisplayName
            TenantId = $organization.Id
            CreatedGroups = @{}
            CreatedAdminAccounts = @{}
            AdminEmail = ""
        }
        
        # Get admin email for ownership assignments
        $script:TenantState.AdminEmail = Read-Host "Enter the email address for the Global Admin account"
        
        return $true
    }
    catch {
        Write-LogMessage -Message "Error verifying tenant domain - $($_.Exception.Message)" -Type Error
        return $false
    }
}

# ===================================================================
# GITHUB MODULE LOADING SYSTEM
# ===================================================================

function Initialize-ModuleCache {
    <#
    .SYNOPSIS
        Initializes the local cache directory for GitHub modules
    #>
    [CmdletBinding()]
    param()
    
    try {
        if (-not (Test-Path -Path $script:GitHubConfig.CacheDirectory)) {
            New-Item -Path $script:GitHubConfig.CacheDirectory -ItemType Directory -Force | Out-Null
            Write-LogMessage -Message "Created module cache directory: $($script:GitHubConfig.CacheDirectory)" -Type Info -LogOnly
        }
        return $true
    }
    catch {
        Write-LogMessage -Message "Failed to initialize module cache - $($_.Exception.Message)" -Type Error
        return $false
    }
}

function Import-ModuleFromCache {
    <#
    .SYNOPSIS
        Downloads and caches modules from GitHub repository
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName
    )
    
    try {
        $fileName = $script:GitHubConfig.ModuleFiles[$ModuleName]
        if (-not $fileName) {
            Write-LogMessage -Message "Unknown module: $ModuleName" -Type Error
            return $false
        }
        
        $url = "$($script:GitHubConfig.BaseUrl)/$fileName"
        $localPath = Join-Path -Path $script:GitHubConfig.CacheDirectory -ChildPath $fileName
        
        Write-LogMessage -Message "Downloading $ModuleName module from GitHub..." -Type Info
        
        # Download with PowerShell 7 enhanced web capabilities
        $webClient = [System.Net.WebClient]::new()
        $webClient.Headers.Add("User-Agent", "PowerShell-M365-Setup/2.0")
        $webClient.DownloadFile($url, $localPath)
        $webClient.Dispose()
        
        if (Test-Path -Path $localPath) {
            Write-LogMessage -Message "$ModuleName module cached successfully" -Type Success
            return $true
        }
        else {
            Write-LogMessage -Message "Failed to cache $ModuleName module" -Type Error
            return $false
        }
    }
    catch {
        Write-LogMessage -Message "Error downloading $ModuleName module - $($_.Exception.Message)" -Type Error
        return $false
    }
}

function Refresh-GitHubModules {
    <#
    .SYNOPSIS
        Refreshes all modules from GitHub repository
    #>
    Write-LogMessage -Message "Refreshing all modules from GitHub repository..." -Type Info
    
    $refreshedCount = 0
    $totalModules = $script:GitHubConfig.ModuleFiles.Count
    
    foreach ($moduleName in $script:GitHubConfig.ModuleFiles.Keys) {
        $refreshedCount++
        Show-Progress -Current $refreshedCount -Total $totalModules -Status "Refreshing module: $moduleName"
        
        $success = Import-ModuleFromCache -ModuleName $moduleName
        if ($success) {
            Write-LogMessage -Message "$moduleName module refreshed successfully" -Type Success -LogOnly
        }
        else {
            Write-LogMessage -Message "Failed to refresh $moduleName module" -Type Warning
        }
    }
    
    Write-Host ""
    Write-LogMessage -Message "Module refresh completed" -Type Success
}

# === Module Operation Handler ===
function Invoke-ModuleOperation {
    <#
    .SYNOPSIS
        Enhanced module operation handler with PowerShell 7 optimizations
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName,
        
        [Parameter(Mandatory = $true)]
        [string]$FunctionName,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Parameters = @{}
    )
    
    try {
        Write-LogMessage -Message "Loading $ModuleName module from cache..." -Type Info
        
        # Import module from cache
        $moduleLoaded = Import-ModuleFromCache -ModuleName $ModuleName
        if (-not $moduleLoaded) {
            Write-LogMessage -Message "Failed to load $ModuleName module. Please check your internet connection." -Type Error
            return $false
        }
        
        # Get the cached module file path
        $fileName = $script:GitHubConfig.ModuleFiles[$ModuleName]
        $localPath = Join-Path -Path $script:GitHubConfig.CacheDirectory -ChildPath $fileName
        
        if (-not (Test-Path -Path $localPath)) {
            Write-LogMessage -Message "Module file not found: $localPath" -Type Error
            return $false
        }
        
        Write-LogMessage -Message "Executing $ModuleName module function: $FunctionName" -Type Info
        
        # Execute the module function with enhanced error handling
        $result = & {
            try {
                # Dot source the module
                . $localPath
                
                # Call the function with parameters if provided
                if ($Parameters.Count -gt 0) {
                    & $FunctionName @Parameters
                }
                else {
                    & $FunctionName
                }
            }
            catch {
                Write-LogMessage -Message "Error executing function $FunctionName in module $ModuleName - $($_.Exception.Message)" -Type Error
                return $false
            }
        }
        
        return $result
    }
    catch {
        Write-LogMessage -Message "Fatal error in module operation - $($_.Exception.Message)" -Type Error
        return $false
    }
}

# ===================================================================
# DEBUG AND UTILITIES
# ===================================================================

function Debug-ExcelDataPS7 {
    <#
    .SYNOPSIS
        Enhanced Excel debugging function with PowerShell 7 features and on-demand module installation
    #>
    [CmdletBinding()]
    param()
    
    Write-LogMessage -Message "Excel Debug Mode - PowerShell 7 Enhanced" -Type Info
    
    # Check if ImportExcel module is available, install if needed
    $excelModule = Get-Module -ListAvailable -Name ImportExcel
    if (-not $excelModule) {
        Write-LogMessage -Message "ImportExcel module not found. Installing..." -Type Warning
        try {
            Install-Module -Name ImportExcel -Force -Scope CurrentUser -AllowClobber
            Write-LogMessage -Message "ImportExcel module installed successfully" -Type Success
        }
        catch {
            Write-LogMessage -Message "Failed to install ImportExcel module. Debug function may not work properly." -Type Error
            return
        }
    }
    
    # Import the module
    Import-Module ImportExcel -Force
    
    # Get Excel file path
    $excelPath = Read-Host "Enter the full path to your Excel file"
    
    if (-not (Test-Path -Path $excelPath)) {
        Write-LogMessage -Message "File not found: $excelPath" -Type Error
        return
    }
    
    try {
        Write-LogMessage -Message "Reading Excel file structure..." -Type Info
        
        # Get workbook info
        $workbook = Import-Excel -Path $excelPath -WorksheetName (Get-ExcelSheetInfo -Path $excelPath)[0].Name -NoHeader
        
        Write-Host ""
        Write-Host "=== Excel File Analysis ===" -ForegroundColor Cyan
        Write-Host "File: $excelPath" -ForegroundColor White
        Write-Host "Rows found: $($workbook.Count)" -ForegroundColor White
        
        # Show first few rows
        Write-Host ""
        Write-Host "First 5 rows:" -ForegroundColor Yellow
        $workbook | Select-Object -First 5 | Format-Table -AutoSize
        
        # Look for password-related columns
        $headers = $workbook[0].PSObject.Properties.Name
        $passwordColumns = $headers | Where-Object { $_ -like "*password*" -or $_ -like "*pwd*" -or $_ -like "*pass*" }
        
        if ($passwordColumns) {
            Write-Host ""
            Write-Host "Potential password columns found:" -ForegroundColor Green
            $passwordColumns | ForEach-Object { Write-Host "  - $_" -ForegroundColor White }
        }
        else {
            Write-Host ""
            Write-Host "No obvious password columns found" -ForegroundColor Red
            Write-Host "Available columns:" -ForegroundColor Yellow
            $headers | ForEach-Object { Write-Host "  - $_" -ForegroundColor White }
        }
    }
    catch {
        Write-LogMessage -Message "Error reading Excel file - $($_.Exception.Message)" -Type Error
    }
}

# ===================================================================
# MAIN APPLICATION LOGIC
# ===================================================================

function Start-Setup {
    <#
    .SYNOPSIS
        Main entry point for the Unified Microsoft 365 Tenant Setup Utility
    #>
    [CmdletBinding()]
    param()
    
    try {
        # Initialize logging
        Initialize-Logging
        Write-LogMessage -Message "Unified Microsoft 365 Tenant Setup Utility - PowerShell 7 Self-Contained Version started" -Type Info
        
        # Test PowerShell 7 features
        Write-LogMessage -Message "Testing PowerShell 7 feature compatibility..." -Type Info
        $ps7Features = Test-PowerShell7Features
        
        if ($PSVersionTable.PSVersion -lt [Version]"7.0") {
            Write-LogMessage -Message "This script is optimized for PowerShell 7.0 or later. Some features may not work." -Type Warning
        }
        
        # Initialize module cache
        $cacheInitialized = Initialize-ModuleCache
        if (-not $cacheInitialized) {
            Write-LogMessage -Message "Failed to initialize module cache. Some features may not work." -Type Warning
        }
        
        # Install and verify required modules
        $modulesInstalled = Install-RequiredModulesWithDependencies
        if (-not $modulesInstalled) {
            Write-LogMessage -Message "Critical modules installation failed. Some features may not work correctly." -Type Warning
            $continue = Read-Host "Continue anyway? (Y/N)"
            if ($continue -ne 'Y' -and $continue -ne 'y') {
                Write-LogMessage -Message "Setup cancelled by user due to module installation failure" -Type Info
                return
            }
        }
        
        # Main menu loop
        $exitScript = $false
        while (-not $exitScript) {
            # Check if connected to Microsoft Graph
            $graphConnected = $null -ne (Get-MgContext)
            
            if (-not $graphConnected) {
                # Limited menu when not connected
                $choice = Show-Menu -Title "Main Menu (Authentication Required)" -Options @(
                    "Connect to Microsoft Graph and Verify Tenant"
                    "Refresh Modules from GitHub"
                    "Exit"
                )
            }
            else {
                # Full menu when connected
                $choice = Show-Menu -Title "Main Menu (Connected: $((Get-MgContext).Account))" -Options @(
                    "Connect to Microsoft Graph and Verify Tenant"
                    "Refresh Modules from GitHub"
                    "Create Security and License Groups"
                    "Create Admin Accounts and Roles"
                    "Configure Conditional Access Policies"
                    "Set Up SharePoint Sites"
                    "Configure Intune Policies"
                    "Create Users from Excel"
                    "Create Admin Helpdesk Role"
                    "Generate Documentation"
                    "Debug Excel File (Check Password Data)"
                    "Exit"
                )
            }
            
            if ($null -eq $choice) {
                continue
            }
            
            # Handle menu choices based on connection status
            if (-not $graphConnected) {
                # Limited menu options when not connected
                switch ($choice) {
                    1 {
                        # Connect to Graph and verify tenant
                        Write-LogMessage -Message "Executing: Connect to Microsoft Graph and Verify Tenant" -Type Info
                        $connected = Connect-ToGraphWithForceAuth
                        if ($connected) {
                            Write-LogMessage -Message "Successfully connected and verified tenant domain" -Type Success
                            Write-Host ""
                            Write-Host "✅ Authentication successful! All menu options are now available." -ForegroundColor Green
                        }
                        Read-Host "Press Enter to continue"
                    }
                    2 {
                        # Refresh modules from GitHub
                        Write-LogMessage -Message "Executing: Refresh Modules from GitHub" -Type Info
                        Refresh-GitHubModules
                        Read-Host "Press Enter to continue"
                    }
                    3 {
                        # Exit
                        $exitScript = $true
                        Write-LogMessage -Message "Unified Microsoft 365 Tenant Setup Utility ended by user request" -Type Info
                    }
                }
            }
            else {
                # Full menu options when connected
                switch ($choice) {
                    1 {
                        # Connect to Graph and verify tenant (reconnect)
                        Write-LogMessage -Message "Executing: Reconnect to Microsoft Graph and Verify Tenant" -Type Info
                        $connected = Connect-ToGraphWithForceAuth
                        if ($connected) {
                            Write-LogMessage -Message "Successfully reconnected and verified tenant domain" -Type Success
                        }
                        Read-Host "Press Enter to continue"
                    }
                    2 {
                        # Refresh modules from GitHub
                        Write-LogMessage -Message "Executing: Refresh Modules from GitHub" -Type Info
                        Refresh-GitHubModules
                        Read-Host "Press Enter to continue"
                    }
                    3 {
                        # Create groups
                        Write-LogMessage -Message "Executing: Create Security and License Groups" -Type Info
                        $success = Invoke-ModuleOperation -ModuleName "Groups" -FunctionName "New-TenantGroups"
                        if ($success) {
                            Write-LogMessage -Message "Groups creation completed successfully" -Type Success
                        }
                        Read-Host "Press Enter to continue"
                    }
                    4 {
                        # Create Admin Accounts
                        Write-LogMessage -Message "Executing: Create Admin Accounts and Roles" -Type Info
                        $success = Invoke-ModuleOperation -ModuleName "AdminAccounts" -FunctionName "New-TenantAdminAccounts"
                        if ($success) {
                            Write-LogMessage -Message "Admin accounts creation completed successfully" -Type Success
                        }
                        Read-Host "Press Enter to continue"
                    }
                    5 {
                        # Configure CA policies
                        Write-LogMessage -Message "Executing: Configure Conditional Access Policies" -Type Info
                        if (-not $script:TenantState -or -not $script:TenantState.CreatedGroups) {
                            Write-LogMessage -Message "Groups not created yet. Please create groups first." -Type Warning
                        }
                        else {
                            $success = Invoke-ModuleOperation -ModuleName "ConditionalAccess" -FunctionName "New-TenantCAPolices"
                            if ($success) {
                                Write-LogMessage -Message "Conditional Access policies configured successfully" -Type Success
                            }
                        }
                        Read-Host "Press Enter to continue"
                    }
                    6 {
                        # Set up SharePoint
                        Write-LogMessage -Message "Executing: Set Up SharePoint Sites" -Type Info
                        $success = Invoke-ModuleOperation -ModuleName "SharePoint" -FunctionName "New-TenantSharePoint"
                        if ($success) {
                            Write-LogMessage -Message "SharePoint setup completed successfully" -Type Success
                        }
                        Read-Host "Press Enter to continue"
                    }
                    7 {
                        # Configure Intune
                        Write-LogMessage -Message "Executing: Configure Intune Policies" -Type Info
                        $success = Invoke-ModuleOperation -ModuleName "Intune" -FunctionName "New-TenantIntune"
                        if ($success) {
                            Write-LogMessage -Message "Intune configuration completed successfully" -Type Success
                        }
                        Read-Host "Press Enter to continue"
                    }
                    8 {
                        # Create users
                        Write-LogMessage -Message "Executing: Create Users from Excel" -Type Info
                        $success = Invoke-ModuleOperation -ModuleName "Users" -FunctionName "New-TenantUsers"
                        if ($success) {
                            Write-LogMessage -Message "User creation completed successfully" -Type Success
                        }
                        Read-Host "Press Enter to continue"
                    }
                    9 {
                        # Create Admin Helpdesk Role
                        Write-LogMessage -Message "Executing: Create Admin Helpdesk Role" -Type Info
                        $success = Invoke-ModuleOperation -ModuleName "AdminCreation" -FunctionName "New-AdminHelpdeskRole"
                        if ($success) {
                            Write-LogMessage -Message "Admin Helpdesk Role created successfully" -Type Success
                        }
                        Read-Host "Press Enter to continue"
                    }
                    10 {
                        # Generate documentation
                        Write-LogMessage -Message "Executing: Generate Documentation" -Type Info
                        if (-not $script:TenantState) {
                            Write-LogMessage -Message "No tenant configuration found. Please connect and configure tenant first." -Type Warning
                        }
                        else {
                            $success = Invoke-ModuleOperation -ModuleName "Documentation" -FunctionName "New-TenantDocumentation"
                            if ($success) {
                                Write-LogMessage -Message "Documentation generated successfully" -Type Success
                            }
                        }
                        Read-Host "Press Enter to continue"
                    }
                    11 {
                        # Debug Excel file
                        Write-LogMessage -Message "Executing: Debug Excel File" -Type Info
                        Debug-ExcelDataPS7
                        Read-Host "Press Enter to continue"
                    }
                    12 {
                        # Exit
                        $exitScript = $true
                        Write-LogMessage -Message "Unified Microsoft 365 Tenant Setup Utility ended by user request" -Type Info
                    }
                }
            }
        }
        
        # Final cleanup
        if (Get-MgContext) {
            Write-LogMessage -Message "Disconnecting from Microsoft Graph..." -Type Info
            Disconnect-MgGraph | Out-Null
        }
        
        Write-Host ""
        Write-Host "Thank you for using the Unified Microsoft 365 Tenant Setup Utility!" -ForegroundColor Cyan
        Write-Host "Session logs saved to: $($script:config.LogFile)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "This self-contained script downloaded specialized modules from:" -ForegroundColor Gray
        Write-Host "$($script:GitHubConfig.BaseUrl)" -ForegroundColor Gray
    }
    catch {
        Write-LogMessage -Message "Fatal error in main application: $($_.Exception.Message)" -Type Error
        Write-Host "An unexpected error occurred. Please check the log file for details." -ForegroundColor Red
    }
}

# ===================================================================
# APPLICATION STARTUP
# ===================================================================

# Start the setup when script is executed directly (not dot-sourced)
if ($MyInvocation.InvocationName -ne '.') {
    Write-Host "Unified Microsoft 365 Tenant Setup Utility - PowerShell 7 Self-Contained" -ForegroundColor Cyan
    Write-Host "Starting up..." -ForegroundColor Gray
    Write-Host ""
    Start-Setup
}