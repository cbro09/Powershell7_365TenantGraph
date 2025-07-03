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
        },
        @{
            Name = 'Microsoft.Graph.Identity.DirectoryManagement'
            MinVersion = '2.0.0'
            Scope = 'CurrentUser'
        },
        @{
            Name = 'Microsoft.Graph.Users'
            MinVersion = '2.0.0'
            Scope = 'CurrentUser'
        },
        @{
            Name = 'Microsoft.Graph.Groups'
            MinVersion = '2.0.0'
            Scope = 'CurrentUser'
        },
        @{
            Name = 'Microsoft.Graph.DeviceManagement'
            MinVersion = '2.0.0'
            Scope = 'CurrentUser'
        },
        @{
            Name = 'Microsoft.Online.SharePoint.PowerShell'
            MinVersion = '16.0.0'
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
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [object]$Value
    )
    
    if ($null -eq $Value) { return $false }
    if ($Value -is [string] -and [string]::IsNullOrWhiteSpace($Value)) { return $false }
    if ($Value -is [array] -and $Value.Count -eq 0) { return $false }
    if ($Value -is [hashtable] -and $Value.Count -eq 0) { return $false }
    
    return $true
}

function Get-SafeString {
    <#
    .SYNOPSIS
        Safe string conversion with null handling and truncation
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [object]$Value,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxLength = -1,
        
        [Parameter(Mandatory = $false)]
        [string]$DefaultValue = ""
    )
    
    # Handle null or empty
    if (-not (Test-NotEmpty -Value $Value)) {
        return $DefaultValue
    }
    
    # Convert to string
    $result = "$Value"
    
    # Truncate if needed
    if ($MaxLength -gt 0 -and $result.Length -gt $MaxLength) {
        $result = $result.Substring(0, $MaxLength)
        Write-LogMessage -Message "String truncated to $MaxLength characters" -Type Warning -LogOnly
    }
    
    return $result
}

function Test-EmailFormat {
    <#
    .SYNOPSIS
        Simple email format validation without regex
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$EmailAddress
    )
    
    # Basic validation using string methods only
    if ([string]::IsNullOrWhiteSpace($EmailAddress)) {
        return $false
    }
    
    $atCount = ($EmailAddress.ToCharArray() | Where-Object { $_ -eq '@' }).Count
    if ($atCount -ne 1) {
        return $false
    }
    
    $parts = $EmailAddress.Split('@')
    if ($parts.Count -ne 2) {
        return $false
    }
    
    $localPart = $parts[0]
    $domainPart = $parts[1]
    
    if ([string]::IsNullOrWhiteSpace($localPart) -or [string]::IsNullOrWhiteSpace($domainPart)) {
        return $false
    }
    
    if ($domainPart.IndexOf('.') -eq -1) {
        return $false
    }
    
    return $true
}

# === Automatic Module Management Implementation ===
function Install-RequiredModulesWithDependencies {
    <#
    .SYNOPSIS
        Implements automatic module dependency handling for PowerShell 7
    #>
    [CmdletBinding()]
    param()
    
    Write-LogMessage -Message "Starting automatic module dependency management..." -Type Info
    Write-LogMessage -Message "PowerShell Version: $($PSVersionTable.PSVersion)" -Type Info
    Write-LogMessage -Message "PowerShell Edition: $($PSVersionTable.PSEdition)" -Type Info
    
    $moduleCount = $script:config.RequiredModules.Count
    $currentModule = 0
    $failedModules = @()
    
    foreach ($moduleConfig in $script:config.RequiredModules) {
        $currentModule++
        $moduleName = $moduleConfig.Name
        $minVersion = $moduleConfig.MinVersion
        $scope = $moduleConfig.Scope
        
        Show-Progress -Current $currentModule -Total $moduleCount -Status "Processing module: $moduleName"
        
        try {
            # Check if module is installed
            $installedModule = Get-Module -ListAvailable -Name $moduleName | 
                               Sort-Object Version -Descending | 
                               Select-Object -First 1
            
            if (-not $installedModule) {
                Write-LogMessage -Message "Installing $moduleName module (Scope: $scope)..." -Type Info
                Install-Module -Name $moduleName -Scope $scope -Force -AllowClobber -AllowPrerelease:$false -ErrorAction Stop
                Write-LogMessage -Message "$moduleName module installed successfully" -Type Success
            }
            elseif ([version]$installedModule.Version -lt [version]$minVersion) {
                Write-LogMessage -Message "Updating $moduleName from $($installedModule.Version) to minimum $minVersion..." -Type Info
                Update-Module -Name $moduleName -Force -ErrorAction Stop
                Write-LogMessage -Message "$moduleName module updated successfully" -Type Success
            }
            else {
                Write-LogMessage -Message "$moduleName module already installed (Version: $($installedModule.Version))" -Type Info -LogOnly
            }
            
            # Import the module if not already loaded
            $loadedModule = Get-Module -Name $moduleName
            if (-not $loadedModule) {
                Write-LogMessage -Message "Importing $moduleName module..." -Type Info -LogOnly
                Import-Module -Name $moduleName -Force -ErrorAction Stop
                Write-LogMessage -Message "$moduleName module imported successfully" -Type Success -LogOnly
            }
            else {
                Write-LogMessage -Message "$moduleName module already loaded" -Type Info -LogOnly
            }
            
        }
        catch {
            Write-LogMessage -Message "Failed to install/import $moduleName module - $($_.Exception.Message)" -Type Error
            $failedModules += $moduleName
        }
    }
    
    Write-Host ""
    
    if ($failedModules.Count -gt 0) {
        Write-LogMessage -Message "Failed to install the following modules: $($failedModules -join ', ')" -Type Error
        Write-LogMessage -Message "Some features may not work correctly. Please install these modules manually." -Type Warning
        return $false
    }
    
    Write-LogMessage -Message "All required modules installed and loaded successfully" -Type Success
    return $true
}

# === Authentication Functions with Force Login ===
function Connect-ToGraphWithForceAuth {
    <#
    .SYNOPSIS
        Connects to Microsoft Graph with forced authentication (no caching)
    #>
    [CmdletBinding()]
    param()
    
    try {
        # Always disconnect any existing sessions to force fresh login
        $existingContext = Get-MgContext -ErrorAction SilentlyContinue
        if ($existingContext) {
            Write-LogMessage -Message "Disconnecting existing Microsoft Graph session..." -Type Info
            Disconnect-MgGraph | Out-Null
        }
        
        Write-LogMessage -Message "Connecting to Microsoft Graph (Force Authentication)..." -Type Info
        Write-LogMessage -Message "Required scopes: $($script:config.GraphScopes -join ', ')" -Type Info
        Write-Host ""
        Write-Host "You will be prompted to sign in. Please use Global Administrator credentials." -ForegroundColor Yellow
        Write-Host ""
        
        # Force interactive authentication by disconnecting first and using NoWelcome
        Connect-MgGraph -Scopes $script:config.GraphScopes -NoWelcome -ErrorAction Stop
        
        $context = Get-MgContext
        if (-not $context) {
            throw "Failed to establish Microsoft Graph context after connection"
        }
        
        Write-LogMessage -Message "Successfully connected to Microsoft Graph" -Type Success
        Write-LogMessage -Message "Account: $($context.Account)" -Type Info
        Write-LogMessage -Message "Tenant ID: $($context.TenantId)" -Type Info
        Write-LogMessage -Message "Environment: $($context.Environment)" -Type Info
        
        # Verify tenant domain
        $verified = Test-TenantDomainPS7
        if (-not $verified) {
            Write-LogMessage -Message "Tenant domain verification failed. Please connect to the correct tenant." -Type Error
            Disconnect-MgGraph | Out-Null
            return $false
        }
        
        return $true
    }
    catch {
        Write-LogMessage -Message "Failed to connect to Microsoft Graph - $($_.Exception.Message)" -Type Error
        return $false
    }
}

function Test-TenantDomainPS7 {
    <#
    .SYNOPSIS
        Enhanced tenant domain verification with PowerShell 7 features
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-LogMessage -Message "Verifying tenant domain and collecting organization information..." -Type Info
        
        # Get organization details with error handling
        $organization = Get-MgOrganization -ErrorAction Stop
        if (-not $organization) {
            throw "Unable to retrieve organization information from Microsoft Graph"
        }
        
        $verifiedDomains = $organization.VerifiedDomains
        $defaultDomain = $verifiedDomains | Where-Object { $_.IsDefault -eq $true }
        
        if (-not $defaultDomain) {
            throw "No default domain found for this tenant"
        }
        
        Write-Host ""
        Write-Host "=== Tenant Information ===" -ForegroundColor Cyan
        Write-Host "Organization Name: " -ForegroundColor Gray -NoNewline
        Write-Host "$($organization.DisplayName)" -ForegroundColor White
        Write-Host "Default Domain: " -ForegroundColor Gray -NoNewline
        Write-Host "$($defaultDomain.Name)" -ForegroundColor White
        Write-Host "Tenant ID: " -ForegroundColor Gray -NoNewline
        Write-Host "$($organization.Id)" -ForegroundColor White
        Write-Host "Verified Domains: " -ForegroundColor Gray -NoNewline
        Write-Host "$($verifiedDomains.Name -join ', ')" -ForegroundColor White
        Write-Host ""
        
        $confirmation = Read-Host "Is this the correct tenant for configuration? (Y/N)"
        if ($confirmation -ne 'Y' -and $confirmation -ne 'y') {
            Write-LogMessage -Message "Tenant verification declined by user" -Type Warning
            Write-Host ""
            Write-Host "Please connect to the correct tenant." -ForegroundColor Yellow
            
            # Ask if user wants to reconnect
            $reconnect = Read-Host "Do you want to sign in to a different tenant? (Y/N)"
            if ($reconnect -eq 'Y' -or $reconnect -eq 'y') {
                # Disconnect current session
                Disconnect-MgGraph | Out-Null
                Write-LogMessage -Message "Disconnected from incorrect tenant. Please reconnect to the correct tenant." -Type Info
                
                # Reconnect with fresh authentication
                Write-Host ""
                Write-Host "You will be prompted to sign in again. Please use credentials for the correct tenant." -ForegroundColor Yellow
                Write-Host ""
                
                Connect-MgGraph -Scopes $script:config.GraphScopes -NoWelcome -ErrorAction Stop
                
                # Recursively call this function to verify the new tenant
                return Test-TenantDomainPS7
            }
            else {
                Write-LogMessage -Message "User chose not to reconnect. Tenant verification failed." -Type Warning
                return $false
            }
        }
        
        # Save tenant state information with enhanced data
        $script:TenantState = @{
            DefaultDomain = $defaultDomain.Name
            TenantName = $organization.DisplayName
            TenantId = $organization.Id
            VerifiedDomains = $verifiedDomains.Name
            CreatedGroups = @{}
            AdminEmail = ""
            LastVerified = Get-Date
        }
        
        # Get admin email for ownership assignments
        Write-Host ""
        $script:TenantState.AdminEmail = Read-Host "Enter the email address for the Global Admin account"
        
        # Validate email format using our custom function
        if (-not (Test-EmailFormat -EmailAddress $script:TenantState.AdminEmail)) {
            Write-LogMessage -Message "Warning: Admin email format may be invalid" -Type Warning
        }
        
        Write-LogMessage -Message "Tenant verification completed successfully" -Type Success
        Write-LogMessage -Message "Tenant: $($script:TenantState.TenantName) ($($script:TenantState.DefaultDomain))" -Type Info
        
        return $true
    }
    catch {
        Write-LogMessage -Message "Error verifying tenant domain - $($_.Exception.Message)" -Type Error
        return $false
    }
}

# === GitHub Module Functions ===
function Initialize-ModuleCache {
    <#
    .SYNOPSIS
        Initializes the GitHub module cache directory
    #>
    try {
        if (-not (Test-Path -Path $script:GitHubConfig.CacheDirectory)) {
            New-Item -Path $script:GitHubConfig.CacheDirectory -ItemType Directory -Force | Out-Null
            Write-LogMessage -Message "Created module cache directory: $($script:GitHubConfig.CacheDirectory)" -Type Info
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
                
                # Check if function exists
                if (-not (Get-Command -Name $FunctionName -ErrorAction SilentlyContinue)) {
                    throw "Function '$FunctionName' not found in module '$ModuleName'"
                }
                
                # Call the function with parameters
                if ($Parameters.Count -gt 0) {
                    & $FunctionName @Parameters
                }
                else {
                    & $FunctionName
                }
            }
            catch {
                Write-LogMessage -Message "Error executing $FunctionName in $ModuleName - $($_.Exception.Message)" -Type Error
                return $false
            }
        }
        
        if ($result) {
            Write-LogMessage -Message "$ModuleName operation completed successfully" -Type Success
            return $true
        }
        else {
            Write-LogMessage -Message "$ModuleName operation completed with warnings or returned false" -Type Warning
            return $false
        }
    }
    catch {
        Write-LogMessage -Message "Failed to execute $ModuleName operation - $($_.Exception.Message)" -Type Error
        return $false
    }
}

# === Excel Data Debugging Function ===
function Debug-ExcelDataPS7 {
    <#
    .SYNOPSIS
        Enhanced Excel data debugging with PowerShell 7 features
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-LogMessage -Message "Starting Excel data debug process..." -Type Info
        
        # Check if ImportExcel module is available, install if needed
        if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
            Write-LogMessage -Message "ImportExcel module not found. Installing..." -Type Info
            try {
                Install-Module -Name ImportExcel -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                Write-LogMessage -Message "ImportExcel module installed successfully" -Type Success
            }
            catch {
                Write-LogMessage -Message "Failed to install ImportExcel module: $($_.Exception.Message)" -Type Error
                return
            }
        }
        
        # Import the module if not already loaded
        if (-not (Get-Module -Name ImportExcel)) {
            Import-Module -Name ImportExcel -Force -ErrorAction Stop
        }
        
        # File selection with PowerShell 7 enhanced dialog
        Add-Type -AssemblyName System.Windows.Forms
        $openFileDialog = [System.Windows.Forms.OpenFileDialog]::new()
        $openFileDialog.Title = "Select Excel File for Debug"
        $openFileDialog.Filter = "Excel Files (*.xlsx;*.xls)|*.xlsx;*.xls|All Files (*.*)|*.*"
        $openFileDialog.InitialDirectory = [Environment]::GetFolderPath("Desktop")
        
        if ($openFileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $excelPath = $openFileDialog.FileName
            Write-LogMessage -Message "Selected file: $excelPath" -Type Info
            
            try {
                # Import Excel data with enhanced error handling
                $excelData = Import-Excel -Path $excelPath -ErrorAction Stop
                
                if (-not $excelData -or $excelData.Count -eq 0) {
                    Write-LogMessage -Message "Excel file is empty or contains no data" -Type Warning
                    return
                }
                
                # Display file information
                Write-Host ""
                Write-Host "=== Excel File Debug Information ===" -ForegroundColor Cyan
                Write-Host "File Path: " -ForegroundColor Gray -NoNewline
                Write-Host "$excelPath" -ForegroundColor White
                Write-Host "Total Rows: " -ForegroundColor Gray -NoNewline
                Write-Host "$($excelData.Count)" -ForegroundColor White
                
                # Get column names
                $columnNames = $excelData[0].PSObject.Properties.Name
                Write-Host "Columns Found: " -ForegroundColor Gray -NoNewline
                Write-Host "$($columnNames -join ', ')" -ForegroundColor White
                Write-Host ""
                
                # Display first few rows
                Write-Host "=== First 3 Rows Preview ===" -ForegroundColor Yellow
                $previewRows = $excelData | Select-Object -First 3
                $previewRows | Format-Table -AutoSize
                
                # Check for common user creation columns
                $requiredColumns = @('FirstName', 'LastName', 'Email', 'Department')
                $missingColumns = $requiredColumns | Where-Object { $_ -notin $columnNames }
                
                if ($missingColumns.Count -gt 0) {
                    Write-Host "=== Missing Required Columns ===" -ForegroundColor Red
                    $missingColumns | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
                }
                else {
                    Write-Host "=== All Required Columns Present ===" -ForegroundColor Green
                }
                
                # Check for password column specifically
                $passwordColumns = $columnNames | Where-Object { $_ -like "*password*" -or $_ -like "*pwd*" }
                if ($passwordColumns.Count -gt 0) {
                    Write-Host ""
                    Write-Host "=== Password Columns Found ===" -ForegroundColor Yellow
                    $passwordColumns | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
                    
                    # Check if passwords are populated
                    $passwordColumn = $passwordColumns[0]
                    $emptyPasswords = $excelData | Where-Object { [string]::IsNullOrWhiteSpace($_.$passwordColumn) }
                    
                    Write-Host "Rows with empty passwords: " -ForegroundColor Gray -NoNewline
                    Write-Host "$($emptyPasswords.Count)" -ForegroundColor $(if ($emptyPasswords.Count -gt 0) { 'Red' } else { 'Green' })
                }
                else {
                    Write-Host ""
                    Write-Host "=== No Password Columns Found ===" -ForegroundColor Red
                    Write-Host "Consider adding a 'Password' or 'InitialPassword' column" -ForegroundColor Yellow
                }
                
                Write-LogMessage -Message "Excel debug completed successfully" -Type Success
            }
            catch {
                Write-LogMessage -Message "Error reading Excel file: $($_.Exception.Message)" -Type Error
            }
        }
        else {
            Write-LogMessage -Message "File selection cancelled by user" -Type Info
        }
    }
    catch {
        Write-LogMessage -Message "Error in Excel debug process: $($_.Exception.Message)" -Type Error
    }
}

# === PowerShell 7 Feature Testing ===
function Test-PowerShell7Features {
    <#
    .SYNOPSIS
        Tests PowerShell 7 specific features availability
    #>
    [CmdletBinding()]
    param()
    
    $features = @{
        'Parallel ForEach' = $null -ne (Get-Command -Name 'ForEach-Object' -ParameterName 'Parallel' -ErrorAction SilentlyContinue)
        'Ternary Operator' = $PSVersionTable.PSVersion -ge [version]'7.0'
        'Null Coalescing' = $PSVersionTable.PSVersion -ge [version]'7.0'
        'Pipeline Chain Operators' = $PSVersionTable.PSVersion -ge [version]'7.0'
        'Updated Get-Error' = $null -ne (Get-Command -Name 'Get-Error' -ErrorAction SilentlyContinue)
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
# MAIN APPLICATION ENTRY POINT
# ===================================================================

function Start-Setup {
    <#
    .SYNOPSIS
        Main application entry point with enhanced error handling
    #>
    [CmdletBinding()]
    param()
    
    try {
        # Initialize logging
        Initialize-Logging
        Write-LogMessage -Message "Unified Microsoft 365 Tenant Setup Utility (PowerShell 7 Self-Contained) started" -Type Info
        
        # Test PowerShell 7 features
        Write-LogMessage -Message "Testing PowerShell 7 features..." -Type Info
        $features = Test-PowerShell7Features
        
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
                    5 {
                        # Set up SharePoint
                        Write-LogMessage -Message "Executing: Set Up SharePoint Sites" -Type Info
                        $success = Invoke-ModuleOperation -ModuleName "SharePoint" -FunctionName "New-TenantSharePoint"
                        if ($success) {
                            Write-LogMessage -Message "SharePoint setup completed successfully" -Type Success
                        }
                        Read-Host "Press Enter to continue"
                    }
                    6 {
                        # Configure Intune
                        Write-LogMessage -Message "Executing: Configure Intune Policies" -Type Info
                        $success = Invoke-ModuleOperation -ModuleName "Intune" -FunctionName "New-TenantIntune"
                        if ($success) {
                            Write-LogMessage -Message "Intune configuration completed successfully" -Type Success
                        }
                        Read-Host "Press Enter to continue"
                    }
                    7 {
                        # Create users
                        Write-LogMessage -Message "Executing: Create Users from Excel" -Type Info
                        $success = Invoke-ModuleOperation -ModuleName "Users" -FunctionName "New-TenantUsers"
                        if ($success) {
                            Write-LogMessage -Message "User creation completed successfully" -Type Success
                        }
                        Read-Host "Press Enter to continue"
                    }
                    8 {
                        # Create Admin Helpdesk Role
                        Write-LogMessage -Message "Executing: Create Admin Helpdesk Role" -Type Info
                        $success = Invoke-ModuleOperation -ModuleName "AdminCreation" -FunctionName "New-AdminHelpdeskRole"
                        if ($success) {
                            Write-LogMessage -Message "Admin Helpdesk Role created successfully" -Type Success
                        }
                        Read-Host "Press Enter to continue"
                    }
                    9 {
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
                    10 {
                        # Debug Excel file
                        Write-LogMessage -Message "Executing: Debug Excel File" -Type Info
                        Debug-ExcelDataPS7
                        Read-Host "Press Enter to continue"
                    }
                    11 {
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