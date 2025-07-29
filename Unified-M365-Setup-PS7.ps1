# ▼ CB & Claude | BITS 365 Automation | v1.0 | "Smarter not Harder"

#requires -Version 7.0
<#
.SYNOPSIS
    Microsoft 365 Unified Tenant Setup - Lightweight Orchestrator with Smart Scope Management
.DESCRIPTION
    Fast, lightweight orchestrator that downloads specialized modules as needed.
    Each module handles its own dependencies - keeping the main script lightning fast.
    Now with intelligent scope grouping to prevent "too many scopes" errors.
.NOTES
    Version: 4.1 - Scope Grouping Edition  
    Requirements: PowerShell 7.0+, Global Administrator role
    Author: CB & Claude Partnership - 365 Engineers
    Philosophy: "Download what you need, when you need it - with the right permissions"
#>

# ===================================================================
# SMART SCOPE CONFIGURATION - PREVENTS "TOO MANY SCOPES" ERRORS
# ===================================================================

$script:ScopeGroups = @{
    'Core' = @(
        "User.ReadWrite.All",
        "Group.ReadWrite.All", 
        "Directory.ReadWrite.All"
    )
    
    'Policy' = @(
        "Policy.ReadWrite.ConditionalAccess"
    )
    
    'Collaboration' = @(
        "Sites.ReadWrite.All",
        "Mail.ReadWrite",
        "Calendars.ReadWrite"
    )
    
    'Security' = @(
        "SecurityEvents.ReadWrite.All",
        "ThreatIndicators.ReadWrite.OwnedBy"
    )
}

# === Operation to Scope Group Mapping ===
$script:OperationScopes = @{
    'Groups' = @('Core')
    'ConditionalAccess' = @('Core', 'Policy')
    'Users' = @('Core')
    'SharePoint' = @('Core', 'Collaboration')
    'Intune' = @('Core', 'Policy')
    'Documentation' = @('Core')  # Read-only operations
    'AdminCreation' = @('Core')
}

$script:Config = @{
    LogFile = "$env:USERPROFILE\Documents\M365TenantSetup_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    
    # MINIMAL required modules - only for basic orchestration
    RequiredModules = @(
        "Microsoft.Graph.Authentication"  # Only auth module - 30x faster than full Graph
    )
}

# GitHub Module Configuration - Your Proven System
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

# Global Variables
$script:TenantState = $null
$script:LogInitialized = $false

# ===================================================================
# CORE UTILITY FUNCTIONS - OPTIMIZED FOR SPEED
# ===================================================================

function Initialize-Logging {
    <#
    .SYNOPSIS
        Lightning-fast logging initialization
    #>
    try {
        $logDirectory = Split-Path -Path $script:Config.LogFile -Parent
        if (-not (Test-Path -Path $logDirectory)) {
            New-Item -Path $logDirectory -ItemType Directory -Force | Out-Null
        }
        
        $logHeader = @"
=================================================================
M365 Tenant Setup Orchestrator - Scope Grouping Edition
PowerShell Version: $($PSVersionTable.PSVersion)
PowerShell Edition: $($PSVersionTable.PSEdition)
Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Strategy: Smart scope management + Download modules as needed
=================================================================

"@
        
        $logHeader | Out-File -FilePath $script:Config.LogFile -Encoding UTF8
        $script:LogInitialized = $true
        return $true
    }
    catch {
        Write-Warning "Logging initialization failed: $($_.Exception.Message)"
        $script:LogInitialized = $false
        return $false
    }
}

function Write-LogMessage {
    <#
    .SYNOPSIS
        Fast logging with console output
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Type = 'Info',
        
        [Parameter(Mandatory = $false)]
        [switch]$LogOnly
    )
    
    $timestamp = Get-Date -Format 'HH:mm:ss'
    $logEntry = "[$timestamp] $Message"
    
    # Console output with colors (unless LogOnly is specified)
    if (-not $LogOnly) {
        switch ($Type) {
            'Success' { Write-Host $logEntry -ForegroundColor Green }
            'Warning' { Write-Host $logEntry -ForegroundColor Yellow }
            'Error' { Write-Host $logEntry -ForegroundColor Red }
            default { Write-Host $logEntry -ForegroundColor White }
        }
    }
    
    # Log to file if available
    if ($script:LogInitialized) {
        try {
            $fileEntry = "[$timestamp] [$Type] $Message"
            $fileEntry | Out-File -FilePath $script:Config.LogFile -Append -Encoding UTF8
        }
        catch { 
            # Silent fail for logging errors
        }
    }
}

# ===================================================================
# SMART SCOPE MANAGEMENT FUNCTIONS
# ===================================================================

function Get-RequiredScopes {
    <#
    .SYNOPSIS
        Returns the required scopes for a specific operation
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Operation
    )
    
    $requiredGroups = $script:OperationScopes[$Operation]
    if (-not $requiredGroups) {
        Write-LogMessage -Message "Unknown operation: $Operation. Using Core scopes." -Type Warning
        $requiredGroups = @('Core')
    }
    
    $allScopes = @()
    foreach ($group in $requiredGroups) {
        $allScopes += $script:ScopeGroups[$group]
    }
    
    return ($allScopes | Select-Object -Unique)
}

function Connect-ToGraphWithScopes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Operation
    )
    
    try {
        $requiredScopes = Get-RequiredScopes -Operation $Operation
        
        # First attempt - normal connection
        Write-LogMessage -Message "Connecting to Microsoft Graph for $Operation operations..." -Type Info
        Write-LogMessage -Message "Required scopes: $($requiredScopes -join ', ')" -Type Info
        
        # Clear any existing connection first
        try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
        
        # Attempt 1: Standard connection
        Connect-MgGraph -Scopes $requiredScopes -NoWelcome -ErrorAction Stop | Out-Null
        
        # Test if we actually got the permissions we need
        $testResult = Test-ActualPermissions -Operation $Operation -RequiredScopes $requiredScopes
        
        if ($testResult.Success) {
            $context = Get-MgContext
            Write-LogMessage -Message "Connected successfully with all required permissions" -Type Success
            Write-LogMessage -Message "Account: $($context.Account)" -Type Info
            return $true
        }
        else {
            Write-LogMessage -Message "Connection successful but missing actual permissions" -Type Warning
            Write-LogMessage -Message "Attempting interactive consent..." -Type Info
            
            # Attempt 2: Force interactive consent
            Disconnect-MgGraph | Out-Null
            Connect-MgGraph -Scopes $requiredScopes -UseDeviceAuthentication -ErrorAction Stop | Out-Null
            
            # Test again
            $testResult = Test-ActualPermissions -Operation $Operation -RequiredScopes $requiredScopes
            
            if ($testResult.Success) {
                Write-LogMessage -Message "Interactive consent successful!" -Type Success
                return $true
            }
            else {
                Write-LogMessage -Message "Even interactive consent failed. Admin consent required." -Type Error
                Write-LogMessage -Message "Please grant admin consent in Azure Portal:" -Type Error
                Write-LogMessage -Message "Azure Portal → App registrations → Microsoft Graph PowerShell → API permissions → Grant admin consent" -Type Error
                return $false
            }
        }
    }
    catch {
        Write-LogMessage -Message "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -Type Error
        return $false
    }
}

function Test-ActualPermissions {
    param(
        [string]$Operation,
        [array]$RequiredScopes
    )
    
    try {
        # Test the actual API endpoint for the operation
        switch ($Operation) {
            "ConditionalAccess" {
                $testCall = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?`$top=1" -ErrorAction Stop
                Write-LogMessage -Message "✅ Conditional Access API test successful" -Type Success
            }
            "Groups" {
                $testCall = Get-MgGroup -Top 1 -ErrorAction Stop
                Write-LogMessage -Message "✅ Groups API test successful" -Type Success
            }
            "Users" {
                $testCall = Get-MgUser -Top 1 -ErrorAction Stop
                Write-LogMessage -Message "✅ Users API test successful" -Type Success
            }
            default {
                # Generic test - try to read basic directory info
                $testCall = Get-MgOrganization -ErrorAction Stop
                Write-LogMessage -Message "✅ Basic Graph API test successful" -Type Success
            }
        }
        
        return @{ Success = $true }
    }
    catch {
        Write-LogMessage -Message "❌ API test failed: $($_.Exception.Message)" -Type Warning
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

function Connect-ForVerification {
    <#
    .SYNOPSIS
        Initial connection for tenant verification with core scopes
    #>
    try {
        Write-LogMessage -Message "Connecting for tenant verification..." -Type Info
        
        # Clear any existing connections
        try { 
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null 
        } 
        catch { 
            # Ignore disconnect errors
        }
        
        # Connect with core scopes for verification
        $coreScopes = $script:ScopeGroups['Core'] + @("Organization.Read.All")
        Connect-MgGraph -Scopes $coreScopes -NoWelcome -ErrorAction Stop | Out-Null
        
        # Quick tenant verification
        $org = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1
        $domains = Get-MgDomain -ErrorAction Stop
        $defaultDomain = $domains | Where-Object { $_.IsDefault -eq $true }
        
        # Display tenant info
        Write-Host ""
        Write-Host "=== TENANT VERIFICATION ===" -ForegroundColor Cyan
        Write-Host "Organization: $($org.DisplayName)" -ForegroundColor Green
        Write-Host "Default Domain: $($defaultDomain.Id)" -ForegroundColor Green
        Write-Host "Total Domains: $($domains.Count)" -ForegroundColor Green
        Write-Host "===========================" -ForegroundColor Cyan
        Write-Host ""
        
        $confirmation = Read-Host "Is this the correct tenant? (Y/N)"
        if ($confirmation -ne 'Y' -and $confirmation -ne 'y') {
            Write-LogMessage -Message "Tenant verification cancelled" -Type Warning
            return $false
        }
        
        # Save minimal tenant state
        $script:TenantState = @{
            DefaultDomain = $defaultDomain.Id
            TenantName = $org.DisplayName
            TenantId = $org.Id
            VerifiedAt = Get-Date
        }
        
        Write-LogMessage -Message "Tenant verified successfully" -Type Success
        return $true
    }
    catch {
        Write-LogMessage -Message "Verification failed: $($_.Exception.Message)" -Type Error
        return $false
    }
}

# ===================================================================
# MINIMAL MODULE MANAGEMENT - AUTHENTICATION ONLY
# ===================================================================

function Install-MinimalModules {
    <#
    .SYNOPSIS
        Installs only the absolute minimum for orchestration
    #>
    Write-LogMessage -Message "Installing minimal modules for orchestration..." -Type Info
    
    foreach ($module in $script:Config.RequiredModules) {
        try {
            if (-not (Get-Module -ListAvailable -Name $module)) {
                Write-LogMessage -Message "Installing: $module" -Type Info
                Install-Module -Name $module -Repository PSGallery -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
            }
            
            if (-not (Get-Module -Name $module)) {
                Import-Module -Name $module -Force -ErrorAction Stop
            }
            
            Write-LogMessage -Message "Ready: $module" -Type Success
        }
        catch {
            Write-LogMessage -Message "Failed to install $module - $($_.Exception.Message)" -Type Error
            return $false
        }
    }
    
    Write-LogMessage -Message "Minimal modules ready - startup optimized!" -Type Success
    return $true
}

# ===================================================================
# GITHUB MODULE SYSTEM - YOUR PROVEN ARCHITECTURE
# ===================================================================

function Initialize-ModuleCache {
    <#
    .SYNOPSIS
        Initialize local cache for GitHub modules
    #>
    try {
        if (-not (Test-Path -Path $script:GitHubConfig.CacheDirectory)) {
            New-Item -Path $script:GitHubConfig.CacheDirectory -ItemType Directory -Force | Out-Null
        }
        return $true
    }
    catch {
        Write-LogMessage -Message "Cache initialization failed: $($_.Exception.Message)" -Type Error
        return $false
    }
}

function Get-ModuleFromGitHub {
    <#
    .SYNOPSIS
        Downloads and caches module from GitHub
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName
    )
    
    if (-not $script:GitHubConfig.ModuleFiles.ContainsKey($ModuleName)) {
        Write-LogMessage -Message "Unknown module: $ModuleName" -Type Error
        return $false
    }
    
    $moduleFileName = $script:GitHubConfig.ModuleFiles[$ModuleName]
    $moduleUrl = "$($script:GitHubConfig.BaseUrl)/$moduleFileName"
    $localPath = Join-Path -Path $script:GitHubConfig.CacheDirectory -ChildPath $moduleFileName
    
    try {
        Write-LogMessage -Message "Downloading: $ModuleName from GitHub..." -Type Info
        Invoke-WebRequest -Uri $moduleUrl -OutFile $localPath -ErrorAction Stop
        Write-LogMessage -Message "Cached: $moduleFileName" -Type Success
        return $true
    }
    catch {
        Write-LogMessage -Message "Download failed for $ModuleName - $($_.Exception.Message)" -Type Error
        return $false
    }
}

function Invoke-ModuleOperationWithAuth {
    <#
    .SYNOPSIS
        Downloads, executes, and manages module operations with smart scope management
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName,
        
        [Parameter(Mandatory = $true)]
        [string]$FunctionName
    )
    
    try {
        Write-LogMessage -Message "Starting $ModuleName operation..." -Type Info
        
        # Connect with operation-specific scopes
        $connected = Connect-ToGraphWithScopes -Operation $ModuleName
        if (-not $connected) {
            Write-LogMessage -Message "Failed to establish Graph connection for $ModuleName" -Type Error
            return $false
        }
        
        # Ensure cache exists
        if (-not (Initialize-ModuleCache)) {
            return $false
        }
        
        # Download module
        if (-not (Get-ModuleFromGitHub -ModuleName $ModuleName)) {
            return $false
        }
        
        # Execute module
        $moduleFileName = $script:GitHubConfig.ModuleFiles[$ModuleName]
        $localPath = Join-Path -Path $script:GitHubConfig.CacheDirectory -ChildPath $moduleFileName
        
        Write-LogMessage -Message "Executing: $ModuleName -> $FunctionName" -Type Info
        
        # Dot-source and execute with TenantState parameter
        . $localPath
        
        # Execute function without parameters - modules handle TenantState via script scope
$result = & $FunctionName
        
        if ($result) {
            Write-LogMessage -Message "$ModuleName operation completed successfully" -Type Success
            return $true
        } else {
            Write-LogMessage -Message "$ModuleName operation failed" -Type Error
            return $false
        }
    }
    catch {
        Write-LogMessage -Message "Error in $ModuleName operation: $($_.Exception.Message)" -Type Error
        
        # Enhanced Graph API error logging
        if ($_.Exception) {
            # Check for Graph API response errors
            if ($_.Exception.Response) {
                try {
                    $errorDetails = $_.Exception.Response.Content.ReadAsStringAsync().Result
                    Write-LogMessage -Message "=== GRAPH API ERROR DETAILS ===" -Type Error
                    Write-LogMessage -Message "Status Code: $($_.Exception.Response.StatusCode)" -Type Error
                    Write-LogMessage -Message "Response Body: $errorDetails" -Type Error
                    Write-LogMessage -Message "================================" -Type Error
                }
                catch {
                    Write-LogMessage -Message "Could not read Graph API error response details" -Type Warning
                }
            }
            
            # Check for PowerShell-specific errors
            if ($_.Exception.InnerException) {
                Write-LogMessage -Message "Inner Exception: $($_.Exception.InnerException.Message)" -Type Error
            }
            
            # Log the full error record for debugging
            Write-LogMessage -Message "Full Error Details: $($_ | Out-String)" -Type Error -LogOnly
        }
        
        return $false
    }
}

# ===================================================================
# MENU SYSTEM - CLEAN AND FAST
# ===================================================================

function Show-Banner {
    Write-Host ""
    Write-Host "+-----------------------------------------------------+" -ForegroundColor Blue
    Write-Host "|  M365 Tenant Setup - Smart Scope Management        |" -ForegroundColor Magenta
    Write-Host "|  Modules downloaded as needed from GitHub           |" -ForegroundColor Magenta  
    Write-Host "+-----------------------------------------------------+" -ForegroundColor Blue
    Write-Host ""
    Write-Host "PowerShell Version: $($PSVersionTable.PSVersion)" -ForegroundColor Cyan
    Write-Host "PowerShell Edition: $($PSVersionTable.PSEdition)" -ForegroundColor Cyan
    Write-Host "Strategy: Right scopes + Download what you need" -ForegroundColor Gray
    Write-Host ""
}

function Show-Menu {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title,
        
        [Parameter(Mandatory = $true)]
        [array]$Options
    )
    
    Clear-Host
    Show-Banner
    Write-Host "== $Title ==" -ForegroundColor Yellow
    Write-Host ""
    
    for ($i = 0; $i -lt $Options.Count; $i++) {
        Write-Host " [$($i + 1)] $($Options[$i])" -ForegroundColor White
    }
    
    Write-Host ""
    $selection = Read-Host "Enter choice (1-$($Options.Count))"
    
    $selectionNumber = $selection -as [int]
    if ($selectionNumber -and $selectionNumber -ge 1 -and $selectionNumber -le $Options.Count) {
        return $selectionNumber
    }
    else {
        Write-Host "Invalid selection. Try again." -ForegroundColor Red
        Start-Sleep -Seconds 1
        return Show-Menu -Title $Title -Options $Options
    }
}

# ===================================================================
# MAIN ORCHESTRATOR - THE HEART OF YOUR SYSTEM
# ===================================================================

function Start-TenantSetup {
    # ▼ CB & Claude | BITS 365 Automation | v1.0 | "Smarter not Harder"
    
    Write-Host "Microsoft 365 Tenant Setup - Smart Scope Management Orchestrator" -ForegroundColor Cyan
    Write-Host "Initializing minimal environment..." -ForegroundColor Gray
    
    # Quick initialization
    Initialize-Logging | Out-Null
    Write-LogMessage -Message "M365 Tenant Setup Orchestrator started with smart scope management" -Type Info
    
    # Install only what we need for orchestration
    $modulesReady = Install-MinimalModules
    if (-not $modulesReady) {
        Write-LogMessage -Message "Critical: Minimal modules failed to install" -Type Error
        Read-Host "Press Enter to exit"
        return
    }
    
    # Initialize GitHub module cache
    Initialize-ModuleCache | Out-Null
    
    # Main menu loop
    $exitScript = $false
    while (-not $exitScript) {
        
        # Dynamic menu based on connection status
        $isConnected = $null -ne (Get-MgContext)
        
        if (-not $isConnected) {
            # Pre-authentication menu
            $choice = Show-Menu -Title "Main Menu (Authentication Required)" -Options @(
                "Connect to Microsoft Graph and Verify Tenant"
                "Refresh Module Cache from GitHub"
                "Exit"
            )
            
            switch ($choice) {
                1 {
                    $connected = Connect-ForVerification
                    if ($connected) {
                        Write-LogMessage -Message "Tenant verified and ready" -Type Success
                    }
                    Read-Host "Press Enter to continue"
                }
                2 {
                    Write-LogMessage -Message "Clearing module cache..." -Type Info
                    if (Test-Path $script:GitHubConfig.CacheDirectory) {
                        Remove-Item $script:GitHubConfig.CacheDirectory -Recurse -Force -ErrorAction SilentlyContinue
                    }
                    Initialize-ModuleCache | Out-Null
                    Write-LogMessage -Message "Module cache refreshed" -Type Success
                    Read-Host "Press Enter to continue"
                }
                3 { 
                    $exitScript = $true 
                }
            }
        }
        else {
            # Full menu when connected
            $currentUser = (Get-MgContext).Account
            $choice = Show-Menu -Title "Main Menu (Connected: $currentUser)" -Options @(
                "Reconnect to Microsoft Graph"
                "Refresh Module Cache from GitHub"
                "Create Security and License Groups"
                "Configure Conditional Access Policies"
                "Set Up SharePoint Sites"
                "Configure Intune Policies (Comprehensive)"
                "Create Users from Excel"
                "Create Admin Helpdesk Role"
                "Generate Documentation"  
                "Debug Excel File (Password Check)"
                "Exit"
            )
            
            switch ($choice) {
                1 {
                    $connected = Connect-ForVerification
                    Read-Host "Press Enter to continue"
                }
                2 {
                    Write-LogMessage -Message "Refreshing GitHub modules..." -Type Info
                    if (Test-Path $script:GitHubConfig.CacheDirectory) {
                        Remove-Item $script:GitHubConfig.CacheDirectory -Recurse -Force -ErrorAction SilentlyContinue
                    }
                    Initialize-ModuleCache | Out-Null
                    Write-LogMessage -Message "Module cache refreshed - latest versions ready" -Type Success
                    Read-Host "Press Enter to continue"
                }
                3 {
                    Write-LogMessage -Message "Launching: Groups Module with Core scopes" -Type Info
                    Invoke-ModuleOperationWithAuth -ModuleName "Groups" -FunctionName "New-TenantGroups" | Out-Null
                    Read-Host "Press Enter to continue"
                }
                4 {
                    Write-LogMessage -Message "Launching: Conditional Access Module with Core+Policy scopes" -Type Info
                    Invoke-ModuleOperationWithAuth -ModuleName "ConditionalAccess" -FunctionName "New-TenantCAPolices" | Out-Null
                    Read-Host "Press Enter to continue"
                }
                5 {
                    Write-LogMessage -Message "Launching: SharePoint Module with Core+Collaboration scopes" -Type Info
                    Invoke-ModuleOperationWithAuth -ModuleName "SharePoint" -FunctionName "New-TenantSharePoint" | Out-Null
                    Read-Host "Press Enter to continue"
                }
                6 {
                    Write-LogMessage -Message "Launching: Intune Module with Core+Policy scopes" -Type Info
                    Invoke-ModuleOperationWithAuth -ModuleName "Intune" -FunctionName "New-TenantIntune" | Out-Null
                    Read-Host "Press Enter to continue"
                }
                7 {
                    Write-LogMessage -Message "Launching: User Creation Module with Core scopes" -Type Info
                    Invoke-ModuleOperationWithAuth -ModuleName "Users" -FunctionName "New-TenantUsers" | Out-Null
                    Read-Host "Press Enter to continue"
                }
                8 {
                    Write-LogMessage -Message "Launching: Admin Role Creation Module with Core scopes" -Type Info
                    Invoke-ModuleOperationWithAuth -ModuleName "AdminCreation" -FunctionName "New-AdminHelpdeskRole" | Out-Null
                    Read-Host "Press Enter to continue"
                }
                9 {
                    Write-LogMessage -Message "Launching: Documentation Module with Core scopes" -Type Info
                    Invoke-ModuleOperationWithAuth -ModuleName "Documentation" -FunctionName "New-TenantDocumentation" | Out-Null
                    Read-Host "Press Enter to continue"
                }
                10 {
                    Write-LogMessage -Message "Excel debugging functionality" -Type Info
                    Write-Host "This will be handled by the Users module when executed." -ForegroundColor Yellow
                    Read-Host "Press Enter to continue"
                }
                11 { 
                    $exitScript = $true 
                }
            }
        }
    }
    
    # Cleanup
    Write-LogMessage -Message "Session ended - cleanup initiated" -Type Info
    
    try {
        Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
    }
    catch {
        # Ignore disconnect errors
    }
    
    Write-Host ""
    Write-Host "Thank you for using the M365 Tenant Setup Orchestrator!" -ForegroundColor Cyan
    Write-Host "Smart Scopes • Module-on-Demand • Always Current" -ForegroundColor Gray
    Write-Host "Session log: $($script:Config.LogFile)" -ForegroundColor Gray
    Write-Host ""
    
    # ▼ CB & Claude | BITS 365 Automation | v1.0 | "Smarter not Harder"
}

# ===================================================================
# SCRIPT ENTRY POINT
# ===================================================================

# PowerShell version check
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Warning "PowerShell 7+ recommended. Current: $($PSVersionTable.PSVersion)"
    Write-Host "Get PowerShell 7: https://aka.ms/powershell" -ForegroundColor Yellow
}

# Check execution policy (informational)
$currentPolicy = Get-ExecutionPolicy
if ($currentPolicy -eq 'Restricted') {
    Write-Host "Execution Policy is Restricted. Consider: Set-ExecutionPolicy RemoteSigned -Scope CurrentUser" -ForegroundColor Yellow
}

# Start the smart scope orchestrator
Start-TenantSetup

# ▼ CB & Claude | BITS 365 Automation | v1.0 | "Smarter not Harder"