# ▼ CB & Claude | BITS 365 Automation | v1.0 | "Smarter not Harder"

#requires -Version 7.0
<#
.SYNOPSIS
    Microsoft 365 Unified Tenant Setup - Lightweight Orchestrator
.DESCRIPTION
    Fast, lightweight orchestrator that downloads specialized modules as needed.
    Each module handles its own dependencies - keeping the main script lightning fast.
.NOTES
    Version: 4.0 - Lightweight Orchestrator Edition  
    Requirements: PowerShell 7.0+, Global Administrator role
    Author: CB & Claude Partnership - 365 Engineers
    Philosophy: "Download what you need, when you need it"
#>

# ===================================================================
# LIGHTWEIGHT CONFIGURATION - MINIMAL DEPENDENCIES
# ===================================================================

$script:Config = @{
    LogFile = "$env:USERPROFILE\Documents\M365TenantSetup_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    
    # MINIMAL required modules - only for basic orchestration
    RequiredModules = @(
        "Microsoft.Graph.Authentication"  # Only auth module - 30x faster than full Graph
    )
    
    # Basic scopes for tenant verification only
    BasicScopes = @(
        "Organization.Read.All",
        "Directory.Read.All"
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
M365 Tenant Setup Orchestrator - Lightweight Edition
PowerShell Version: $($PSVersionTable.PSVersion)
PowerShell Edition: $($PSVersionTable.PSEdition)
Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Strategy: Download modules as needed for maximum speed
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
# BASIC AUTHENTICATION - TENANT VERIFICATION ONLY
# ===================================================================

function Connect-ForVerification {
    <#
    .SYNOPSIS
        Lightweight connection for tenant verification only
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
        
        # Updated scopes to include Conditional Access permissions
        $requiredScopes = @(
            "Organization.Read.All",
            "Directory.Read.All",
            "Policy.ReadWrite.ConditionalAccess",  # Required for CA policies
            "Group.Read.All"                       # Needed for NoMFA group check
        )
        
        # Connect with all required scopes
        Connect-MgGraph -Scopes $requiredScopes -NoWelcome -ErrorAction Stop | Out-Null
        
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
        
        Write-LogMessage -Message "Tenant verified successfully with required permissions" -Type Success
        return $true
    }
    catch {
        Write-LogMessage -Message "Verification failed: $($_.Exception.Message)" -Type Error
        return $false
    }
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

function Invoke-ModuleFunction {
    <#
    .SYNOPSIS
        Downloads, executes, and manages module operations with enhanced error handling
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName,
        
        [Parameter(Mandatory = $true)]
        [string]$FunctionName
    )
    
    try {
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
        
        # Pass TenantState if it exists
        if ($script:TenantState) {
            $result = & $FunctionName -TenantState $script:TenantState
        } else {
            $result = & $FunctionName
        }
        
        Write-LogMessage -Message "Module execution completed" -Type Success
        return $result
    }
    catch {
        Write-LogMessage -Message "Module execution failed: $($_.Exception.Message)" -Type Error
        
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
    Write-Host "|    M365 Tenant Setup - Lightning Fast Orchestrator |" -ForegroundColor Magenta
    Write-Host "|    Modules downloaded as needed from GitHub         |" -ForegroundColor Magenta  
    Write-Host "+-----------------------------------------------------+" -ForegroundColor Blue
    Write-Host ""
    Write-Host "PowerShell Version: $($PSVersionTable.PSVersion)" -ForegroundColor Cyan
    Write-Host "PowerShell Edition: $($PSVersionTable.PSEdition)" -ForegroundColor Cyan
    Write-Host "Strategy: Download what you need, when you need it" -ForegroundColor Gray
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
    
    Write-Host "Microsoft 365 Tenant Setup - Lightning Fast Orchestrator" -ForegroundColor Cyan
    Write-Host "Initializing minimal environment..." -ForegroundColor Gray
    
    # Quick initialization
    Initialize-Logging | Out-Null
    Write-LogMessage -Message "M365 Tenant Setup Orchestrator started" -Type Info
    
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
                    Write-LogMessage -Message "Launching: Groups Module" -Type Info
                    Invoke-ModuleFunction -ModuleName "Groups" -FunctionName "New-TenantGroups" | Out-Null
                    Read-Host "Press Enter to continue"
                }
                4 {
                    Write-LogMessage -Message "Launching: Conditional Access Module" -Type Info
                    Invoke-ModuleFunction -ModuleName "ConditionalAccess" -FunctionName "New-TenantCAPolices" | Out-Null
                    Read-Host "Press Enter to continue"
                }
                5 {
                    Write-LogMessage -Message "Launching: SharePoint Module" -Type Info
                    Invoke-ModuleFunction -ModuleName "SharePoint" -FunctionName "New-TenantSharePoint" | Out-Null
                    Read-Host "Press Enter to continue"
                }
                6 {
                    Write-LogMessage -Message "Launching: Intune Module (Comprehensive)" -Type Info
                    Invoke-ModuleFunction -ModuleName "Intune" -FunctionName "New-TenantIntune" | Out-Null
                    Read-Host "Press Enter to continue"
                }
                7 {
                    Write-LogMessage -Message "Launching: User Creation Module" -Type Info
                    Invoke-ModuleFunction -ModuleName "Users" -FunctionName "New-TenantUsers" | Out-Null
                    Read-Host "Press Enter to continue"
                }
                8 {
                    Write-LogMessage -Message "Launching: Admin Role Creation Module" -Type Info
                    Invoke-ModuleFunction -ModuleName "AdminCreation" -FunctionName "New-AdminHelpdeskRole" | Out-Null
                    Read-Host "Press Enter to continue"
                }
                9 {
                    Write-LogMessage -Message "Launching: Documentation Module" -Type Info
                    Invoke-ModuleFunction -ModuleName "Documentation" -FunctionName "New-TenantDocumentation" | Out-Null
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
    Write-Host "Lightning Fast • Module-on-Demand • Always Current" -ForegroundColor Gray
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

# Start the lightning-fast orchestrator
Start-TenantSetup

# ▼ CB & Claude | BITS 365 Automation | v1.0 | "Smarter not Harder"