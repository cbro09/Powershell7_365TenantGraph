#requires -Version 7.0
<#
.SYNOPSIS
    SharePoint Sites Module - PowerShell 7 Compatible
.DESCRIPTION
    Creates and configures SharePoint sites in hub and spoke architecture.
    Supports two creation modes: Standard (auto-complete) and Interactive (custom configuration).
    
    Features:
    - Hub and spoke site architecture
    - Security group creation and assignment  
    - Site template configuration
    - Storage quota management
    - Navigation and permissions setup
    
    Mode 1 - Standard Creation: 
    - Auto-extracts tenant name from tenant state
    - Creates predefined sites (HR, Finance, IT, Projects, Marketing)
    - Root site as hub with spoke sites
    - Auto-creates security groups
    
    Mode 2 - Interactive Configuration:
    - Custom site names and configurations
    - Hub site selection and customization
    - Site template selection
    - Custom owners and storage quotas
    
.NOTES
    Version: 2.0
    Requirements: PowerShell 7.0 or later
    Author: 365 Engineer
    Dependencies: Microsoft.Online.SharePoint.PowerShell, Microsoft.Graph.Groups
    Prerequisites: SharePoint Administrator permissions required
    
    Security Note: Creates security groups for site access control
#>

# === Automatic Module Management ===
$RequiredModules = @(
    'Microsoft.Online.SharePoint.PowerShell',
    'Microsoft.Graph.Groups',
    'Microsoft.Graph.Identity.DirectoryManagement'
)

foreach ($Module in $RequiredModules) {
    if (!(Get-Module -ListAvailable -Name $Module)) {
        Write-LogMessage -Message "Installing $Module module..." -Type Info
        Install-Module $Module -Force -Scope CurrentUser -AllowClobber
        Write-LogMessage -Message "$Module module installed successfully" -Type Success
    }
    if (!(Get-Module -Name $Module)) {
        Import-Module $Module -Force
        Write-LogMessage -Message "$Module module imported" -Type Info
    }
}

# === Configuration ===
$SharePointConfig = @{
    DefaultSites = @("HR", "Finance", "IT", "Projects", "Marketing")
    StorageQuota = 1024  # MB
    SiteTemplate = "STS#3"  # Modern Team Site
    HubSiteTemplate = "SITEPAGEPUBLISHING#0"  # Communication Site for hub
}

# === Main SharePoint Function ===
function New-TenantSharePoint {
    <#
    .SYNOPSIS
        Creates SharePoint sites with hub and spoke architecture
    .DESCRIPTION
        Main function that provides two creation modes for SharePoint site setup.
        Updates tenant state with created site information.
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-LogMessage -Message "Starting SharePoint sites creation process..." -Type Info
        
        # Verify Graph connection
        if (-not (Get-MgContext)) {
            Write-LogMessage -Message "Not connected to Microsoft Graph. Please connect first." -Type Error
            return $false
        }
        
        # Verify tenant state
        if (-not $script:TenantState) {
            Write-LogMessage -Message "No tenant state found. Please connect and verify tenant first." -Type Error
            return $false
        }
        
        # Check prerequisites
        if (-not (Test-SharePointPrerequisites)) {
            Write-LogMessage -Message "Prerequisites not met for SharePoint site creation" -Type Error
            return $false
        }
        
        Write-LogMessage -Message "Tenant: $($script:TenantState.TenantName)" -Type Info
        Write-LogMessage -Message "Admin: $($script:TenantState.AdminEmail)" -Type Info
        
        # Show mode selection
        Write-Host ""
        Write-Host "=== SharePoint Creation Modes ===" -ForegroundColor Cyan
        Write-Host "[1] Standard Creation (Auto-Complete)" -ForegroundColor White
        Write-Host "    - Creates predefined sites automatically" -ForegroundColor Gray
        Write-Host "    - Uses tenant name for URLs" -ForegroundColor Gray
        Write-Host "    - Default security groups and permissions" -ForegroundColor Gray
        Write-Host ""
        Write-Host "[2] Interactive Configuration" -ForegroundColor White
        Write-Host "    - Custom site names and settings" -ForegroundColor Gray
        Write-Host "    - Hub site customization" -ForegroundColor Gray
        Write-Host "    - Site template and owner selection" -ForegroundColor Gray
        Write-Host ""
        
        $modeChoice = Read-Host "Select creation mode (1-2)"
        
        switch ($modeChoice) {
            "1" {
                Write-LogMessage -Message "Using Standard Creation mode" -Type Info
                return New-SharePointStandard
            }
            "2" {
                Write-LogMessage -Message "Using Interactive Configuration mode" -Type Info
                return New-SharePointInteractive
            }
            default {
                Write-LogMessage -Message "Invalid selection. Please choose 1 or 2." -Type Warning
                return $false
            }
        }
        
    }
    catch {
        Write-LogMessage -Message "Error in SharePoint sites creation process - $($_.Exception.Message)" -Type Error
        return $false
    }
}

# === Mode 1: Standard Creation ===
function New-SharePointStandard {
    <#
    .SYNOPSIS
        Creates SharePoint sites using standard configuration
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-LogMessage -Message "Starting Standard SharePoint creation..." -Type Info
        
        # Get tenant information
        $tenantName = $script:TenantState.TenantName
        $adminEmail = $script:TenantState.AdminEmail
        
        # Auto-extract SharePoint tenant name from admin email or ask user
        $tenantDomain = $adminEmail.Split('@')[1]
        $spTenantName = $tenantDomain.Split('.')[0]
        
        Write-Host ""
        Write-Host "Detected SharePoint tenant: $spTenantName" -ForegroundColor Cyan
        Write-Host "This will create admin URL: https://$spTenantName-admin.sharepoint.com" -ForegroundColor Gray
        $confirm = Read-Host "Is this correct? (Y/N) [Y]"
        
        if ($confirm -eq 'N' -or $confirm -eq 'n') {
            Write-Host ""
            Write-Host "Please enter your SharePoint tenant name." -ForegroundColor Yellow
            Write-Host "Examples:" -ForegroundColor Gray
            Write-Host "  If your SharePoint URL is contoso.sharepoint.com → enter 'contoso'" -ForegroundColor Gray
            Write-Host "  If your SharePoint URL is fabrikam.sharepoint.com → enter 'fabrikam'" -ForegroundColor Gray
            Write-Host ""
            $spTenantName = Read-Host "SharePoint tenant name (without .sharepoint.com)"
            
            if ([string]::IsNullOrWhiteSpace($spTenantName)) {
                Write-LogMessage -Message "Tenant name cannot be empty" -Type Error
                return $false
            }
        }
        
        # Validate and construct SharePoint URLs
        $adminUrl = "https://$spTenantName-admin.sharepoint.com"
        $tenantUrl = "https://$spTenantName.sharepoint.com"
        $hubSiteUrl = $tenantUrl  # Use root site as hub
        
        Write-LogMessage -Message "SharePoint Admin URL: $adminUrl" -Type Info
        Write-LogMessage -Message "SharePoint Tenant URL: $tenantUrl" -Type Info
        Write-LogMessage -Message "Hub Site URL: $hubSiteUrl" -Type Info
        
        # Validate tenant URL format
        if (-not (Test-SharePointTenantUrl -TenantName $spTenantName)) {
            Write-LogMessage -Message "Invalid SharePoint tenant name format" -Type Error
            return $false
        }
        
        # Connect to SharePoint Online
        if (-not (Connect-SharePointOnline -AdminUrl $adminUrl)) {
            return $false
        }
        
        # Configure hub site
        $hubConfigured = Configure-HubSite -HubSiteUrl $hubSiteUrl -TenantName $tenantName -AdminEmail $adminEmail
        if (-not $hubConfigured) {
            Write-LogMessage -Message "Hub site configuration failed" -Type Error
            return $false
        }
        
        # Create spoke sites
        $spokeSites = @()
        foreach ($siteName in $SharePointConfig.DefaultSites) {
            $spokeSites += @{
                Name = $siteName
                URL = "$tenantUrl/sites/$($siteName.ToLower())"
                Owner = $adminEmail
                Template = $SharePointConfig.SiteTemplate
                StorageQuota = $SharePointConfig.StorageQuota
            }
        }
        
        $createdSites = Create-SpokeSites -SpokeSites $spokeSites -HubSiteUrl $hubSiteUrl
        if ($createdSites.Count -eq 0) {
            Write-LogMessage -Message "No spoke sites were created successfully" -Type Error
            return $false
        }
        
        # Create security groups
        $securityGroups = Create-SecurityGroups -Sites $spokeSites -IncludeHub $true -HubName $tenantName
        
        # Associate spoke sites with hub
        $hubAssociations = Associate-SitesWithHub -SpokeSites $spokeSites -HubSiteUrl $hubSiteUrl
        
        # Update tenant state
        Update-SharePointTenantState -CreatedSites $createdSites -SecurityGroups $securityGroups -HubSiteUrl $hubSiteUrl
        
        # Display results
        Show-SharePointResults -Mode "Standard" -CreatedSites $createdSites -SecurityGroups $securityGroups -HubSiteUrl $hubSiteUrl
        
        return $true
        
    }
    catch {
        Write-LogMessage -Message "Error in Standard SharePoint creation - $($_.Exception.Message)" -Type Error
        return $false
    }
}

# === Mode 2: Interactive Configuration ===
function New-SharePointInteractive {
    <#
    .SYNOPSIS
        Creates SharePoint sites using interactive configuration
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-LogMessage -Message "Starting Interactive SharePoint configuration..." -Type Info
        
        # Get tenant information
        $tenantName = $script:TenantState.TenantName
        $adminEmail = $script:TenantState.AdminEmail
        
        # Get SharePoint tenant name
        $tenantDomain = $adminEmail.Split('@')[1]
        $defaultSpTenant = $tenantDomain.Split('.')[0]
        
        Write-Host ""
        Write-Host "=== SharePoint Tenant Configuration ===" -ForegroundColor Cyan
        Write-Host "Detected tenant: $defaultSpTenant" -ForegroundColor Gray
        Write-Host "This will create admin URL: https://$defaultSpTenant-admin.sharepoint.com" -ForegroundColor Gray
        Write-Host ""
        $spTenantName = Read-Host "SharePoint tenant name [$defaultSpTenant]"
        if ([string]::IsNullOrWhiteSpace($spTenantName)) {
            $spTenantName = $defaultSpTenant
        }
        
        # Validate tenant URL format
        if (-not (Test-SharePointTenantUrl -TenantName $spTenantName)) {
            Write-LogMessage -Message "Invalid SharePoint tenant name format" -Type Error
            return $false
        }
        
        # Construct SharePoint URLs
        $adminUrl = "https://$spTenantName-admin.sharepoint.com"
        $tenantUrl = "https://$spTenantName.sharepoint.com"
        
        Write-LogMessage -Message "SharePoint Admin URL: $adminUrl" -Type Info
        Write-LogMessage -Message "SharePoint Tenant URL: $tenantUrl" -Type Info
        
        # Connect to SharePoint Online
        if (-not (Connect-SharePointOnline -AdminUrl $adminUrl)) {
            return $false
        }
        
        # Hub site configuration
        Write-Host ""
        Write-Host "=== Hub Site Configuration ===" -ForegroundColor Cyan
        Write-Host "[1] Use root site as hub (recommended)" -ForegroundColor White
        Write-Host "[2] Create new communication site as hub" -ForegroundColor White
        Write-Host "[3] Use existing site as hub" -ForegroundColor White
        
        $hubChoice = Read-Host "Select hub option (1-3) [1]"
        if ([string]::IsNullOrWhiteSpace($hubChoice)) { $hubChoice = "1" }
        
        $hubSiteUrl = ""
        $hubSiteName = ""
        
        switch ($hubChoice) {
            "1" {
                $hubSiteUrl = $tenantUrl
                $hubSiteName = "$tenantName Hub"
                Write-LogMessage -Message "Using root site as hub: $hubSiteUrl" -Type Info
            }
            "2" {
                $hubSiteName = Read-Host "Enter hub site name [$tenantName Hub]"
                if ([string]::IsNullOrWhiteSpace($hubSiteName)) { $hubSiteName = "$tenantName Hub" }
                $hubSiteUrl = "$tenantUrl/sites/$(($hubSiteName -replace '\s', '').ToLower())"
                Write-LogMessage -Message "Will create new hub site: $hubSiteUrl" -Type Info
            }
            "3" {
                $hubSiteUrl = Read-Host "Enter existing hub site URL"
                $hubSiteName = "Existing Hub"
                Write-LogMessage -Message "Using existing hub site: $hubSiteUrl" -Type Info
            }
        }
        
        # Configure or create hub site
        if ($hubChoice -eq "2") {
            $hubCreated = Create-CommunicationSite -SiteUrl $hubSiteUrl -SiteName $hubSiteName -Owner $adminEmail
            if (-not $hubCreated) {
                Write-LogMessage -Message "Failed to create hub site" -Type Error
                return $false
            }
        }
        
        $hubConfigured = Configure-HubSite -HubSiteUrl $hubSiteUrl -TenantName $hubSiteName -AdminEmail $adminEmail
        if (-not $hubConfigured) {
            Write-LogMessage -Message "Hub site configuration failed" -Type Error
            return $false
        }
        
        # Site creation configuration
        Write-Host ""
        Write-Host "=== Site Creation Configuration ===" -ForegroundColor Cyan
        $siteCount = Read-Host "How many sites do you want to create? [5]"
        if ([string]::IsNullOrWhiteSpace($siteCount)) { $siteCount = 5 }
        
        $spokeSites = @()
        for ($i = 1; $i -le [int]$siteCount; $i++) {
            Write-Host ""
            Write-Host "--- Site $i Configuration ---" -ForegroundColor Yellow
            
            $siteName = Read-Host "Site $i name"
            if ([string]::IsNullOrWhiteSpace($siteName)) {
                Write-LogMessage -Message "Site name cannot be empty. Skipping site $i." -Type Warning
                continue
            }
            
            $siteUrl = "$tenantUrl/sites/$($siteName.ToLower() -replace '\s', '')"
            Write-Host "Site URL will be: $siteUrl" -ForegroundColor Gray
            
            # Site template selection
            Write-Host "Site templates:" -ForegroundColor Cyan
            Write-Host "[1] Team Site (collaboration)" -ForegroundColor White
            Write-Host "[2] Communication Site (publishing)" -ForegroundColor White
            $templateChoice = Read-Host "Select template (1-2) [1]"
            
            $template = $SharePointConfig.SiteTemplate  # Default team site
            if ($templateChoice -eq "2") {
                $template = "SITEPAGEPUBLISHING#0"  # Communication site
            }
            
            # Owner selection
            $owner = Read-Host "Site owner email [$adminEmail]"
            if ([string]::IsNullOrWhiteSpace($owner)) { $owner = $adminEmail }
            
            # Storage quota
            $storageQuota = Read-Host "Storage quota in MB [$($SharePointConfig.StorageQuota)]"
            if ([string]::IsNullOrWhiteSpace($storageQuota)) { $storageQuota = $SharePointConfig.StorageQuota }
            
            # Hub association
            $associateWithHub = Read-Host "Associate with hub site? (Y/N) [Y]"
            $hubAssociation = ($associateWithHub -ne 'N' -and $associateWithHub -ne 'n')
            
            $spokeSites += @{
                Name = $siteName
                URL = $siteUrl
                Owner = $owner
                Template = $template
                StorageQuota = [int]$storageQuota
                AssociateWithHub = $hubAssociation
            }
        }
        
        if ($spokeSites.Count -eq 0) {
            Write-LogMessage -Message "No sites configured for creation" -Type Warning
            return $false
        }
        
        # Create spoke sites
        $createdSites = Create-SpokeSites -SpokeSites $spokeSites -HubSiteUrl $hubSiteUrl
        if ($createdSites.Count -eq 0) {
            Write-LogMessage -Message "No spoke sites were created successfully" -Type Error
            return $false
        }
        
        # Create security groups
        $securityGroups = Create-SecurityGroups -Sites $spokeSites -IncludeHub $true -HubName $hubSiteName
        
        # Associate spoke sites with hub
        $hubAssociations = Associate-SitesWithHub -SpokeSites $spokeSites -HubSiteUrl $hubSiteUrl
        
        # Update tenant state
        Update-SharePointTenantState -CreatedSites $createdSites -SecurityGroups $securityGroups -HubSiteUrl $hubSiteUrl
        
        # Display results
        Show-SharePointResults -Mode "Interactive" -CreatedSites $createdSites -SecurityGroups $securityGroups -HubSiteUrl $hubSiteUrl
        
        return $true
        
    }
    catch {
        Write-LogMessage -Message "Error in Interactive SharePoint configuration - $($_.Exception.Message)" -Type Error
        return $false
    }
}

# === Helper Functions ===
function Test-SharePointPrerequisites {
    <#
    .SYNOPSIS
        Tests all prerequisites for SharePoint site creation
    #>
    [CmdletBinding()]
    param()
    
    $prerequisites = @{
        'Graph Connection' = $null -ne (Get-MgContext)
        'Tenant State' = $null -ne $script:TenantState
        'Required Modules' = $true
        'SharePoint Permissions' = $false
    }
    
    # Test required modules
    $missingModules = @()
    foreach ($module in $RequiredModules) {
        if (-not (Get-Module -Name $module)) {
            $missingModules += $module
        }
    }
    $prerequisites['Required Modules'] = $missingModules.Count -eq 0
    
    # Test Graph permissions (basic test)
    try {
        Get-MgGroup -Top 1 -ErrorAction Stop | Out-Null
        $prerequisites['SharePoint Permissions'] = $true
    }
    catch {
        $prerequisites['SharePoint Permissions'] = $false
        Write-LogMessage -Message "SharePoint Administrator permissions may be required" -Type Warning
    }
    
    Write-Host "=== SharePoint Prerequisites ===" -ForegroundColor Cyan
    foreach ($prereq in $prerequisites.GetEnumerator()) {
        $status = if ($prereq.Value) { "✓ Met" } else { "✗ Not Met" }
        $color = if ($prereq.Value) { "Green" } else { "Red" }
        Write-Host ("{0}: " -f $prereq.Key) -ForegroundColor Gray -NoNewline
        Write-Host $status -ForegroundColor $color
    }
    Write-Host ""
    
    return ($prerequisites.Values -notcontains $false)
}

function Test-SharePointTenantUrl {
    <#
    .SYNOPSIS
        Validates SharePoint tenant name format
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantName
    )
    
    # Check for valid characters (letters, numbers, hyphens)
    if ($TenantName -notmatch '^[a-zA-Z0-9\-]+$') {
        Write-LogMessage -Message "Tenant name contains invalid characters. Use only letters, numbers, and hyphens." -Type Error
        return $false
    }
    
    # Check length (typically 3-63 characters)
    if ($TenantName.Length -lt 3 -or $TenantName.Length -gt 63) {
        Write-LogMessage -Message "Tenant name must be between 3 and 63 characters" -Type Error
        return $false
    }
    
    # Check for valid start/end (cannot start or end with hyphen)
    if ($TenantName.StartsWith('-') -or $TenantName.EndsWith('-')) {
        Write-LogMessage -Message "Tenant name cannot start or end with a hyphen" -Type Error
        return $false
    }
    
    Write-LogMessage -Message "SharePoint tenant name format is valid" -Type Success
    return $true
}

function Connect-SharePointOnline {
    <#
    .SYNOPSIS
        Connects to SharePoint Online Admin Center with multiple authentication methods
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AdminUrl
    )
    
    try {
        Write-LogMessage -Message "Connecting to SharePoint Online Admin Center..." -Type Info
        Write-LogMessage -Message "Admin URL: $AdminUrl" -Type Info
        
        # Try multiple connection methods
        $connectionSuccess = $false
        
        # Method 1: Try interactive web login (most reliable)
        try {
            Write-LogMessage -Message "Attempting interactive web authentication..." -Type Info
            Connect-SPOService -Url $AdminUrl -UseWebLogin
            $connectionSuccess = $true
            Write-LogMessage -Message "Connected using interactive web login" -Type Success
        }
        catch {
            Write-LogMessage -Message "Interactive web login failed: $($_.Exception.Message)" -Type Warning
        }
        
        # Method 2: Try modern auth if web login failed
        if (-not $connectionSuccess) {
            try {
                Write-LogMessage -Message "Attempting modern authentication..." -Type Info
                Connect-SPOService -Url $AdminUrl
                $connectionSuccess = $true
                Write-LogMessage -Message "Connected using modern authentication" -Type Success
            }
            catch {
                Write-LogMessage -Message "Modern auth failed: $($_.Exception.Message)" -Type Warning
            }
        }
        
        if (-not $connectionSuccess) {
            Write-LogMessage -Message "All connection methods failed" -Type Error
            Write-LogMessage -Message "Please verify:" -Type Info
            Write-LogMessage -Message "1. You have SharePoint Administrator permissions" -Type Info
            Write-LogMessage -Message "2. The tenant URL is correct: $AdminUrl" -Type Info
            Write-LogMessage -Message "3. SharePoint Online is activated in your tenant" -Type Info
            return $false
        }
        
        # Verify connection and permissions
        try {
            $tenantInfo = Get-SPOTenant -ErrorAction Stop
            Write-LogMessage -Message "Successfully verified SharePoint Administrator permissions" -Type Success
            Write-LogMessage -Message "SharePoint tenant ID: $($tenantInfo.Title)" -Type Info
            return $true
        }
        catch {
            Write-LogMessage -Message "Connected but may not have SharePoint Administrator permissions" -Type Warning
            Write-LogMessage -Message "Some operations may fail. Contact your admin to assign SharePoint Administrator role." -Type Warning
            
            # Ask user if they want to continue
            Write-Host ""
            $continue = Read-Host "Continue anyway? (Y/N) [Y]"
            if ($continue -eq 'N' -or $continue -eq 'n') {
                return $false
            }
            return $true
        }
    }
    catch {
        Write-LogMessage -Message "Failed to connect to SharePoint Online - $($_.Exception.Message)" -Type Error
        Write-LogMessage -Message "Troubleshooting tips:" -Type Info
        Write-LogMessage -Message "1. Verify SharePoint tenant URL format" -Type Info
        Write-LogMessage -Message "2. Check if SharePoint Online is licensed and activated" -Type Info
        Write-LogMessage -Message "3. Ensure you have Global Admin or SharePoint Admin role" -Type Info
        return $false
    }
}

function Configure-HubSite {
    <#
    .SYNOPSIS
        Configures a site as a hub site
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HubSiteUrl,
        
        [Parameter(Mandatory = $true)]
        [string]$TenantName,
        
        [Parameter(Mandatory = $true)]
        [string]$AdminEmail
    )
    
    try {
        Write-LogMessage -Message "Configuring hub site: $HubSiteUrl" -Type Info
        
        # Check if site exists and get its information
        try {
            $siteInfo = Get-SPOSite -Identity $HubSiteUrl -Detailed -ErrorAction Stop
            Write-LogMessage -Message "Hub site found - Title: '$($siteInfo.Title)'" -Type Success
        }
        catch {
            Write-LogMessage -Message "Hub site not accessible or does not exist: $HubSiteUrl" -Type Error
            return $false
        }
        
        # Update site title if needed
        $hubTitle = "$TenantName Hub"
        if ($siteInfo.Title -ne $hubTitle) {
            try {
                Set-SPOSite -Identity $HubSiteUrl -Title $hubTitle -ErrorAction Stop
                Write-LogMessage -Message "Updated hub site title to '$hubTitle'" -Type Success
            }
            catch {
                Write-LogMessage -Message "Could not update hub site title - $($_.Exception.Message)" -Type Warning
            }
        }
        
        # Register as hub site
        try {
            $existingHubs = Get-SPOHubSite -ErrorAction SilentlyContinue
            $isAlreadyHub = $existingHubs | Where-Object { $_.SiteUrl -eq $HubSiteUrl }
            
            if ($isAlreadyHub) {
                Write-LogMessage -Message "Site is already registered as a hub site" -Type Warning
            }
            else {
                Register-SPOHubSite -Site $HubSiteUrl -Principals @($AdminEmail)
                Write-LogMessage -Message "Successfully registered hub site" -Type Success
                Start-Sleep -Seconds 15  # Allow time for registration
            }
        }
        catch {
            Write-LogMessage -Message "Hub site registration failed - $($_.Exception.Message)" -Type Error
            return $false
        }
        
        # Set site collection admin
        try {
            Set-SPOUser -Site $HubSiteUrl -LoginName $AdminEmail -IsSiteCollectionAdmin $true -ErrorAction Stop
            Write-LogMessage -Message "Set site collection admin for hub site" -Type Success
        }
        catch {
            Write-LogMessage -Message "Failed to set site collection admin - $($_.Exception.Message)" -Type Warning
        }
        
        return $true
    }
    catch {
        Write-LogMessage -Message "Error configuring hub site - $($_.Exception.Message)" -Type Error
        return $false
    }
}

function Create-CommunicationSite {
    <#
    .SYNOPSIS
        Creates a new communication site
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SiteUrl,
        
        [Parameter(Mandatory = $true)]
        [string]$SiteName,
        
        [Parameter(Mandatory = $true)]
        [string]$Owner
    )
    
    try {
        Write-LogMessage -Message "Creating communication site: $SiteName" -Type Info
        
        New-SPOSite -Url $SiteUrl -Owner $Owner -StorageQuota $SharePointConfig.StorageQuota -Title $SiteName -Template "SITEPAGEPUBLISHING#0"
        Write-LogMessage -Message "Communication site created: $SiteUrl" -Type Success
        
        # Wait for site provisioning
        Start-Sleep -Seconds 30
        
        return $true
    }
    catch {
        Write-LogMessage -Message "Failed to create communication site - $($_.Exception.Message)" -Type Error
        return $false
    }
}

function Create-SpokeSites {
    <#
    .SYNOPSIS
        Creates spoke sites
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$SpokeSites,
        
        [Parameter(Mandatory = $true)]
        [string]$HubSiteUrl
    )
    
    $createdSites = @()
    
    foreach ($site in $SpokeSites) {
        try {
            Write-LogMessage -Message "Creating site: $($site.Name)" -Type Info
            
            # Check if site already exists
            try {
                $existingSite = Get-SPOSite -Identity $site.URL -ErrorAction Stop
                Write-LogMessage -Message "Site '$($site.Name)' already exists: $($site.URL)" -Type Warning
                $createdSites += $site.URL
                continue
            }
            catch {
                # Site does not exist, proceed with creation
            }
            
            # Create the site
            New-SPOSite -Url $site.URL -Owner $site.Owner -StorageQuota $site.StorageQuota -Title $site.Name -Template $site.Template
            Write-LogMessage -Message "Created site: $($site.Name) at $($site.URL)" -Type Success
            $createdSites += $site.URL
            
        }
        catch {
            if ($_.Exception.Message -like "*already exists*") {
                Write-LogMessage -Message "Site '$($site.Name)' already exists: $($site.URL)" -Type Warning
                $createdSites += $site.URL
            }
            else {
                Write-LogMessage -Message "Failed to create site '$($site.Name)' - $($_.Exception.Message)" -Type Error
            }
        }
    }
    
    if ($createdSites.Count -gt 0) {
        Write-LogMessage -Message "Waiting for site provisioning (2 minutes)..." -Type Info
        Start-Sleep -Seconds 120
    }
    
    return $createdSites
}

function Create-SecurityGroups {
    <#
    .SYNOPSIS
        Creates security groups for SharePoint sites
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Sites,
        
        [Parameter(Mandatory = $false)]
        [bool]$IncludeHub = $false,
        
        [Parameter(Mandatory = $false)]
        [string]$HubName = "Hub"
    )
    
    $securityGroups = @{}
    
    try {
        Write-LogMessage -Message "Creating security groups for SharePoint sites..." -Type Info
        
        # Create hub security groups if requested
        if ($IncludeHub) {
            foreach ($groupType in @("Members", "Owners", "Visitors")) {
                $groupName = "$HubName SharePoint $groupType"
                $mailNickname = "Hub-SPO-$groupType"
                
                $groupId = Create-SecurityGroup -GroupName $groupName -MailNickname $mailNickname
                if ($groupId) {
                    $securityGroups["Hub-$groupType"] = $groupId
                }
            }
        }
        
        # Create spoke site security groups
        foreach ($site in $Sites) {
            $siteName = $site.Name
            Write-LogMessage -Message "Creating security groups for site: $siteName" -Type Info
            
            foreach ($groupType in @("Members", "Owners", "Visitors")) {
                $groupName = "$siteName SharePoint $groupType"
                $mailNickname = "$siteName-SPO-$groupType"
                
                $groupId = Create-SecurityGroup -GroupName $groupName -MailNickname $mailNickname
                if ($groupId) {
                    $securityGroups["$siteName-$groupType"] = $groupId
                }
            }
        }
        
        if ($securityGroups.Count -gt 0) {
            Write-LogMessage -Message "Created $($securityGroups.Count) security groups" -Type Success
            Start-Sleep -Seconds 30  # Allow time for group propagation
        }
        
        return $securityGroups
    }
    catch {
        Write-LogMessage -Message "Error creating security groups - $($_.Exception.Message)" -Type Error
        return @{}
    }
}

function Create-SecurityGroup {
    <#
    .SYNOPSIS
        Creates a single security group
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$GroupName,
        
        [Parameter(Mandatory = $true)]
        [string]$MailNickname
    )
    
    try {
        # Check if group already exists
        $existingGroup = Get-MgGroup -Filter "displayName eq '$GroupName'" -ErrorAction SilentlyContinue
        if ($existingGroup) {
            Write-LogMessage -Message "Security group already exists: $GroupName" -Type Warning
            return $existingGroup.Id
        }
        
        # Create new security group
        $newGroup = New-MgGroup -DisplayName $GroupName -MailEnabled:$false -MailNickname $MailNickname -SecurityEnabled:$true
        Write-LogMessage -Message "Created security group: $GroupName" -Type Success
        return $newGroup.Id
    }
    catch {
        Write-LogMessage -Message "Failed to create security group '$GroupName' - $($_.Exception.Message)" -Type Error
        return $null
    }
}

function Associate-SitesWithHub {
    <#
    .SYNOPSIS
        Associates spoke sites with hub site
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$SpokeSites,
        
        [Parameter(Mandatory = $true)]
        [string]$HubSiteUrl
    )
    
    $successfulAssociations = 0
    
    foreach ($site in $SpokeSites) {
        if ($site.AssociateWithHub -eq $false) {
            Write-LogMessage -Message "Skipping hub association for $($site.Name) (user preference)" -Type Info
            continue
        }
        
        try {
            Add-SPOHubSiteAssociation -Site $site.URL -HubSite $HubSiteUrl -ErrorAction Stop
            Write-LogMessage -Message "Associated $($site.Name) with hub site" -Type Success
            $successfulAssociations++
        }
        catch {
            Write-LogMessage -Message "Failed to associate $($site.Name) with hub - $($_.Exception.Message)" -Type Warning
        }
    }
    
    Write-LogMessage -Message "Successfully associated $successfulAssociations sites with hub" -Type Info
    return $successfulAssociations
}

function Update-SharePointTenantState {
    <#
    .SYNOPSIS
        Updates tenant state with SharePoint information
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$CreatedSites,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$SecurityGroups,
        
        [Parameter(Mandatory = $true)]
        [string]$HubSiteUrl
    )
    
    try {
        $script:TenantState.SharePointSites = @{
            HubSiteUrl = $HubSiteUrl
            CreatedSites = $CreatedSites
            SecurityGroups = $SecurityGroups
            CreationDate = Get-Date
        }
        
        Write-LogMessage -Message "Updated tenant state with SharePoint information" -Type Success
    }
    catch {
        Write-LogMessage -Message "Failed to update tenant state - $($_.Exception.Message)" -Type Warning
    }
}

function Show-SharePointResults {
    <#
    .SYNOPSIS
        Displays SharePoint creation results
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Mode,
        
        [Parameter(Mandatory = $true)]
        [array]$CreatedSites,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$SecurityGroups,
        
        [Parameter(Mandatory = $true)]
        [string]$HubSiteUrl
    )
    
    Write-Host ""
    Write-Host "=== SharePoint Sites Creation Summary ($Mode Mode) ===" -ForegroundColor Cyan
    Write-Host "Hub Site: $HubSiteUrl" -ForegroundColor Green
    Write-Host "Total Sites Created/Configured: $($CreatedSites.Count)" -ForegroundColor Green
    Write-Host "Security Groups Created: $($SecurityGroups.Count)" -ForegroundColor Green
    Write-Host ""
    
    if ($CreatedSites.Count -gt 0) {
        Write-Host "Created Sites:" -ForegroundColor Yellow
        foreach ($siteUrl in $CreatedSites) {
            Write-Host "  - $siteUrl" -ForegroundColor White
        }
        Write-Host ""
    }
    
    if ($SecurityGroups.Count -gt 0) {
        Write-Host "Security Groups Available for Assignment:" -ForegroundColor Yellow
        foreach ($groupKey in $SecurityGroups.Keys) {
            $groupType = $groupKey.Split('-')[-1]
            $siteName = $groupKey.Substring(0, $groupKey.LastIndexOf('-'))
            Write-Host "  - $siteName SharePoint $groupType" -ForegroundColor White
        }
        Write-Host ""
    }
    
    Write-Host "⚠️  IMPORTANT NEXT STEPS:" -ForegroundColor Yellow
    Write-Host "1. Verify all sites are accessible and properly configured" -ForegroundColor Gray
    Write-Host "2. Assign users to appropriate security groups" -ForegroundColor Gray
    Write-Host "3. Configure site permissions and sharing settings" -ForegroundColor Gray
    Write-Host "4. Set up site content and navigation" -ForegroundColor Gray
    Write-Host ""
    
    # Disconnect SharePoint session
    try {
        Disconnect-SPOService
        Write-LogMessage -Message "Disconnected from SharePoint Online" -Type Info
    }
    catch {
        # Ignore disconnect errors
    }
}
