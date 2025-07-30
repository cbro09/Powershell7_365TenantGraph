# ▼ CB & Claude | BITS 365 Automation | v1.0 | "Smarter not Harder"

#requires -Version 7.0
<#
.SYNOPSIS
    SharePoint 5-Sites Creator - PowerShell 7 Fixed Version
.DESCRIPTION
    Creates 5 SharePoint sites with hub architecture using PnP PowerShell.
    Fixed variable parsing issues for PowerShell 7+ compatibility.
    
    Creates:
    - Root site as hub
    - 5 spoke sites: HR, Finance, IT, Projects, Marketing
    - Security groups for each site
    - Hub navigation and associations
    
.NOTES
    Version: 2.1 - PowerShell 7 Parsing Fixed
    Requirements: PowerShell 7.0 or later
    Author: CB & Claude Partnership
    Dependencies: PnP.PowerShell, Microsoft.Graph.Groups
    
    Fixed Issues:
    - Variable reference parsing with colons
    - Module import error handling
    - PowerShell 7+ compatibility
#>

# === Automatic Module Management (Official SharePoint Module) ===
$RequiredModules = @(
    'Microsoft.Online.SharePoint.PowerShell',
    'Microsoft.Graph.Groups',
    'Microsoft.Graph.Identity.DirectoryManagement',
    'Microsoft.Graph.Authentication'
)

foreach ($Module in $RequiredModules) {
    Write-Host "Processing module: ${Module}" -ForegroundColor Cyan
    
    # Check if module is available
    $moduleAvailable = Get-Module -ListAvailable -Name $Module
    
    if (!$moduleAvailable) {
        Write-Host "Installing ${Module} module..." -ForegroundColor Yellow
        try {
            Install-Module $Module -Force -Scope CurrentUser -AllowClobber -ErrorAction Stop
            Write-Host "${Module} installed successfully" -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to install ${Module} - $($_.Exception.Message)" -ForegroundColor Red
            exit 1
        }
    }
    
    # Import if not already loaded
    if (!(Get-Module -Name $Module)) {
        try {
            Import-Module $Module -Force -ErrorAction Stop
            Write-Host "${Module} imported successfully" -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to import ${Module} - $($_.Exception.Message)" -ForegroundColor Red
            exit 1
        }
    }
    else {
        Write-Host "${Module} already loaded" -ForegroundColor Gray
    }
}

# === Configuration ===
$SharePointConfig = @{
    DefaultSites = @("HR", "Finance", "IT", "Projects", "Marketing")
    StorageQuota = 1024  # MB
    SiteTemplate = "STS#3"  # Modern Team Site
    HubSiteTemplate = "SITEPAGEPUBLISHING#0"  # Communication Site for hub
}

# === Logging Function ===
function Write-LogMessage {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Type = 'Info'
    )
    
    $timestamp = Get-Date -Format 'HH:mm:ss'
    
    switch ($Type) {
        'Success' { Write-Host "[$timestamp] $Message" -ForegroundColor Green }
        'Warning' { Write-Host "[$timestamp] $Message" -ForegroundColor Yellow }
        'Error' { Write-Host "[$timestamp] $Message" -ForegroundColor Red }
        default { Write-Host "[$timestamp] $Message" -ForegroundColor White }
    }
}

# === Main SharePoint Function ===
function New-TenantSharePoint {
    <#
    .SYNOPSIS
        Creates 5 SharePoint sites with hub architecture
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-LogMessage -Message "Starting SharePoint 5-Sites creation..." -Type Info
        
        # === FORCE AUTHENTICATION ===
        Write-LogMessage -Message "Forcing fresh authentication to Microsoft Graph..." -Type Info
        
        # Clear any existing connections
        try {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
            Disconnect-PnPOnline -ErrorAction SilentlyContinue
        }
        catch {
            # Ignore cleanup errors
        }
        
        # Connect to Microsoft Graph with required scopes
        $graphScopes = @(
            "User.ReadWrite.All",
            "Group.ReadWrite.All",
            "Directory.ReadWrite.All"
        )
        
        Write-LogMessage -Message "Connecting to Microsoft Graph..." -Type Info
        Connect-MgGraph -Scopes $graphScopes -NoWelcome -ErrorAction Stop | Out-Null
        
        $context = Get-MgContext
        Write-LogMessage -Message "Connected to Graph as: $($context.Account)" -Type Success
        
        # === GET TENANT INFORMATION ===
        Write-LogMessage -Message "Gathering tenant information..." -Type Info
        
        # Get organization info
        $org = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1
        $domains = Get-MgDomain -ErrorAction Stop
        $defaultDomain = $domains | Where-Object { $_.IsDefault -eq $true }
        
        $tenantName = $org.DisplayName
        $adminEmail = $context.Account
        
        Write-Host ""
        Write-Host "=== TENANT INFORMATION ===" -ForegroundColor Cyan
        Write-Host "Organization: $tenantName" -ForegroundColor Green
        Write-Host "Default Domain: $($defaultDomain.Id)" -ForegroundColor Green
        Write-Host "Admin Email: $adminEmail" -ForegroundColor Green
        Write-Host "=========================" -ForegroundColor Cyan
        Write-Host ""
        
        # === GET SHAREPOINT TENANT NAME ===
        $tenantDomain = $adminEmail.Split('@')[1]
        $spTenantName = $tenantDomain.Split('.')[0]
        
        Write-Host "=== SharePoint Configuration ===" -ForegroundColor Cyan
        Write-Host "Detected SharePoint tenant: $spTenantName" -ForegroundColor Yellow
        Write-Host "This will create admin URL: https://${spTenantName}-admin.sharepoint.com" -ForegroundColor Gray
        Write-Host ""
        
        $confirm = Read-Host "Is this correct? (Y/N) [Y]"
        if ($confirm -eq 'N' -or $confirm -eq 'n') {
            Write-Host ""
            $spTenantName = Read-Host "Enter your SharePoint tenant name (without .sharepoint.com)"
            
            if ([string]::IsNullOrWhiteSpace($spTenantName)) {
                Write-LogMessage -Message "Tenant name cannot be empty" -Type Error
                return $false
            }
        }
        
        # Construct SharePoint URLs
        $adminUrl = "https://${spTenantName}-admin.sharepoint.com"
        $tenantUrl = "https://${spTenantName}.sharepoint.com"
        $hubSiteUrl = $tenantUrl  # Use root site as hub
        
        Write-LogMessage -Message "SharePoint Admin URL: $adminUrl" -Type Info
        Write-LogMessage -Message "SharePoint Tenant URL: $tenantUrl" -Type Info
        Write-LogMessage -Message "Hub Site URL: $hubSiteUrl" -Type Info
        
        # === CONNECT TO SHAREPOINT ===
        Write-LogMessage -Message "Connecting to SharePoint Online using PnP PowerShell..." -Type Info
        
        try {
            Connect-PnPOnline -Url $adminUrl -Interactive -ErrorAction Stop
            Write-LogMessage -Message "Successfully connected to SharePoint Online" -Type Success
            
            # Verify permissions
            try {
                $tenantInfo = Get-PnPTenant -ErrorAction Stop
                Write-LogMessage -Message "SharePoint Administrator permissions verified" -Type Success
            }
            catch {
                Write-LogMessage -Message "Connected but may not have SharePoint Administrator permissions" -Type Warning
            }
        }
        catch {
            Write-LogMessage -Message "Failed to connect to SharePoint - $($_.Exception.Message)" -Type Error
            return $false
        }
        
        # === CONFIGURE HUB SITE ===
        Write-LogMessage -Message "Configuring root site as hub..." -Type Info
        
        try {
            # Get root site info
            $rootSiteInfo = Get-PnPSite -Identity $hubSiteUrl -ErrorAction Stop
            Write-LogMessage -Message "Root site found - Title: '$($rootSiteInfo.Title)'" -Type Success
            
            # Update root site title
            $hubTitle = "${tenantName} Hub"
            if ($rootSiteInfo.Title -ne $hubTitle) {
                try {
                    Connect-PnPOnline -Url $hubSiteUrl -Interactive
                    Set-PnPSite -Title $hubTitle -ErrorAction Stop
                    Write-LogMessage -Message "Updated hub site title to '$hubTitle'" -Type Success
                    
                    # Reconnect to admin center
                    Connect-PnPOnline -Url $adminUrl -Interactive
                }
                catch {
                    Write-LogMessage -Message "Could not update hub site title - $($_.Exception.Message)" -Type Warning
                }
            }
            
            # Register as hub site
            $existingHubs = Get-PnPHubSite -ErrorAction SilentlyContinue
            $isAlreadyHub = $existingHubs | Where-Object { $_.SiteUrl -eq $hubSiteUrl }
            
            if ($isAlreadyHub) {
                Write-LogMessage -Message "Root site is already registered as a hub site" -Type Warning
            }
            else {
                Register-PnPHubSite -Site $hubSiteUrl
                Write-LogMessage -Message "Successfully registered root site as hub" -Type Success
                Start-Sleep -Seconds 15
            }
        }
        catch {
            Write-LogMessage -Message "Hub site configuration failed - $($_.Exception.Message)" -Type Error
            return $false
        }
        
        # === CREATE SECURITY GROUPS ===
        Write-LogMessage -Message "Creating security groups for all sites..." -Type Info
        
        $securityGroups = @{}
        $allSites = @("Hub") + $SharePointConfig.DefaultSites
        
        foreach ($siteName in $allSites) {
            foreach ($groupType in @("Members", "Owners", "Visitors")) {
                $groupName = "${siteName} SharePoint ${groupType}"
                $mailNickname = "${siteName}-SPO-${groupType}"
                
                try {
                    # Check if group exists
                    $existingGroup = Get-MgGroup -Filter "displayName eq '$groupName'" -ErrorAction SilentlyContinue
                    
                    if ($existingGroup) {
                        Write-LogMessage -Message "Security group already exists: $groupName" -Type Warning
                        $securityGroups["${siteName}-${groupType}"] = $existingGroup.Id
                    }
                    else {
                        # Create new security group
                        $newGroup = New-MgGroup -DisplayName $groupName -MailEnabled:$false -MailNickname $mailNickname -SecurityEnabled:$true
                        $securityGroups["${siteName}-${groupType}"] = $newGroup.Id
                        Write-LogMessage -Message "Created security group: $groupName" -Type Success
                    }
                }
                catch {
                    Write-LogMessage -Message "Failed to create security group '$groupName' - $($_.Exception.Message)" -Type Error
                }
            }
        }
        
        # Wait for group propagation
        if ($securityGroups.Count -gt 0) {
            Write-LogMessage -Message "Waiting for security groups to propagate (2 minutes)..." -Type Info
            Start-Sleep -Seconds 120
        }
        
        # === CREATE 5 SPOKE SITES ===
        Write-LogMessage -Message "Creating 5 spoke sites..." -Type Info
        
        $createdSites = @()
        
        foreach ($siteName in $SharePointConfig.DefaultSites) {
            try {
                $siteUrl = "${tenantUrl}/sites/$($siteName.ToLower())"
                $siteAlias = $siteName.ToLower()
                
                Write-LogMessage -Message "Creating site: $siteName at $siteUrl" -Type Info
                
                # Check if site already exists
                try {
                    $existingSite = Get-PnPSite -Identity $siteUrl -ErrorAction Stop
                    Write-LogMessage -Message "Site '$siteName' already exists" -Type Warning
                    $createdSites += $siteUrl
                    continue
                }
                catch {
                    # Site doesn't exist, proceed with creation
                }
                
                # Create the site
                try {
                    New-PnPSite -Type TeamSite -Title $siteName -Alias $siteAlias -Owner $adminEmail -ErrorAction Stop
                    Write-LogMessage -Message "Created site: $siteName" -Type Success
                    $createdSites += $siteUrl
                }
                catch {
                    if ($_.Exception.Message -like "*already exists*") {
                        Write-LogMessage -Message "Site '$siteName' already exists" -Type Warning
                        $createdSites += $siteUrl
                    }
                    else {
                        Write-LogMessage -Message "Failed to create site '$siteName' - $($_.Exception.Message)" -Type Error
                    }
                }
            }
            catch {
                Write-LogMessage -Message "Error processing site '$siteName' - $($_.Exception.Message)" -Type Error
            }
        }
        
        if ($createdSites.Count -gt 0) {
            Write-LogMessage -Message "Waiting for site provisioning (3 minutes)..." -Type Info
            Start-Sleep -Seconds 180
        }
        
        # === ASSOCIATE SITES WITH HUB ===
        Write-LogMessage -Message "Associating spoke sites with hub..." -Type Info
        
        $successfulAssociations = 0
        foreach ($siteUrl in $createdSites) {
            try {
                Add-PnPHubSiteAssociation -Site $siteUrl -HubSite $hubSiteUrl -ErrorAction Stop
                $siteName = ($siteUrl -split '/sites/')[-1]
                Write-LogMessage -Message "Associated $siteName with hub" -Type Success
                $successfulAssociations++
            }
            catch {
                $siteName = ($siteUrl -split '/sites/')[-1]
                Write-LogMessage -Message "Failed to associate $siteName with hub - $($_.Exception.Message)" -Type Warning
            }
        }
        
        # === CONFIGURE HUB NAVIGATION ===
        Write-LogMessage -Message "Configuring hub navigation..." -Type Info
        
        try {
            $navigationItems = @()
            foreach ($siteUrl in $createdSites) {
                $siteName = ($siteUrl -split '/sites/')[-1]
                $navigationItems += @{
                    "displayName" = $siteName.ToUpper()
                    "url" = $siteUrl
                }
            }
            
            if ($navigationItems.Count -gt 0) {
                $navigationJson = $navigationItems | ConvertTo-Json -Depth 3
                Set-PnPHubSite -Identity $hubSiteUrl -MenuConfiguration $navigationJson
                Write-LogMessage -Message "Hub navigation configured with $($navigationItems.Count) site links" -Type Success
            }
        }
        catch {
            Write-LogMessage -Message "Failed to configure hub navigation - $($_.Exception.Message)" -Type Warning
        }
        
        # === DISPLAY RESULTS ===
        Write-Host ""
        Write-Host "=== SharePoint 5-Sites Creation Complete ===" -ForegroundColor Cyan
        Write-Host "Hub Site: $hubSiteUrl" -ForegroundColor Green
        Write-Host "Created/Configured Sites: $($createdSites.Count)" -ForegroundColor Green
        Write-Host "Security Groups Created: $($securityGroups.Count)" -ForegroundColor Green
        Write-Host "Hub Associations: $successfulAssociations" -ForegroundColor Green
        Write-Host ""
        
        Write-Host "Created Sites:" -ForegroundColor Yellow
        foreach ($siteUrl in $createdSites) {
            Write-Host "  ✓ $siteUrl" -ForegroundColor White
        }
        Write-Host ""
        
        Write-Host "Security Groups Created:" -ForegroundColor Yellow
        foreach ($groupKey in $securityGroups.Keys) {
            $parts = $groupKey.Split('-')
            $siteName = $parts[0]
            $groupType = $parts[1]
            Write-Host "  ✓ ${siteName} SharePoint ${groupType}" -ForegroundColor White
        }
        Write-Host ""
        
        Write-Host "Next Steps:" -ForegroundColor Cyan
        Write-Host "1. Assign users to security groups" -ForegroundColor Gray
        Write-Host "2. Configure site permissions" -ForegroundColor Gray
        Write-Host "3. Add content and customize sites" -ForegroundColor Gray
        Write-Host "4. Set up additional navigation" -ForegroundColor Gray
        Write-Host ""
        
        Write-LogMessage -Message "SharePoint 5-Sites creation completed successfully!" -Type Success
        
        return $true
        
    }
    catch {
        Write-LogMessage -Message "Critical error in SharePoint creation - $($_.Exception.Message)" -Type Error
        return $false
    }
    finally {
        # Cleanup connections
        try {
            Disconnect-PnPOnline -ErrorAction SilentlyContinue
            Write-LogMessage -Message "Disconnected from SharePoint" -Type Info
        }
        catch {
            # Ignore cleanup errors
        }
    }
}

# === SCRIPT EXECUTION ===
Write-Host ""
Write-Host "SharePoint 5-Sites Creator - PowerShell 7 Fixed" -ForegroundColor Magenta
Write-Host "Ready to create: HR, Finance, IT, Projects, Marketing" -ForegroundColor Cyan
Write-Host ""

# Execute the function
$result = New-TenantSharePoint

if ($result) {
    Write-Host "🎉 SharePoint creation completed successfully!" -ForegroundColor Green
}
else {
    Write-Host "❌ SharePoint creation failed. Check the logs above." -ForegroundColor Red
}

# ▼ CB & Claude | BITS 365 Automation | v1.0 | "Smarter not Harder"