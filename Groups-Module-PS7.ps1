#requires -Version 7.0
<#
.SYNOPSIS
    Groups Creation Module - PowerShell 7 Compatible
.DESCRIPTION
    Creates security and license groups for Microsoft 365 tenant setup.
    Handles both security groups for access control and license groups for user management.
    
    Dynamic Membership Rules:
    - License Groups: Use extensionAttribute1 for automatic license assignment (enabled accounts only)
    - Domain Users: Use userType to include all non-guest users (enabled accounts only)
    - Security Groups: Manual membership for security control
    
.NOTES
    Version: 2.0
    Requirements: PowerShell 7.0 or later
    Author: 365 Engineer
    Dependencies: Microsoft.Graph.Groups, Microsoft.Graph.Users
    
    Creates:
    - Security Groups (Static): BITS Admin, SSPR Enabled, NoMFA Exemption
    - License Groups (Dynamic): BusinessBasic, BusinessStandard, BusinessPremium, ExchangeOnline1, ExchangeOnline2
    - Domain Group (Dynamic): [TenantName] Users (all non-guest enabled users)
    
    Dynamic Rules Used:
    - License assignment: (user.extensionAttribute1 -eq "[LicenseType]") and (user.accountEnabled -eq true)
    - Domain membership: (user.userType -ne "Guest") and (user.accountEnabled -eq true)
#>

# === Automatic Module Management ===
$RequiredModules = @(
    'Microsoft.Graph.Groups',
    'Microsoft.Graph.Users',
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

# === Main Groups Creation Function ===
function New-TenantGroups {
    <#
    .SYNOPSIS
        Creates security and license groups for Microsoft 365 tenant
    .DESCRIPTION
        Creates standardized security groups for access control and license groups
        for user management. Updates tenant state with created group information.
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-LogMessage -Message "Starting tenant groups creation process..." -Type Info
        
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
        
        # Initialize group tracking
        $createdGroups = @{
            Security = @{}
            License = @{}
            Failed = @()
            Total = 0
            Success = 0
        }
        
        $tenantName = $script:TenantState.TenantName
        $adminEmail = $script:TenantState.AdminEmail
        
        Write-LogMessage -Message "Creating groups for tenant: $tenantName" -Type Info
        Write-LogMessage -Message "Admin owner: $adminEmail" -Type Info
        
        # Get admin user object for ownership
        $adminUser = $null
        try {
            $adminUser = Get-MgUser -Filter "userPrincipalName eq '$adminEmail'" -ErrorAction Stop
            Write-LogMessage -Message "Found admin user: $($adminUser.DisplayName)" -Type Success
        }
        catch {
            Write-LogMessage -Message "Warning: Could not find admin user. Groups will be created without specific owner." -Type Warning
        }
        
        # === Create Security Groups ===
        Write-LogMessage -Message "Creating security groups..." -Type Info
        
        $securityGroups = @(
            @{
                Name = "BITS Admin"
                Description = "Administrative users with elevated privileges for tenant management"
                MailNickname = "bits-admin"
            },
            @{
                Name = "SSPR Enabled"
                Description = "Users enabled for Self-Service Password Reset functionality"
                MailNickname = "sspr-enabled"
            },
            @{
                Name = "NoMFA Exemption"
                Description = "Users exempted from Multi-Factor Authentication requirements (use sparingly)"
                MailNickname = "nomfa-exemption"
            }
        )
        
        foreach ($groupConfig in $securityGroups) {
            $createdGroups.Total++
            $result = New-SecurityGroup -GroupConfig $groupConfig -AdminUser $adminUser
            
            if ($result.Success) {
                $createdGroups.Security[$groupConfig.Name] = $result.Group
                $createdGroups.Success++
                Write-LogMessage -Message "Created security group: $($groupConfig.Name)" -Type Success
            }
            else {
                $createdGroups.Failed += $groupConfig.Name
                Write-LogMessage -Message "Failed to create security group: $($groupConfig.Name)" -Type Error
            }
        }
        
        # === Create License Groups (Dynamic Membership) ===
        Write-LogMessage -Message "Creating dynamic license groups..." -Type Info
        
        $licenseGroups = @(
            @{
                Name = "Microsoft 365 BusinessBasic Users"
                Description = "Dynamic license group for BusinessBasic - Users with extensionAttribute1 = BusinessBasic (enabled accounts only)"
                MailNickname = "BusinessBasicUsers"
                MembershipRule = '(user.extensionAttribute1 -eq "BusinessBasic") and (user.accountEnabled -eq true)'
                Dynamic = $true
            },
            @{
                Name = "Microsoft 365 BusinessStandard Users"
                Description = "Dynamic license group for BusinessStandard - Users with extensionAttribute1 = BusinessStandard (enabled accounts only)"
                MailNickname = "BusinessStandardUsers"
                MembershipRule = '(user.extensionAttribute1 -eq "BusinessStandard") and (user.accountEnabled -eq true)'
                Dynamic = $true
            },
            @{
                Name = "Microsoft 365 BusinessPremium Users"
                Description = "Dynamic license group for BusinessPremium - Users with extensionAttribute1 = BusinessPremium (enabled accounts only)"
                MailNickname = "BusinessPremiumUsers"
                MembershipRule = '(user.extensionAttribute1 -eq "BusinessPremium") and (user.accountEnabled -eq true)'
                Dynamic = $true
            },
            @{
                Name = "Exchange Online Plan 1 Users"
                Description = "Dynamic license group for ExchangeOnline1 - Users with extensionAttribute1 = ExchangeOnline1 (enabled accounts only)"
                MailNickname = "ExchangeOnline1Users"
                MembershipRule = '(user.extensionAttribute1 -eq "ExchangeOnline1") and (user.accountEnabled -eq true)'
                Dynamic = $true
            },
            @{
                Name = "Exchange Online Plan 2 Users"
                Description = "Dynamic license group for ExchangeOnline2 - Users with extensionAttribute1 = ExchangeOnline2 (enabled accounts only)"
                MailNickname = "ExchangeOnline2Users"
                MembershipRule = '(user.extensionAttribute1 -eq "ExchangeOnline2") and (user.accountEnabled -eq true)'
                Dynamic = $true
            }
        )
        
        foreach ($groupConfig in $licenseGroups) {
            $createdGroups.Total++
            $result = New-SecurityGroup -GroupConfig $groupConfig -AdminUser $adminUser
            
            if ($result.Success) {
                $createdGroups.License[$groupConfig.Name] = $result.Group
                $createdGroups.Success++
                Write-LogMessage -Message "Created dynamic license group: $($groupConfig.Name)" -Type Success
            }
            else {
                $createdGroups.Failed += $groupConfig.Name
                Write-LogMessage -Message "Failed to create license group: $($groupConfig.Name)" -Type Error
            }
        }
        
        # === Create Domain Users Group (Dynamic) ===
        Write-LogMessage -Message "Creating domain users dynamic group..." -Type Info
        
        $domainGroupConfig = @{
            Name = "$tenantName Users"
            Description = "Dynamic group for all enabled users in $tenantName tenant (excludes guests and disabled accounts)"
            MailNickname = "DomainUsers"
            MembershipRule = '(user.userType -ne "Guest") and (user.accountEnabled -eq true)'
            Dynamic = $true
        }
        
        $createdGroups.Total++
        $result = New-SecurityGroup -GroupConfig $domainGroupConfig -AdminUser $adminUser
        
        if ($result.Success) {
            $createdGroups.License[$domainGroupConfig.Name] = $result.Group
            $createdGroups.Success++
            Write-LogMessage -Message "Created domain users dynamic group: $($domainGroupConfig.Name)" -Type Success
        }
        else {
            $createdGroups.Failed += $domainGroupConfig.Name
            Write-LogMessage -Message "Failed to create domain users group: $($domainGroupConfig.Name)" -Type Error
        }
        
        # === Add Admin to BITS Admin Group (Static Group Only) ===
        if ($adminUser -and $createdGroups.Security["BITS Admin"]) {
            try {
                $bitsAdminGroup = $createdGroups.Security["BITS Admin"]
                New-MgGroupMember -GroupId $bitsAdminGroup.Id -DirectoryObjectId $adminUser.Id -ErrorAction Stop
                Write-LogMessage -Message "Added $($adminUser.DisplayName) to BITS Admin group" -Type Success
            }
            catch {
                # Check if already a member (might happen if group already existed)
                if ($_.Exception.Message -like "*already exists*" -or $_.Exception.Message -like "*already a member*") {
                    Write-LogMessage -Message "$($adminUser.DisplayName) is already a member of BITS Admin group" -Type Info
                }
                else {
                    Write-LogMessage -Message "Warning: Could not add admin to BITS Admin group - $($_.Exception.Message)" -Type Warning
                }
            }
        }
        
        # === Update Tenant State ===
        $script:TenantState.CreatedGroups = $createdGroups
        $script:TenantState.LastGroupCreation = Get-Date
        
        # === Display Results ===
        Write-Host ""
        Write-Host "=== Groups Creation Summary ===" -ForegroundColor Cyan
        Write-Host "Total groups processed: " -ForegroundColor Gray -NoNewline
        Write-Host "$($createdGroups.Total)" -ForegroundColor White
        Write-Host "Successfully created: " -ForegroundColor Gray -NoNewline
        Write-Host "$($createdGroups.Success)" -ForegroundColor Green
        Write-Host "Failed: " -ForegroundColor Gray -NoNewline
        Write-Host "$($createdGroups.Failed.Count)" -ForegroundColor $(if ($createdGroups.Failed.Count -gt 0) { 'Red' } else { 'Green' })
        
        if ($createdGroups.Failed.Count -gt 0) {
            Write-Host ""
            Write-Host "Failed groups:" -ForegroundColor Red
            $createdGroups.Failed | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
        }
        
        Write-Host ""
        Write-Host "Security Groups Created (Static):" -ForegroundColor Yellow
        $createdGroups.Security.Keys | ForEach-Object { Write-Host "  ✓ $_" -ForegroundColor Green }
        
        Write-Host ""
        Write-Host "License Groups Created (Dynamic):" -ForegroundColor Yellow
        $createdGroups.License.Keys | ForEach-Object { 
            if ($_ -like "*Users" -and $_ -notlike "*$tenantName*") {
                Write-Host "  ✓ $_ (Dynamic: extensionAttribute1 + enabled accounts)" -ForegroundColor Green
            }
            else {
                Write-Host "  ✓ $_ (Dynamic: non-guests + enabled accounts)" -ForegroundColor Green
            }
        }
        
        Write-Host ""
        Write-Host "=== Dynamic Membership Information ===" -ForegroundColor Cyan
        Write-Host "License Groups: " -ForegroundColor Gray -NoNewline
        Write-Host "Enabled users automatically added based on extensionAttribute1 value" -ForegroundColor White
        Write-Host "Domain Group: " -ForegroundColor Gray -NoNewline
        Write-Host "All non-guest enabled users automatically included" -ForegroundColor White
        Write-Host ""
        Write-Host "Automatic Cleanup: " -ForegroundColor Yellow -NoNewline
        Write-Host "Disabled users are automatically removed from all dynamic groups" -ForegroundColor White
        Write-Host ""
        Write-Host "To assign licenses automatically:" -ForegroundColor Yellow
        Write-Host "  Set user extensionAttribute1 to: BusinessBasic, BusinessStandard, BusinessPremium, etc." -ForegroundColor Gray
        
        # Determine overall success
        $overallSuccess = $createdGroups.Success -gt 0 -and $createdGroups.Failed.Count -eq 0
        
        if ($overallSuccess) {
            Write-LogMessage -Message "Groups creation completed successfully - $($createdGroups.Success)/$($createdGroups.Total) groups created" -Type Success
        }
        elseif ($createdGroups.Success -gt 0) {
            Write-LogMessage -Message "Groups creation completed with warnings - $($createdGroups.Success)/$($createdGroups.Total) groups created" -Type Warning
        }
        else {
            Write-LogMessage -Message "Groups creation failed - no groups were created successfully" -Type Error
        }
        
        return $overallSuccess
        
    }
    catch {
        Write-LogMessage -Message "Error in groups creation process - $($_.Exception.Message)" -Type Error
        return $false
    }
}

# === Helper Functions ===
function New-SecurityGroup {
    <#
    .SYNOPSIS
        Creates a single security group with proper configuration (static or dynamic)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$GroupConfig,
        
        [Parameter(Mandatory = $false)]
        [object]$AdminUser
    )
    
    try {
        $groupName = $GroupConfig.Name
        $description = $GroupConfig.Description
        $mailNickname = $GroupConfig.MailNickname
        $isDynamic = $GroupConfig.Dynamic -eq $true
        $membershipRule = $GroupConfig.MembershipRule
        
        # Check if group already exists
        $existingGroup = Get-MgGroup -Filter "displayName eq '$groupName'" -ErrorAction SilentlyContinue
        if ($existingGroup) {
            Write-LogMessage -Message "Group '$groupName' already exists, skipping creation" -Type Warning
            return @{
                Success = $true
                Group = $existingGroup
                AlreadyExists = $true
            }
        }
        
        # Create group parameters
        if ($isDynamic -and $membershipRule) {
            # Dynamic group configuration
            $groupParams = @{
                displayName = $groupName
                description = $description
                mailNickname = $mailNickname
                securityEnabled = $true
                mailEnabled = $false
                groupTypes = @("DynamicMembership")
                membershipRule = $membershipRule
                membershipRuleProcessingState = "On"
            }
            
            Write-LogMessage -Message "Creating dynamic group: $groupName with rule: $membershipRule" -Type Info
            
            # Use direct Graph API call for dynamic groups (more reliable)
            $result = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/groups" -Body $groupParams
            
            if ($result -and $result.id) {
                # Get the created group object
                $newGroup = Get-MgGroup -GroupId $result.id
                Write-LogMessage -Message "Successfully created dynamic group: $groupName (ID: $($result.id))" -Type Success
                return @{
                    Success = $true
                    Group = $newGroup
                    AlreadyExists = $false
                }
            }
            else {
                throw "Dynamic group creation returned null or invalid response"
            }
        }
        else {
            # Static group configuration
            $groupParams = @{
                DisplayName = $groupName
                Description = $description
                MailNickname = $mailNickname
                SecurityEnabled = $true
                MailEnabled = $false
                GroupTypes = @()
            }
            
            # Add owner if admin user is available
            if ($AdminUser) {
                $groupParams['Owners@odata.bind'] = @("https://graph.microsoft.com/v1.0/users/$($AdminUser.Id)")
            }
            
            Write-LogMessage -Message "Creating static group: $groupName" -Type Info
            $newGroup = New-MgGroup -BodyParameter $groupParams -ErrorAction Stop
            
            # Verify creation
            if ($newGroup -and $newGroup.Id) {
                Write-LogMessage -Message "Successfully created static group: $groupName (ID: $($newGroup.Id))" -Type Success
                return @{
                    Success = $true
                    Group = $newGroup
                    AlreadyExists = $false
                }
            }
            else {
                throw "Static group creation returned null or invalid response"
            }
        }
        
    }
    catch {
        Write-LogMessage -Message "Failed to create group '$($GroupConfig.Name)' - $($_.Exception.Message)" -Type Error
        return @{
            Success = $false
            Group = $null
            Error = $_.Exception.Message
        }
    }
}

function Test-GroupCreationPrerequisites {
    <#
    .SYNOPSIS
        Tests all prerequisites for group creation
    #>
    [CmdletBinding()]
    param()
    
    $prerequisites = @{
        'Graph Connection' = $null -ne (Get-MgContext)
        'Tenant State' = $null -ne $script:TenantState
        'Required Modules' = $true
        'Graph Permissions' = $false
    }
    
    # Test required modules
    $missingModules = @()
    foreach ($module in $RequiredModules) {
        if (-not (Get-Module -Name $module)) {
            $missingModules += $module
        }
    }
    $prerequisites['Required Modules'] = $missingModules.Count -eq 0
    
    # Test Graph permissions
    try {
        # Try to read groups to test permissions
        Get-MgGroup -Top 1 -ErrorAction Stop | Out-Null
        $prerequisites['Graph Permissions'] = $true
    }
    catch {
        $prerequisites['Graph Permissions'] = $false
    }
    
    Write-Host "=== Groups Creation Prerequisites ===" -ForegroundColor Cyan
    foreach ($prereq in $prerequisites.GetEnumerator()) {
        $status = if ($prereq.Value) { "✓ Met" } else { "✗ Not Met" }
        $color = if ($prereq.Value) { "Green" } else { "Red" }
        Write-Host "$($prereq.Key): " -ForegroundColor Gray -NoNewline
        Write-Host $status -ForegroundColor $color
    }
    Write-Host ""
    
    return ($prerequisites.Values -notcontains $false)
}

# === Export Functions ===
Export-ModuleMember -Function New-TenantGroups, Test-GroupCreationPrerequisites