#requires -Version 7.0
<#
.SYNOPSIS
    Conditional Access Policies Module - PowerShell 7 Compatible
.DESCRIPTION
    Creates and configures essential Conditional Access policies for Microsoft 365 tenant security.
    Includes comprehensive security policies for MFA, device compliance, and risk-based access control.
    
    Policies Created:
    - C001: Block High Risk Users
    - C002: MFA Required for All Users (with NoMFA Exemption group exclusion)
    - C003: Block Non Corporate Devices (Report-Only Mode)
    - C004: Require Password Change and MFA for High Risk Users
    - C005: Require MFA for Risky Sign-Ins
    
.NOTES
    Version: 2.0
    Requirements: PowerShell 7.0 or later
    Author: 365 Engineer
    Dependencies: Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Groups, Microsoft.Graph.Identity.SignIns
    Prerequisites: Groups must be created first (requires NoMFA Exemption group)
    
    Security Note: All policies are created in enabled state except C003 which starts in report-only mode
#>

# === Automatic Module Management ===
$RequiredModules = @(
    'Microsoft.Graph.Identity.DirectoryManagement',
    'Microsoft.Graph.Groups', 
    'Microsoft.Graph.Identity.SignIns'
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
function Test-SecurityDefaults {
    try {
        # Use the correct parameter approach from Microsoft docs
        $result = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction Stop
        return $result.IsEnabled
    }
    catch {
        Write-LogMessage -Message "Cannot check Security Defaults status: $($_.Exception.Message)" -Type Warning
        # Try alternative method
        try {
            $uri = "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"
            $result = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
            return $result.isEnabled
        }
        catch {
            Write-LogMessage -Message "Both methods failed - will proceed with assumption" -Type Warning
            return $null
        }
    }
}

function Disable-SecurityDefaults {
    try {
        Write-LogMessage -Message "Disabling Security Defaults (Microsoft recommended when using CA policies)..." -Type Info
        
        # Method 1: Use the official PowerShell cmdlet (Microsoft recommended)
        $body = @{ isEnabled = $false }
        Update-MgPolicyIdentitySecurityDefaultEnforcementPolicy -BodyParameter $body -ErrorAction Stop
        
        Write-LogMessage -Message "Security Defaults disabled successfully using PowerShell cmdlet" -Type Success
        return $true
    }
    catch {
        Write-LogMessage -Message "PowerShell cmdlet failed, trying direct Graph API..." -Type Warning
        
        # Method 2: Fallback to direct Graph API
        try {
            $uri = "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"
            $body = @{ isEnabled = $false }
            Invoke-MgGraphRequest -Method PATCH -Uri $uri -Body $body -ErrorAction Stop
            
            Write-LogMessage -Message "Security Defaults disabled successfully using Graph API" -Type Success
            return $true
        }
        catch {
            Write-LogMessage -Message "Failed to disable Security Defaults: $($_.Exception.Message)" -Type Error
            return $false
        }
    }
}
# === Main Conditional Access Function ===
function New-TenantCAPolices {
    <#
    .SYNOPSIS
        Creates essential Conditional Access policies for tenant security
    .DESCRIPTION
        Creates standardized Conditional Access policies including MFA requirements,
        device compliance, and risk-based access controls. Updates tenant state with policy information.
    .PARAMETER TenantState
        Optional hashtable containing tenant information. If not provided, will attempt to gather from Graph.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [hashtable]$TenantState
    )
    
    try {
        Write-LogMessage -Message "Starting Conditional Access policies creation process..." -Type Info
        
        # Handle TenantState - use provided or gather from Graph
        if ($TenantState) {
            $script:TenantState = $TenantState
            Write-LogMessage -Message "Using provided TenantState" -Type Info
        }
        elseif (-not $script:TenantState) {
            try {
                $org = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1
                $currentUser = (Get-MgContext).Account
                $script:TenantState = @{
                    TenantName = $org.DisplayName
                    AdminEmail = $currentUser
                    TenantId = $org.Id
                    CreatedGroups = @{}
                }
                Write-LogMessage -Message "Gathered tenant information from Graph API" -Type Info
            }
            catch {
                Write-LogMessage -Message "Failed to gather tenant information: $($_.Exception.Message)" -Type Error
                return $false
            }
        }
        
        # Check prerequisites
        if (-not (Test-CAPolicyPrerequisites)) {
            Write-LogMessage -Message "Prerequisites not met for Conditional Access policy creation" -Type Error
            return $false
        }
        Write-LogMessage -Message "Checking Security Defaults status..." -Type Info
$securityDefaultsEnabled = Test-SecurityDefaults

if ($securityDefaultsEnabled -eq $true) {
    Write-LogMessage -Message "Security Defaults is currently enabled" -Type Warning
    $disableResult = Disable-SecurityDefaults
    
    if (-not $disableResult) {
        Write-LogMessage -Message "Cannot proceed with CA policies while Security Defaults is enabled" -Type Error
        return $false
    }
}
elseif ($securityDefaultsEnabled -eq $false) {
    Write-LogMessage -Message "Security Defaults is already disabled - CA policies can proceed" -Type Success
}
else {
    Write-LogMessage -Message "Could not determine Security Defaults status - proceeding with caution" -Type Warning
}
# *** ADD DEBUG CODE RIGHT HERE ***
    Write-LogMessage -Message "=== ACTUAL TOKEN SCOPES DEBUG ===" -Type Info
    $context = Get-MgContext
    Write-LogMessage -Message "Connected Account: $($context.Account)" -Type Info
    Write-LogMessage -Message "Scopes in token:" -Type Info
    $context.Scopes | ForEach-Object { Write-LogMessage -Message "  - $_" -Type Info }
    
    # Test the actual token with CA API
    try {
        $testRead = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?`$top=1"
        Write-LogMessage -Message "✅ Token ACTUALLY works for CA read" -Type Success
    } catch {
        Write-LogMessage -Message "❌ Token DOESN'T work for CA: $($_.Exception.Message)" -Type Error
    }
    Write-LogMessage -Message "=== END DEBUG ===" -Type Info


        # Initialize tracking
        $script:TenantState.ConditionalAccessPolicies = @{}
        $createdPolicies = @{
            Total = 0
            Success = 0
            Failed = @()
            Policies = @{}
        }
        
        Write-LogMessage -Message "Tenant: $($script:TenantState.TenantName)" -Type Info
        Write-LogMessage -Message "Admin: $($script:TenantState.AdminEmail)" -Type Info
        
        # Get NoMFA Exemption group if available
        $noMfaGroupId = $null
        if ($script:TenantState.CreatedGroups -and $script:TenantState.CreatedGroups["NoMFA Exemption"]) {
            $noMfaGroupId = $script:TenantState.CreatedGroups["NoMFA Exemption"]
            Write-LogMessage -Message "Found NoMFA Exemption group in TenantState: $noMfaGroupId" -Type Success
        }
        else {
            # Try to find the group directly
            try {
                $noMfaGroup = Get-MgGroup -Filter "displayName eq 'NoMFA Exemption'" -ErrorAction Stop
                if ($noMfaGroup) {
                    $noMfaGroupId = $noMfaGroup.Id
                    # Update TenantState if we found the group
                    if (-not $script:TenantState.CreatedGroups) {
                        $script:TenantState.CreatedGroups = @{}
                    }
                    $script:TenantState.CreatedGroups["NoMFA Exemption"] = $noMfaGroupId
                    Write-LogMessage -Message "Located NoMFA Exemption group via Graph: $noMfaGroupId" -Type Success
                }
                else {
                    Write-LogMessage -Message "NoMFA Exemption group not found. Policies will apply to all users." -Type Warning
                }
            }
            catch {
                Write-LogMessage -Message "Error searching for NoMFA Exemption group: $($_.Exception.Message)" -Type Warning
            }
        }
        
        # === Create C001 - Block High Risk Users ===
        $createdPolicies.Total++
        $result = New-CAPolicyC001
        if ($result.Success) {
            $createdPolicies.Success++
            $createdPolicies.Policies["C001"] = $result.Policy
            Write-LogMessage -Message "Created C001 - Block High Risk Users" -Type Success
        }
        else {
            $createdPolicies.Failed += "C001 - Block High Risk Users"
            Write-LogMessage -Message "Failed to create C001: $($result.Error)" -Type Error
        }
        
        # === Create C002 - MFA Required for All Users ===
        $createdPolicies.Total++
        $result = New-CAPolicyC002 -NoMfaGroupId $noMfaGroupId
        if ($result.Success) {
            $createdPolicies.Success++
            $createdPolicies.Policies["C002"] = $result.Policy
            Write-LogMessage -Message "Created C002 - MFA Required for All Users" -Type Success
        }
        else {
            $createdPolicies.Failed += "C002 - MFA Required for All Users"
            Write-LogMessage -Message "Failed to create C002: $($result.Error)" -Type Error
        }
        
        # === Create C003 - Block Non Corporate Devices ===
        $createdPolicies.Total++
        $result = New-CAPolicyC003
        if ($result.Success) {
            $createdPolicies.Success++
            $createdPolicies.Policies["C003"] = $result.Policy
            Write-LogMessage -Message "Created C003 - Block Non Corporate Devices (Report-Only)" -Type Success
        }
        else {
            $createdPolicies.Failed += "C003 - Block Non Corporate Devices"
            Write-LogMessage -Message "Failed to create C003: $($result.Error)" -Type Error
        }
        
        # === Create C004 - Require Password Change and MFA for High Risk Users ===
        $createdPolicies.Total++
        $result = New-CAPolicyC004
        if ($result.Success) {
            $createdPolicies.Success++
            $createdPolicies.Policies["C004"] = $result.Policy
            Write-LogMessage -Message "Created C004 - Require Password Change and MFA for High Risk Users" -Type Success
        }
        else {
            $createdPolicies.Failed += "C004 - Require Password Change and MFA for High Risk Users"
            Write-LogMessage -Message "Failed to create C004: $($result.Error)" -Type Error
        }
        
        # === Create C005 - Require MFA for Risky Sign-Ins ===
        $createdPolicies.Total++
        $result = New-CAPolicyC005
        if ($result.Success) {
            $createdPolicies.Success++
            $createdPolicies.Policies["C005"] = $result.Policy
            Write-LogMessage -Message "Created C005 - Require MFA for Risky Sign-Ins" -Type Success
        }
        else {
            $createdPolicies.Failed += "C005 - Require MFA for Risky Sign-Ins"
            Write-LogMessage -Message "Failed to create C005: $($result.Error)" -Type Error
        }
        
        # Update tenant state
        $script:TenantState.ConditionalAccessPolicies = $createdPolicies.Policies
        $script:TenantState.LastCAPolicyOperation = Get-Date
        
        # Display results summary
        Write-Host ""
        Write-Host "=== Conditional Access Policies Creation Summary ===" -ForegroundColor Cyan
        Write-Host "Total Policies: $($createdPolicies.Total)" -ForegroundColor Gray
        Write-Host "Successfully Created: $($createdPolicies.Success)" -ForegroundColor Green
        Write-Host "Failed: $($createdPolicies.Failed.Count)" -ForegroundColor Red
        
        if ($createdPolicies.Failed.Count -gt 0) {
            Write-Host "Failed Policies:" -ForegroundColor Red
            foreach ($failed in $createdPolicies.Failed) {
                Write-Host "  - $failed" -ForegroundColor Red
            }
        }
        Write-Host ""
        
        # Determine overall success
        $overallSuccess = $createdPolicies.Success -gt 0 -and $createdPolicies.Failed.Count -eq 0
        
        if ($overallSuccess) {
            Write-LogMessage -Message "Conditional Access policies creation completed successfully - $($createdPolicies.Success)/$($createdPolicies.Total) policies created" -Type Success
            Write-Host ""
            Write-Host "⚠️  IMPORTANT SECURITY REMINDERS:" -ForegroundColor Yellow
            Write-Host "1. C003 (Device Compliance) is in Report-Only mode - enable when ready" -ForegroundColor Gray
            Write-Host "2. Test all policies with a pilot group before full deployment" -ForegroundColor Gray
            Write-Host "3. Ensure emergency access accounts are properly excluded" -ForegroundColor Gray
            Write-Host "4. Monitor sign-in logs for policy impacts" -ForegroundColor Gray
        }
        elseif ($createdPolicies.Success -gt 0) {
            Write-LogMessage -Message "Conditional Access policies creation completed with warnings - $($createdPolicies.Success)/$($createdPolicies.Total) policies created" -Type Warning
        }
        else {
            Write-LogMessage -Message "Conditional Access policies creation failed - no policies were created successfully" -Type Error
        }
        
        return $overallSuccess
        
    }
    catch {
        Write-LogMessage -Message "Error in Conditional Access policies creation process - $($_.Exception.Message)" -Type Error
        return $false
    }
}

# === Policy Creation Functions ===
function New-CAPolicyC001 {
    <#
    .SYNOPSIS
        Creates C001 - Block High Risk Users policy
    #>
    [CmdletBinding()]
    param()
    
    try {
        $policyName = "C001 - Block High Risk Users"
        
        # Check if policy already exists
        $existingPolicy = Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq '$policyName'" -ErrorAction SilentlyContinue
        if ($existingPolicy) {
            Write-LogMessage -Message "Policy '$policyName' already exists" -Type Warning
            return @{
                Success = $true
                Policy = $existingPolicy
                AlreadyExists = $true
            }
        }
        
        $policyParams = @{
            DisplayName = $policyName
            State = "enabled"
            Conditions = @{
                Users = @{
                    IncludeUsers = @("All")
                }
                Applications = @{
                    IncludeApplications = @("All")
                }
                UserRiskLevels = @("high")
            }
            GrantControls = @{
                Operator = "OR"
                BuiltInControls = @("block")
            }
        }
        
        $newPolicy = New-MgIdentityConditionalAccessPolicy -BodyParameter $policyParams -ErrorAction Stop
        Write-LogMessage -Message "Created CA policy: $policyName" -Type Success
        
        return @{
            Success = $true
            Policy = $newPolicy
            AlreadyExists = $false
        }
    }
    catch {
        Write-LogMessage -Message "Failed to create policy '$policyName' - $($_.Exception.Message)" -Type Error
        return @{
            Success = $false
            Policy = $null
            Error = $_.Exception.Message
        }
    }
}

function New-CAPolicyC002 {
    <#
    .SYNOPSIS
        Creates C002 - MFA Required for All Users policy (with NoMFA exemption)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$NoMfaGroupId
    )
    
    try {
        $policyName = "C002 - MFA Required for All Users"
        
        # Check if policy already exists
        $existingPolicy = Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq '$policyName'" -ErrorAction SilentlyContinue
        if ($existingPolicy) {
            Write-LogMessage -Message "Policy '$policyName' already exists" -Type Warning
            return @{
                Success = $true
                Policy = $existingPolicy
                AlreadyExists = $true
            }
        }
        
        $userConditions = @{
            IncludeUsers = @("All")
        }
        
        # Add NoMFA group exclusion if available
        if ($NoMfaGroupId) {
            $userConditions.ExcludeGroups = @($NoMfaGroupId)
            Write-LogMessage -Message "Added NoMFA Exemption group to policy exclusions" -Type Info
        }
        
        $policyParams = @{
            DisplayName = $policyName
            State = "enabled"
            Conditions = @{
                Users = $userConditions
                Applications = @{
                    IncludeApplications = @("All")
                }
                ClientAppTypes = @("browser", "mobileAppsAndDesktopClients")
            }
            GrantControls = @{
                Operator = "OR"
                BuiltInControls = @("mfa")
            }
        }
        
        $newPolicy = New-MgIdentityConditionalAccessPolicy -BodyParameter $policyParams -ErrorAction Stop
        Write-LogMessage -Message "Created CA policy: $policyName" -Type Success
        
        return @{
            Success = $true
            Policy = $newPolicy
            AlreadyExists = $false
        }
    }
    catch {
        Write-LogMessage -Message "Failed to create policy '$policyName' - $($_.Exception.Message)" -Type Error
        return @{
            Success = $false
            Policy = $null
            Error = $_.Exception.Message
        }
    }
}

function New-CAPolicyC003 {
    <#
    .SYNOPSIS
        Creates C003 - Block Non Corporate Devices policy (Report-Only Mode)
    #>
    [CmdletBinding()]
    param()
    
    try {
        $policyName = "C003 - Block Non Corporate Devices"
        
        # Check if policy already exists
        $existingPolicy = Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq '$policyName'" -ErrorAction SilentlyContinue
        if ($existingPolicy) {
            Write-LogMessage -Message "Policy '$policyName' already exists" -Type Warning
            return @{
                Success = $true
                Policy = $existingPolicy
                AlreadyExists = $true
            }
        }
        
        $policyParams = @{
            DisplayName = $policyName
            State = "enabledForReportingButNotEnforced"  # Start in report-only mode
            Conditions = @{
                Users = @{
                    IncludeUsers = @("All")
                    ExcludeRoles = @("d29b2b05-8046-44ba-8758-1e26182fcf32")  # Global Admin role
                }
                Applications = @{
                    IncludeApplications = @("All")
                }
                ClientAppTypes = @("all")
                Platforms = @{
                    IncludePlatforms = @("all")
                }
            }
            GrantControls = @{
                Operator = "OR"
                BuiltInControls = @("compliantDevice", "domainJoinedDevice")
            }
        }
        
        $newPolicy = New-MgIdentityConditionalAccessPolicy -BodyParameter $policyParams -ErrorAction Stop
        Write-LogMessage -Message "Created CA policy: $policyName (Report-Only Mode)" -Type Success
        
        return @{
            Success = $true
            Policy = $newPolicy
            AlreadyExists = $false
        }
    }
    catch {
        Write-LogMessage -Message "Failed to create policy '$policyName' - $($_.Exception.Message)" -Type Error
        return @{
            Success = $false
            Policy = $null
            Error = $_.Exception.Message
        }
    }
}

function New-CAPolicyC004 {
    <#
    .SYNOPSIS
        Creates C004 - Require Password Change and MFA for High Risk Users policy
    #>
    [CmdletBinding()]
    param()
    
    try {
        $policyName = "C004 - Require Password Change and MFA for High Risk Users"
        
        # Check if policy already exists
        $existingPolicy = Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq '$policyName'" -ErrorAction SilentlyContinue
        if ($existingPolicy) {
            Write-LogMessage -Message "Policy '$policyName' already exists" -Type Warning
            return @{
                Success = $true
                Policy = $existingPolicy
                AlreadyExists = $true
            }
        }
        
        $policyParams = @{
            DisplayName = $policyName
            State = "enabled"
            Conditions = @{
                Users = @{
                    IncludeUsers = @("All")
                }
                Applications = @{
                    IncludeApplications = @("All")
                }
                UserRiskLevels = @("high")
            }
            GrantControls = @{
                Operator = "AND"
                BuiltInControls = @("mfa", "passwordChange")
            }
        }
        
        $newPolicy = New-MgIdentityConditionalAccessPolicy -BodyParameter $policyParams -ErrorAction Stop
        Write-LogMessage -Message "Created CA policy: $policyName" -Type Success
        
        return @{
            Success = $true
            Policy = $newPolicy
            AlreadyExists = $false
        }
    }
    catch {
        Write-LogMessage -Message "Failed to create policy '$policyName' - $($_.Exception.Message)" -Type Error
        return @{
            Success = $false
            Policy = $null
            Error = $_.Exception.Message
        }
    }
}

function New-CAPolicyC005 {
    <#
    .SYNOPSIS
        Creates C005 - Require MFA for Risky Sign-Ins policy
    #>
    [CmdletBinding()]
    param()
    
    try {
        $policyName = "C005 - Require MFA for Risky Sign-Ins"
        
        # Check if policy already exists
        $existingPolicy = Get-MgIdentityConditionalAccessPolicy -Filter "displayName eq '$policyName'" -ErrorAction SilentlyContinue
        if ($existingPolicy) {
            Write-LogMessage -Message "Policy '$policyName' already exists" -Type Warning
            return @{
                Success = $true
                Policy = $existingPolicy
                AlreadyExists = $true
            }
        }
        
        $policyParams = @{
            DisplayName = $policyName
            State = "enabled"
            Conditions = @{
                Users = @{
                    IncludeUsers = @("All")
                }
                Applications = @{
                    IncludeApplications = @("All")
                }
                SignInRiskLevels = @("high", "medium")
            }
            GrantControls = @{
                Operator = "OR"
                BuiltInControls = @("mfa")
            }
        }
        
        $newPolicy = New-MgIdentityConditionalAccessPolicy -BodyParameter $policyParams -ErrorAction Stop
        Write-LogMessage -Message "Created CA policy: $policyName" -Type Success
        
        return @{
            Success = $true
            Policy = $newPolicy
            AlreadyExists = $false
        }
    }
    catch {
        Write-LogMessage -Message "Failed to create policy '$policyName' - $($_.Exception.Message)" -Type Error
        return @{
            Success = $false
            Policy = $null
            Error = $_.Exception.Message
        }
    }
}

# === Helper Functions ===
# === Helper Functions ===
function Test-CAPolicyPrerequisites {
    <#
    .SYNOPSIS
        Tests all prerequisites for Conditional Access policy creation
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
    
    # Test Graph permissions by checking scopes
    try {
        $currentScopes = (Get-MgContext).Scopes
        $requiredScopes = @(
            "Policy.ReadWrite.ConditionalAccess",
            "Directory.Read.All",
            "Group.Read.All"
        )
        
        $missingScopes = $requiredScopes | Where-Object { $_ -notin $currentScopes }
        
        if ($missingScopes.Count -eq 0) {
            $prerequisites['Graph Permissions'] = $true
        }
        else {
            Write-LogMessage -Message "Missing required permissions: $($missingScopes -join ', ')" -Type Warning
            $prerequisites['Graph Permissions'] = $false
        }
    }
    catch {
        Write-LogMessage -Message "Error checking permissions: $($_.Exception.Message)" -Type Error
        $prerequisites['Graph Permissions'] = $false
    }
    
    Write-Host "=== Conditional Access Prerequisites ===" -ForegroundColor Cyan
    foreach ($prereq in $prerequisites.GetEnumerator()) {
        $status = if ($prereq.Value) { "✓ Met" } else { "✗ Not Met" }
        $color = if ($prereq.Value) { "Green" } else { "Red" }
        Write-Host ("{0}: " -f $prereq.Key) -ForegroundColor Gray -NoNewline
        Write-Host $status -ForegroundColor $color
        
        # Show missing scopes if permissions check failed
        if ($prereq.Key -eq 'Graph Permissions' -and -not $prereq.Value -and $missingScopes) {
            Write-Host "  Missing Scopes: $($missingScopes -join ', ')" -ForegroundColor Yellow
            Write-Host "  Run: Connect-MgGraph -Scopes '$($requiredScopes -join "','")'" -ForegroundColor Gray
        }
    }
    Write-Host ""
    
    return ($prerequisites.Values -notcontains $false)
}

function Test-ExistingCAPolicies {
    <#
    .SYNOPSIS
        Checks for existing Conditional Access policies
    #>
    [CmdletBinding()]
    param()
    
    try {
        $existingPolicies = Get-MgIdentityConditionalAccessPolicy -ErrorAction Stop
        $targetPolicies = @("C001 - Block High Risk Users", "C002 - MFA Required for All Users", "C003 - Block Non Corporate Devices", "C004 - Require Password Change and MFA for High Risk Users", "C005 - Require MFA for Risky Sign-Ins")
        
        Write-Host "=== Existing Conditional Access Policies Check ===" -ForegroundColor Cyan
        foreach ($targetPolicy in $targetPolicies) {
            $exists = $existingPolicies | Where-Object { $_.DisplayName -eq $targetPolicy }
            if ($exists) {
                Write-Host ("{0}: " -f $targetPolicy) -ForegroundColor Gray -NoNewline
                Write-Host "Already Exists" -ForegroundColor Yellow
            }
            else {
                Write-Host ("{0}: " -f $targetPolicy) -ForegroundColor Gray -NoNewline
                Write-Host "Will Be Created" -ForegroundColor Green
            }
        }
        Write-Host ""
        
        return $true
    }
    catch {
        Write-LogMessage -Message "Error checking existing CA policies: $($_.Exception.Message)" -Type Error
        return $false
    }
}
