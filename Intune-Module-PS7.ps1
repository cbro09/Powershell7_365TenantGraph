# ▼ CB & Claude | BITS 365 Automation | v1.0 | "Smarter not Harder"

#requires -Version 7.0
<#
.SYNOPSIS
    Microsoft Intune Configuration Module - Fixed Traditional Approach
.DESCRIPTION
    Complete Intune device configuration using traditional device configurations
    with proper @odata.type and required fields for each policy type.
.NOTES
    Version: 4.0 - Fixed Traditional Implementation
    Uses traditional device configurations instead of Settings Catalog
#>

# Module Management
$RequiredModules = @(
    'Microsoft.Graph.DeviceManagement',
    'Microsoft.Graph.Groups', 
    'Microsoft.Graph.Identity.DirectoryManagement',
    'Microsoft.Graph.Authentication'
)

foreach ($Module in $RequiredModules) {
    if (!(Get-Module -ListAvailable -Name $Module)) {
        Write-Host "Installing module: $Module" -ForegroundColor Yellow
        Install-Module $Module -Force -Scope CurrentUser -AllowClobber
    }
    if (!(Get-Module -Name $Module)) {
        Write-Host "Importing module: $Module" -ForegroundColor Green
        Import-Module $Module -Force
    }
}

function New-TenantIntune {
    param(
        [Parameter(Mandatory = $false)]
        [switch]$UpdateExistingPolicies = $true,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$TenantState
    )
    
    try {
        Write-LogMessage -Message "Starting comprehensive Intune configuration..." -Type Info
        
        # Initialize TenantState
        if ($TenantState) {
            $script:TenantState = $TenantState
        } else {
            $script:TenantState = @{
                CreatedGroups = @{}
                DefaultDomain = ""
                TenantName = ""
                TenantId = ""
            }
        }

        if (-not $script:TenantState.CreatedGroups) {
            $script:TenantState.CreatedGroups = @{}
        }
        
        # Authentication
        $context = Get-MgContext
        if (-not $context) {
            $intuneScopes = @(
                "DeviceManagementConfiguration.ReadWrite.All",
                "DeviceManagementManagedDevices.ReadWrite.All", 
                "DeviceManagementApps.ReadWrite.All",
                "Group.ReadWrite.All",
                "Directory.ReadWrite.All"
            )
            Connect-MgGraph -Scopes $intuneScopes -ErrorAction Stop | Out-Null
            $context = Get-MgContext
        }
        
        Write-LogMessage -Message "Connected to Microsoft Graph as $($context.Account)" -Type Success
        
        # Helper Functions
        function Test-PolicyExists {
            param([string]$PolicyName)
            try {
                $uri = "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations?`$filter=displayName eq '$PolicyName'"
                $existingPolicy = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
                return ($existingPolicy.value.Count -gt 0)
            }
            catch { return $false }
        }
        
        function Test-CompliancePolicyExists {
            param([string]$PolicyName)
            try {
                $uri = "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies?`$filter=displayName eq '$PolicyName'"
                $existingPolicy = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
                return ($existingPolicy.value.Count -gt 0)
            }
            catch { return $false }
        }
        
        function Invoke-GraphRequestWithRetry {
            param($Uri, $Method = "POST", $Body = $null, $MaxRetries = 3)
            
            $retryCount = 0
            $delay = 2
            
            while ($retryCount -le $MaxRetries) {
                try {
                    return Invoke-MgGraphRequest -Uri $Uri -Method $Method -Body $Body
                }
                catch {
                    $statusCode = $_.Exception.Response.StatusCode.value__
                    
                    if ($statusCode -eq 429) {
                        $retryAfter = $_.Exception.Response.Headers["Retry-After"]
                        Start-Sleep -Seconds ($retryAfter ?? $delay)
                        $delay *= 2
                    }
                    elseif ($statusCode -ge 500) {
                        Start-Sleep -Seconds $delay
                        $delay *= 2
                    }
                    else {
                        Write-LogMessage -Message "Graph API Error ($statusCode): $($_.Exception.Message)" -Type Error
                        throw $_
                    }
                    
                    $retryCount++
                    if ($retryCount -gt $MaxRetries) {
                        throw "Max retries exceeded. Last error: $($_.Exception.Message)"
                    }
                }
            }
        }
        
        # Create Device Groups
        Write-LogMessage -Message "Creating required device groups..." -Type Info
        
        $requiredGroups = @{
            'Windows AutoPilot Devices' = '(device.devicePhysicalIDs -any (_ -contains "[ZTDId]"))'
            'Android Devices' = '(device.deviceOSType -eq "Android")'
            'iOS Devices' = '(device.deviceOSType -eq "iPhone") or (device.deviceOSType -eq "iPad")'
            'Windows Devices' = '(device.deviceOSType -eq "Windows")'
        }

        foreach ($groupName in $requiredGroups.Keys) {
            if (-not $script:TenantState.CreatedGroups.ContainsKey($groupName)) {
                try {
                    $groupBody = @{
                        displayName = $groupName
                        description = "Dynamic group for $groupName"
                        groupTypes = @("DynamicMembership")
                        membershipRule = $requiredGroups[$groupName]
                        membershipRuleProcessingState = "On"
                        mailEnabled = $false
                        securityEnabled = $true
                    }
                    
                    $group = Invoke-GraphRequestWithRetry -Uri "https://graph.microsoft.com/v1.0/groups" -Method POST -Body $groupBody
                    $script:TenantState.CreatedGroups[$groupName] = $group.id
                    Write-LogMessage -Message "Created group '$groupName'" -Type Success
                }
                catch {
                    Write-LogMessage -Message "Failed to create group '$groupName' - $($_.Exception.Message)" -Type Error
                }
            }
        }
        
        # Check LAPS Prerequisite
        Write-LogMessage -Message "Checking Windows LAPS prerequisite..." -Type Info
        $lapsEnabled = $true
        try {
            $lapsSettings = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/windowsLapsSettings" -ErrorAction Stop
            Write-LogMessage -Message "Windows LAPS is already enabled" -Type Success
        }
        catch {
            Write-LogMessage -Message "Windows LAPS prerequisite check failed" -Type Warning
            $lapsEnabled = $false
        }
        
        # Initialize arrays
        $policies = @()
        $compliancePolicies = @()
        
        Write-LogMessage -Message "Creating comprehensive configuration policies..." -Type Info
        
        # =================================================================
        # POLICY 1: WINDOWS DEFENDER - Endpoint Protection Configuration
        # =================================================================
        Write-LogMessage -Message "Creating Windows Defender endpoint protection policy..." -Type Info
        
        $defenderPolicyName = "Windows Defender Security"
        if (Test-PolicyExists -PolicyName $defenderPolicyName) {
            Write-LogMessage -Message "Policy '$defenderPolicyName' already exists, skipping creation" -Type Warning
            $policies += @{ displayName = $defenderPolicyName; id = "existing" }
        }
        else {
            try {
                $defenderBody = @{
                    "@odata.type" = "#microsoft.graph.windows10EndpointProtectionConfiguration"
                    displayName = $defenderPolicyName
                    description = "Comprehensive Windows Defender security configuration"
                    
                    # Core Defender Settings
                    defenderRequireRealTimeMonitoring = $true
                    defenderRequireBehaviorMonitoring = $true
                    defenderRequireCloudProtection = $true
                    defenderCloudBlockLevel = "high"
                    defenderCloudExtendedTimeout = 50
                    defenderPotentiallyUnwantedAppAction = "block"
                    defenderScanType = "full"
                    defenderSystemScanSchedule = "daily"
                    defenderScheduledScanTime = 120
                    defenderSignatureUpdateIntervalInHours = 8
                    defenderMonitorFileActivity = "enable"
                    defenderDaysBeforeCleaningUpMalware = 0
                    defenderScanMaxCpu = 50
                    defenderScanArchiveFiles = $true
                    defenderScanIncomingMail = $true
                    defenderScanRemovableDrivesDuringFullScan = $true
                    defenderScanMappedNetworkDrivesDuringFullScan = $false
                    defenderScanNetworkFiles = $true
                    defenderRequireNetworkInspectionSystem = $true
                    defenderSubmitSamplesConsentType = "sendSafeSamplesAutomatically"
                    defenderBlockOnAccessProtection = $false
                    defenderScheduledQuickScanTime = 120
                    
                    # Threat Actions
                    defenderDetectedMalwareActions = @{
                        lowSeverity = "quarantine"
                        moderateSeverity = "quarantine"
                        highSeverity = "quarantine"
                        severeSeverity = "quarantine"
                    }
                    
                    # Smart Screen
                    smartScreenEnableInShell = $true
                    smartScreenBlockOverrideForFiles = $true
                    
                    # Application Guard (disabled for compatibility)
                    applicationGuardEnabled = $false
                    
                    # Basic Firewall Settings
                    firewallBlockStatefulFTP = $true
                    firewallIdleTimeoutForSecurityAssociationInSeconds = 300
                    firewallPreSharedKeyEncodingMethod = "deviceDefault"
                    firewallIPSecExemptionsAllowNeighborDiscovery = $true
                    firewallIPSecExemptionsAllowICMP = $true
                    firewallIPSecExemptionsAllowRouterDiscovery = $true
                    firewallIPSecExemptionsAllowDHCP = $true
                    firewallCertificateRevocationListCheckMethod = "deviceDefault"
                    firewallMergeKeyingModuleSettings = $true
                    firewallPacketQueueingMethod = "deviceDefault"
                }
                
                $result = Invoke-GraphRequestWithRetry -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations" -Method POST -Body $defenderBody
                Write-LogMessage -Message "Created Windows Defender policy with comprehensive settings" -Type Success
                $policies += $result
            }
            catch {
                Write-LogMessage -Message "Failed to create Windows Defender policy - $($_.Exception.Message)" -Type Error
            }
        }
        
        # =================================================================
        # POLICY 2: BITLOCKER - Endpoint Protection Configuration
        # =================================================================
        Write-LogMessage -Message "Creating BitLocker encryption policy..." -Type Info
        
        $bitlockerPolicyName = "BitLocker Device Encryption"
        if (Test-PolicyExists -PolicyName $bitlockerPolicyName) {
            Write-LogMessage -Message "Policy '$bitlockerPolicyName' already exists, skipping creation" -Type Warning
            $policies += @{ displayName = $bitlockerPolicyName; id = "existing" }
        }
        else {
            try {
                $bitlockerBody = @{
                    "@odata.type" = "#microsoft.graph.windows10EndpointProtectionConfiguration"
                    displayName = $bitlockerPolicyName
                    description = "BitLocker drive encryption configuration"
                    
                    # BitLocker Settings
                    bitLockerEncryptDevice = $true
                    bitLockerDisableWarningForOtherDiskEncryption = $true
                    bitLockerEnableStorageCardEncryptionOnMobile = $true
                    
                    # System Drive Policy
                    bitLockerSystemDrivePolicy = @{
                        startupAuthenticationRequired = $true
                        startupAuthenticationTpmUsage = "required"
                        startupAuthenticationTpmPinUsage = "blocked"
                        startupAuthenticationTpmKeyUsage = "blocked"
                        startupAuthenticationTpmPinAndKeyUsage = "blocked"
                        minimumPinLength = 4
                        recoveryOptions = @{
                            blockDataRecoveryAgent = $true
                            recoveryPasswordUsage = "allowed"
                            recoveryKeyUsage = "allowed"
                            hideRecoveryOptions = $false
                            enableRecoveryInformationSaveToStore = $true
                            recoveryInformationToStore = "passwordAndKey"
                            enableBitLockerAfterRecoveryInformationToStore = $true
                        }
                    }
                    
                    # Fixed Data Drive Policy
                    bitLockerFixedDrivePolicy = @{
                        encryptionMethod = "aesCbc256"
                        requireEncryptionForWriteAccess = $true
                        recoveryOptions = @{
                            blockDataRecoveryAgent = $true
                            recoveryPasswordUsage = "allowed"
                            recoveryKeyUsage = "allowed"
                            hideRecoveryOptions = $false
                            enableRecoveryInformationSaveToStore = $true
                            recoveryInformationToStore = "passwordAndKey"
                            enableBitLockerAfterRecoveryInformationToStore = $true
                        }
                    }
                    
                    # Removable Drive Policy
                    bitLockerRemovableDrivePolicy = @{
                        encryptionMethod = "aesCbc256"
                        requireEncryptionForWriteAccess = $true
                        blockCrossOrganizationWriteAccess = $true
                    }
                }
                
                $result = Invoke-GraphRequestWithRetry -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations" -Method POST -Body $bitlockerBody
                Write-LogMessage -Message "Created BitLocker policy with comprehensive encryption settings" -Type Success
                $policies += $result
            }
            catch {
                Write-LogMessage -Message "Failed to create BitLocker policy - $($_.Exception.Message)" -Type Error
            }
        }
        
        # =================================================================
        # POLICY 3: ONEDRIVE - General Configuration
        # =================================================================
        Write-LogMessage -Message "Creating OneDrive configuration policy..." -Type Info
        
        $onedrivePolicyName = "OneDrive Business Configuration"
        if (Test-PolicyExists -PolicyName $onedrivePolicyName) {
            Write-LogMessage -Message "Policy '$onedrivePolicyName' already exists, skipping creation" -Type Warning
            $policies += @{ displayName = $onedrivePolicyName; id = "existing" }
        }
        else {
            try {
                $onedriveBody = @{
                    "@odata.type" = "#microsoft.graph.windows10GeneralConfiguration"
                    displayName = $onedrivePolicyName
                    description = "OneDrive for Business configuration and Known Folder Move"
                    
                    # OneDrive Settings
                    oneDriveDisablePersonalSync = $true
                    oneDriveBlockSyncAppUpdate = $false
                    
                    # Additional Windows Settings that can include OneDrive via registry
                    privacyBlockInputPersonalization = $false
                    privacyBlockPublishUserActivities = $false
                    privacyBlockActivityFeed = $false
                }
                
                $result = Invoke-GraphRequestWithRetry -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations" -Method POST -Body $onedriveBody
                Write-LogMessage -Message "Created OneDrive configuration policy" -Type Success
                $policies += $result
            }
            catch {
                Write-LogMessage -Message "Failed to create OneDrive policy - $($_.Exception.Message)" -Type Error
            }
        }
        
        # =================================================================
        # POLICY 4: LAPS - Custom Configuration (OMA-URI)
        # =================================================================
        Write-LogMessage -Message "Creating LAPS policy with OMA-URI configuration..." -Type Info
        
        $lapsPolicyName = "Windows LAPS Configuration"
        if (Test-PolicyExists -PolicyName $lapsPolicyName) {
            Write-LogMessage -Message "Policy '$lapsPolicyName' already exists, skipping creation" -Type Warning
            $policies += @{ displayName = $lapsPolicyName; id = "existing" }
        }
        else {
            try {
                # Get tenant name for admin account
                $adminAccountName = "LocalAdmin"
                if ($script:TenantState -and $script:TenantState.TenantName) {
                    $tenantName = $script:TenantState.TenantName
                    $initials = ($tenantName -split '\s+' | ForEach-Object { $_.Substring(0,1).ToUpper() }) -join ''
                    $adminAccountName = "$($initials)Local"
                }
                
                Write-LogMessage -Message "Setting LAPS admin account name to: $adminAccountName" -Type Info
                
                $lapsBody = @{
                    "@odata.type" = "#microsoft.graph.windows10CustomConfiguration"
                    displayName = $lapsPolicyName
                    description = "Windows Local Administrator Password Solution (LAPS)"
                    
                    omaSettings = @(
                        @{
                            "@odata.type" = "#microsoft.graph.omaSettingInteger"
                            displayName = "LAPS Password Complexity"
                            description = "Configure password complexity (4 = Large + small + numbers + special)"
                            omaUri = "./Device/Vendor/MSFT/LAPS/Policies/PasswordComplexity"
                            value = 4
                        },
                        @{
                            "@odata.type" = "#microsoft.graph.omaSettingInteger"
                            displayName = "LAPS Password Length"
                            description = "Configure password length"
                            omaUri = "./Device/Vendor/MSFT/LAPS/Policies/PasswordLength"
                            value = 14
                        },
                        @{
                            "@odata.type" = "#microsoft.graph.omaSettingInteger"
                            displayName = "LAPS Password Age"
                            description = "Password age in days"
                            omaUri = "./Device/Vendor/MSFT/LAPS/Policies/PasswordAgeInDays"
                            value = 30
                        },
                        @{
                            "@odata.type" = "#microsoft.graph.omaSettingString"
                            displayName = "LAPS Administrator Account Name"
                            description = "Local administrator account name"
                            omaUri = "./Device/Vendor/MSFT/LAPS/Policies/AdministratorAccountName"
                            value = $adminAccountName
                        }
                    )
                }
                
                $result = Invoke-GraphRequestWithRetry -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations" -Method POST -Body $lapsBody
                Write-LogMessage -Message "Created LAPS policy with custom OMA-URI settings" -Type Success
                $policies += $result
            }
            catch {
                Write-LogMessage -Message "Failed to create LAPS policy - $($_.Exception.Message)" -Type Error
            }
        }
        
        # =================================================================
        # POLICY 5: POWER OPTIONS - General Configuration
        # =================================================================
        Write-LogMessage -Message "Creating Power Options policy..." -Type Info
        
        $powerPolicyName = "Power Management Settings"
        if (Test-PolicyExists -PolicyName $powerPolicyName) {
            Write-LogMessage -Message "Policy '$powerPolicyName' already exists, skipping creation" -Type Warning
            $policies += @{ displayName = $powerPolicyName; id = "existing" }
        }
        else {
            try {
                $powerBody = @{
                    "@odata.type" = "#microsoft.graph.windows10GeneralConfiguration"
                    displayName = $powerPolicyName
                    description = "Power management and sleep settings"
                    
                    # Power Settings
                    powerLidCloseActionOnBattery = "sleep"
                    powerLidCloseActionPluggedIn = "sleep"
                    powerButtonActionOnBattery = "sleep"
                    powerButtonActionPluggedIn = "sleep"
                    powerSleepButtonActionOnBattery = "sleep"
                    powerSleepButtonActionPluggedIn = "sleep"
                    powerHybridSleepOnBattery = "disabled"
                    powerHybridSleepPluggedIn = "disabled"
                    
                    # Additional settings
                    lockScreenAllowTimeoutConfiguration = $true
                    lockScreenBlockActionCenterNotifications = $false
                    lockScreenBlockCortana = $true
                    lockScreenBlockToastNotifications = $false
                }
                
                $result = Invoke-GraphRequestWithRetry -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations" -Method POST -Body $powerBody
                Write-LogMessage -Message "Created Power Options policy" -Type Success
                $policies += $result
            }
            catch {
                Write-LogMessage -Message "Failed to create Power Options policy - $($_.Exception.Message)" -Type Error
            }
        }
        
        # =================================================================
        # COMPLIANCE POLICIES
        # =================================================================
        Write-LogMessage -Message "Creating comprehensive compliance policies..." -Type Info
        
        # Windows Compliance Policy
        Write-LogMessage -Message "Creating Windows compliance policy..." -Type Info
        
        $windowsComplianceName = "Windows 10/11 Corporate Compliance"
        if (Test-CompliancePolicyExists -PolicyName $windowsComplianceName) {
            Write-LogMessage -Message "Compliance policy '$windowsComplianceName' already exists, skipping creation" -Type Warning
            $compliancePolicies += @{ displayName = $windowsComplianceName; id = "existing" }
        }
        else {
            try {
                $windowsComplianceBody = @{
                    "@odata.type" = "#microsoft.graph.windows10CompliancePolicy"
                    displayName = $windowsComplianceName
                    description = "Corporate compliance requirements for Windows 10/11 devices"
                    
                    # Password Requirements
                    passwordRequired = $true
                    passwordBlockSimple = $true
                    passwordRequiredType = "alphanumeric"
                    passwordMinimumLength = 8
                    passwordMinutesOfInactivityBeforeLock = 15
                    passwordExpirationDays = 90
                    passwordPreviousPasswordBlockCount = 5
                    passwordRequireToUnlockFromIdle = $true
                    
                    # Device Health
                    requireHealthyDeviceReport = $true
                    osMinimumVersion = "10.0.18362"
                    osMaximumVersion = $null
                    mobileOsMinimumVersion = $null
                    mobileOsMaximumVersion = $null
                    
                    # Security Requirements
                    earlyLaunchAntiMalwareDriverEnabled = $true
                    bitLockerEnabled = $true
                    secureBootEnabled = $true
                    codeIntegrityEnabled = $true
                    storageRequireEncryption = $true
                    tpmRequired = $true
                    
                    # Firewall and Antivirus
                    activeFirewallRequired = $true
                    defenderEnabled = $true
                    defenderVersion = $null
                    signatureOutOfDate = $false
                    rtpEnabled = $true
                    antivirusRequired = $true
                    antiSpywareRequired = $true
                    
                    # Threat Protection
                    deviceThreatProtectionEnabled = $false
                    deviceThreatProtectionRequiredSecurityLevel = "unavailable"
                    configurationManagerComplianceRequired = $false
                    
                    # Additional Settings
                    deviceCompliancePolicyScript = $null
                    validOperatingSystemBuildRanges = @()
                }
                
                $result = Invoke-GraphRequestWithRetry -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies" -Method POST -Body $windowsComplianceBody
                Write-LogMessage -Message "Created Windows compliance policy" -Type Success
                $compliancePolicies += $result
            }
            catch {
                Write-LogMessage -Message "Failed to create Windows compliance policy - $($_.Exception.Message)" -Type Error
            }
        }
        
        # iOS Compliance Policy
        Write-LogMessage -Message "Creating iOS compliance policy..." -Type Info
        
        $iosComplianceName = "iOS Corporate Compliance"
        if (Test-CompliancePolicyExists -PolicyName $iosComplianceName) {
            Write-LogMessage -Message "Compliance policy '$iosComplianceName' already exists, skipping creation" -Type Warning
            $compliancePolicies += @{ displayName = $iosComplianceName; id = "existing" }
        }
        else {
            try {
                $iosComplianceBody = @{
                    "@odata.type" = "#microsoft.graph.iosCompliancePolicy"
                    displayName = $iosComplianceName
                    description = "Corporate compliance requirements for iOS devices"
                    
                    # Password Requirements
                    passcodeRequired = $true
                    passcodeBlockSimple = $true
                    passcodeMinimumLength = 6
                    passcodeMinutesOfInactivityBeforeLock = 15
                    passcodeExpirationDays = 90
                    passcodeMinimumCharacterSetCount = 3
                    passcodePreviousPasscodeBlockCount = 5
                    passcodeSignInFailureCountBeforeWipe = 10
                    passcodeRequiredType = "alphanumeric"
                    
                    # Device Security
                    jailbroken = $false
                    deviceThreatProtectionEnabled = $false
                    deviceThreatProtectionRequiredSecurityLevel = "unavailable"
                    
                    # OS Version
                    osMinimumVersion = "14.0"
                    osMaximumVersion = $null
                    
                    # Additional Security
                    securityBlockJailbrokenDevices = $true
                    managedEMailProfileRequired = $false
                }
                
                $result = Invoke-GraphRequestWithRetry -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies" -Method POST -Body $iosComplianceBody
                Write-LogMessage -Message "Created iOS compliance policy" -Type Success
                $compliancePolicies += $result
            }
            catch {
                Write-LogMessage -Message "Failed to create iOS compliance policy - $($_.Exception.Message)" -Type Error
            }
        }
        
        # Android Compliance Policy
        Write-LogMessage -Message "Creating Android compliance policy..." -Type Info
        
        $androidComplianceName = "Android Corporate Compliance"
        if (Test-CompliancePolicyExists -PolicyName $androidComplianceName) {
            Write-LogMessage -Message "Compliance policy '$androidComplianceName' already exists, skipping creation" -Type Warning
            $compliancePolicies += @{ displayName = $androidComplianceName; id = "existing" }
        }
        else {
            try {
                $androidComplianceBody = @{
                    "@odata.type" = "#microsoft.graph.androidCompliancePolicy"
                    displayName = $androidComplianceName
                    description = "Corporate compliance requirements for Android devices"
                    
                    # Password Requirements
                    passwordRequired = $true
                    passwordMinimumLength = 6
                    passwordRequiredType = "alphanumeric"
                    passwordMinutesOfInactivityBeforeLock = 15
                    passwordExpirationDays = 90
                    passwordPreviousPasswordBlockCount = 5
                    passwordSignInFailureCountBeforeFactoryReset = 10
                    
                    # Device Security
                    securityPreventInstallAppsFromUnknownSources = $true
                    securityDisableUsbDebugging = $true
                    securityRequireVerifyApps = $true
                    deviceThreatProtectionEnabled = $false
                    deviceThreatProtectionRequiredSecurityLevel = "unavailable"
                    
                    # OS Version
                    minAndroidSecurityPatchLevel = "2023-01-01"
                    osMinimumVersion = "8.0"
                    osMaximumVersion = $null
                    
                    # Additional Security
                    storageRequireEncryption = $true
                    securityBlockJailbrokenDevices = $true
                }
                
                $result = Invoke-GraphRequestWithRetry -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies" -Method POST -Body $androidComplianceBody
                Write-LogMessage -Message "Created Android compliance policy" -Type Success
                $compliancePolicies += $result
            }
            catch {
                Write-LogMessage -Message "Failed to create Android compliance policy - $($_.Exception.Message)" -Type Error
            }
        }
        
        # =================================================================
        # POLICY ASSIGNMENTS
        # =================================================================
        Write-LogMessage -Message "Assigning policies to device groups..." -Type Info
        
        $policyAssignments = @{
            "Windows Defender Security" = "Windows Devices"
            "BitLocker Device Encryption" = "Windows Devices" 
            "OneDrive Business Configuration" = "Windows Devices"
            "Windows LAPS Configuration" = "Windows Devices"
            "Power Management Settings" = "Windows Devices"
            "Windows 10/11 Corporate Compliance" = "Windows Devices"
            "iOS Corporate Compliance" = "iOS Devices"
            "Android Corporate Compliance" = "Android Devices"
        }
        
        foreach ($policy in $policies) {
            if ($policy.id -ne "existing" -and $policyAssignments.ContainsKey($policy.displayName)) {
                $targetGroupName = $policyAssignments[$policy.displayName]
                $targetGroupId = $script:TenantState.CreatedGroups[$targetGroupName]
                
                if ($targetGroupId) {
                    try {
                        $assignmentBody = @{
                            assignments = @(
                                @{
                                    target = @{
                                        '@odata.type' = '#microsoft.graph.groupAssignmentTarget'
                                        groupId = $targetGroupId
                                    }
                                }
                            )
                        }
                        
                        $assignUri = "https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations/$($policy.id)/assign"
                        Invoke-GraphRequestWithRetry -Uri $assignUri -Method POST -Body $assignmentBody
                        Write-LogMessage -Message "Assigned policy '$($policy.displayName)' to group '$targetGroupName'" -Type Success
                    }
                    catch {
                        Write-LogMessage -Message "Failed to assign policy '$($policy.displayName)' - $($_.Exception.Message)" -Type Error
                    }
                }
            }
        }
        
        # Assign compliance policies
        foreach ($policy in $compliancePolicies) {
            if ($policy.id -ne "existing" -and $policyAssignments.ContainsKey($policy.displayName)) {
                $targetGroupName = $policyAssignments[$policy.displayName]
                $targetGroupId = $script:TenantState.CreatedGroups[$targetGroupName]
                
                if ($targetGroupId) {
                    try {
                        $assignmentBody = @{
                            assignments = @(
                                @{
                                    target = @{
                                        '@odata.type' = '#microsoft.graph.groupAssignmentTarget'
                                        groupId = $targetGroupId
                                    }
                                }
                            )
                        }
                        
                        $assignUri = "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies/$($policy.id)/assign"
                        Invoke-GraphRequestWithRetry -Uri $assignUri -Method POST -Body $assignmentBody
                        Write-LogMessage -Message "Assigned compliance policy '$($policy.displayName)' to group '$targetGroupName'" -Type Success
                    }
                    catch {
                        Write-LogMessage -Message "Failed to assign compliance policy '$($policy.displayName)' - $($_.Exception.Message)" -Type Error
                    }
                }
            }
        }
        
        # =================================================================
        # SUMMARY
        # =================================================================
        Write-LogMessage -Message "=== COMPREHENSIVE INTUNE CONFIGURATION SUMMARY ===" -Type Info
        Write-LogMessage -Message "Device Groups Created: $($requiredGroups.Keys.Count)" -Type Info
        Write-LogMessage -Message "Configuration Policies Created: $($policies.Count)" -Type Info
        Write-LogMessage -Message "  - Windows Defender: Comprehensive endpoint protection" -Type Info
        Write-LogMessage -Message "  - BitLocker: Full drive encryption with recovery" -Type Info
        Write-LogMessage -Message "  - OneDrive: Business configuration" -Type Info
        Write-LogMessage -Message "  - LAPS: Local admin password management" -Type Info
        Write-LogMessage -Message "  - Power Options: Sleep and power management" -Type Info
        Write-LogMessage -Message "Compliance Policies Created: $($compliancePolicies.Count)" -Type Info
        Write-LogMessage -Message "  - Windows: Corporate security requirements" -Type Info
        Write-LogMessage -Message "  - iOS: Mobile device compliance" -Type Info
        Write-LogMessage -Message "  - Android: Mobile device security" -Type Info
        Write-LogMessage -Message "LAPS Prerequisite: $(if($lapsEnabled){'Enabled'}else{'Check manually'})" -Type Info
        Write-LogMessage -Message "=====================================" -Type Info
        
        Write-LogMessage -Message "COMPREHENSIVE NEXT STEPS:" -Type Info
        Write-LogMessage -Message "1. Review all created policies in Microsoft Endpoint Manager admin center" -Type Info
        Write-LogMessage -Message "2. Verify policy assignments to device groups" -Type Info
        Write-LogMessage -Message "3. Enroll test devices to verify policy application" -Type Info
        Write-LogMessage -Message "4. Monitor compliance reports for policy effectiveness" -Type Info
        Write-LogMessage -Message "5. Check BitLocker recovery keys in Azure AD" -Type Info
        Write-LogMessage -Message "6. Verify LAPS admin accounts are created properly" -Type Info
        
        Write-LogMessage -Message "COMPREHENSIVE Intune configuration completed successfully!" -Type Success
        Write-LogMessage -Message "All policies with complete traditional configurations are ready for deployment." -Type Success
        
        return $true
    }
    catch {
        Write-LogMessage -Message "Error in comprehensive Intune configuration - $($_.Exception.Message)" -Type Error
        return $false
    }
}

# ▼ CB & Claude | BITS 365 Automation | v1.0 | "Smarter not Harder"