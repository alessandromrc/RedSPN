#Requires -Modules ActiveDirectory
#Requires -Version 5.1

<#
.SYNOPSIS
    Active Directory Security Audit Script
.DESCRIPTION
    Enumerates AD objects and security configurations for auditing purposes
.PARAMETER OutputPath
    Path to save the JSON output file
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "ad_audit_data.json",
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipComputerSecurityChecks,
    
    [Parameter(Mandatory=$false)]
    [int]$MaxComputersToCheck = 50
)

$ErrorActionPreference = "Stop"

# Initialize output object
$auditData = @{
    Timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    Domain = $env:USERDOMAIN
    Users = @()
    Computers = @()
    ServiceAccounts = @()
    NTLMEvents = @()
    KrbtgtInfo = $null
    PasswordPolicy = $null
    AccountLockoutPolicy = $null
    DomainControllers = @()
    TrustRelationships = @()
    OrganizationalUnits = @()
    SecurityGroups = @()
    ComputerSecurityStatus = @()
    DomainInfo = $null
    ForestInfo = $null
    LDAPPolicy = $null
    SMBPolicy = $null
    GPOSettings = @()
    FineGrainedPasswordPolicies = @()
    CertificateAuthorities = @()
    CertificateTemplates = @()
    EmptyGroups = @()
    LargeGroups = @()
    SuspiciousAccounts = @()
    FailedLogons = @()
    DangerousPermissions = @()
    NestedGroups = @()
    OutdatedComputers = @()
    ServiceAccountIssues = @()
    GPOIssues = @()
    EventLogSettings = @()
    KerberosPolicy = $null
    AccountPolicy = $null
    AnonymousAccess = $null
    SMBv1Usage = @()
    RDPEnabled = @()
    WinRMEnabled = @()
    Statistics = @{}
}

# ASCII Art Banner
$banner = @"
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║  ░█████████                    ░██   ░██████   ░█████████  ░███    ░██        ║
║  ░██     ░██                   ░██  ░██   ░██  ░██     ░██ ░████   ░██        ║
║  ░██     ░██  ░███████   ░████████ ░██         ░██     ░██ ░██░██  ░██        ║
║  ░█████████  ░██    ░██ ░██    ░██  ░████████  ░█████████  ░██ ░██ ░██        ║
║  ░██   ░██   ░█████████ ░██    ░██         ░██ ░██         ░██  ░██░██        ║
║  ░██    ░██  ░██        ░██   ░███  ░██   ░██  ░██         ░██   ░████        ║
║  ░██     ░██  ░███████   ░█████░██   ░██████   ░██         ░██    ░███        ║
║                                                                               ║
║                    Active Directory Security Audit Tool                       ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"@

Write-Host $banner -ForegroundColor Red
Write-Host ""

# Neofetch-style system info
try {
    $domain = Get-ADDomain -ErrorAction SilentlyContinue
    $forest = Get-ADForest -ErrorAction SilentlyContinue
    $dc = Get-ADDomainController -Discover -ErrorAction SilentlyContinue
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    $psVersion = $PSVersionTable.PSVersion
    
    $neofetch = @"
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║  Domain          $($domain.Name.PadRight(60)) ║
║  NetBIOS         $($domain.NetBIOSName.PadRight(60)) ║
║  Forest          $($forest.Name.PadRight(60)) ║
║  Domain Mode     $($domain.DomainMode.PadRight(60)) ║
║  Forest Mode     $($forest.ForestMode.PadRight(60)) ║
║  DC              $($dc.HostName.PadRight(60)) ║
║  OS              $($os.Caption.PadRight(60)) ║
║  PowerShell      $($psVersion.ToString().PadRight(60)) ║
║  User            $($env:USERNAME.PadRight(60)) ║
║  Computer        $($env:COMPUTERNAME.PadRight(60)) ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"@
    Write-Host $neofetch -ForegroundColor Green
} catch {
    # If we can't get AD info, show basic system info
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    $psVersion = $PSVersionTable.PSVersion
    
    $neofetch = @"
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║  Domain          $($env:USERDOMAIN.PadRight(60)) ║
║  OS              $($os.Caption.PadRight(60)) ║
║  PowerShell      $($psVersion.ToString().PadRight(60)) ║
║  User            $($env:USERNAME.PadRight(60)) ║
║  Computer        $($env:COMPUTERNAME.PadRight(60)) ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"@
    Write-Host $neofetch -ForegroundColor Green
}

Write-Host ""
Write-Host "Starting comprehensive AD security audit..." -ForegroundColor Cyan
Write-Host ""

# Function to convert encryption types
function Get-EncryptionTypes {
    param([int]$encryptionTypes)
    
    $types = @()
    if ($encryptionTypes -band 0x1) { $types += "DES" }
    if ($encryptionTypes -band 0x2) { $types += "RC4" }
    if ($encryptionTypes -band 0x4) { $types += "AES128" }
    if ($encryptionTypes -band 0x8) { $types += "AES256" }
    if ($types.Count -eq 0) { $types = @("None") }
    
    return $types
}

# Function to check group membership
function Test-GroupMembership {
    param(
        [string]$DistinguishedName,
        [string[]]$GroupNames
    )
    
    $memberOf = @()
    try {
        $user = Get-ADUser -Identity $DistinguishedName -Properties MemberOf -ErrorAction SilentlyContinue
        if ($user) {
            foreach ($group in $GroupNames) {
                $groupDN = (Get-ADGroup -Identity $group -ErrorAction SilentlyContinue).DistinguishedName
                if ($groupDN -and $user.MemberOf -contains $groupDN) {
                    $memberOf += $group
                }
            }
        }
    } catch {}
    
    return $memberOf
}

# Enumerate User Accounts
Write-Host "Enumerating user accounts..." -ForegroundColor Cyan
try {
    $users = Get-ADUser -Filter * -Properties `
        ServicePrincipalName, PasswordLastSet, PasswordNeverExpires, `
        msDS-SupportedEncryptionTypes, adminCount, TrustedForDelegation, `
        TrustedToAuthForDelegation, Enabled, LastLogonDate, `
        UserAccountControl, DistinguishedName, SamAccountName, `
        DisplayName, Description, PasswordExpired, PasswordNotRequired, `
        DoesNotRequirePreAuth, UseDESKeyOnly, AccountExpirationDate, `
        SmartcardLogonRequired, LogonWorkstations, LogonHours, `
        CannotChangePassword, AccountLockoutTime
    
    foreach ($user in $users) {
        if ($null -eq $user) { continue }
        
        $userObj = @{
            SamAccountName = $user.SamAccountName
            DisplayName = $user.DisplayName
            DistinguishedName = $user.DistinguishedName
            Enabled = $user.Enabled
            SPNs = @($user.ServicePrincipalName)
            PasswordLastSet = if ($user.PasswordLastSet) { $user.PasswordLastSet.ToString("yyyy-MM-ddTHH:mm:ssZ") } else { $null }
            PasswordNeverExpires = $user.PasswordNeverExpires
            PasswordExpired = $user.PasswordExpired
            PasswordNotRequired = $user.PasswordNotRequired
            EncryptionTypes = Get-EncryptionTypes -encryptionTypes $user.'msDS-SupportedEncryptionTypes'
            adminCount = if ($user.adminCount) { $user.adminCount } else { 0 }
            TrustedForDelegation = $user.TrustedForDelegation
            TrustedToAuthForDelegation = $user.TrustedToAuthForDelegation
            LastLogonDate = if ($user.LastLogonDate) { $user.LastLogonDate.ToString("yyyy-MM-ddTHH:mm:ssZ") } else { $null }
            AccountExpirationDate = if ($user.AccountExpirationDate) { $user.AccountExpirationDate.ToString("yyyy-MM-ddTHH:mm:ssZ") } else { $null }
            Description = $user.Description
            DoesNotRequirePreAuth = $user.DoesNotRequirePreAuth
            UseDESKeyOnly = $user.UseDESKeyOnly
        }
        
        # Check group memberships
        $userObj.MemberOf = Test-GroupMembership -DistinguishedName $user.DistinguishedName -GroupNames @("Domain Admins", "Enterprise Admins", "Protected Users")
        
        # Calculate days since last password change
        if ($userObj.PasswordLastSet) {
            $pwdDate = [DateTime]::Parse($userObj.PasswordLastSet)
            $userObj.DaysSincePasswordChange = [int]((Get-Date) - $pwdDate).TotalDays
        } else {
            $userObj.DaysSincePasswordChange = $null
        }
        
        # Calculate days since last logon
        if ($userObj.LastLogonDate) {
            $logonDate = [DateTime]::Parse($userObj.LastLogonDate)
            $userObj.DaysSinceLastLogon = [int]((Get-Date) - $logonDate).TotalDays
        } else {
            $userObj.DaysSinceLastLogon = $null
        }
        
        $auditData.Users += $userObj
    }
    
    Write-Host "   ✓ Found $($auditData.Users.Count) user accounts" -ForegroundColor Green
} catch {
    Write-Host "   ✗ Error enumerating users: $_" -ForegroundColor Red
}

# Enumerate Computer Accounts
Write-Host "Enumerating computer accounts..." -ForegroundColor Cyan
try {
    $computers = Get-ADComputer -Filter * -Properties `
        ServicePrincipalName, TrustedForDelegation, TrustedToAuthForDelegation, `
        msDS-SupportedEncryptionTypes, Enabled, DistinguishedName, `
        SamAccountName, OperatingSystem, OperatingSystemVersion, `
        LastLogonDate, Description, msDS-AllowedToDelegateTo, `
        IPv4Address, DNSHostName, OperatingSystemHotfix, `
        PasswordLastSet, whenCreated, whenChanged
    
    foreach ($computer in $computers) {
        if ($null -eq $computer) { continue }
        
        $compObj = @{
            SamAccountName = $computer.SamAccountName
            DistinguishedName = $computer.DistinguishedName
            Enabled = $computer.Enabled
            OperatingSystem = $computer.OperatingSystem
            OperatingSystemVersion = $computer.OperatingSystemVersion
            SPNs = @($computer.ServicePrincipalName)
            TrustedForDelegation = $computer.TrustedForDelegation
            TrustedToAuthForDelegation = $computer.TrustedToAuthForDelegation
            ConstrainedDelegation = if ($computer.'msDS-AllowedToDelegateTo') { @($computer.'msDS-AllowedToDelegateTo') } else { @() }
            EncryptionTypes = Get-EncryptionTypes -encryptionTypes $computer.'msDS-SupportedEncryptionTypes'
            LastLogonDate = if ($computer.LastLogonDate) { $computer.LastLogonDate.ToString("yyyy-MM-ddTHH:mm:ssZ") } else { $null }
            Description = $computer.Description
            IsDomainController = $computer.SamAccountName -like "*$"
            IPv4Address = $computer.IPv4Address
            DNSHostName = $computer.DNSHostName
            OperatingSystemHotfix = $computer.OperatingSystemHotfix
            PasswordLastSet = if ($computer.PasswordLastSet) { $computer.PasswordLastSet.ToString("yyyy-MM-ddTHH:mm:ssZ") } else { $null }
            Created = if ($computer.whenCreated) { $computer.whenCreated.ToString("yyyy-MM-ddTHH:mm:ssZ") } else { $null }
            Modified = if ($computer.whenChanged) { $computer.whenChanged.ToString("yyyy-MM-ddTHH:mm:ssZ") } else { $null }
        }
        
        # Calculate days since computer password change
        if ($compObj.PasswordLastSet) {
            $pwdDate = [DateTime]::Parse($compObj.PasswordLastSet)
            $compObj.DaysSincePasswordChange = [int]((Get-Date) - $pwdDate).TotalDays
        } else {
            $compObj.DaysSincePasswordChange = $null
        }
        
        # Calculate days since last logon
        if ($compObj.LastLogonDate) {
            $logonDate = [DateTime]::Parse($compObj.LastLogonDate)
            $compObj.DaysSinceLastLogon = [int]((Get-Date) - $logonDate).TotalDays
        } else {
            $compObj.DaysSinceLastLogon = $null
        }
        
        $auditData.Computers += $compObj
    }
    
    Write-Host "   ✓ Found $($auditData.Computers.Count) computer accounts" -ForegroundColor Green
} catch {
    Write-Host "   ✗ Error enumerating computers: $_" -ForegroundColor Red
}

# Identify Service Accounts (gMSA and accounts with passwords)
Write-Host "Identifying service accounts..." -ForegroundColor Cyan
try {
    # Get gMSA accounts
    $gmsaAccounts = Get-ADServiceAccount -Filter * -Properties `
        ServicePrincipalName, DistinguishedName, SamAccountName, `
        Enabled, Description, msDS-ManagedPasswordInterval
    
    foreach ($gmsa in $gmsaAccounts) {
        $svcObj = @{
            Type = "gMSA"
            SamAccountName = $gmsa.SamAccountName
            DistinguishedName = $gmsa.DistinguishedName
            Enabled = $gmsa.Enabled
            SPNs = @($gmsa.ServicePrincipalName)
            Description = $gmsa.Description
            ManagedPasswordInterval = $gmsa.'msDS-ManagedPasswordInterval'
        }
        $auditData.ServiceAccounts += $svcObj
    }
    
    # Identify user accounts that might be service accounts (heuristics)
    foreach ($user in $auditData.Users) {
        $isServiceAccount = $false
        $indicators = @()
        
        if ($user.SPNs.Count -gt 0) { 
            $isServiceAccount = $true
            $indicators += "Has SPNs"
        }
        if ($user.SamAccountName -like "svc_*" -or $user.SamAccountName -like "*service*" -or $user.SamAccountName -like "*svc*") {
            $isServiceAccount = $true
            $indicators += "Naming convention"
        }
        if ($user.Description -and ($user.Description -like "*service*" -or $user.Description -like "*application*")) {
            $isServiceAccount = $true
            $indicators += "Description"
        }
        if ($user.TrustedForDelegation -or $user.TrustedToAuthForDelegation) {
            $isServiceAccount = $true
            $indicators += "Delegation enabled"
        }
        
        if ($isServiceAccount) {
            $svcObj = @{
                Type = "User Service Account"
                SamAccountName = $user.SamAccountName
                DistinguishedName = $user.DistinguishedName
                Enabled = $user.Enabled
                SPNs = $user.SPNs
                Indicators = $indicators
                TrustedForDelegation = $user.TrustedForDelegation
                TrustedToAuthForDelegation = $user.TrustedToAuthForDelegation
            }
            $auditData.ServiceAccounts += $svcObj
        }
    }
    
    Write-Host "   ✓ Found $($auditData.ServiceAccounts.Count) service accounts" -ForegroundColor Green
} catch {
    Write-Host "   ✗ Error identifying service accounts" -ForegroundColor Red
}

# Check krbtgt account
Write-Host "Checking krbtgt account..." -ForegroundColor Cyan
try {
    $krbtgt = Get-ADUser -Identity "krbtgt" -Properties PasswordLastSet, Enabled, DistinguishedName
    if ($krbtgt) {
        $auditData.KrbtgtInfo = @{
            PasswordLastSet = if ($krbtgt.PasswordLastSet) { $krbtgt.PasswordLastSet.ToString("yyyy-MM-ddTHH:mm:ssZ") } else { $null }
            Enabled = $krbtgt.Enabled
            DistinguishedName = $krbtgt.DistinguishedName
        }
        
        if ($auditData.KrbtgtInfo.PasswordLastSet) {
            $pwdDate = [DateTime]::Parse($auditData.KrbtgtInfo.PasswordLastSet)
            $auditData.KrbtgtInfo.DaysSincePasswordChange = [int]((Get-Date) - $pwdDate).TotalDays
        }
        
        Write-Host "   ✓ krbtgt password last set: $($auditData.KrbtgtInfo.PasswordLastSet)" -ForegroundColor Green
    }
} catch {
    Write-Host "   ✗ Error checking krbtgt" -ForegroundColor Red
}

# Audit NTLM usage from Security Event Log
Write-Host "Scanning Security Event Log for NTLM usage..." -ForegroundColor Cyan
try {
    $events = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -MaxEvents 1000 -ErrorAction SilentlyContinue
    
    if (-not $events) {
        Write-Host "   [!] No Event ID 4624 events found" -ForegroundColor Yellow
        $auditData.NTLMEvents = @()
    } else {
        
        $ntlmEvents = @()
        foreach ($event in $events) {
            $xml = [xml]$event.ToXml()
            $eventData = @{}
            
            foreach ($data in $xml.Event.EventData.Data) {
                $eventData[$data.Name] = $data.'#text'
            }
            
            $authPackage = $eventData.AuthenticationPackageName
            $logonType = $eventData.LogonType
            
            # Check if NTLM was actually used (check AuthenticationPackageName for "NTLM")
            # Also include LogonType 2 (Interactive) and 3 (Network) which are commonly NTLM
            # but prioritize events where AuthenticationPackageName explicitly contains NTLM
            $isNTLM = $false
            if ($authPackage -and $authPackage -like "*NTLM*") {
                $isNTLM = $true
            } elseif ($logonType -eq "3" -or $logonType -eq "2") {
                # LogonType 3 (Network) and 2 (Interactive) can be NTLM or Kerberos
                # Include them but mark as "possible NTLM" if auth package doesn't explicitly say NTLM
                $isNTLM = $true
            }
            
            if ($isNTLM) {
                $ntlmObj = @{
                    TimeCreated = $event.TimeCreated.ToString("yyyy-MM-ddTHH:mm:ssZ")
                    AccountName = $eventData.TargetUserName
                    AccountDomain = $eventData.TargetDomainName
                    LogonType = $logonType
                    AuthenticationPackageName = $authPackage
                    WorkstationName = $eventData.WorkstationName
                    IPAddress = $eventData.IpAddress
                }
                $ntlmEvents += $ntlmObj
            }
        }
        
        $auditData.NTLMEvents = $ntlmEvents | Select-Object -First 100  # Limit to 100 most recent
        Write-Host "   ✓ Found $($auditData.NTLMEvents.Count) recent NTLM authentication events" -ForegroundColor Green
        if ($auditData.NTLMEvents.Count -eq 0) {
        }
    }
} catch {
    Write-Host "   ✗ Error scanning event log (requires elevated permissions)" -ForegroundColor Red
    $auditData.NTLMEvents = @()
}

# Function to get antivirus status via WMI
function Get-AntivirusStatus {
    param([string]$ComputerName)
    
    $avStatus = @{
        Installed = $false
        ProductName = $null
        ProductState = $null
        RealTimeProtectionEnabled = $null
        LastScanDate = $null
        Error = $null
        Online = $false
    }
    
    try {
        # First check if computer is online
        $ping = Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction SilentlyContinue
        if (-not $ping) {
            $avStatus.Error = "Computer offline or unreachable"
            return $avStatus
        }
        
        $avStatus.Online = $true
        
        # Try CIM first (preferred for newer systems)
        try {
            $avProducts = Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName AntiVirusProduct -ComputerName $ComputerName -ErrorAction SilentlyContinue
            if (-not $avProducts) {
                $avProducts = Get-CimInstance -Namespace "root\SecurityCenter" -ClassName AntiVirusProduct -ComputerName $ComputerName -ErrorAction SilentlyContinue
            }
        } catch {
            # Fallback to WMI
            $avProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct -ComputerName $ComputerName -ErrorAction SilentlyContinue
            if (-not $avProducts) {
                $avProducts = Get-WmiObject -Namespace "root\SecurityCenter" -Class AntiVirusProduct -ComputerName $ComputerName -ErrorAction SilentlyContinue
            }
        }
        
        if ($avProducts) {
            $avStatus.Installed = $true
            $avStatus.ProductName = $avProducts.displayName
            $avStatus.ProductState = $avProducts.productState
            # ProductState is a bitmask, check if real-time protection is enabled (bit 0x1000)
            $avStatus.RealTimeProtectionEnabled = ($avProducts.productState -band 0x1000) -eq 0x1000
        }
    } catch {
        $avStatus.Error = $_.Exception.Message
    }
    
    return $avStatus
}

# Function to get BitLocker status
function Get-BitLockerStatus {
    param([string]$ComputerName)
    
    $bitlockerStatus = @{
        Enabled = $false
        ProtectionStatus = $null
        EncryptionPercentage = $null
        VolumeStatus = @()
        Error = $null
        Online = $false
    }
    
    try {
        # Check if computer is online
        $ping = Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction SilentlyContinue
        if (-not $ping) {
            $bitlockerStatus.Error = "Computer offline or unreachable"
            return $bitlockerStatus
        }
        
        $bitlockerStatus.Online = $true
        
        # Try CIM first
        try {
            $volumes = Get-CimInstance -Namespace "Root\CIMV2\Security\MicrosoftVolumeEncryption" -ClassName Win32_EncryptableVolume -ComputerName $ComputerName -ErrorAction SilentlyContinue
        } catch {
            # Fallback to WMI
            $volumes = Get-WmiObject -Namespace "Root\CIMV2\Security\MicrosoftVolumeEncryption" -Class Win32_EncryptableVolume -ComputerName $ComputerName -ErrorAction SilentlyContinue
        }
        
        if ($volumes) {
            foreach ($vol in $volumes) {
                try {
                    $protStatus = $vol.GetProtectionStatus()
                    $convStatus = $vol.GetConversionStatus()
                    $volStatus = @{
                        DriveLetter = $vol.DriveLetter
                        ProtectionStatus = $protStatus.ProtectionStatus
                        EncryptionStatus = $convStatus.EncryptionStatus
                        EncryptionPercentage = $convStatus.EncryptionPercentage
                    }
                    $bitlockerStatus.VolumeStatus += $volStatus
                    if ($volStatus.ProtectionStatus -eq 1) {
                        $bitlockerStatus.Enabled = $true
                    }
                } catch {
                    # Skip volume if we can't get status
                }
            }
        }
    } catch {
        $bitlockerStatus.Error = $_.Exception.Message
    }
    
    return $bitlockerStatus
}

# Function to get Windows Update status
function Get-WindowsUpdateStatus {
    param([string]$ComputerName)
    
    $updateStatus = @{
        LastUpdateCheck = $null
        PendingUpdates = $null
        AutoUpdateEnabled = $null
        Error = $null
        Online = $false
    }
    
    try {
        # Check if computer is online
        $ping = Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction SilentlyContinue
        if (-not $ping) {
            $updateStatus.Error = "Computer offline or unreachable"
            return $updateStatus
        }
        
        $updateStatus.Online = $true
        
        # Check Windows Update service
        try {
            $wuService = Get-Service -Name wuauserv -ComputerName $ComputerName -ErrorAction SilentlyContinue
            if ($wuService) {
                $updateStatus.AutoUpdateEnabled = $wuService.Status -eq 'Running'
            }
        } catch {
            # Service check failed, but continue
        }
        
        # Note: COM objects don't work remotely, so we can't check pending updates remotely
        # This would require running locally on each machine or using WSUS/Group Policy
        
    } catch {
        $updateStatus.Error = $_.Exception.Message
    }
    
    return $updateStatus
}

# Function to get firewall status
function Get-FirewallStatus {
    param([string]$ComputerName)
    
    $firewallStatus = @{
        Enabled = $false
        Profiles = @()
        Error = $null
        Online = $false
    }
    
    try {
        # Check if computer is online
        $ping = Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction SilentlyContinue
        if (-not $ping) {
            $firewallStatus.Error = "Computer offline or unreachable"
            return $firewallStatus
        }
        
        $firewallStatus.Online = $true
        
        # Try CIM session
        try {
            $cimSession = New-CimSession -ComputerName $ComputerName -ErrorAction SilentlyContinue
            if ($cimSession) {
                $fwProfiles = Get-NetFirewallProfile -CimSession $cimSession -ErrorAction SilentlyContinue
                Remove-CimSession $cimSession
                
                if ($fwProfiles) {
                    foreach ($profile in $fwProfiles) {
                        $firewallStatus.Profiles += @{
                            Name = $profile.Name
                            Enabled = $profile.Enabled
                        }
                        if ($profile.Enabled) {
                            $firewallStatus.Enabled = $true
                        }
                    }
                }
            }
        } catch {
            # CIM failed, try WMI
            try {
                $fw = Get-WmiObject -Namespace "root\StandardCimv2" -Class MSFT_NetFirewallProfile -ComputerName $ComputerName -ErrorAction SilentlyContinue
                if ($fw) {
                    foreach ($profile in $fw) {
                        $firewallStatus.Profiles += @{
                            Name = $profile.Name
                            Enabled = $profile.Enabled
                        }
                        if ($profile.Enabled) {
                            $firewallStatus.Enabled = $true
                        }
                    }
                }
            } catch {
                $firewallStatus.Error = "Unable to query firewall status"
            }
        }
    } catch {
        $firewallStatus.Error = $_.Exception.Message
    }
    
    return $firewallStatus
}

# Get Computer Security Status (Antivirus, BitLocker, Firewall, Updates)
if (-not $SkipComputerSecurityChecks) {
    Write-Host "Gathering computer security status (AV, BitLocker, Firewall, Updates)..." -ForegroundColor Cyan
    Write-Host "    This may take a while for large environments..." -ForegroundColor Yellow
    Write-Host "    (Use -SkipComputerSecurityChecks to skip this step)" -ForegroundColor Yellow
    try {
        $computerCount = 0
        $enabledComputers = $auditData.Computers | Where-Object { $_.Enabled -eq $true } | Select-Object -First $MaxComputersToCheck
    
    foreach ($computer in $enabledComputers) {
        $computerCount++
        
        # Try to get the best computer name to use for connection
        $computerName = $null
        if ($computer.DNSHostName) {
            $computerName = $computer.DNSHostName
        } elseif ($computer.IPv4Address) {
            $computerName = $computer.IPv4Address
        } else {
            $computerName = $computer.SamAccountName -replace '\$', ''
        }
        
        if ($computerCount % 10 -eq 0) {
            Write-Host "    Processed $computerCount / $($enabledComputers.Count) computers..." -ForegroundColor Gray
        }
        
        Write-Host "    Checking $computerName ($($computer.SamAccountName))..." -ForegroundColor Gray
        
        try {
            $avStatus = Get-AntivirusStatus -ComputerName $computerName
            $bitlockerStatus = Get-BitLockerStatus -ComputerName $computerName
            $updateStatus = Get-WindowsUpdateStatus -ComputerName $computerName
            $firewallStatus = Get-FirewallStatus -ComputerName $computerName
            
            $securityStatus = @{
                ComputerName = $computerName
                SamAccountName = $computer.SamAccountName
                DNSHostName = if ($computer.DNSHostName) { $computer.DNSHostName } else { $null }
                IPv4Address = if ($computer.IPv4Address) { $computer.IPv4Address } else { $null }
                Antivirus = $avStatus
                BitLocker = $bitlockerStatus
                WindowsUpdate = $updateStatus
                Firewall = $firewallStatus
                LastChecked = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            }
            
            # Add to array - ensure we're working with the actual hashtable reference
            $auditData['ComputerSecurityStatus'] += ,$securityStatus
        } catch {
            # Silently continue on individual computer errors
            # Still add an entry with error info
            $securityStatus = @{
                ComputerName = $computerName
                SamAccountName = $computer.SamAccountName
                DNSHostName = if ($computer.DNSHostName) { $computer.DNSHostName } else { $null }
                IPv4Address = if ($computer.IPv4Address) { $computer.IPv4Address } else { $null }
                Antivirus = @{ Installed = $false; Online = $false; Error = $_.Exception.Message }
                BitLocker = @{ Enabled = $false; Online = $false; Error = $_.Exception.Message }
                WindowsUpdate = @{ Online = $false; Error = $_.Exception.Message }
                Firewall = @{ Enabled = $false; Online = $false; Error = $_.Exception.Message }
                LastChecked = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
            }
            # Add to array - ensure we're working with the actual hashtable reference
            $auditData['ComputerSecurityStatus'] += ,$securityStatus
        }
    }
    
        Write-Host "   ✓ Security status gathered for $computerCount computers" -ForegroundColor Green
    } catch {
        Write-Host "   ✗ Error gathering computer security status" -ForegroundColor Red
    }
} else {
    Write-Host "Skipping computer security checks" -ForegroundColor Yellow
}

# Ensure ComputerSecurityStatus is always present in the export (even if empty)
if (-not $auditData.ContainsKey('ComputerSecurityStatus')) {
    $auditData.ComputerSecurityStatus = @()
}

# Get Password Policy
Write-Host "Retrieving password policy..." -ForegroundColor Cyan
try {
    $domainPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue
    if ($domainPolicy) {
        $auditData.PasswordPolicy = @{
            MinPasswordLength = $domainPolicy.MinPasswordLength
            PasswordHistoryCount = $domainPolicy.PasswordHistoryCount
            MaxPasswordAge = if ($domainPolicy.MaxPasswordAge) { $domainPolicy.MaxPasswordAge.Days } else { $null }
            MinPasswordAge = if ($domainPolicy.MinPasswordAge) { $domainPolicy.MinPasswordAge.Days } else { $null }
            LockoutThreshold = $domainPolicy.LockoutThreshold
            LockoutDuration = if ($domainPolicy.LockoutDuration) { $domainPolicy.LockoutDuration.Minutes } else { $null }
            LockoutObservationWindow = if ($domainPolicy.LockoutObservationWindow) { $domainPolicy.LockoutObservationWindow.Minutes } else { $null }
            ComplexityEnabled = $domainPolicy.ComplexityEnabled
            ReversibleEncryptionEnabled = $domainPolicy.ReversibleEncryptionEnabled
        }
        Write-Host "   ✓ Password policy retrieved" -ForegroundColor Green
    }
} catch {
    Write-Host "   ✗ Error retrieving password policy" -ForegroundColor Red
}

# Get Account Lockout Policy
Write-Host "Retrieving account lockout policy..." -ForegroundColor Cyan
try {
    $domainPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue
    if ($domainPolicy) {
        $auditData.AccountLockoutPolicy = @{
            LockoutThreshold = $domainPolicy.LockoutThreshold
            LockoutDuration = if ($domainPolicy.LockoutDuration) { 
                $domainPolicy.LockoutDuration.TotalMinutes 
            } else { 
                $null 
            }
            LockoutObservationWindow = if ($domainPolicy.LockoutObservationWindow) { 
                $domainPolicy.LockoutObservationWindow.TotalMinutes 
            } else { 
                $null 
            }
        }
        Write-Host "   ✓ Account lockout policy retrieved" -ForegroundColor Green
    } else {
        Write-Host "   [!] Account lockout policy not configured" -ForegroundColor Yellow
        $auditData.AccountLockoutPolicy = @{
            LockoutThreshold = $null
            LockoutDuration = $null
            LockoutObservationWindow = $null
        }
    }
} catch {
    Write-Host "   ✗ Error retrieving account lockout policy" -ForegroundColor Red
    $auditData.AccountLockoutPolicy = @{
        LockoutThreshold = $null
        LockoutDuration = $null
        LockoutObservationWindow = $null
    }
}

# Get Domain Controllers
Write-Host "Enumerating domain controllers..." -ForegroundColor Cyan
try {
    $dcs = Get-ADDomainController -Filter * -ErrorAction SilentlyContinue
    foreach ($dc in $dcs) {
        $dcInfo = @{
            Name = $dc.Name
            HostName = $dc.HostName
            IPv4Address = $dc.IPv4Address
            OperatingSystem = $dc.OperatingSystem
            OperatingSystemVersion = $dc.OperatingSystemVersion
            Site = $dc.Site
            IsGlobalCatalog = $dc.IsGlobalCatalog
            IsReadOnly = $dc.IsReadOnly
        }
        $auditData.DomainControllers += $dcInfo
    }
    Write-Host "   ✓ Found $($auditData.DomainControllers.Count) domain controllers" -ForegroundColor Green
} catch {
    Write-Host "   ✗ Error enumerating domain controllers" -ForegroundColor Red
}

# Get Trust Relationships
Write-Host "Enumerating trust relationships..." -ForegroundColor Cyan
try {
    $trusts = Get-ADTrust -Filter * -ErrorAction SilentlyContinue
    foreach ($trust in $trusts) {
        $trustInfo = @{
            Name = $trust.Name
            Direction = $trust.Direction
            TrustType = $trust.TrustType
            Source = $trust.Source
            Target = $trust.Target
            SelectiveAuthentication = $trust.SelectiveAuthentication
            SIDFilteringForestAware = $trust.SIDFilteringForestAware
            SIDFilteringQuarantined = $trust.SIDFilteringQuarantined
        }
        $auditData.TrustRelationships += $trustInfo
    }
    Write-Host "   ✓ Found $($auditData.TrustRelationships.Count) trust relationships" -ForegroundColor Green
} catch {
    Write-Host "   ✗ Error enumerating trust relationships" -ForegroundColor Red
}

# Get Organizational Units
Write-Host "Enumerating organizational units..." -ForegroundColor Cyan
try {
    $ous = Get-ADOrganizationalUnit -Filter * -Properties ProtectedFromAccidentalDeletion, Description -ErrorAction SilentlyContinue
    foreach ($ou in $ous) {
        $ouInfo = @{
            Name = $ou.Name
            DistinguishedName = $ou.DistinguishedName
            ProtectedFromAccidentalDeletion = $ou.ProtectedFromAccidentalDeletion
            Description = $ou.Description
            Created = if ($ou.Created) { $ou.Created.ToString("yyyy-MM-ddTHH:mm:ssZ") } else { $null }
            Modified = if ($ou.Modified) { $ou.Modified.ToString("yyyy-MM-ddTHH:mm:ssZ") } else { $null }
        }
        $auditData.OrganizationalUnits += $ouInfo
    }
    Write-Host "   ✓ Found $($auditData.OrganizationalUnits.Count) organizational units" -ForegroundColor Green
} catch {
    Write-Host "   ✗ Error enumerating organizational units" -ForegroundColor Red
}

# Get Security Groups (focus on high-privilege groups)
Write-Host "Enumerating security groups..." -ForegroundColor Cyan
try {
    $privilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Account Operators", 
                          "Backup Operators", "Server Operators", "Print Operators", "Replicator",
                          "Domain Controllers", "Read-Only Domain Controllers", "Protected Users",
                          "Group Policy Creator Owners", "DnsAdmins", "Cryptographic Operators")
    
    foreach ($groupName in $privilegedGroups) {
        try {
            $group = Get-ADGroup -Identity $groupName -Properties Members, Description, GroupScope, GroupCategory -ErrorAction SilentlyContinue
            if ($group) {
                $members = @()
                foreach ($member in $group.Members) {
                    $memberObj = Get-ADObject -Identity $member -Properties SamAccountName, ObjectClass -ErrorAction SilentlyContinue
                    if ($memberObj) {
                        $members += @{
                            SamAccountName = $memberObj.SamAccountName
                            ObjectClass = $memberObj.ObjectClass
                            DistinguishedName = $memberObj.DistinguishedName
                        }
                    }
                }
                
                $groupInfo = @{
                    Name = $group.Name
                    DistinguishedName = $group.DistinguishedName
                    Description = $group.Description
                    GroupScope = $group.GroupScope
                    GroupCategory = $group.GroupCategory
                    MemberCount = $members.Count
                    Members = $members
                }
                $auditData.SecurityGroups += $groupInfo
            }
        } catch {
            # Group doesn't exist, skip
        }
    }
    
    # Also get custom groups with "admin" in name
    $adminGroups = Get-ADGroup -Filter "Name -like '*admin*' -or Name -like '*Admin*'" -Properties Members, Description, GroupScope, GroupCategory -ErrorAction SilentlyContinue
    foreach ($group in $adminGroups) {
        if ($group.Name -notin ($auditData.SecurityGroups | ForEach-Object { $_.Name })) {
            $groupInfo = @{
                Name = $group.Name
                DistinguishedName = $group.DistinguishedName
                Description = $group.Description
                GroupScope = $group.GroupScope
                GroupCategory = $group.GroupCategory
                MemberCount = $group.Members.Count
            }
            $auditData.SecurityGroups += $groupInfo
        }
    }
    
    Write-Host "   ✓ Found $($auditData.SecurityGroups.Count) security groups" -ForegroundColor Green
} catch {
    Write-Host "   ✗ Error enumerating security groups" -ForegroundColor Red
}

# Find Empty Groups
Write-Host "Finding empty security groups..." -ForegroundColor Cyan
try {
    $allGroups = Get-ADGroup -Filter * -Properties Members -ErrorAction SilentlyContinue
    foreach ($group in $allGroups) {
        if ($group.Members.Count -eq 0) {
            $auditData.EmptyGroups += @{
                Name = $group.Name
                DistinguishedName = $group.DistinguishedName
                GroupScope = $group.GroupScope
                GroupCategory = $group.GroupCategory
            }
        }
    }
    Write-Host "   ✓ Found $($auditData.EmptyGroups.Count) empty groups" -ForegroundColor Green
} catch {
    Write-Host "   ✗ Error finding empty groups" -ForegroundColor Red
}

# Find Large Groups (potential security risk)
Write-Host "Finding large security groups..." -ForegroundColor Cyan
try {
    $allGroups = Get-ADGroup -Filter * -Properties Members -ErrorAction SilentlyContinue
    foreach ($group in $allGroups) {
        if ($group.Members.Count -gt 1000) {
            $auditData.LargeGroups += @{
                Name = $group.Name
                DistinguishedName = $group.DistinguishedName
                MemberCount = $group.Members.Count
                GroupScope = $group.GroupScope
            }
        }
    }
    Write-Host "   ✓ Found $($auditData.LargeGroups.Count) groups with >1000 members" -ForegroundColor Green
} catch {
    Write-Host "   ✗ Error finding large groups" -ForegroundColor Red
}

# Find Suspicious Accounts
Write-Host "Identifying suspicious accounts..." -ForegroundColor Cyan
try {
    $suspiciousAccounts = @()
    
    # Exclude normal/expected accounts
    $excludedAccounts = @("Guest", "krbtgt")
    
    # Accounts with password never expires in privileged groups
    $privilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Account Operators", "Backup Operators")
    foreach ($user in $auditData.Users) {
        # Skip excluded accounts
        if ($user.SamAccountName -in $excludedAccounts) {
            continue
        }
        
        $isSuspicious = $false
        $reasons = @()
        
        if ($user.PasswordNeverExpires -and ($user.MemberOf | Where-Object { $_ -in $privilegedGroups })) {
            $isSuspicious = $true
            $reasons += "Password never expires in privileged group"
        }
        
        # Password not required is only suspicious for non-Guest accounts
        if ($user.PasswordNotRequired) {
            $isSuspicious = $true
            $reasons += "Password not required"
        }
        
        if ($user.DoesNotRequirePreAuth -and ($user.MemberOf | Where-Object { $_ -in $privilegedGroups })) {
            $isSuspicious = $true
            $reasons += "Does not require pre-auth in privileged group"
        }
        
        if ($user.Enabled -and $user.LastLogonDate) {
            try {
                $lastLogon = [DateTime]::Parse($user.LastLogonDate)
                $daysSinceLogon = ((Get-Date) - $lastLogon).TotalDays
                if ($daysSinceLogon -gt 365) {
                    $isSuspicious = $true
                    $reasons += "Enabled but not logged in for >365 days"
                }
            } catch {
                # Skip if date parsing fails
            }
        }
        
        if ($isSuspicious) {
            $suspiciousAccounts += @{
                SamAccountName = $user.SamAccountName
                DisplayName = $user.DisplayName
                Enabled = $user.Enabled
                Reasons = $reasons
                MemberOf = $user.MemberOf
            }
        }
    }
    
    $auditData.SuspiciousAccounts = $suspiciousAccounts
    Write-Host "   ✓ Found $($suspiciousAccounts.Count) suspicious accounts" -ForegroundColor Yellow
} catch {
    Write-Host "   ✗ Error identifying suspicious accounts" -ForegroundColor Red
}

# Check for Failed Logon Attempts (Event ID 4625)
Write-Host "Scanning for failed logon attempts..." -ForegroundColor Cyan
try {
    $failedLogons = @()
    $events = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 500 -ErrorAction SilentlyContinue
    
    if ($events) {
        foreach ($event in $events) {
            $xml = [xml]$event.ToXml()
            $eventData = @{}
            
            foreach ($data in $xml.Event.EventData.Data) {
                $eventData[$data.Name] = $data.'#text'
            }
            
            $failedLogon = @{
                TimeCreated = $event.TimeCreated.ToString("yyyy-MM-ddTHH:mm:ssZ")
                AccountName = $eventData.TargetUserName
                AccountDomain = $eventData.TargetDomainName
                FailureReason = $eventData.SubStatus
                IPAddress = $eventData.IpAddress
                WorkstationName = $eventData.WorkstationName
            }
            $failedLogons += $failedLogon
        }
    }
    
    $auditData.FailedLogons = $failedLogons | Select-Object -First 100
    Write-Host "   ✓ Found $($auditData.FailedLogons.Count) recent failed logon attempts" -ForegroundColor Green
} catch {
    Write-Host "   ✗ Error scanning failed logons (requires Security log access)" -ForegroundColor Red
    $auditData.FailedLogons = @()
}

# Get GPO Security Settings
Write-Host "Enumerating GPO security settings..." -ForegroundColor Cyan
try {
    $gpos = Get-GPO -All -ErrorAction SilentlyContinue
    foreach ($gpo in $gpos) {
        $gpoInfo = @{
            DisplayName = $gpo.DisplayName
            GUID = $gpo.Id.ToString()
            Created = if ($gpo.CreationTime) { $gpo.CreationTime.ToString("yyyy-MM-ddTHH:mm:ssZ") } else { $null }
            Modified = if ($gpo.ModificationTime) { $gpo.ModificationTime.ToString("yyyy-MM-ddTHH:mm:ssZ") } else { $null }
            Enabled = $gpo.GpoStatus -eq 'AllSettingsEnabled'
        }
        $auditData.GPOSettings += $gpoInfo
    }
    Write-Host "   ✓ Found $($auditData.GPOSettings.Count) GPOs" -ForegroundColor Green
} catch {
    Write-Host "   ✗ Error enumerating GPOs (Group Policy module may not be installed)" -ForegroundColor Red
}

# Calculate statistics
Write-Host "Calculating statistics..." -ForegroundColor Cyan
$auditData.Statistics = @{
    TotalUsers = $auditData.Users.Count
    EnabledUsers = ($auditData.Users | Where-Object { $_.Enabled }).Count
    UsersWithSPNs = ($auditData.Users | Where-Object { $_.SPNs.Count -gt 0 }).Count
    UsersWithDelegation = ($auditData.Users | Where-Object { $_.TrustedForDelegation -or $_.TrustedToAuthForDelegation }).Count
    DomainAdmins = ($auditData.Users | Where-Object { $_.MemberOf -contains "Domain Admins" }).Count
    EnterpriseAdmins = ($auditData.Users | Where-Object { $_.MemberOf -contains "Enterprise Admins" }).Count
    ProtectedUsers = ($auditData.Users | Where-Object { $_.MemberOf -contains "Protected Users" }).Count
    TotalComputers = $auditData.Computers.Count
    ComputersWithDelegation = ($auditData.Computers | Where-Object { $_.TrustedForDelegation -or $_.TrustedToAuthForDelegation -or $_.ConstrainedDelegation.Count -gt 0 }).Count
    TotalServiceAccounts = $auditData.ServiceAccounts.Count
    NTLMEventCount = $auditData.NTLMEvents.Count
    DomainControllers = $auditData.DomainControllers.Count
    TrustRelationships = $auditData.TrustRelationships.Count
    OrganizationalUnits = $auditData.OrganizationalUnits.Count
    SecurityGroups = $auditData.SecurityGroups.Count
    ComputersWithAV = ($auditData.ComputerSecurityStatus | Where-Object { $_.Antivirus.Installed -eq $true }).Count
    ComputersWithBitLocker = ($auditData.ComputerSecurityStatus | Where-Object { $_.BitLocker.Enabled -eq $true }).Count
    ComputersWithFirewall = ($auditData.ComputerSecurityStatus | Where-Object { $_.Firewall.Enabled -eq $true }).Count
    EmptyGroups = if ($auditData.EmptyGroups) { $auditData.EmptyGroups.Count } else { 0 }
    LargeGroups = if ($auditData.LargeGroups) { $auditData.LargeGroups.Count } else { 0 }
    SuspiciousAccounts = if ($auditData.SuspiciousAccounts) { $auditData.SuspiciousAccounts.Count } else { 0 }
    FailedLogonCount = if ($auditData.FailedLogons) { $auditData.FailedLogons.Count } else { 0 }
    FineGrainedPasswordPolicies = if ($auditData.FineGrainedPasswordPolicies) { $auditData.FineGrainedPasswordPolicies.Count } else { 0 }
    CertificateAuthorities = if ($auditData.CertificateAuthorities) { $auditData.CertificateAuthorities.Count } else { 0 }
    CertificateTemplates = if ($auditData.CertificateTemplates) { $auditData.CertificateTemplates.Count } else { 0 }
    GPOCount = if ($auditData.GPOSettings) { $auditData.GPOSettings.Count } else { 0 }
    NestedGroups = if ($auditData.NestedGroups) { $auditData.NestedGroups.Count } else { 0 }
    OutdatedComputers = if ($auditData.OutdatedComputers) { $auditData.OutdatedComputers.Count } else { 0 }
    ServiceAccountIssues = if ($auditData.ServiceAccountIssues) { $auditData.ServiceAccountIssues.Count } else { 0 }
    GPOIssues = if ($auditData.GPOIssues) { $auditData.GPOIssues.Count } else { 0 }
    SMBv1Enabled = if ($auditData.SMBv1Usage) { ($auditData.SMBv1Usage | Where-Object { $_.SMBv1ClientEnabled -or $_.SMBv1ServerEnabled }).Count } else { 0 }
    RDPEnabledCount = if ($auditData.RDPEnabled) { $auditData.RDPEnabled.Count } else { 0 }
    WinRMEnabledCount = if ($auditData.WinRMEnabled) { $auditData.WinRMEnabled.Count } else { 0 }
}

# Export to JSON
# Ensure ComputerSecurityStatus is a proper array for JSON serialization
if ($null -eq $auditData.ComputerSecurityStatus) {
    $auditData.ComputerSecurityStatus = @()
}

# Resolve the output path to ensure it's absolute
if (-not [System.IO.Path]::IsPathRooted($OutputPath)) {
    $OutputPath = Join-Path (Get-Location) $OutputPath
}
$OutputPath = [System.IO.Path]::GetFullPath($OutputPath)

Write-Host "Exporting data to $OutputPath..." -ForegroundColor Cyan

try {
    # Ensure directory exists
    $outputDir = Split-Path $OutputPath -Parent
    if (-not (Test-Path $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    }
    
    # Check if file exists and is locked
    if (Test-Path $OutputPath) {
        try {
            # Try to open the file for writing to check if it's locked
            $fileStream = [System.IO.File]::Open($OutputPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
            $fileStream.Close()
        } catch {
            $tempPath = $OutputPath + ".tmp"
            $OutputPath = $tempPath
        }
    }
    
    # Convert to JSON with error handling
    $jsonContent = $auditData | ConvertTo-Json -Depth 10 -ErrorAction Stop
    
    # Write UTF-8 without BOM (Python-compatible)
    # Use multiple methods to ensure file is written
    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    $bytes = $utf8NoBom.GetBytes($jsonContent)
    
    try {
        # Try WriteAllText first
        [System.IO.File]::WriteAllText($OutputPath, $jsonContent, $utf8NoBom)
    } catch {
        # Alternative: Use FileStream
        try {
            $fileStream = [System.IO.File]::Create($OutputPath)
            $fileStream.Write($bytes, 0, $bytes.Length)
            $fileStream.Close()
        } catch {
            Write-Host "    FileStream also failed: $_" -ForegroundColor Red
            # Last resort: Use Out-File
            try {
                $jsonContent | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
            } catch {
                Write-Host "    All write methods failed: $_" -ForegroundColor Red
                throw
            }
        }
    }
    
    # Verify the file was written
    Start-Sleep -Milliseconds 100  # Give filesystem time to sync
    if (Test-Path $OutputPath) {
        $fileInfo = Get-Item $OutputPath
        
        # Verify JSON can be read back
        try {
            $verifyData = Get-Content $OutputPath -Raw -Encoding UTF8 | ConvertFrom-Json
        } catch {
        }
    } else {
        Write-Host "✗ ERROR: File was not created after all write attempts!" -ForegroundColor Red
    }
    
    Write-Host ""
    Write-Host "✓ Audit complete! Data exported to: $OutputPath" -ForegroundColor Green
} catch {
    Write-Host "✗ ERROR exporting data: $_" -ForegroundColor Red
    Write-Host "    Error details: $($_.Exception.Message)" -ForegroundColor Red
    throw
}

Write-Host "Run the Python script to generate HTML report: python .\generate_report.py" -ForegroundColor Cyan

