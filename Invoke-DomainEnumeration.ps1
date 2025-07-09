# Usage: Invoke-DomainEnumeration -DC 10.10.10.10 -Username user1@domain.com -Password s3cr3tPass

function Invoke-DomainEnumeration {
    param (
        [Parameter(Mandatory = $true)]
        [string]$DC,

        [Parameter(Mandatory = $false)]
        [string]$Domain,

        [Parameter(Mandatory = $false)]
        [string]$Username,

        [Parameter(Mandatory = $false)]
        [string]$Password
    )

    function Print-SectionHeader {
        param (
            [string]$Header
        )
        $width = 40
        $centeredHeader = $Header.PadLeft(($Header.Length + $width) / 2).PadRight($width)
        Write-Host ("`n" + "-" * $width)
        Write-Host -ForegroundColor Cyan $centeredHeader
        Write-Host ("-" * $width)
    }

    # Embed the C# code using Add-Type
    if (-not ([System.Management.Automation.PSTypeName]"RpcDump").Type) {
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public class RpcDump
{
    private const string MS_PAR_UUID = "76F03F96-CDFD-44FC-A22C-64950A001209";
    private const string MS_RPRN_UUID = "12345678-1234-ABCD-EF00-0123456789AB";

    [DllImport("Rpcrt4.dll", CharSet = CharSet.Auto)]
    private static extern int RpcBindingFromStringBinding(
        string StringBinding,
        out IntPtr Binding
    );

    [DllImport("Rpcrt4.dll")]
    private static extern int RpcBindingFree(
        ref IntPtr Binding
    );

    [DllImport("Rpcrt4.dll", CharSet = CharSet.Auto)]
    private static extern int RpcMgmtIsServerListening(
        IntPtr Binding
    );

    [DllImport("Rpcrt4.dll", CharSet = CharSet.Auto)]
    private static extern int RpcStringBindingCompose(
        string ObjUuid,
        string ProtSeq,
        string NetworkAddr,
        string Endpoint,
        string Options,
        out string StringBinding
    );

    public static string CheckRpcInterface(string hostname, string uuid, string protocolName, string description)
    {
        IntPtr binding = IntPtr.Zero;
        string stringBinding;
        StringBuilder output = new StringBuilder();

        try
        {
            int result = RpcStringBindingCompose(
                uuid,
                "ncacn_ip_tcp",
                hostname,
                "135",
                null,
                out stringBinding
            );

            if (result == 0)
            {
                result = RpcBindingFromStringBinding(stringBinding, out binding);
                if (result == 0)
                {
                    result = RpcMgmtIsServerListening(binding);
                    if (result == 0)
                    {
                        output.AppendLine("Protocol: [" + protocolName + "]: " + description);
                    }
                }
            }
        }
        finally
        {
            if (binding != IntPtr.Zero)
            {
                RpcBindingFree(ref binding);
            }
        }

        return output.ToString();
    }

    public static string RunRpcDump(string hostname)
    {
        StringBuilder output = new StringBuilder();

        // Check MS-PAR
        output.Append(CheckRpcInterface(hostname, MS_PAR_UUID, "MS-PAR", "Print System Asynchronous Remote Protocol"));

        // Check MS-RPRN
        output.Append(CheckRpcInterface(hostname, MS_RPRN_UUID, "MS-RPRN", "Print System Remote Protocol"));

        return output.ToString();
    }
}
"@
    }

    # Function to perform RPC dump check against all domain computers
    function Invoke-RpcDumpCheck {
        param (
            [System.DirectoryServices.DirectoryEntry]$Connection,
            [string]$BaseDN
        )

        Print-SectionHeader "RPCDump Check"

        # Get all domain computers (excluding MSA/GMSA)
        $computerSearch = [adsisearcher]"(&(objectClass=computer)(!(objectClass=msDS-ManagedServiceAccount))(!(objectClass=msDS-GroupManagedServiceAccount)))"
        $computerSearch.SearchRoot = [adsi]"LDAP://$DC/$BaseDN"
        $computerSearch.PropertiesToLoad.AddRange(@("dNSHostName"))
        $computers = $computerSearch.FindAll()

        foreach ($computer in $computers) {
            $computerFQDN = $computer.Properties['dNSHostName'][0]
        
            # Skip if the computer FQDN is empty or invalid
            if ([string]::IsNullOrEmpty($computerFQDN)) {
                continue
            }

            # Run the RPC dump check
            try {
                # Capture the output of the RPC dump check
                $output = [RpcDump]::RunRpcDump($computerFQDN)

                # If the output contains RPC protocol information, display the computer and results
                if (-not [string]::IsNullOrEmpty($output)) {
                    Write-Host "Computer Account: $computerFQDN" -ForegroundColor Yellow
                    Write-Host $output -ForegroundColor Red
                }
            }
            catch {
                # Silently handle errors (e.g., offline or unreachable computers)
            }
        }
    }

    function List-GPOsAndLinks {
        param (
            [System.DirectoryServices.DirectoryEntry]$Connection,
            [string]$BaseDN
        )

        Print-SectionHeader "GPO Enumeration"

        # First, get all GPOs in the domain and store them in a hashtable for quick lookup
        $gpoSearch = [adsisearcher]"(&(objectClass=groupPolicyContainer))"
        $gpoSearch.SearchRoot = [adsi]"LDAP://$DC/$BaseDN"
        $gpoSearch.PropertiesToLoad.AddRange(@("displayName", "cn", "gPCFileSysPath"))
        $gpos = $gpoSearch.FindAll()

        if ($gpos.Count -eq 0) {
            Write-Host "No GPOs found in the domain."
            return
        }

        # Create a hashtable to map GPO GUIDs (with curly braces) to their display names
        $gpoMap = @{}
        foreach ($gpo in $gpos) {
            $gpoGuid = $gpo.Properties['cn'][0]  # The GUID is stored in the 'cn' attribute (with curly braces)
            $gpoName = $gpo.Properties['displayName'][0]
            $gpoMap[$gpoGuid] = $gpoName
        }

        # Now, search for all objects (OUs, domains, and containers) that have the gPLink attribute
        $gpoLinkSearch = [adsisearcher]"(gPLink=*)"
        $gpoLinkSearch.SearchRoot = [adsi]"LDAP://$DC/$BaseDN"
        $gpoLinkSearch.PropertiesToLoad.AddRange(@("distinguishedName", "gPLink"))
        $gpoLinks = $gpoLinkSearch.FindAll()

        if ($gpoLinks.Count -eq 0) {
            Write-Host "No GPO links found in the domain."
            return
        }

        # Parse the gPLink attribute for each object
        foreach ($gpoLink in $gpoLinks) {
            $objectDN = $gpoLink.Properties['distinguishedName'][0]
            $gpoLinkValue = $gpoLink.Properties['gPLink'][0]

            Write-Host "Linked to: $objectDN" -ForegroundColor Yellow

            # Parse the gPLink value to extract GPO GUIDs (with curly braces)
            $gpoGuids = $gpoLinkValue -split '\]\[' | ForEach-Object {
                if ($_ -match '\{([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\}') {
                    "{$($matches[1])}"  # Extract the GPO GUID and wrap it in curly braces
                }
            }

            # Display the GPOs linked to this object
            foreach ($gpoGuid in $gpoGuids) {
                if ($gpoMap.ContainsKey($gpoGuid)) {
                    Write-Host "  - GPO: $($gpoMap[$gpoGuid]) (GUID: $gpoGuid)" -ForegroundColor Green
                }
                else {
                    Write-Host "  - GPO: [Unknown] (GUID: $gpoGuid)" -ForegroundColor Red
                }
            }

            Write-Host " "
        }
    }

    function Get-DomainInfo {
        param (
            [System.DirectoryServices.DirectoryEntry]$Connection,
            [string]$BaseDN
        )
        $domain = [adsi]"LDAP://$DC/$BaseDN"
        Print-SectionHeader "Domain Info"
    
        # Construct the full domain name from the BaseDN
        $fullDomainName = ($BaseDN -replace 'DC=', '') -replace ',', '.'
        Write-Host "Domain Name: $fullDomainName"
    
        # Convert the SID byte array to a proper SID string
        if ($domain.objectSid -ne $null) {
            $sid = New-Object System.Security.Principal.SecurityIdentifier($domain.objectSid[0], 0)
            Write-Host "Domain SID: $($sid.Value)"
        }
        else {
            Write-Host "Domain SID: [Not available]"
        }
    
        # Get ms-DS-MachineAccountQuota value
        $machineAccountQuota = $domain.Properties['ms-DS-MachineAccountQuota'][0]
        if ($machineAccountQuota -ne $null) {

            if ($machineAccountQuota -gt 0) { Write-Host "Machine Account Quota: $machineAccountQuota " -ForegroundColor Red }
            else { Write-Host "Machine Account Quota: $machineAccountQuota " }
        }
        else {
            Write-Host "Machine Account Quota: [Not available]"
        }
    }

    function Get-WSUSConfiguration {
        Print-SectionHeader "WSUS Configuration Check"
    
        $regPath = "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"
        
        try {
            # Check if the registry path exists
            if (Test-Path $regPath) {
                $wuServer = Get-ItemProperty -Path $regPath -Name "WUServer" -ErrorAction SilentlyContinue
                
                if ($wuServer -and $wuServer.WUServer) {
                    Write-Host "WSUS Server detected:" -ForegroundColor Yellow
                    Write-Host "WUServer: $($wuServer.WUServer)" -ForegroundColor Green
                    
                    # Check for additional relevant values
                    $wuStatusServer = Get-ItemProperty -Path $regPath -Name "WUStatusServer" -ErrorAction SilentlyContinue
                    if ($wuStatusServer -and $wuStatusServer.WUStatusServer) {
                        Write-Host "WUStatusServer: $($wuStatusServer.WUStatusServer)" -ForegroundColor Green
                    }
                }
                else {
                    Write-Host "No WSUS server configured in registry (WUServer value not found)."
                }
            }
            else {
                Write-Host "WindowsUpdate registry key not found. WSUS likely not configured via Group Policy."
            }
        }
        catch {
            Write-Host "Error checking WSUS configuration: $_" -ForegroundColor Red
        }
        
        Write-Host " "
    }
    function Get-EnterpriseCA {
        param (
            [System.DirectoryServices.DirectoryEntry]$Connection,
            [string]$ConfigNC
        )
        $caSearchBase = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$ConfigNC"
        $caSearch = [adsisearcher]"(&(objectClass=pKIEnrollmentService))"
        $caSearch.SearchRoot = [adsi]"LDAP://$DC/$caSearchBase"
        $caSearch.PropertiesToLoad.AddRange(@("name", "dNSHostName", "cn"))  # Added cn for CA name
        $cas = $caSearch.FindAll()

        Print-SectionHeader "ADCS Info"
        if ($cas.Count -gt 0) {
            foreach ($ca in $cas) {
                $caName = $ca.Properties['name'][0]
                $caServer = $ca.Properties['dNSHostName'][0]
                $caCN = $ca.Properties['cn'][0]

                Write-Host "Enterprise CA: $caServer\$caName" -ForegroundColor Green
                Write-Host "- CA Common Name: $caCN"
                Write-Host " "

                # Check if web enrollment is running
                $webEnrollmentUrl = "http://$caServer/certsrv"
                try {
                    $request = [System.Net.WebRequest]::Create($webEnrollmentUrl)
                    $request.Method = "HEAD"  # Use HEAD to only fetch headers
                    $request.Timeout = 5000  # 5 second timeout
    
                    try {
                        $response = $request.GetResponse()
                        $statusCode = [int]$response.StatusCode
            
                        # Check for NTLM authentication header
                        $ntlmAuthEnabled = $false
                        $authHeaders = $response.Headers["WWW-Authenticate"]
                        if ($authHeaders -match "NTLM") {
                            $ntlmAuthEnabled = $true
                        }
            
                        $response.Close()
        
                        if ($statusCode -eq 200 -or $statusCode -eq 401) {
                            Write-Host "- [!] Web Enrollment over HTTP: RUNNING (ESC8)" -ForegroundColor Yellow
                            Write-Host "- [!] Relay URL: $webEnrollmentUrl/certfnsh.asp" -ForegroundColor Red
                
                            # Report NTLM auth status
                            if ($ntlmAuthEnabled) {
                                Write-Host "- [!] NTLM Authentication: ENABLED" -ForegroundColor Red
                            }
                            else {
                                Write-Host "- [!] NTLM Authentication: DISABLED" -ForegroundColor Green
                            }
                        }
                    }
                    catch [System.Net.WebException] {
                        $statusCode = [int]$_.Exception.Response.StatusCode
                        $authHeaders = $_.Exception.Response.Headers["WWW-Authenticate"]
                        $ntlmAuthEnabled = $authHeaders -match "NTLM"
            
                        if ($statusCode -eq 401) {
                            Write-Host "- [!] Web Enrollment over HTTP: RUNNING (ESC8)" -ForegroundColor Yellow
                            Write-Host "- [!] Relay URL: $webEnrollmentUrl/certfnsh.asp" -ForegroundColor Red
                
                            if ($ntlmAuthEnabled) {
                                Write-Host "- [!] NTLM Authentication: ENABLED" -ForegroundColor Red
                            }
                            else {
                                Write-Host "- [!] NTLM Authentication: DISABLED" -ForegroundColor Green
                            }
                        }
                    }
                }
                catch {
                    # Silently handle other errors (e.g., inaccessible servers)
                }

                try {
                    $CASecurity = certutil.exe -config "$caServer\$caName" -getreg "CA\Security" 2>&1 | Out-String
        
                    $defaultGroups = @(
                        "NT AUTHORITY\Authenticated Users",
                        "BUILTIN\Administrators",
                        "Domain Admins",
                        "Enterprise Admins"
                    )
        
                    $permissions = @{}
        
                    # Process each line of the certutil output
                    foreach ($line in $CASecurity -split "`r`n") {
                        if ($line -match "Allow\s+(.*?)\t(.*)") {
                            $permTypes = $matches[1].Trim()
                            $principal = $matches[2].Trim()
                    
                            # Skip default groups - check if principal ends with any default group name
                            $isDefault = $false
                            foreach ($group in $defaultGroups) {
                                if ($principal -like "*\$group" -or $principal -eq $group) {
                                    $isDefault = $true
                                    break
                                }
                            }
                            if ($isDefault) {
                                continue
                            }
                    
                            # Initialize principal if not already in hash
                            if (-not $permissions.ContainsKey($principal)) {
                                $permissions[$principal] = @{
                                    "CA Administrator"    = $false
                                    "Certificate Manager" = $false
                                }
                            }
                    
                            # Check for CA Administrator permission
                            if ($permTypes -match "CA Administrator") {
                                $permissions[$principal]["CA Administrator"] = $true
                            }
                    
                            # Check for Certificate Manager permission
                            if ($permTypes -match "Certificate Manager") {
                                $permissions[$principal]["Certificate Manager"] = $true
                            }
                        }
                    }
            
                    # Display results
                    if ($permissions.Count -gt 0) {
                        Write-Host " "
                        Write-Host "- [!] Non-default users with CA permissions (ESC7):" -ForegroundColor Yellow
                        foreach ($principal in $permissions.Keys) {
                            $perms = @()
                            if ($permissions[$principal]["CA Administrator"]) { $perms += "CA Administrator" }
                            if ($permissions[$principal]["Certificate Manager"]) { $perms += "Certificate Manager" }
                    
                            Write-Host "   - $principal : $($perms -join ', ')" -ForegroundColor Red
                        }
                        Write-Host " "
                    }
                }
                catch {
                    Write-Host "- Error checking CA security permissions: $_" -ForegroundColor Red
                }

                try {
                    $CASecurity2 = certutil.exe -config "$caServer\$caName" -getreg "policy\EditFlags" 2>&1 | Out-String
                    if ($CASecurity2 -like "*EDITF_ATTRIBUTESUBJECTALTNAME2*") {
                        Write-Host "- [!] Vulnerable flag found: EDITF_ATTRIBUTESUBJECTALTNAME2 (Potential ESC6)" -ForegroundColor Yellow
                        Write-Host " "
                    }
                    $CASecurity3 = certutil.exe -config "$caServer\$caName" -getreg "CA\InterfaceFlags" 2>&1 | Out-String
                    if ($CASecurity3 -like "*InterfaceFlags*REG_DWORD*10*") {
                        Write-Host "- [!] Vulnerable flag found: Encryption is not enforced for RPC requests (ESC11)" -ForegroundColor Yellow
                        Write-Host " "
                    }
                }
                catch {
                    Write-Host "- Error checking CA flags: $_" -ForegroundColor Red
                }
                Write-Host " "
            }

            # Enumerate Certificate Templates
            $defaultTemplates = @(
                "Administrator", "CA", "CAExchange", "CEPEncryption", "ClientAuth", 
                "CodeSigning", "CrossCA", "CTLSigning", "DirectoryEmailReplication", 
                "DomainController", "DomainControllerAuthentication", "EFS", 
                "EFSRecovery", "EnrollmentAgent", "EnrollmentAgentOffline", 
                "ExchangeUser", "ExchangeUserSignature", "IPSECIntermediateOffline", 
                "IPSECIntermediateOnline", "KerberosAuthentication", "KeyRecoveryAgent", 
                "Machine", "MachineEnrollmentAgent", "OCSPResponseSigning", 
                "OfflineRouter", "RASAndIASServer", "SmartcardLogon", "SmartcardUser", 
                "SubCA", "User", "UserSignature", "WebServer", "Workstation"
            )

            $templateSearchBase = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigNC"
            $templateSearch = [adsisearcher]"(&(objectClass=pKICertificateTemplate))"
            $templateSearch.SearchRoot = [adsi]"LDAP://$DC/$templateSearchBase"
            $templateSearch.PropertiesToLoad.AddRange(@("name", "displayName", "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag", "msPKI-Private-Key-Flag"))
            $templates = $templateSearch.FindAll()
            $nonDefaultTemplates = @()
            $vulnerableTemplates = @()

            foreach ($template in $templates) {
                $templateName = $template.Properties['name'][0]
                $displayName = $template.Properties['displayName'][0]
            
                if ($defaultTemplates -notcontains $templateName) {
                    $nonDefaultTemplates += $templateName
                    Write-Host "- [!] Non-default template found: $templateName ($displayName)" -ForegroundColor Yellow
                }

                # Check for vulnerable settings (ESC1, ESC2, etc.)
                $enrollmentFlags = $template.Properties['msPKI-Enrollment-Flag'][0]
                $certNameFlags = $template.Properties['msPKI-Certificate-Name-Flag'][0]
                $privateKeyFlags = $template.Properties['msPKI-Private-Key-Flag'][0]

                # ESC1: ENROLLEE_SUPPLIES_SUBJECT + CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
                if (($enrollmentFlags -band 0x00040000) -and ($certNameFlags -band 0x00000001)) {
                    $vulnerableTemplates += "$templateName (ESC1 - Enrollee Supplies Subject)"
                }

                # ESC2: Any Purpose or Certificate Request Agent
                if (($enrollmentFlags -band 0x00080000) -or ($templateName -eq "EnrollmentAgent")) {
                    $vulnerableTemplates += "$templateName (ESC2 - Any Purpose/Agent)"
                }
            }
            if ($vulnerableTemplates.Count -gt 0) {
                Write-Host "`n- [!] Found $($vulnerableTemplates.Count) potentially vulnerable templates:" -ForegroundColor Red
                $vulnerableTemplates | ForEach-Object { Write-Host "   - $_" -ForegroundColor Red }
            }
        }
        else {
            Write-Host "Enterprise CA not found."
        }
    }

    function Get-TrustedDomainDCs {
        param (
            [string]$DomainName
        )

        try {
            # Method 1: DNS Query (SRV records)
            Write-Host "`nEnumerating DCs for domain: $DomainName" -ForegroundColor Cyan
            $dnsQuery = Resolve-DnsName -Type SRV -Name "_ldap._tcp.dc._msdcs.$DomainName" -ErrorAction SilentlyContinue
            $dcs = $dnsQuery | Where-Object { $_.Type -eq 'SRV' } | Select-Object NameTarget -Unique

            if ($dcs) {
                Write-Host "[+] Domain Controllers in '$DomainName':" -ForegroundColor Green
                $dcs | ForEach-Object { Write-Host "  - $($_.NameTarget)" }
                Write-Host " "
            }
            else {
                # Method 2: Fallback to LDAP (if DNS fails)
                Write-Host "[!] DNS query failed. Trying LDAP..." -ForegroundColor Yellow
                $domainEntry = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainName"
                $searcher = New-Object System.DirectoryServices.DirectorySearcher($domainEntry)
                $searcher.Filter = "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"  # 8192 = DC
                $searcher.PropertiesToLoad.Add("name") | Out-Null
                $dcResults = $searcher.FindAll()

                if ($dcResults.Count -gt 0) {
                    Write-Host "[+] Domain Controllers in '$DomainName':" -ForegroundColor Green
                    $dcResults | ForEach-Object { Write-Host "  - $($_.Properties['name'][0])" }
                }
                else {
                    Write-Host "[-] No DCs found for '$DomainName'." -ForegroundColor Red
                }
            }
        }
        catch {
            Write-Host "[!] Error fetching DCs for '$DomainName': $_" -ForegroundColor Red
        }
    }
    function List-Trusts {
        param (
            [System.DirectoryServices.DirectoryEntry]$Connection,
            [string]$BaseDN
        )

        Print-SectionHeader "Active Directory Trusts"

        try {
            # Get current domain name (for SourceName)
            $currentDomain = ($BaseDN -replace 'DC=', '' -replace ',', '.')

            # Search for all trust objects in the System container
            $trustSearch = [adsisearcher]"(&(objectClass=trustedDomain))"
            $trustSearch.SearchRoot = [adsi]"LDAP://$DC/CN=System,$BaseDN"
            $trustSearch.PropertiesToLoad.AddRange(@(
                    "name", # Target domain name (e.g., "logistics.ad")
                    "trustDirection", # 1=Inbound, 2=Outbound, 3=Bidirectional
                    "trustType", # 1=Downlevel (NT), 2=Uplevel (AD), etc.
                    "trustAttributes", # Flags (e.g., FOREST_TRANSITIVE, WITHIN_FOREST)
                    "securityIdentifier", # SID of the trusted domain
                    "flatName"            # NetBIOS name (e.g., "LOGISTICS")
                ))
            $trusts = $trustSearch.FindAll()

            if ($trusts.Count -eq 0) {
                Write-Host "No domain trusts found." -ForegroundColor Yellow
                return
            }

            foreach ($trust in $trusts) {
                $targetName = $trust.Properties['name'][0]
                $netBiosName = if ($trust.Properties['flatName']) { $trust.Properties['flatName'][0] } else { "N/A" }
                $trustDirection = $trust.Properties['trustDirection'][0]
                $trustType = $trust.Properties['trustType'][0]
                $trustAttributes = $trust.Properties['trustAttributes'][0]
                $trustSid = if ($trust.Properties['securityIdentifier']) { 
                    (New-Object System.Security.Principal.SecurityIdentifier($trust.Properties['securityIdentifier'][0], 0)).Value 
                }
                else { "N/A" }

                $directionMap = @{
                    0 = "Disabled"
                    1 = "Inbound"
                    2 = "Outbound"
                    3 = "Bidirectional"
                }
                $directionText = $directionMap[$trustDirection]

                $typeMap = @{
                    1 = "DOWNLEVEL"  # NT domain
                    2 = "WINDOWS_ACTIVE_DIRECTORY"
                    3 = "MIT"
                    4 = "DCE"
                }
                $typeText = $typeMap[$trustType]

                # Decode trustAttributes (like PowerView)
                $attributeFlags = @()
                if ($trustAttributes -band 0x1) { $attributeFlags += "NON_TRANSITIVE" }
                if ($trustAttributes -band 0x2) { $attributeFlags += "UPLEVEL_ONLY" }
                if ($trustAttributes -band 0x4) { $attributeFlags += "QUARANTINED_DOMAIN" }
                if ($trustAttributes -band 0x8) { $attributeFlags += "FOREST_TRANSITIVE (Forest-wide Authentication)" }
                if ($trustAttributes -band 0x10) { $attributeFlags += "CROSS_ORGANIZATION (Selective Authentication)" }
                if ($trustAttributes -band 0x20) { $attributeFlags += "WITHIN_FOREST" }
                if ($trustAttributes -band 0x40) { $attributeFlags += "TREAT_AS_EXTERNAL" }
                if ($trustAttributes -band 0x80) { $attributeFlags += "USES_RC4_ENCRYPTION" }
                if ($trustAttributes -band 0x100) { $attributeFlags += "USES_AES_KEYS" }
                if ($trustAttributes -band 0x200) { $attributeFlags += "CROSS_ORGANIZATION_NO_TGT_DELEGATION" }
                if ($trustAttributes -band 0x400) { $attributeFlags += "PIM_TRUST" }
                if ($trustAttributes -band 0x800) { $attributeFlags += "CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION" }
                $attributesText = if ($attributeFlags.Count -gt 0) { $attributeFlags -join "," } else { "None" }

                $highlightColor = if (
                    ($trustDirection -eq 3) -or
                    ($trustAttributes -band 0x40) -or
                    ($trustAttributes -band 0x8) -or
                    ($trustAttributes -band 0x800) -or
                    ($trustAttributes -band 0x80)
                ) { "Red" } else { "Green" }

                # Display trust details (PowerView-style)
                Write-Host "SourceName      : $currentDomain" -ForegroundColor Green
                Write-Host "TargetName      : $targetName ($netBiosName)" -ForegroundColor Green
                Write-Host "TrustType       : $typeText"
                Write-Host "TrustAttributes : $attributesText" -ForegroundColor $highlightColor
                Write-Host "TrustDirection  : $directionText"
                Write-Host "TrustSID        : $trustSid"
                Write-Host " "
            
                if ($trustDirection -eq 1 -or $trustDirection -eq 3) {
                    Get-TrustedDomainDCs -DomainName $targetName
                }
            }
        }
        catch {
            Write-Host "Error enumerating trusts: $_" -ForegroundColor Red
        }
    }
    function List-Users {
        param (
            [System.DirectoryServices.DirectoryEntry]$Connection,
            [string]$BaseDN
        )
        Print-SectionHeader "All Domain Users"

        # Get current domain trusts first (for SID History matching)
        $trusts = @{}
        try {
            $trustSearch = [adsisearcher]"(&(objectClass=trustedDomain))"
            $trustSearch.SearchRoot = [adsi]"LDAP://$DC/CN=System,$BaseDN"
            $trustSearch.PropertiesToLoad.AddRange(@("name", "securityIdentifier"))
            $trustResults = $trustSearch.FindAll()
        
            foreach ($trust in $trustResults) {
                if ($trust.Properties['securityIdentifier']) {
                    $trustSid = (New-Object System.Security.Principal.SecurityIdentifier($trust.Properties['securityIdentifier'][0], 0)).Value
                    $trusts[$trustSid] = $trust.Properties['name'][0]
                }
            }
        }
        catch {
            Write-Host "Error enumerating trusts for SID History matching: $_" -ForegroundColor Yellow
        }

        # Create a directory searcher with explicit property loading
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($Connection)
        $searcher.Filter = "(&(objectCategory=person)(objectClass=user))"
        $searcher.PropertiesToLoad.AddRange(@("sAMAccountName", "userPrincipalName", "distinguishedName", "sIDHistory", "scriptPath"))
        $searcher.PageSize = 1000

        $usersWithScripts = 0
        $allUsers = 0
        $usersWithSidHistory = 0

        try {
            $results = $searcher.FindAll()
            foreach ($result in $results) {
                $allUsers++
                $username = $result.Properties['sAMAccountName'][0]
                $upn = $result.Properties['userPrincipalName'][0]
                $dn = $result.Properties['distinguishedName'][0]
            
                # Explicitly check for scriptPath in Properties collection
                $scriptPath = $null
                if ($result.Properties.Contains('scriptPath') -and $result.Properties['scriptPath'].Count -gt 0) {
                    $scriptPath = $result.Properties['scriptPath'][0]
                }

                if (-not [string]::IsNullOrEmpty($scriptPath)) {
                    $usersWithScripts++
                }

                # Always write these common properties
                Write-Host "samAccountName: $username"
                Write-Host "UPN: $upn"
                Write-Host "DN: $dn"
            
                if (-not [string]::IsNullOrEmpty($scriptPath)) {
                    Write-Host "scriptPath: $scriptPath" -ForegroundColor Red
                }
            
                # Handle SID History
                if ($result.Properties['sIDHistory'] -and $result.Properties['sIDHistory'].Count -gt 0) {
                    $usersWithSidHistory++
                    foreach ($sidBytes in $result.Properties['sIDHistory']) {
                        try {
                            $sid = New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)
                            $sidString = $sid.Value
                            Write-Host "SID History: $sidString" -ForegroundColor Yellow
            
                            # Split the SID into parts
                            $sidParts = $sidString -split '-'
            
                            # Only proceed if we have a valid SID format
                            if ($sidParts.Count -ge 4) {
                                # Get the domain portion (remove the last RID component)
                                $domainSid = $sidParts[0..($sidParts.Count - 2)] -join '-'
                
                                # Check against all trusted domains
                                foreach ($trust in $trusts.GetEnumerator()) {
                                    $trustSid = $trust.Key
                                    $trustName = $trust.Value
                    
                                    # Compare the domain portions
                                    if ($domainSid -eq $trustSid) {
                                        Write-Host "  [!] SID History allows access to: $trustName" -ForegroundColor Red
                                        break
                                    }
                                }
                            }
                        }
                        catch {
                            
                        }
                    }
                }
                Write-Host " "
            }
        }
        finally {
            if ($results -ne $null) { $results.Dispose() }
        }
    
        Write-Host "`nProcessed $allUsers users total." -ForegroundColor Cyan
        if ($usersWithScripts -gt 0) {
            Write-Host "Found $usersWithScripts users with scriptPath attribute." -ForegroundColor Cyan
        }
        if ($usersWithSidHistory -gt 0) {
            Write-Host "Found $usersWithSidHistory users with SID History." -ForegroundColor Cyan
        }
    }

    function List-Computers {
        param (
            [System.DirectoryServices.DirectoryEntry]$Connection,
            [string]$BaseDN
        )
        $computerSearch = [adsisearcher]"(&(objectClass=computer)(!(objectClass=msDS-ManagedServiceAccount))(!(objectClass=msDS-GroupManagedServiceAccount)))"
        $computerSearch.SearchRoot = [adsi]"LDAP://$DC/$BaseDN"
        $computerSearch.PropertiesToLoad.AddRange(@("sAMAccountName", "distinguishedName", "operatingSystem"))
        $computers = $computerSearch.FindAll()

        Print-SectionHeader "All Domain Computers"
        foreach ($computer in $computers) {
            Write-Host "Computer: $($computer.Properties['sAMAccountName'][0])"
            Write-Host "DN: $($computer.Properties['distinguishedName'][0])"
            Write-Host "Platform: $($computer.Properties['operatingSystem'][0])"
            Write-Host " "
        }
    }
    function List-ShadowPrincipals {
        param (
            [System.DirectoryServices.DirectoryEntry]$Connection,
            [string]$ConfigNC
        )
    
        Print-SectionHeader "Shadow Principals"
    
        try {
            $shadowPrincipalBase = "CN=Shadow Principal Configuration,CN=Services,$ConfigNC"
            $shadowPrincipalSearch = [adsisearcher]"(&(objectClass=msDS-ShadowPrincipal))"
            $shadowPrincipalSearch.SearchRoot = [adsi]"LDAP://$DC/$shadowPrincipalBase"
            $shadowPrincipalSearch.PropertiesToLoad.AddRange(@("name", "member", "msDS-ShadowPrincipalSid"))
            $shadowPrincipals = $shadowPrincipalSearch.FindAll()

            if ($shadowPrincipals.Count -eq 0) {
                Write-Host "No Shadow Principals found." -ForegroundColor Yellow
                return
            }

            # Get all domain trusts for SID mapping
            $trusts = @{}
            $trustSearch = [adsisearcher]"(&(objectClass=trustedDomain))"
            $trustSearch.SearchRoot = [adsi]"LDAP://$DC/CN=System,$($connection.distinguishedName)"
            $trustSearch.PropertiesToLoad.AddRange(@("name", "securityIdentifier", "flatName"))
            $trustResults = $trustSearch.FindAll()
        
            foreach ($trust in $trustResults) {
                if ($trust.Properties['securityIdentifier']) {
                    $trustSid = (New-Object System.Security.Principal.SecurityIdentifier($trust.Properties['securityIdentifier'][0], 0)).Value
                    $trusts[$trustSid] = @{
                        "Domain"  = $trust.Properties['name'][0]
                        "NetBIOS" = if ($trust.Properties['flatName']) { $trust.Properties['flatName'][0] } else { $null }
                    }
                }
            }

            foreach ($principal in $shadowPrincipals) {
                $name = $principal.Properties['name'][0]
                $members = $principal.Properties['member']
                $shadowSid = if ($principal.Properties['msDS-ShadowPrincipalSid']) { 
                    $sidBytes = $principal.Properties['msDS-ShadowPrincipalSid'][0]
                    $sid = New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)
                    $sid.Value
                }
                else { $null }

                # Only show if there are members
                if ($members -and $members.Count -gt 0) {
                    Write-Host "Shadow Principal: $name" -ForegroundColor Yellow
                
                    if ($shadowSid) {
                        # First try to resolve locally
                        $resolvedName = $null
                        $sourceDomain = $null
                        $objectType = $null
                    
                        try {
                            $ntAccount = $sid.Translate([System.Security.Principal.NTAccount])
                            $resolvedName = $ntAccount.Value
                        
                            # Determine object type
                            try {
                                $obj = [adsi]("LDAP://<SID=$shadowSid>")
                                if ($obj.Properties['objectClass'] -contains 'group') {
                                    $objectType = "Group"
                                }
                                elseif ($obj.Properties['objectClass'] -contains 'user') {
                                    $objectType = "User"
                                }
                                else {
                                    $objectType = "Unknown"
                                }
                            }
                            catch {
                                $objectType = "Unknown"
                            }
                        
                            Write-Host "Shadow SID: $shadowSid ($resolvedName - $objectType)" -ForegroundColor Cyan
                        }
                        catch {
                            # If local translation fails, try to identify the source domain
                            $sidParts = $shadowSid -split '-'
                            if ($sidParts.Count -ge 3) {
                                $domainSid = $sidParts[0..($sidParts.Count - 2)] -join '-'
                            
                                # Check if this is from a known trusted domain
                                $trustMatch = $trusts.GetEnumerator() | Where-Object { $_.Key -eq $domainSid } | Select-Object -First 1
                            
                                if ($trustMatch) {
                                    $sourceDomain = $trustMatch.Value.Domain
                                    $netbiosName = $trustMatch.Value.NetBIOS
                                
                                    # Try to resolve the SID in the foreign domain
                                    $foreignObject = $null
                                    try {
                                        # Create a connection to the foreign domain
                                        $foreignDN = ($sourceDomain.Split('.') | ForEach-Object { "DC=$_" }) -join ','
                                        $foreignLDAP = "LDAP://$DC/$foreignDN"
                                    
                                        if ($Username -and $Password) {
                                            $foreignConn = New-Object System.DirectoryServices.DirectoryEntry($foreignLDAP, $Username, $Password)
                                        }
                                        else {
                                            $foreignConn = New-Object System.DirectoryServices.DirectoryEntry($foreignLDAP)
                                        }
                                    
                                        if ($foreignConn.Path) {
                                            # Try to find the object by SID
                                            $searcher = New-Object System.DirectoryServices.DirectorySearcher($foreignConn)
                                            $searcher.Filter = "(objectSid=$shadowSid)"
                                            $searcher.PropertiesToLoad.AddRange(@("samAccountName", "objectClass", "distinguishedName"))
                                            $result = $searcher.FindOne()
                                        
                                            if ($result) {
                                                $samAccount = $result.Properties['samAccountName'][0]
                                                $dn = $result.Properties['distinguishedName'][0]
                                            
                                                if ($result.Properties['objectClass'] -contains 'group') {
                                                    $objectType = "Group"
                                                    $resolvedName = "$netbiosName\$samAccount"
                                                }
                                                elseif ($result.Properties['objectClass'] -contains 'user') {
                                                    $objectType = "User"
                                                    $resolvedName = "$netbiosName\$samAccount"
                                                }
                                                else {
                                                    $objectType = "Unknown"
                                                    $resolvedName = "$netbiosName\$samAccount"
                                                }
                                            
                                                Write-Host "Shadow SID: $shadowSid ($resolvedName - $objectType)" -ForegroundColor Red
                                                Write-Host "  DN: $dn" -ForegroundColor DarkCyan
                                            }
                                            else {
                                                Write-Host "Shadow SID: $shadowSid (From $sourceDomain but object not found)" -ForegroundColor Red
                                            }
                                        }
                                        else {
                                            Write-Host "Shadow SID: $shadowSid (From $sourceDomain but could not connect)" -ForegroundColor Red
                                        }
                                    }
                                    catch {
                                        Write-Host "Shadow SID: $shadowSid (From $sourceDomain but resolution failed: $($_.Exception.Message))" -ForegroundColor Yellow
                                    }
                                }
                                else {
                                    Write-Host "Shadow SID: $shadowSid (Unknown source - not from any trusted domain)" -ForegroundColor Red
                                }
                            }
                            else {
                                Write-Host "Shadow SID: $shadowSid (Invalid SID format)" -ForegroundColor Red
                            }
                        }
                    }
                    else {
                        Write-Host "Shadow SID: [Not set]" -ForegroundColor Yellow
                    }

                    Write-Host "Members:"
                    foreach ($member in $members) {
                        Write-Host "  - $member" -ForegroundColor Green
                    }
                    Write-Host " "
                }
            }
        }
        catch {
            Write-Host "Error enumerating Shadow Principals: $_" -ForegroundColor Red
        }
    }

    function List-ManagedServiceAccounts {
        param (
            [System.DirectoryServices.DirectoryEntry]$Connection,
            [string]$BaseDN
        )
        $managedSearch = [adsisearcher]"(|(objectClass=msDS-GroupManagedServiceAccount)(objectClass=msDS-ManagedServiceAccount))"
        $managedSearch.SearchRoot = [adsi]"LDAP://$DC/$BaseDN"
        $managedSearch.PropertiesToLoad.AddRange(@("sAMAccountName", "userPrincipalName", "distinguishedName", "description", "objectClass", "msDS-GroupMSAMembership", "objectSid"))
        $managedAccounts = $managedSearch.FindAll()

        Print-SectionHeader "Service Accounts"
        foreach ($account in $managedAccounts) {
            $samAccountName = $account.Properties['sAMAccountName'][0]
            $description = if ($account.Properties['description']) { $account.Properties['description'][0] } else { $null }
            $objectClass = $account.Properties['objectClass']
            $objectSid = if ($account.Properties['objectSid']) { 
                (New-Object System.Security.Principal.SecurityIdentifier($account.Properties['objectSid'][0], 0)).Value 
            }
            else { $null }
            if ($objectClass -contains "msDS-GroupManagedServiceAccount") {
                $accountType = "Group Managed Service Account (gMSA)"
            
                # Get principals that can retrieve the gMSA password
                $allowedPrincipals = @()
                if ($account.Properties['msDS-GroupMSAMembership']) {
                    $sdBytes = $account.Properties['msDS-GroupMSAMembership'][0]
                    try {
                        # Create a security descriptor from the byte array
                        $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
                        $sd.SetSecurityDescriptorBinaryForm($sdBytes)
                    
                        # Get all access rules
                        foreach ($rule in $sd.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])) {
                            if ($rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow) {
                                $identity = $rule.IdentityReference.Value
                                $allowedPrincipals += $identity
                            }
                        }
                    }
                    catch {
                        Write-Host "  - [Error] Could not parse security descriptor: $_" -ForegroundColor Red
                    }
                }
            }
            elseif ($objectClass -contains "msDS-ManagedServiceAccount") {
                $accountType = "Managed Service Account (MSA)"
            }
            else {
                $accountType = "Unknown"
            }

            Write-Host "SAM Account Name: $samAccountName"
            Write-Host "Account Type: $accountType"
            if ($objectSid) {
                Write-Host "Object SID: $objectSid"
            }
            if ($description) {
                Write-Host "Description: $description" -ForegroundColor Yellow
            }
        
            if ($allowedPrincipals.Count -gt 0) {
                Write-Host "Password Retrieval Allowed For:" -ForegroundColor Red
                foreach ($principal in $allowedPrincipals) {
                    Write-Host "  - $principal" -ForegroundColor Red
                }
            }
            Write-Host " "
        }
    }

    function List-DomainControllers {
        param (
            [System.DirectoryServices.DirectoryEntry]$Connection,
            [string]$BaseDN
        )
        $dcSearch = [adsisearcher]"(&(userAccountControl:1.2.840.113556.1.4.803:=8192))"
        $dcSearch.SearchRoot = [adsi]"LDAP://$DC/$BaseDN"
        $dcSearch.PropertiesToLoad.AddRange(@("sAMAccountName", "distinguishedName", "serverReferenceBL"))
        $dcs = $dcSearch.FindAll()

        Print-SectionHeader "Domain Controllers"
        foreach ($dc in $dcs) {
            Write-Host "Domain Controller: $($dc.Properties['sAMAccountName'][0]), DN: $($dc.Properties['distinguishedName'][0])"
            $site = $($dc.Properties['serverReferenceBL'][0])
            if ($site -match 'CN=([^,]+),CN=Sites') {
                $adsite = $matches[1]
                Write-Host "AD Site: $adsite "
            }
        }
    }

    function List-KerberoastableUsers {
        param (
            [System.DirectoryServices.DirectoryEntry]$Connection,
            [string]$BaseDN
        )
        $kerberoastableSearch = [adsisearcher]"(&(userAccountControl:1.2.840.113556.1.4.803:=512)(servicePrincipalName=*))"
        $kerberoastableSearch.SearchRoot = [adsi]"LDAP://$DC/$BaseDN"
        $kerberoastableSearch.PropertiesToLoad.AddRange(@("sAMAccountName", "userPrincipalName", "distinguishedName"))
        $kerberoastableUsers = $kerberoastableSearch.FindAll()

        Print-SectionHeader "Kerberoastable Users"
        foreach ($user in $kerberoastableUsers) {
            Write-Host "Username: $($user.Properties['sAMAccountName'][0]), UPN: $($user.Properties['userPrincipalName'][0]), DN: $($user.Properties['distinguishedName'][0])"
        }
    }

    function List-ASREPRoastableUsers {
        param (
            [System.DirectoryServices.DirectoryEntry]$Connection,
            [string]$BaseDN
        )
        $asrepRoastableSearch = [adsisearcher]"(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        $asrepRoastableSearch.SearchRoot = [adsi]"LDAP://$DC/$BaseDN"
        $asrepRoastableSearch.PropertiesToLoad.AddRange(@("sAMAccountName", "userAccountControl"))
        $asrepRoastableUsers = $asrepRoastableSearch.FindAll()

        Print-SectionHeader "AS-REP Roastable Users"
        foreach ($user in $asrepRoastableUsers) {
            if ($user.Properties['userAccountControl'][0] -ne 4194304) {
                Write-Host "sAMAccountName: $($user.Properties['sAMAccountName'][0])"
            }
        }
    }

    function List-AdminCountEquals1Users {
        param (
            [System.DirectoryServices.DirectoryEntry]$Connection,
            [string]$BaseDN
        )
    
        # Define default admin accounts
        $defaultAdminAccounts = @(
            "Administrator",
            "krbtgt"
        )

        $adminCountSearch = [adsisearcher]"(&(objectClass=user)(adminCount=1))"
        $adminCountSearch.SearchRoot = [adsi]"LDAP://$DC/$BaseDN"
        $adminCountSearch.PropertiesToLoad.AddRange(@("sAMAccountName", "userPrincipalName", "distinguishedName"))
        $adminCountUsers = $adminCountSearch.FindAll()

        Print-SectionHeader "Users with adminCount=1"
        foreach ($user in $adminCountUsers) {
            $username = $user.Properties['sAMAccountName'][0]
            $upn = $user.Properties['userPrincipalName'][0]
            $dn = $user.Properties['distinguishedName'][0]
        
            if ($defaultAdminAccounts -contains $username) {
                Write-Host "Username: $username"
                Write-Host "UPN: $upn"
                Write-Host "DN: $dn"
            }
            else {
                Write-Host "Username: $username" -ForegroundColor Yellow
                Write-Host "UPN: $upn" -ForegroundColor Yellow
                Write-Host "DN: $dn" -ForegroundColor Yellow
            }
            Write-Host " "
        }
    }

    function List-AdminCountEquals1Groups {
        param (
            [System.DirectoryServices.DirectoryEntry]$Connection,
            [string]$BaseDN
        )
    
        # Define default admin groups
        $defaultAdminGroups = @(
            "Administrators",
            "Print Operators",
            "Backup Operators",
            "Replicator",
            "Enterprise Key Admins",
            "Key Admins",
            "Domain Controllers",
            "Schema Admins",
            "Enterprise Admins",
            "Domain Admins",
            "Server Operators",
            "Account Operators",
            "Read-only Domain Controllers"
        )

        $adminCountSearch = [adsisearcher]"(&(objectClass=group)(adminCount=1))"
        $adminCountSearch.SearchRoot = [adsi]"LDAP://$DC/$BaseDN"
        $adminCountSearch.PropertiesToLoad.AddRange(@("sAMAccountName", "objectSid", "distinguishedName"))
        $adminCountGroups = $adminCountSearch.FindAll()

        Print-SectionHeader "Groups with adminCount=1"
        foreach ($group in $adminCountGroups) {
            $groupName = $group.Properties['sAMAccountName'][0]
            $dn = $group.Properties['distinguishedName'][0]
            $sid = if ($group.Properties['objectSid']) { 
                (New-Object System.Security.Principal.SecurityIdentifier($group.Properties['objectSid'][0], 0)).Value 
            }
            else { "N/A" }
        
            if ($defaultAdminGroups -contains $groupName) {
                Write-Host "Group name: $groupName"
                Write-Host "SID: $sid"
                Write-Host "DN: $dn"
            }
            else {
                Write-Host "Group name: $groupName" -ForegroundColor Yellow
                Write-Host "SID: $sid" -ForegroundColor Yellow
                Write-Host "DN: $dn" -ForegroundColor Yellow
            }
            Write-Host " "
        }
    }

    function List-UsersWithWeakDescription {
        param (
            [System.DirectoryServices.DirectoryEntry]$Connection,
            [string]$BaseDN
        )
        $weakDescriptionSearch = [adsisearcher]"(&(objectClass=user)(description=*))"
        $weakDescriptionSearch.SearchRoot = [adsi]"LDAP://$DC/$BaseDN"
        $weakDescriptionSearch.PropertiesToLoad.AddRange(@("sAMAccountName", "userPrincipalName", "distinguishedName", "description"))
        $weakDescriptionUsers = $weakDescriptionSearch.FindAll()

        Print-SectionHeader "Users with Description"
        foreach ($user in $weakDescriptionUsers) {
            Write-Host "SAM Account Name: $($user.Properties['sAMAccountName'][0])"
            Write-Host "Description: $($user.Properties['description'][0])"
            Write-Host " "
        }
    }

    function List-DomainAdmins {
        param (
            [System.DirectoryServices.DirectoryEntry]$Connection,
            [string]$BaseDN
        )
        $domainAdminsSearch = [adsisearcher]"(&(memberOf=CN=Domain Admins,CN=Users,$BaseDN))"
        $domainAdminsSearch.SearchRoot = [adsi]"LDAP://$DC/$BaseDN"
        $domainAdminsSearch.PropertiesToLoad.AddRange(@("sAMAccountName", "userPrincipalName", "distinguishedName"))
        $domainAdmins = $domainAdminsSearch.FindAll()

        Print-SectionHeader "Domain Admins"
        foreach ($admin in $domainAdmins) {
            Write-Host "Admin Username: $($admin.Properties['sAMAccountName'][0]), UPN: $($admin.Properties['userPrincipalName'][0]), DN: $($admin.Properties['distinguishedName'][0])"
        }
    }

    function List-SCCMInstances {
        param (
            [System.DirectoryServices.DirectoryEntry]$Connection,
            [string]$BaseDN
        )
        Print-SectionHeader "SCCM Info"
        try {
            $sccmSearch = [adsisearcher]"(objectClass=mSSMSManagementPoint)"
            $sccmSearch.SearchRoot = [adsi]"LDAP://$DC/$BaseDN"
            $sccmSearch.PropertiesToLoad.Add("dNSHostName") | Out-Null
            $sccmInstances = $sccmSearch.FindAll()

            if ($sccmInstances.Count -gt 0) {
                foreach ($instance in $sccmInstances) {
                    $dnsHostName = $instance.Properties['dNSHostName'][0]
                    Write-Host "SCCM Management Point: $dnsHostName"
                    Write-Host " "
                }
            }
            else {
                Write-Host "No SCCM instances found."
            }
        }
        catch {
            Write-Host "SCCM is not installed or the schema is not extended."
            Write-Host "Error: $_"
        }
    }

    function List-ConstrainedDelegationAccounts {
        param (
            [System.DirectoryServices.DirectoryEntry]$Connection,
            [string]$BaseDN
        )
    
        Print-SectionHeader "Accounts with Constrained Delegation"
    
        try {
            # First get all computer accounts in the domain for SPN validation
            $allComputers = @{}
            $computerSearch = [adsisearcher]"(&(objectClass=computer))"
            $computerSearch.SearchRoot = [adsi]"LDAP://$DC/$BaseDN"
            $computerSearch.PropertiesToLoad.AddRange(@("dNSHostName", "servicePrincipalName"))
            $computerResults = $computerSearch.FindAll()
        
            foreach ($computer in $computerResults) {
                if ($computer.Properties['dNSHostName'] -and $computer.Properties['dNSHostName'][0]) {
                    $computerName = $computer.Properties['dNSHostName'][0]
                    $allComputers[$computerName] = $true
                
                    # Also add the computer name without domain for matching
                    if ($computerName -match "^([^\.]+)\.") {
                        $allComputers[$matches[1]] = $true
                    }
                }
            
                # Add any SPNs for this computer
                if ($computer.Properties['servicePrincipalName']) {
                    foreach ($spn in $computer.Properties['servicePrincipalName']) {
                        if ($spn -match "^[^/]+/([^/]+)") {
                            $allComputers[$matches[1]] = $true
                        }
                    }
                }
            }

            # Now find all accounts with constrained delegation
            $constrainedDelegationSearch = [adsisearcher]"(msDS-AllowedToDelegateTo=*)"
            $constrainedDelegationSearch.SearchRoot = [adsi]"LDAP://$DC/$BaseDN"
            $constrainedDelegationSearch.PropertiesToLoad.AddRange(@("sAMAccountName", "msDS-AllowedToDelegateTo"))
            $constrainedDelegationAccounts = $constrainedDelegationSearch.FindAll()

            foreach ($account in $constrainedDelegationAccounts) {
                $accountName = $account.Properties['sAMAccountName'][0]
                $delegateTo = $account.Properties['msDS-AllowedToDelegateTo']
            
                if (-not $delegateTo -or $delegateTo.Count -eq 0) {
                    continue
                }

                Write-Host "Account: $accountName" -ForegroundColor Yellow
                Write-Host "Allowed to Delegate To:"
            
                $orphanedSPNs = @()
            
                foreach ($target in $delegateTo) {
                    if (-not $target) { continue }
                
                    # Extract the target server name from the SPN (format is usually service/host)
                    $targetServer = $target -replace "^[^/]+/([^/:]+).*", '$1'
                
                    # Check if the target exists in our computer list
                    $isOrphaned = $true
                
                    # Check different variations of the target name
                    if ($allComputers.ContainsKey($targetServer)) {
                        $isOrphaned = $false
                    }
                    else {
                        # If it's a FQDN, check the base computer name
                        $shortName = $targetServer.Split('.')[0]
                        if ($allComputers.ContainsKey($shortName)) {
                            $isOrphaned = $false
                        }
                    }
                
                    if ($isOrphaned) {
                        Write-Host "  - $target [ORPHANED]" -ForegroundColor Red
                        $orphanedSPNs += $target
                    }
                    else {
                        Write-Host "  - $target" -ForegroundColor Green
                    }
                }
                Write-Host "`n"
            }
        }
        catch {
            Write-Host "Error in List-ConstrainedDelegationAccounts: $_" -ForegroundColor Red
        }
    }

    function List-TrustedForDelegationAccounts {
        param (
            [System.DirectoryServices.DirectoryEntry]$Connection,
            [string]$BaseDN
        )
        $trustedForDelegationSearch = [adsisearcher]"(&(userAccountControl:1.2.840.113556.1.4.803:=524288))"
        $trustedForDelegationSearch.SearchRoot = [adsi]"LDAP://$DC/$BaseDN"
        $trustedForDelegationSearch.PropertiesToLoad.AddRange(@("sAMAccountName", "userPrincipalName", "distinguishedName"))
        $trustedForDelegationAccounts = $trustedForDelegationSearch.FindAll()

        Print-SectionHeader "Accounts Trusted for Delegation"
        foreach ($account in $trustedForDelegationAccounts) {
            Write-Host "Account: $($account.Properties['sAMAccountName'][0]), UPN: $($account.Properties['userPrincipalName'][0]), DN: $($account.Properties['distinguishedName'][0])"
        }
    }

    function Check-PotentialPrinterBug {
        param (
            [System.DirectoryServices.DirectoryEntry]$Connection,
            [string]$BaseDN
        )
        # Search filter to exclude MSA and GMSA accounts
        $computerSearch = [adsisearcher]"(&(objectClass=computer)(!(objectClass=msDS-ManagedServiceAccount))(!(objectClass=msDS-GroupManagedServiceAccount)))"
        $computerSearch.SearchRoot = [adsi]"LDAP://$DC/$BaseDN"
        $computerSearch.PageSize = 1000
        $computers = $computerSearch.FindAll()

        Print-SectionHeader "Potential Printer Bug Abuse"
        foreach ($computer in $computers) {
            $computerName = $computer.Properties["name"][0]
            $computerFQDN = "$computerName.$BaseDN".Replace(",DC=", ".").Replace("DC=", "")

            # Check if the spoolss pipe exists using Get-ChildItem
            try {
                $spoolssPath = "\\$computerFQDN\pipe\spoolss"
                $spoolssExists = ls $spoolssPath -ErrorAction SilentlyContinue
                if ($spoolssExists) {
                    Write-Host "Computer Account: $computerFQDN" -ForegroundColor Yellow
                    Write-Host "$spoolssExists" -ForegroundColor Red
                    Write-Host " "
                }
            }
            catch {
                # Silently handle errors (e.g., inaccessible computers)
            }
        }
    }

    function List-AccountsWithPasswordAttributes {
        param (
            [System.DirectoryServices.DirectoryEntry]$Connection,
            [string]$BaseDN
        )
        $passwordAttributesSearch = [adsisearcher]"(|(unixUserPassword=*)(userPassword=*))"
        $passwordAttributesSearch.SearchRoot = [adsi]"LDAP://$DC/$BaseDN"
        $passwordAttributesSearch.PropertiesToLoad.AddRange(@("sAMAccountName", "userPrincipalName", "distinguishedName", "unixUserPassword", "userPassword"))
        $accountsWithPasswordAttributes = $passwordAttributesSearch.FindAll()

        Print-SectionHeader "Accounts with Password Attributes"
        foreach ($account in $accountsWithPasswordAttributes) {
            Write-Host "Account: $($account.Properties['sAMAccountName'][0]), UPN: $($account.Properties['userPrincipalName'][0]), DN: $($account.Properties['distinguishedName'][0])"
        
            # Convert Unix User Password byte array to string (if not null)
            if ($account.Properties['unixUserPassword'] -and $account.Properties['unixUserPassword'][0] -ne $null) {
                $unixUserPasswordBytes = $account.Properties['unixUserPassword'][0]
                try {
                    $unixUserPasswordString = [System.Text.Encoding]::ASCII.GetString($unixUserPasswordBytes)
                    Write-Host "unixUserPassword: $unixUserPasswordString" -ForegroundColor Red
                }
                catch {
                    Write-Host "unixUserPassword: [Unable to decode]"
                }
            }
            else {
                Write-Host "unixUserPassword: [Not set]"
            }
        
            # Convert User Password byte array to string (if not null)
            if ($account.Properties['userPassword'] -and $account.Properties['userPassword'][0] -ne $null) {
                $userPasswordBytes = $account.Properties['userPassword'][0]
                try {
                    $userPasswordString = [System.Text.Encoding]::ASCII.GetString($userPasswordBytes)
                    Write-Host "userPassword: $userPasswordString" -ForegroundColor Red
                }
                catch {
                    Write-Host "userPassword: [Unable to decode]"
                }
            }
            else {
                Write-Host "userPassword: [Not set]"
            }
        
            Write-Host " "
        }
    }
    function Invoke-SYSVOLSweep {
        param (
            [string]$DomainName
        )

        Print-SectionHeader "SYSVOL Sweep"

        # Part 1: Find interesting files in SYSVOL
        $interestingExtensions = @("*.vbs", "*.bat", "*.ps1", "*.txt", "*.js", "*.vba", "*.sql", "id_rsa", "*.sqlite", "*.pfx", "*.crt", "*.config", "*.cfg", "*.sqldump", "*.ovpn", "*.pcap", "*.dmp", "*.py")
        $sysvolPath = "\\$DomainName\SYSVOL\$DomainName"

        Write-Host "Searching for interesting files..."
        foreach ($extension in $interestingExtensions) {
            $files = Get-ChildItem -Path $sysvolPath -Recurse -Filter $extension -ErrorAction SilentlyContinue
            foreach ($file in $files) {
                Write-Host "Found interesting file: $($file.FullName)" -ForegroundColor Yellow
            }
        }
        Write-Host " "
        # Part 2: Find and decrypt cpassword credentials in GPP XML files
        $gppFiles = @('Groups.xml', 'Services.xml', 'Scheduledtasks.xml', 'DataSources.xml', 'Printers.xml', 'Drives.xml')
        $policiesPath = "\\$DomainName\SYSVOL\$DomainName\Policies"

        Write-Host "Searching for GPP XML files with cpassword..."
        foreach ($gppFile in $gppFiles) {
            $xmlFiles = Get-ChildItem -Path $policiesPath -Recurse -Filter $gppFile -ErrorAction SilentlyContinue
            foreach ($xmlFile in $xmlFiles) {
                #Write-Host "Found GPP XML file: $($xmlFile.FullName)" -ForegroundColor Yellow
                $xmlContent = Get-Content -Path $xmlFile.FullName -Raw
                if ($xmlContent -match 'cpassword="([^"]+)"') {
                    Write-Host "Found cpassword value(s) in $($xmlFile.FullName)" -ForegroundColor Red
                    Write-Host " "
                    $cpassword = $matches[1]
                    #Write-Host "cpassword value: $cpassword" -ForegroundColor Cyan

                    # Debug: Check if the cpassword is a valid Base64 string
                    try {
                        $paddingNeeded = $cpassword.Length % 4
                        if ($paddingNeeded -gt 0) {
                            $cpassword += "=" * (4 - $paddingNeeded)
                        }
                        $cpasswordBytes = [System.Convert]::FromBase64String($cpassword)
                        #Write-Host "cpassword is a valid Base64 string." -ForegroundColor Green
                    }
                    catch {
                        #Write-Host "cpassword is NOT a valid Base64 string: $_" -ForegroundColor Red
                        continue
                    }

                    # Parse the XML and extract the name and cpassword
                    $xml = [xml]$xmlContent
                    $nodes = $xml.SelectNodes("//*[@cpassword]")
                    foreach ($node in $nodes) {
                        # Extract the name attribute
                        $name = $node.GetAttribute("name")
                        if ([string]::IsNullOrEmpty($name)) {
                            # If name is not found, try to get it from a parent or sibling node
                            $name = $node.ParentNode.GetAttribute("name")
                        }

                        # Extract the cpassword attribute
                        $cpassword = $node.GetAttribute("cpassword")
                        $decryptedPassword = Decrypt-GPPPassword $cpassword

                        # Display the results
                        Write-Host "Name: $name" -ForegroundColor Cyan
                        Write-Host "cpassword: $cpassword" -ForegroundColor Red
                        Write-Host "Decrypted Password: $decryptedPassword" -ForegroundColor Green
                        Write-Host " "
                    }
                }
            }
        }
    }

    # Function to decrypt GPP cpassword
    function Decrypt-GPPPassword {
        param (
            [string]$cpassword
        )

        # AES key for decrypting cpassword
        $key = @(0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9, 0xfa, 0xf4, 0x93, 0x10, 0x62, 0x0f, 0xfe, 0xe8,
            0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 0x79, 0x90, 0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b)

        # Ensure the cpassword is properly padded for Base64 decoding
        $paddingNeeded = $cpassword.Length % 4
        if ($paddingNeeded -gt 0) {
            $cpassword += "=" * (4 - $paddingNeeded)
        }

        try {
            # Convert the cpassword from Base64 to bytes
            $cpasswordBytes = [System.Convert]::FromBase64String($cpassword)

            # Create AES decryptor
            $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
            $aes.Key = $key
            $aes.IV = New-Object byte[] 16
            $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
            $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

            # Decrypt the password
            $decryptor = $aes.CreateDecryptor()
            $decryptedBytes = $decryptor.TransformFinalBlock($cpasswordBytes, 0, $cpasswordBytes.Length)
            $decryptedPassword = [System.Text.Encoding]::Unicode.GetString($decryptedBytes)

            return $decryptedPassword
        }
        catch {
            Write-Host "Failed to decrypt cpassword: $_" -ForegroundColor Red
            return "[Decryption Failed]"
        }
    }
    function Find-PossibleRBCD {
        param (
            [System.DirectoryServices.DirectoryEntry]$Connection,
            [string]$BaseDN
        )
        $excludedEntities = 'NT AUTHORITY\SYSTEM', 'NT AUTHORITY\SELF', 'BUILTIN\Administrators', 'BUILTIN\Account Operators', 'S-1-5-32-548'
        $domainPrefixedEntities = 'Domain Admins', 'Enterprise Admins', 'exchange trusted subsystem', 'organization management', 'exchange windows permissions', 'Cert Publishers', 'Enterprise Key Admins', 'Key Admins'

        # Filter out MSA and GMSA accounts
        $computerSearch = [adsisearcher]"(&(objectClass=computer)(!(objectClass=msDS-ManagedServiceAccount))(!(objectClass=msDS-GroupManagedServiceAccount)))"
        $computerSearch.SearchRoot = [adsi]"LDAP://$DC/$BaseDN"
        $computerSearch.PageSize = 1000
        $computers = $computerSearch.FindAll()

        Print-SectionHeader "Potential RBCD Abuse"
        foreach ($computer in $computers) {
            $computerDN = $computer.Properties["distinguishedName"][0]
            $acl = (New-Object System.DirectoryServices.DirectoryEntry "LDAP://$computerDN").ObjectSecurity.Access
            $permissions = @{}

            foreach ($ace in $acl) {
                $identity = $ace.IdentityReference.Value

                # Resolve SID to account name
                try {
                    $sid = New-Object System.Security.Principal.SecurityIdentifier($identity)
                    $account = $sid.Translate([System.Security.Principal.NTAccount])
                    $identity = $account.Value
                }
                catch {
                    # If translation fails, keep the SID
                    $identity = $ace.IdentityReference.Value
                }

                # Check if the identity is in the excluded entities list
                $isExcluded = $excludedEntities -contains $identity -or $domainPrefixedEntities -contains $identity.Split('\')[-1]

                # Exclude Account Operators and other excluded entities
                if ($ace.ActiveDirectoryRights -match 'GenericWrite|GenericAll|WriteDacl|WriteProperty|WriteOwner|WriteAccountRestrictions|AllowedToAct' -and -not $isExcluded) {
                    if (-not $permissions.ContainsKey($identity)) { $permissions[$identity] = @() }
                    $permissions[$identity] += $ace.ActiveDirectoryRights
                }
            }

            if ($permissions.Count -gt 0) {
                Write-Host "[!] Computer object:" 
                Write-Host "$($computer.Properties["name"][0])" -ForegroundColor Yellow
                Write-Host "[!] Users with permissions:" 
                #foreach ($user in $permissions.Keys) { Write-Host "$user -> $($permissions[$user] -join ', ')" -ForegroundColor Yellow }
                foreach ($user in $permissions.Keys) { Write-Host "$user -> $(($permissions[$user] | Select-Object -Unique) -join ', ')" -ForegroundColor Yellow }

                Write-Host " "
            }
        }
    }
    # Main script execution
    try {
        # Extract domain name from the provided username
        
        if ($Domain) {
            if ($Domain -notmatch "\.") {
                $Domain = Write-Host "[X] Invalid domain name format." -ForegroundColor Yellow
                break
            }
            else {
                $domainName = $Domain
            }
        }
        elseif ($Username -and ($Username -match "^[^@]+@[^@]+\.[^@]+$")) {
            $domainName = $Username.Split('@')[-1]
        }
        else {
            $domainName = (Get-WmiObject Win32_ComputerSystem).Domain
            if ($domainName -notmatch "\.") {
                $domainName = Write-Host "[X] This machine is not domain-joined. Enter domain name (e.g., company.local)" -ForegroundColor Yellow
                break
            }
        }
        $baseDN = ($domainName.Split('.') | ForEach-Object { "DC=$_" }) -join ','

        # Create a connection to the LDAP server
        if ($Username -and $Password) {
            $connection = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DC/$baseDN", $Username, $Password)
        }
        else {
            $connection = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DC/$baseDN")
        }

        if ($connection.Path -eq $null) {
            throw "Failed to connect to the LDAP server."
        }

        # Get RootDSE information
        $rootDSE = [adsi]"LDAP://$DC/RootDSE"
        $configNC = $rootDSE.configurationNamingContext

        Get-DomainInfo -Connection $connection -BaseDN $baseDN
        List-Trusts -Connection $connection -BaseDN $baseDN
        List-ShadowPrincipals -Connection $connection -ConfigNC $configNC
        Get-EnterpriseCA -Connection $connection -ConfigNC $configNC
        List-SCCMInstances -Connection $connection -BaseDN $baseDN
        Get-WSUSConfiguration
        List-Users -Connection $connection -BaseDN $baseDN
        List-Computers -Connection $connection -BaseDN $baseDN
        Find-PossibleRBCD -Connection $connection -BaseDN $baseDN
        Check-PotentialPrinterBug -Connection $connection -BaseDN $baseDN
        Invoke-RpcDumpCheck -Connection $connection -BaseDN $baseDN
        List-ManagedServiceAccounts -Connection $connection -BaseDN $baseDN
        List-DomainControllers -Connection $connection -BaseDN $baseDN
        List-KerberoastableUsers -Connection $connection -BaseDN $baseDN
        List-ASREPRoastableUsers -Connection $connection -BaseDN $baseDN
        List-AdminCountEquals1Users -Connection $connection -BaseDN $baseDN
        List-AdminCountEquals1Groups -Connection $connection -BaseDN $baseDN
        List-UsersWithWeakDescription -Connection $connection -BaseDN $baseDN
        List-DomainAdmins -Connection $connection -BaseDN $baseDN
        List-ConstrainedDelegationAccounts -Connection $connection -BaseDN $baseDN
        List-TrustedForDelegationAccounts -Connection $connection -BaseDN $baseDN
        List-AccountsWithPasswordAttributes -Connection $connection -BaseDN $baseDN
        List-GPOsAndLinks -Connection $connection -BaseDN $baseDN
        Invoke-SYSVOLSweep -DomainName $domainName

        Write-Host ("`n" + "-" * 40)
    }
    catch {
        Write-Host "An error occurred: $_"
    }
}
