Function Invoke-NewGPO {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Domain, # Domain name (e.g., bank.local)

        [Parameter(Mandatory = $true)]
        [string]$GPOName, # Name of the GPO to create

        [Parameter(Mandatory = $true)]
        [string]$TargetOUDN # Distinguished name of the target OU or domain (e.g., OU=testOU,DC=bank,DC=local)
    )

    # Validate the $TargetOUDN format
    if ($TargetOUDN -notmatch '^OU=[^,]+,DC=[^,]+,DC=[^,]+$') {
        Write-Host "Invalid TargetOUDN format. Expected format: OU=YourOU,DC=domain,DC=com" -ForegroundColor Red
        break
    }

    # Step 0: Check if the target OU exists
    try {
        # Attempt to bind to the target OU
        $targetOu = [ADSI]"LDAP://$TargetOUDN"
        # Check if the Properties collection is accessible
        if ($null -eq $targetOu.Properties) {
            throw "The target OU '$TargetOUDN' does not exist. Please verify the distinguished name (DN)."
            break
        }

        # Check if the 'name' property exists
        if (-not $targetOu.Properties.Contains('name')) {
            throw "The target OU '$TargetOUDN' does not exist. Please verify the distinguished name (DN)."
            break
        }

        # Debug: Display the OU name to confirm it exists
        Write-Host "Target OU exists: $($targetOu.Properties['name'].Value)" -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to verify the target OU: $_" -ForegroundColor Red
        break
    }

    # Define SYSVOL path and generate GUID for the GPO
    $sysvolPath = "\\$Domain\SYSVOL\$Domain\Policies"
    $guid = [guid]::NewGuid().ToString() # Generate a new GUID for the GPO
    $gpoDn = "CN={$guid},CN=Policies,CN=System,DC=$($Domain -replace '\.', ',DC=')"

    # Step 1: Create the GPO in Active Directory (GPC part)
    try {
        # Connect to the Policies container
        $policiesContainer = [ADSI]"LDAP://CN=Policies,CN=System,DC=$($Domain -replace '\.', ',DC=')"
    
        # Create the GPO object
        $newGPO = $policiesContainer.Create("groupPolicyContainer", "CN={$guid}")
        $newGPO.Put("displayName", $GPOName)
        $newGPO.Put("gPCFileSysPath", "$sysvolPath\{$guid}")
        $newGPO.Put("gPCFunctionalityVersion", 2)

        # Set the required attributes
        $newGPO.Put("flags", 0) # Set flags to 0
        $newGPO.Put("versionNumber", 0) # Set versionNumber to 0

        $newGPO.SetInfo()
        Write-Host "GPO '$GPOName' created successfully with GUID: $guid" -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to create GPO: $_" -ForegroundColor Red
        break
    }

    # Step 2: Create the SYSVOL folder for the GPO (GPT part)
    try {
        $gpoFolderPath = "$sysvolPath\{$guid}"
        if (-not (Test-Path $gpoFolderPath)) {
            New-Item -ItemType Directory -Path $gpoFolderPath | Out-Null
        }

        # Create the GPT.INI file
        $gptIniPath = "$gpoFolderPath\GPT.INI"
        @"
[General]
Version=0
"@ | Set-Content -Path $gptIniPath

        # Create the Machine and User folders in SYSVOL (GPT part)
        $machineFolderPath = "$gpoFolderPath\Machine"
        $userFolderPath = "$gpoFolderPath\User"
        New-Item -ItemType Directory -Path $machineFolderPath | Out-Null
        New-Item -ItemType Directory -Path $userFolderPath | Out-Null

        # Create and initialize Registry.pol files (required for Group Policy Preferences)
        $machineRegistryPolPath = "$machineFolderPath\Registry.pol"
        $userRegistryPolPath = "$userFolderPath\Registry.pol"

        # Initialize Registry.pol files with the correct header
        $registryPolHeader = [byte[]]@(0x50, 0x52, 0x65, 0x67, 0x66, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00)
        Set-Content -Path $machineRegistryPolPath -Value $registryPolHeader -Encoding Byte
        Set-Content -Path $userRegistryPolPath -Value $registryPolHeader -Encoding Byte
    }
    catch {
        Write-Host "Failed to create SYSVOL folder or files: $_" -ForegroundColor Red
        break
    }

    # Step 3: Create the Machine and User folders in the GPC part (AD)
    try {
        # Connect to the GPO container in AD
        $gpoContainer = [ADSI]"LDAP://$gpoDn"

        # Create the Machine folder in AD
        $machineFolderAD = $gpoContainer.Create("container", "CN=Machine")
        $machineFolderAD.SetInfo()

        # Create the User folder in AD
        $userFolderAD = $gpoContainer.Create("container", "CN=User")
        $userFolderAD.SetInfo()
    }
    catch {
        Write-Host "Failed to create Machine or User folders in AD: $_" -ForegroundColor Red
        break
    }

    # Step 4: Set permissions for the GPO folder to match GPMC
    try {
        # Get the SIDs for the required groups
        $enterpriseDomainControllersSid = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-9")
        $authenticatedUsersSid = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-11")
        $systemSid = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-18")
        $creatorOwnerSid = [System.Security.Principal.SecurityIdentifier]::new("S-1-3-0")

        # Resolve the SIDs for Domain Admins and Enterprise Admins
        $domainAdminsSid = ([System.Security.Principal.NTAccount]"$Domain\Domain Admins").Translate([System.Security.Principal.SecurityIdentifier])
        $enterpriseAdminsSid = ([System.Security.Principal.NTAccount]"$Domain\Enterprise Admins").Translate([System.Security.Principal.SecurityIdentifier])
        $myself = whoami
        $mySid = ([System.Security.Principal.NTAccount]"$myself").Translate([System.Security.Principal.SecurityIdentifier])
        # Set permissions on the parent policy folder
        $gpoFolderAcl = Get-Acl -Path $gpoFolderPath

        # Remove all existing permissions
        $gpoFolderAcl.SetAccessRuleProtection($true, $false) # Disable inheritance and remove all inherited permissions
        $gpoFolderAcl.Access | ForEach-Object { $gpoFolderAcl.RemoveAccessRule($_) } # Remove all explicit permissions

        # Add the required permissions
        $gpoFolderAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $domainAdminsSid,
                    "FullControl",
                    "ContainerInherit, ObjectInherit",
                    "None",
                    "Allow"
                )))
        $gpoFolderAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $mySid,
                    "FullControl",
                    "ContainerInherit, ObjectInherit",
                    "None",
                    "Allow"
                )))
        $gpoFolderAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $enterpriseAdminsSid,
                    "FullControl",
                    "ContainerInherit, ObjectInherit",
                    "None",
                    "Allow"
                )))
        $gpoFolderAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $enterpriseDomainControllersSid,
                    "ReadAndExecute",
                    "ContainerInherit, ObjectInherit",
                    "None",
                    "Allow"
                )))
        $gpoFolderAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $authenticatedUsersSid,
                    "ReadAndExecute",
                    "ContainerInherit, ObjectInherit",
                    "None",
                    "Allow"
                )))
        $gpoFolderAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $systemSid,
                    "FullControl",
                    "ContainerInherit, ObjectInherit",
                    "None",
                    "Allow"
                )))
        $gpoFolderAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $creatorOwnerSid,
                    "FullControl",
                    "ContainerInherit, ObjectInherit",
                    "InheritOnly",
                    "Allow"
                )))

        # Apply the updated ACL
        Set-Acl -Path $gpoFolderPath -AclObject $gpoFolderAcl
    }
    catch {
        Write-Host "Failed to set permissions for GPO folder: $_" -ForegroundColor Red
        break
    }

    # Step 5: Link the GPO to the target OU or domain
    try {
        # Get the target OU
        $targetOu = [ADSI]"LDAP://$TargetOUDN"

        # Check if the gPLink attribute exists
        if (-not $targetOu.Properties.Contains("gPLink")) {
            $targetOu.Properties["gPLink"].Add("")  # Initialize the gPLink attribute with an empty string
        }

        # Get the current gPLink value
        $currentGpLinks = $targetOu.Properties["gPLink"].Value

        # Add the GPO link to the target OU
        $gpoLink = "[LDAP://$gpoDn;0]"
        if ([string]::IsNullOrEmpty($currentGpLinks)) {
            $newGpLinks = $gpoLink
        }
        else {
            $newGpLinks = "$gpoLink$currentGpLinks"
        }

        # Update the gPLink attribute
        $targetOu.Properties["gPLink"].Clear()  # Clear the existing gPLink value
        $targetOu.Properties["gPLink"].Add($newGpLinks)  # Add the new gPLink value
        $targetOu.SetInfo()
        Write-Host "GPO '$GPOName' linked to OU: $TargetOUDN" -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to link GPO to OU: $_" -ForegroundColor Red
        break
    }
}
