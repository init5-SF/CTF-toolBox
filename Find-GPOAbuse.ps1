#- Made for HTB' CAPE path
#- Don't forget to import PowerView.ps1 first


$dom = (Get-Domain).name

function Test-SYSVOLWritePermissions {
    param (
        [string]$User,
        [string]$SYSVOLPath = "\\$dom\SYSVOL\$dom\Policies"
    )
    
    # Get the ACL for the SYSVOL Policies folder
    $acl = Get-Acl -Path $SYSVOLPath
    
    # Extract just the username part (after the backslash)
    $userName = $User.Split('\')[1]
    
    # Check each access rule in the ACL
    foreach ($rule in $acl.Access) {
        # Check if the rule applies to the current user
        if ($rule.IdentityReference -like "*\$userName") {
            # Check if the rule has Write permissions (W)
            if ($rule.FileSystemRights -like "*Write*" -or 
                $rule.FileSystemRights -like "*Modify*" -or 
                $rule.FileSystemRights -like "*FullControl*") {
                return $true
            }
        }
    }
    return $false
}

# Get the domain SID dynamically
$domainSID = Get-DomainSID

# Get all GPOs with dangerous permissions
$results = Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | Where-Object { 
    $_.ActiveDirectoryRights -match "CreateChild|WriteProperty|DeleteChild|DeleteTree|WriteDacl|WriteOwner" -and 
    $_.SecurityIdentifier -match "^$([regex]::Escape($domainSID))-[\d]{4,10}$" 
}

# Function to parse GPLink status
function Get-GPLinkStatus {
    param (
        [string]$gplink,
        [string]$gpoGuid
    )
    
    if (-not $gplink) { return $null }
    
    $pattern = "\[LDAP://CN=\{$gpoGuid\}.*?;(\d)\]"
    if ($gplink -match $pattern) {
        $statusCode = $matches[1]
        switch ($statusCode) {
            '0' { return "Enabled" }
            '1' { return "Disabled" }
            '2' { return "Enforced" }
            '3' { return "Enforced but Disabled" }
            default { return "Unknown status ($statusCode)" }
        }
    }
    return $null
}
Write-Host "-------- Vulnerable GPOs Scan:" -ForegroundColor Green
# Process each result
$results | ForEach-Object {
    # Extract GUID from ObjectDN
    if ($_.ObjectDN -match '{([A-F0-9\-]+)}') {
        $gpoGuid = $matches[1]
        
        # Create base output object
        $output = [PSCustomObject]@{
            GPO_Name    = ""
            GPO_Path    = ""
            Principal   = ""
            LinkedOUs   = @()
            LinkedSites = @()
        }
        
        # Get GPO details
        $gpo = Get-DomainGPO -Identity $_.ObjectDN | Select-Object displayName, gpcFileSysPath
        $output.GPO_Name = $gpo.displayName
        $output.GPO_Path = $gpo.gpcFileSysPath
        $output.Principal = ConvertFrom-SID $_.SecurityIdentifier
        
        # Display formatted output
        Write-Host "`n[+] Vulnerable GPO Found"
        Write-Host "  GPO Name: $($output.GPO_Name)" -ForegroundColor Red
        Write-Host "  Principal: $($output.Principal)" -ForegroundColor Red
        Write-Host "  Path: $($output.GPO_Path)`n"
        
        # Find and process OUs linked to this GPO
        $linkedOUs = Get-DomainOU -Properties gplink, distinguishedName | Where-Object { $_.gplink -match $gpoGuid }
        
        if ($linkedOUs) {
            Write-Host "  Linked OUs and Computers:" -ForegroundColor Cyan
            
            $ouComputers = foreach ($ou in $linkedOUs) {
                $status = Get-GPLinkStatus -gplink $ou.gplink -gpoGuid $gpoGuid
                $computers = Get-DomainComputer -SearchBase $ou.distinguishedName -Properties dnsHostname -ErrorAction SilentlyContinue
                
                [PSCustomObject]@{
                    OU_Path    = $ou.distinguishedName
                    LinkStatus = $status
                    Computers  = if ($computers) { $computers.dnsHostname } else { @("(No computers found)") }
                }
            }
            
            $output.LinkedOUs = $ouComputers
            
            foreach ($ou in $output.LinkedOUs) {
                Write-Host "  - OU: $($ou.OU_Path)" -ForegroundColor Yellow
                Write-Host "    Link Status: $($ou.LinkStatus)"
                foreach ($computer in $ou.Computers) {
                    Write-Host "    [-] $computer"
                }
                Write-Host ""
            }
        }
        else {
            Write-Host "  GPO not linked to any OUs" -ForegroundColor Yellow
        }
        
        # Find and process Sites linked to this GPO
        $linkedSites = Get-DomainSite -Properties gplink, name | Where-Object { $_.gplink -match $gpoGuid }
        
        if ($linkedSites) {
            Write-Host "  Linked AD Sites:" -ForegroundColor Cyan
            
            $siteInfo = foreach ($site in $linkedSites) {
                $status = Get-GPLinkStatus -gplink $site.gplink -gpoGuid $gpoGuid
                [PSCustomObject]@{
                    SiteName   = $site.name
                    LinkStatus = $status
                }
            }
            
            $output.LinkedSites = $siteInfo
            
            foreach ($site in $output.LinkedSites) {
                Write-Host "  - Site: $($site.SiteName)" -ForegroundColor Magenta
                Write-Host "    Link Status: $($site.LinkStatus)"
            }
            Write-Host ""
        }
        else {
            Write-Host "  GPO not linked to any AD Sites" -ForegroundColor Yellow
            Write-Host ""
        }
    }
}
Write-Host "-------- Principals who can create GPOs:" -ForegroundColor Green
Write-Host "|"
$identity = (Get-DomainGPO).distinguishedname -replace 'CN=\{[A-F0-9-]+\},', ''

Write-Host "|_ CreateChild permissions over Policies container" -foregroundcolor yellow
$createChild = Get-DomainObjectACL -Identity $identity -ResolveGUIDs | Where-Object { $_.ActiveDirectoryRights -contains "CreateChild" -and $_.SecurityIdentifier -match '^S-1-5-.*-[1-9]\d{3,}$' } | ForEach-Object { ConvertFrom-SID $_.SecurityIdentifier }
if ($createChild -ne $null) {

    $createChild.Split(" ") | ForEach-Object {
        Write-Host "|  |_ $_ " -foregroundcolor red
        if (Test-SYSVOLWritePermissions -User $_) { Write-Host "|     |_ !!! Has SYSVOL write permissions too !!!" -foregroundcolor cyan }
    }

}
else {
    write-host "   |_ [None found]"
}
Write-Host "|"
Write-Host "|_ GenericAll permissions over Policies container" -foregroundcolor yellow
$genericAll = Get-DomainObjectACL -Identity $identity -ResolveGUIDs | Where-Object { $_.ActiveDirectoryRights -contains "GenericAll" } | ForEach-Object { ConvertFrom-SID $_.SecurityIdentifier }
if ($genericAll -ne $null) {
    $d = (Get-Domain).Name
    $s = $d.Split('.')[0]
    $ea = $s + "\Enterprise Admins"
    $genericAll = $genericAll | Where-Object { $_ -ne 'Local System' }
    $genericAll = $genericAll | Where-Object { $_ -ne $ea }
    if ($genericAll -ne $null) { 
        $genericAll.Split(" ") | ForEach-Object {
            Write-Host "|  |_ $_ " -foregroundcolor red 
            if (Test-SYSVOLWritePermissions -User $_) { Write-Host "|     |_ !!! Has SYSVOL write permissions too !!!" -foregroundcolor cyan }
        }
    }
    else {
        write-host "|  |_ [None found]"
    }
}
else {
    write-host "|  |_ [None found]"
}
Write-Host "|"
Write-Host "|_ Member in Group Policy Creator Owners" -foregroundcolor yellow
$gpoGroupMembers = Get-DomainGroupMember -Identity 'group policy creator owners' | Select-Object -ExpandProperty membername

if ($gpoGroupMembers -ne $null) {
    $gpoGroupMembers = $gpoGroupMembers | Where-Object { $_ -ne 'Administrator' }
    if ($gpoGroupMembers -ne $null) {
        foreach ($member in $gpoGroupMembers) {
            write-host "   |_ $member " -foregroundcolor red
        }
    }
    else {
        write-host "   |_ [None found]"    
    }
}
else {
    write-host "   |_ [None found]"
}

Write-Host " "

Write-Host "-------- Principals who can link GPOs to Domain:" -ForegroundColor Green
Get-DomainObjectAcl -SearchScope Base -ResolveGUIDs | where { $_.ObjectAceType -eq "GP-Link" -and $_.ActiveDirectoryRights -match "WriteProperty" } | fl @{Name = 'Principal'; Expression = { ConvertFrom-SID $_.SecurityIdentifier } } 
Write-Host " "

Write-Host "-------- Principals who can link GPOs to sites:" -ForegroundColor Green
Get-DomainSite -Properties distinguishedname | foreach { Get-DomainObjectAcl -SearchBase $_.distinguishedname -ResolveGUIDs | where { $_.ObjectAceType -eq "GP-Link" -and $_.ActiveDirectoryRights -match "WriteProperty" } | select ObjectDN, @{Name = 'Principal'; Expression = { ConvertFrom-SID $_.SecurityIdentifier } } | Format-List }
Write-Host " "

Write-Host "-------- Principals who can link GPOs to OUs:" -ForegroundColor Green
Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | where { $_.ObjectAceType -eq "GP-Link" -and $_.ActiveDirectoryRights -match "WriteProperty" } | select ObjectDN, @{Name = 'Principal'; Expression = { ConvertFrom-SID $_.SecurityIdentifier } } | Format-List
Write-Host " "
