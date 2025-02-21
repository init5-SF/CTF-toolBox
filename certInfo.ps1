param(
    [Parameter(Mandatory=$true)]
    [string]$Path,
    [Parameter(Mandatory=$false)]
    [string]$Password

)


try {
    # Load the certificate with password
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    $cert.Import($Path, $Password, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet)

    # Get current date for expiration calculation
    $currentDate = Get-Date

    # Extract Principal Name from Subject Alternative Name
    $sanExtension = $cert.Extensions | Where-Object {$_.Oid.FriendlyName -eq "Subject Alternative Name"}
    $principalName = if ($sanExtension) {
        $sanData = $sanExtension.Format(0).Split("`n")
        $otherNameEntry = $sanData | Where-Object { $_ -match "Other Name:" }
        if ($otherNameEntry) {
            $otherNameEntry -match "Principal Name=(.*)" | Out-Null
            $matches[1].Trim()
        } else {
            "Principal: $($cert.Subject)"
        }
    } else {
        "Subject Alternative Name extension not found"
    }

    # Display the required information
    Write-Host " "
    Write-Host "Certificate Information:"
    Write-Host "----------------------"
    Write-Host " "
    Write-Host "Serial Number: $($cert.SerialNumber)"
    Write-Host "Enhanced Key Usage: $($cert.EnhancedKeyUsageList.FriendlyName -join ', ')"
    Write-Host "Principal Name: $principalName"

    $timeLeft = $cert.NotAfter - $currentDate
    Write-Host "Time until expiration: $($timeLeft.Days) days, $($timeLeft.Hours) hours, $($timeLeft.Minutes) minutes"
    Write-Host " "
}
catch {
    #Write-Host "An error occurred: $_"
    Write-Host -Foregroundcolor Red "An error occurred - Probably password mismatch!"
}
finally {
    # Clean up
    if ($cert) { $cert.Dispose() }
}
