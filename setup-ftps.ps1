Function Generate-Password ($Length = 14) {
        $Letters = 65..90 + 97..122
        $Digits = 48..57
        
        $NewPassword = get-random -count $length -input ($Digits + $Letters) | % -begin { $pass = $null } -process {$pass += [char]$_} -end {$pass}

        return $NewPassword
    }

# Run the method without parameter and get a password with 15 characters long
# Generate-Password
# Run the method with parameter and get a password with desired characters long
# Generate-Password(10)   


Function Create-FtpSite() {
    $DefaultFtpPath = "c:\inetpub\wwwroot\"
    $DefaultNonSecureFtpPort = 21
    #$DefaultFtpSiteName = "Default FTP Site"
    $DefaultFtpSiteName = "FTP31"
    $DefaultFtpUser = $DefaultFtpSiteName + "user"

    # Create FTP user Account
    $newFtpPassword = Generate-Password
	net user /add $DefaultFtpUser $newFtpPassword
    Write-Host "[*] Completed '$DefaultFtpUser' creation"
    
    #Start-Sleep -Seconds 1
	New-WebFtpSite -Name $DefaultFtpSiteName -PhysicalPath $DefaultFtpPath  -Port $DefaultNonSecureFtpPort -IPAddress * 
    
    # appcmd will be replace on the next version
    c:\windows\system32\inetsrv\appcmd.exe set site /site.name:$DefaultFtpSiteName /ftpServer.security.ssl.controlChannelPolicy:SslRequire
    c:\windows\system32\inetsrv\appcmd.exe set site /site.name:$DefaultFtpSiteName /ftpServer.security.ssl.dataChannelPolicy:SslRequire
    c:\windows\system32\inetsrv\appcmd.exe set site /site.name:$DefaultFtpSiteName /ftpServer.security.ssl.ssl128:true
    c:\windows\system32\inetsrv\appcmd.exe set site /site.name:$DefaultFtpSiteName /ftpServer.security.authentication.basicAuthentication.enabled:true
    c:\windows\system32\inetsrv\appcmd.exe set config $DefaultFtpSiteName /section:system.ftpserver/security/authorization /+"[accessType='Allow',permissions='Read,Write',users='$DefaultFtpUser']" /commit:apphost
    c:\windows\system32\inetsrv\appcmd.exe set config -section:system.ftpServer/firewallSupport /lowDataChannelPort:'5000' /commit:apphost
    c:\windows\system32\inetsrv\appcmd.exe set config -section:system.ftpServer/firewallSupport /highDataChannelPort:'5050' /commit:apphost
    

 
    
    $OS = (Get-WmiObject Win32_OperatingSystem).Version
    if ($OS -lt "6.1.7601") 
    {
	    Write-Warning "[*] Windows Server 2003 and Windows Server 2003 R2 are not supported!"
    }
    elseif ($OS -eq "6.2.9200") {
        $SelfSignedCert = "CN=MgmtSvc*"
    }
    elseif ($OS -eq "6.1.7601") {
            $SelfSignedCert = "CN=WMSvc*"
    }
     

        cd Microsoft.PowerShell.Security\Certificate::localmachine\my
        $cert = Get-ChildItem | Where-Object {$_.subject -like $SelfSignedCert } | select thumbprint | foreach { $_.thumbprint }
        c:\windows\system32\inetsrv\appcmd.exe set config -section:system.applicationHost/sites /[name="'$DefaultFtpSiteName'"].ftpServer.security.ssl.serverCertHash:$cert /commit:apphost
        Write-Host "Disploay certificate"
        Write-Host $cert

        Write-Host "[*] Completed $DefaultFtpSiteName creation"	

	    netsh advfirewall set global StatefulFTP disable
        Write-output "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        Write-Host "[*] Stateful FTP is disableed"
        Write-output "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        Write-Host "[*] FTP username '$DefaultFtpUser'"
        Write-Host "[*] FTP password '$newFtpPassword'"
        Write-output "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        Write-output "[*] FTP service status"
        Restart-Service ftpsvc
        Get-Service ftpsvc
    }


Function Add-FtpDependencies () {
    Import-Module ServerManager
    #Get-WindowsFeature
    $out = Add-WindowsFeature -Name Web-Ftp-Server -IncludeAllSubFeature
    if ($out.ExitCode -eq "NoChangeNeeded"){
        Write-Host "[*] FTP server is already installed"
    }
    else {
        Write-Host "[*] FTP Server and dependencies have been installed"
    }
}

# There is a cmdlet to get the IP on 2012 but not 2008. Using this method for now
Function List-Ips(){
    $Computer = "." 
    $IPconfigset = Get-WmiObject Win32_NetworkAdapterConfiguration

    Write-output "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    Write-output "[*] List of IPs"
    Write-output "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" 
    $count = 0 
    foreach ($IPConfig in $IPConfigSet) { 
    if ($Ipconfig.IPaddress) { 
        foreach ($addr in $Ipconfig.Ipaddress) { 
            "IP Address   : {0}" -f  $addr; 
            $count++  
        } 
    }
    
} 
if ($count -eq 0) {"No IP addresses found"} 

else {"[*] $Count IP addresses found on this system"} 
Write-output "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
}


# main 

Add-FtpDependencies
Create-FtpSite
List-Ips
