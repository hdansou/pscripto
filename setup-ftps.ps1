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
    Import-Module WebAdministration
    $DefaultFtpPath = "c:\inetpub\wwwroot\"
    $DefaultNonSecureFtpPort = 21
    #$DefaultFtpSiteName = "Default FTP Site"
    $DefaultFtpSiteName = "FTPSSite001"
    $DefaultFtpUser = $DefaultFtpSiteName + "user"

    # Create FTP user Account
    $newFtpPassword = Generate-Password
    net user /add $DefaultFtpUser $newFtpPassword
    Write-Host "[*] Completed '$DefaultFtpUser' creation"
    
    #Start-Sleep -Seconds 1
    New-WebFtpSite -Name $DefaultFtpSiteName -PhysicalPath $DefaultFtpPath  -Port $DefaultNonSecureFtpPort -IPAddress * 
    
    # Apply permissions to wwwroot Folder
    $acl = (Get-Item $DefaultFtpPath).GetAccessControl("Access")
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($DefaultFtpUser,"Modify","ContainerInherit, ObjectInherit","None","Allow")
    $acl.AddAccessRule($rule)
    Set-Acl $DefaultFtpPath $acl
    
    # appcmd replacement
    # Configure IIS Site Properties
    Set-ItemProperty IIS:\Sites\$DefaultFtpSiteName -Name ftpServer.security.ssl.controlChannelPolicy -Value 1
    Set-ItemProperty IIS:\Sites\$DefaultFtpSiteName -Name ftpServer.security.ssl.dataChannelPolicy -Value 1
    Set-ItemProperty IIS:\Sites\$DefaultFtpSiteName -Name ftpServer.security.ssl.ssl128 -Value $true
    Set-ItemProperty IIS:\Sites\$DefaultFtpSiteName -Name ftpServer.security.authentication.basicAuthentication.enabled -Value $true
    # Alter FTPServer Configuration
    # Add Allow rule for our ftpGroup (Permission=3 ==> Read+Write)
    Add-WebConfiguration "/system.ftpServer/security/authorization"  -value @{accessType="Allow"; users=$DefaultFtpUser; permissions=3} -PSPath IIS:\ -location $DefaultFtpSiteName
    # Change the lower and upper dataChannel ports
    $firewallSupport = Get-WebConfiguration system.ftpServer/firewallSupport
    $firewallSupport.lowDataChannelPort = 5001
    $firewallSupport.highDataChannelPort = 5050
    $firewallSupport | Set-WebConfiguration system.ftpServer/firewallSupport

   # Less than 2008
    if ($OS -lt "6.1.7601")
    {
        Write-Warning "[*] Windows Server 2003 and Windows Server 2003 R2 are not supported!"
    }
    # 2008 ++
    elseif ($OS -ge "6.1.7601") {
        $SelfSignedCert = "CN=WMSvc*"
    }
    # Not working as intended on some builds
    # 2012
    #elseif ($OS -eq "6.2.9200") {
    #    $SelfSignedCert = "CN=MgmtSvc*"
    #}

    cd Microsoft.PowerShell.Security\Certificate::localmachine\my
    #$cert = Get-ChildItem | Where-Object {$_.subject -like $env:COMPUTERNAME } | select thumbprint | foreach { $_.thumbprint }
    $cert = Get-ChildItem | Where-Object {$_.subject -like $SelfSignedCert } | select thumbprint | foreach { $_.thumbprint }
    Set-ItemProperty IIS:\Sites\$DefaultFtpSiteName -Name ftpServer.security.ssl.serverCertHash -Value $cert
    Write-Host "Disploay certificate"
    Write-Host $cert
    
    Write-Host "[*] Completed $DefaultFtpSiteName creation"	
    netsh advfirewall set global StatefulFTP disable
    Write-output "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    Write-Host "[*] Stateful FTP is disabled"
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
