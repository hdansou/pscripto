# Setup FTP in IIS based on user isolation setup with FTP over SSL
# Author : John Moore
# Version : 0.0.1
# Date : 13/5/2013

Function Generate-Password ($Length = 14) {
    # Author : Hounsou Dansou
    # Source : Setup-FTPS.ps1
    # Run the method without parameter and get a password with 15 characters long
    # Generate-Password
    # Run the method with parameter and get a password with desired characters long
    # Generate-Password(10)

    $Letters = 65..90 + 97..122
    $Digits = 48..57
        
    $NewPassword = get-random -count $length -input ($Digits + $Letters) | % -begin { $pass = $null } -process {$pass += [char]$_} -end {$pass}

    return $NewPassword
}


Function Create-Isolated-Ftpsite() {
    Import-Module WebAdministration
    $DefaultWebPath = "c:\inetpub\wwwroot\"
    $DefaultFtpPath = "c:\inetpub\ftproot\"
    $DefaultNonSecureFtpPort = 21
    $DefaultLocalUserPath = $DefaultFtpPath + "LocalUser"
    $DefaultFtpSiteName = "FTPSIsolated001"
    $DefaultFtpUserFolder = $DefaultLocalUserPath + '\' + $DefaultFtpUser
    $DefaultFtpUser = $DefaultFtpSiteName + "user"
    $DefaultFtpGroup = "FTP_USERS"
    $HardPath = $DefaultLocalUserPath + '\' + $DefaultFtpUser + '\wwwroot'
    $VirtualPath = 'IIS:\Sites\' + $DefaultFtpSiteName + '\LocalUser\' + $DefaultFtpUser + '\wwwroot'
    $OS = (Get-WmiObject Win32_OperatingSystem).Version

    # Create FTP user Account
    $newFtpPassword = Generate-Password
    net user /add $DefaultFtpUser $newFtpPassword
    Write-Host "[*] Completed '$DefaultFtpUser' creation"
    
    # Create FTP Users Group
    net localgroup $DefaultFtpGroup /add
    net localgroup $DefaultFtpGroup $DefaultFtpUser /add

    #Start-Sleep -Seconds 1
    New-WebFtpSite -Name $DefaultFtpSiteName -PhysicalPath $DefaultFtpPath -Port $DefaultNonSecureFtpPort -IPAddress *
    
    # Create Isolated Environment
    New-Item -Type Directory -Path $DefaultLocalUserPath
    New-Item -Type Directory -Path $DefaultFtpUserFolder

    # Apply permissions to LocalUser Folder
    $acl = (Get-Item $DefaultLocalUserPath).GetAccessControl("Access")
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($DefaultFtpGroup,"Modify","ContainerInherit, ObjectInherit","None","Allow")
    $acl.AddAccessRule($rule)
    Set-Acl $DefaultLocalUserPath $acl

    # Apply permissions to wwwroot Folder
    $acl = (Get-Item $DefaultWebPath).GetAccessControl("Access")
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($DefaultFtpUser,"Modify","ContainerInherit, ObjectInherit","None","Allow")
    $acl.AddAccessRule($rule)
    Set-Acl $DefaultWebPath $acl

    # Create a Directory and a Virtual Directory for wwwroot
    # Compatible with IIS 7/8
    New-Item -Type Directory -Path $HardPath
    New-Item $VirtualPath -Type VirtualDirectory -PhysicalPath $DefaultWebPath

    # appcmd replacement
    # Configure IIS Site Properties
    Set-ItemProperty IIS:\Sites\$DefaultFtpSiteName -Name ftpServer.security.ssl.controlChannelPolicy -Value 1
    Set-ItemProperty IIS:\Sites\$DefaultFtpSiteName -Name ftpServer.security.ssl.dataChannelPolicy -Value 1
    Set-ItemProperty IIS:\Sites\$DefaultFtpSiteName -Name ftpServer.security.ssl.ssl128 -Value $true
    Set-ItemProperty IIS:\Sites\$DefaultFtpSiteName -Name ftpServer.security.authentication.basicAuthentication.enabled -Value $true
    # Configure Directory Browsing
    Set-ItemProperty IIS:\Sites\$DefaultFtpSiteName -Name ftpServer.directoryBrowse.showflags -Value 32
    # Enable FTP User isolation
    Set-ItemProperty IIS:\Sites\$DefaultFtpSiteName -Name ftpserver.userisolation.mode -Value 3

    # Alter FTPServer Configuration
    # Add Allow rule for our ftpGroup (Permission=3 ==> Read+Write)
    Add-WebConfiguration "/system.ftpServer/security/authorization"  -value @{accessType="Allow"; roles=$DefaultFtpGroup; permissions=3} -PSPath IIS:\ -location $DefaultFtpSiteName
    # Change the lower and upper dataChannel ports
    $firewallSupport = Get-WebConfiguration system.ftpServer/firewallSupport
    $firewallSupport.lowDataChannelPort = 5001
    $firewallSupport.highDataChannelPort = 5050
    $firewallSupport | Set-WebConfiguration system.ftpServer/firewallSupport

    # Depricated Section
    ## appcmd will be replace on the next version
    ##c:\windows\system32\inetsrv\appcmd.exe set site /site.name:$DefaultFtpSiteName /ftpServer.security.ssl.controlChannelPolicy:SslRequire
    ##c:\windows\system32\inetsrv\appcmd.exe set site /site.name:$DefaultFtpSiteName /ftpServer.security.ssl.dataChannelPolicy:SslRequire
    ##c:\windows\system32\inetsrv\appcmd.exe set site /site.name:$DefaultFtpSiteName /ftpServer.security.ssl.ssl128:true
    ##c:\windows\system32\inetsrv\appcmd.exe set site /site.name:$DefaultFtpSiteName /ftpServer.security.authentication.basicAuthentication.enabled:true
    ##c:\windows\system32\inetsrv\appcmd.exe set config $DefaultFtpSiteName /section:system.ftpserver/security/authorization /+"[accessType='Allow',permissions='Read,Write',users='$DefaultFtpUser']" /commit:apphost
    ##c:\windows\system32\inetsrv\appcmd.exe set config -section:system.ftpServer/firewallSupport /lowDataChannelPort:'5000' /commit:apphost
    ##c:\windows\system32\inetsrv\appcmd.exe set config -section:system.ftpServer/firewallSupport /highDataChannelPort:'5050' /commit:apphost
    
    # Check which version of Windows Server we are running
    # Less than 2008
    if ($OS -lt "6.1.7601")
    {
        Write-Warning "[*] Windows Server 2003 and Windows Server 2003 R2 are not supported!"
    }
    # 2008
    elseif ($OS -eq "6.1.7601") {
        $SelfSignedCert = "CN=WMSvc*"
    }
    # 2012
    elseif ($OS -eq "6.2.9200") {
        $SelfSignedCert = "CN=MgmtSvc*"
    }
    
    # Get SelfSignedCert
    cd Microsoft.PowerShell.Security\Certificate::localmachine\my
    $cert = Get-ChildItem | Where-Object {$_.subject -like $SelfSignedCert } | select thumbprint | foreach { $_.thumbprint }
    # Set site to use SelfSignedCert
    Set-ItemProperty IIS:\Sites\$DefaultFtpSiteName -Name ftpServer.security.ssl.serverCertHash -Value $cert

    #Depricated
    ##c:\windows\system32\inetsrv\appcmd.exe set config -section:system.applicationHost/sites /[name="'$DefaultFtpSiteName'"].ftpServer.security.ssl.serverCertHash:$cert /commit:apphost
    Write-Host "Display certificate Hash"
    Write-Host $cert

    Write-Host "[*] Completed $DefaultFtpSiteName creation"  

    netsh advfirewall set global StatefulFTP disable
    Write-output "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    Write-Host "[*] Stateful FTP is disabled"
    Write-output "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    Write-Host "[*] FTP username '$DefaultFtpUser'"
    Write-Host "[*] FTP password '$newFtpPassword'"
    Write-output "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    Write-Host "[*] FTP service status"
    Restart-Service ftpsvc
    Get-Service ftpsvc
}

Function Add-FtpDependencies () {
    # Author : Hounsou Dansou
    # Source : Setup-FTPS.ps1
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

Function List-Ips(){
    # Author : Hounsou Dansou
    # Source : Setup-FTPS.ps1
    # There is a cmdlet to get the IP on 2012 but not 2008. Using this method for now

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

# Main
Add-FtpDependencies
Create-Isolated-FtpSite
List-Ips
