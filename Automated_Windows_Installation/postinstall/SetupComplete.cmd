start /wait PowerShell.exe -ExecutionPolicy Bypass "iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))"
start /wait C:\ProgramData\chocolatey\bin\choco install 7zip anydesk.install googlechrome firefox adobereader notepadplusplus totalcommander ccleaner cyberduck javaruntime libreoffice skype teamviewer thunderbird vlc xnview -y -f --ignorechecksum
