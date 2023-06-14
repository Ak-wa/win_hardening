@echo off
echo.
echo [+] Checking Windows information (Check if EOL)
wmic os get Caption, BuildNumber, CSName, osarchitecture
echo.

echo [+] PowerShell language mode (Not restricted?) 
powershell.exe -c "Get-ExecutionPolicy"
echo.

echo [+] Checking if UAC is enabled (0x00 is disabled)
REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA
echo.

echo [+] Enumerating password policy (weak?)
net accounts
echo.

echo [+] Looking for stored credentials
cmdkey /list
echo.

echo [+] Last 10 Hotfixes dates (recently updated?)
powershell -c "Get-HotFix | sort-object InstalledOn -Descending | select -first 10"
