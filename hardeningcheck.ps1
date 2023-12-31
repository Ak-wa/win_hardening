# _______________________________________________________________________________________________________________________________
Write-Host "### - - - - - - - - - - - - - - - - Redacted Hardening Check - - - - - - - - - - - - - - - - ### " -Foregroundcolor Green -Backgroundcolor Black
$hostname = $(hostname)
$ips = Get-NetIPAddress -AddressFamily IPv4 | Select-Object -ExpandProperty IPAddress
$currentuser = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
$osInfo = Get-CimInstance Win32_OperatingSystem
$processorInfo = Get-CimInstance Win32_Processor
$memoryInfo = Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum


Write-Host "| Hostname		" -Foregroundcolor Green -Backgroundcolor Black $hostname
Write-Host "| User			" -Foregroundcolor Green -Backgroundcolor Black $currentuser
Write-Host "| Operating System: 	$($osInfo.Caption) $($osInfo.Version)" -Foregroundcolor Green -Backgroundcolor Black
Write-Host "| Processor: 		$($processorInfo.Name)" -Foregroundcolor Green -Backgroundcolor Black
Write-Host "| Memory: 		$($memoryInfo.Sum / 1GB) GB" -Foregroundcolor Green -Backgroundcolor Black

foreach ($ip in $ips) {Write-Host "| IPv4			" -Foregroundcolor Green -Backgroundcolor Black $ip}

Write-Host "### - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ### " -Foregroundcolor Green -Backgroundcolor Black


# HIGH RISK VULNS ________________________________________________________________________________________________________________________________
Write-Host "[-                 High risk vulnerabilities                  -]" -Foregroundcolor White -Backgroundcolor DarkGray
Write-Host "`n"

# MEDIUM RISK VULNS ________________________________________________________________________________________________________________________________
Write-Host "[-                 Medium risk vulnerabilities                -]" -Foregroundcolor White -Backgroundcolor DarkGray
Write-Host "`n"

# Checking AppLocker policy
if ((Get-AppLockerPolicy -Effective).RuleCollections.Count -eq 0) {
	Write-Host "[!] AppLocker policy not defined!" -Foregroundcolor Red
	Write-Host "    PoC via 'Get-AppLockerPolicy -Effective'`n" -Foregroundcolor Magenta
} else {
	Write-Host "[+] AppLocker policy is defined" -Foregroundcolor Green
}

# Checking PowerShell language mode / Script execution policy
$currentpolicy = Get-ExecutionPolicy
if ($currentpolicy -ne "Restricted") {
	Write-Host "[!] Powershell Execution Policy is not set to restricted." -ForegroundColor DarkCyan
	Write-Host "    Current value: "$currentpolicy -ForeGroundColor Magenta
	Write-Host "    PoC via command: Get-ExecutionPolicy `n" -ForeGroundcolor Magenta
	
} else {
	Write-host "[-] Powershell Execution Policy is set to restricted." -ForegroundColor DarkCyan
}

# LOW RISK VULNS ________________________________________________________________________________________________________________________________
Write-Host "[-                 Low risk vulnerabilities                  -]" -Foregroundcolor White -Backgroundcolor DarkGray
Write-Host "`n"

# Checking UAC (User account control)
if ((Get-ItemPropertyValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA") -eq "1") { 
	Write-Host "[-] UAC (User Account Control) is activated." -ForegroundColor DarkGray 
	if ((Get-ItemPropertyValue -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin") -eq "0") {
		Write-Host "    [!] Slider is apparently set to 0 (never notify)" -ForegroundColor Yellow
		Write-Host "    Verify manually by starting 'useraccountcontrolsettings'`n" -ForegroundColor Magenta
	} else {
		Write-Host "    Slider is not set to 0 (never notify)`n" -ForegroundColor Green
	}
} else { 
	Write-Host "[!] UAC (User Account Control) is not activated." -ForegroundColor Yellow
	Write-Host "    PoC via starting 'useraccountcontrolsettings' in cmd `n"
	}


# Checking if SMB Signing is enabled and if its required #### 
if ((Get-SmbServerConfiguration).RequireSecuritySignature -eq $true) {
	Write-Host "[-] SMB Signing is enabled`n" -Foregroundcolor DarkGray
} else {
	Write-Host "[!] SMB Signing is disabled" -Foregroundcolor DarkCyan
	Write-Host "    PoC via running 'Get-SmbServerConfiguration | ft EnableSecuritySignature, RequireSecuritySignature'`n" -Foregroundcolor Magenta
}


# Checking Core Isolation (Enabled/Disabled)
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
$regName = "Enabled"
try {
    $enabledValue = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop
    $coreIsolationStatus = $enabledValue.$regName -eq 1

    if ($coreIsolationStatus) {
        $coreIsolationStatus = "[-] Core Isolation / Memory Integrity is enabled.`n"
        Write-Host $coreIsolationStatus -ForegroundColor DarkGray
    } else {
        $coreIsolationStatus = "[!] Core Isolation / Memory Integrity is disabled."
        Write-Host $coreIsolationStatus -ForegroundColor DarkCyan
		Write-Host "    PoC via Windows settings > Security & Update > Device Security > Core Isolation > Details`n" -ForegroundColor Magenta
    }
} catch {
	$coreIsolationStatus = "[!] Core Isolation / Memory Integrity is disabled."
    Write-Host $coreIsolationStatus -ForegroundColor DarkCyan
    Write-Host "    PoC via Windows settings > Security & Update > Device Security > Core Isolation > Details`n" -ForegroundColor Magenta
}

# Checking if guest account enabled
if ((Get-LocalUser -Name "Guest").Enabled) {
	Write-Host "[!] Windows user 'Guest' is enabled" -Foregroundcolor DarkCyan
	Write-Host "    PoC via 'net user Guest'`n" -Foregroundcolor Magenta
} else {
	Write-Host "[-] Windows user 'Guest' is disabled`n" -Foregroundcolor DarkGray
}
	
# Checking for users which passwords never expire
$localUsers = Get-WmiObject Win32_UserAccount | Where-Object { $_.LocalAccount -eq $true }
foreach ($userAccount in $localUsers) {
    # Get the username and check if the password expires
    $username = $userAccount.Name
    $passwordExpires = $userAccount.PasswordExpires

    # Check if the password never expires
    if ($passwordExpires -eq $false) {
        Write-Host "[!] The password for user '$username' does not expire." -Foregroundcolor DarkCyan
} }

# Informational RISK VULNS ________________________________________________________________________________________________________________________________
Write-Host "[-                 Informational risk vulnerabilities        -]" -Foregroundcolor White -Backgroundcolor DarkGray
Write-Host "`n"
# Checking BitLocker on C: drive
$bitLockerStatus = (New-Object -ComObject Shell.Application).NameSpace('C:').Self.ExtendedProperty('System.Volume.BitLockerProtection')

switch ($bitLockerStatus) {
    0 { Write-Host "[+] BitLocker is unencryptable`n" -ForegroundColor Red }
    1 { Write-Host "[+] BitLocker is enabled`n" -ForegroundColor DarkGreen }
    2 { 
	Write-Host "[!] BitLocker is disabled on C: drive" -ForegroundColor Yellow 
	Write-Host "    PoC via 'explorer.exe -> right-click C:\ drive if it says 'Turn on BitLocker'`n" -ForegroundColor Magenta
	}
    3 { Write-Host "[+] BitLocker is encrypting`n" -ForegroundColor DarkGreen }
    4 { Write-Host "[+] BitLocker is decrypting`n" -ForegroundColor Yellow }
    5 { Write-Host "[!] BitLocker is suspended`n" -ForegroundColor Yellow }
    6 { Write-Host "[+] BitLocker is enabled and locked`n" -ForegroundColor DarkGreen }
    8 { Write-Host "[+] BitLocker is waiting for activation`n" -ForegroundColor Yellow }
    default { Write-Host "[+] Unknown BitLocker status`n" -ForegroundColor White }
}

#### TODO
# Krbtgt domain account long time no passwd
# ADD WSUS HTTP CHECK
# ADD LSA (RunasPPL) 


Write-Host "[-                 General Enumeration                -]" -Foregroundcolor Green -Backgroundcolor Black
Write-Host "[# Systeminfo" -Foregroundcolor Green -Backgroundcolor Black
systeminfo | findstr "Hostname systemname version model typ" 
# systeminfo | findstr systemname
# systeminfo | findstr version
# systeminfo | findstr model
# systeminfo | findstr typ
Write-Host "[# Privileges?" -Foregroundcolor Green -Backgroundcolor Black
whoami /priv
Write-Host "[# Active Anti-Virus" -Foregroundcolor Green -Backgroundcolor Black
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntivirusProduct Get displayName
Write-Host "[# Local users" -Foregroundcolor Green -Backgroundcolor Black
net users
Write-Host "[# Environment variables " -Foregroundcolor Green -Backgroundcolor Black
Get-ChildItem Env: | ft Key,Value
Write-Host "[# Searching for passwords " -Foregroundcolor Green -Backgroundcolor Black
cd "C:\"
Get-ChildItem -Recurse -File | Where-Object {
    $_.Name -notmatch 'hardening|pentest'
} | ForEach-Object {
    $filePath = $_.FullName
    $content = Get-Content $filePath | Select-String "password=" -Context 0, 1
    if ($content) {
        $content | ForEach-Object {
            $line = $_.Line
            if ($line.Length -gt 500) {
                $line = $line.Substring(0, 500)
            }
            Write-Host "$filePath" -ForegroundColor Yellow
            Write-Host "$line" -ForegroundColor Red
        }
    }
}
#cmd.exe /c 'findstr /SI /M "password=" *.txt 2>nul'
#cmd.exe /c 'findstr /si password *.txt *.config *.cnf 2>nul'
#cmd.exe /c 'findstr /spin "password=" *.* 2>nul'
