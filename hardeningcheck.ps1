# HIGH RISK VULNS ________________________________________________________________________________________________________________________________
Write-Host "[-                 High risk vulnerabilities                  -]" -Foregroundcolor White -Backgroundcolor DarkGray
Write-Host "`n"
# Checking AppLocker policy
if ((Get-AppLockerPolicy -Effective).RuleCollections.Count -eq 0) {
	Write-Host "[!] AppLocker policy not defined!" -Foregroundcolor Red
	Write-Host "    PoC via 'Get-AppLockerPolicy -Effective'`n" -Foregroundcolor Magenta
} else {
	Write-Host "[+] AppLocker policy is defined" -Foregroundcolor Green
}

# MEDIUM RISK VULNS ________________________________________________________________________________________________________________________________
Write-Host "[-                 Medium risk vulnerabilities                -]" -Foregroundcolor White -Backgroundcolor DarkGray
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


# Checking if SMB Signing is enabled and if its required
if ((Get-SmbServerConfiguration).EnableSecuritySignature -eq $true) {
	Write-Host "[-] SMB Signing is enabled`n" -Foregroundcolor DarkGray
	if ((Get-SmbServerConfiguration).RequireSecuritySignature -eq $false) {
		Write-Host "    ! It is not set to required!`n" -Foregroundcolor Red
	}
} else {
	Write-Host "[!] SMB Signing is disabled" -Foregroundcolor DarkCyan
	Write-Host "    PoC via running 'Get-SmbServerConfiguration | ft EnableSecuritySignature, RequireSecuritySignature'`n" -Foregroundcolor Magenta
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
    Write-Host "[+] Core Isolation Status: Error: $_" -ForegroundColor Yellow
    Write-Host
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
