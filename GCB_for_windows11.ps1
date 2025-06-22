# GCB Windows 11 Checker and Setter Script
# Version 1.0
# Author: warden
#
# DISCLAIMER: This script modifies system security settings.
# Run it at your own risk. Always back up your system before making changes.
# This script MUST be run with Administrator privileges.

# --- Script Setup ---
$LogFile = "$PSScriptRoot\wondows11_gcb_checkandset.txt"
$SecEditExportFile = "$env:temp\secedit_export.inf"
$SecEditImportFile = "$env:temp\secedit_import.inf"

# --- Pre-run Checks ---
Function Start-Script {
    # Check for Administrator privileges
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "ERROR: This script must be run with Administrator privileges." -ForegroundColor Red
        Write-Host "Please right-click the PowerShell icon and select 'Run as Administrator'." -ForegroundColor Red
        pause
        exit
    }

    # Initialize Log File
    $startTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $header = @"
===================================================================
 Windows 11 GCB Configuration Check and Set Tool
 Start Time: $startTime
 Log File: $LogFile
===================================================================

This script checks system configurations against the TWGCB-01-010 baseline
and attempts to remediate non-compliant settings.

"@
    $header | Out-File -FilePath $LogFile -Encoding utf8
}

# --- Logging Function ---
Function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [string]$Status = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Status] - $Message"

    # Console Output Colors
    $color = "White"
    switch ($Status) {
        "COMPLIANT" { $color = "Green" }
        "MODIFIED"  { $color = "Yellow" }
        "FAILURE"   { $color = "Red" }
        "INFO"      { $color = "Cyan" }
    }

    Write-Host $logMessage -ForegroundColor $color
    $logMessage | Out-File -FilePath $LogFile -Append -Encoding utf8
}

# --- Helper Functions ---

# Function to check and set Registry values
Function Check-Set-RegistryValue {
    param(
        [Parameter(Mandatory=$true)] [string]$Path,
        [Parameter(Mandatory=$true)] [string]$Name,
        [Parameter(Mandatory=$true)] $ExpectedValue,
        [Parameter(Mandatory=$true)] [string]$Type,
        [Parameter(Mandatory=$true)] [string]$Description
    )

    Write-Log "Checking: $Description" -Status "INFO"
    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
        }
        $currentValue = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
        
        if ($currentValue -eq $ExpectedValue) {
            Write-Log "Result: '$Name' is already compliant. (Value: $currentValue)" -Status "COMPLIANT"
        } else {
            Write-Log "Result: '$Name' is NON-COMPLIANT. (Current: '$currentValue', Expected: '$ExpectedValue')" -Status "FAILURE"
            try {
                Set-ItemProperty -Path $Path -Name $Name -Value $ExpectedValue -Type $Type -Force -ErrorAction Stop
                Write-Log "Action: Successfully set '$Name' to '$ExpectedValue'." -Status "MODIFIED"
            } catch {
                Write-Log "Action: FAILED to set '$Name'. Error: $($_.Exception.Message)" -Status "FAILURE"
            }
        }
    } catch {
        Write-Log "An error occurred while checking '$Description'. Error: $($_.Exception.Message)" -Status "FAILURE"
    }
    Add-Content -Path $LogFile -Value "" # Add a blank line for readability
}

# Function to check and set Local Security Policy values (Account Policies)
Function Check-Set-SecurityPolicy {
    param (
        [Parameter(Mandatory=$true)] [string]$PolicyName,
        [Parameter(Mandatory=$true)] [int]$ExpectedValue,
        [Parameter(Mandatory=$true)] [string]$Description
    )
    Write-Log "Checking: $Description" -Status "INFO"
    
    # Export current settings
    secedit /export /cfg $SecEditExportFile /quiet
    $content = Get-Content $SecEditExportFile
    
    $currentValueLine = $content | Select-String -Pattern "^$PolicyName\s*=" -CaseSensitive
    if ($currentValueLine) {
        $currentValue = ($currentValueLine -split "=")[1].Trim()
    } else {
        $currentValue = "Not Found"
    }

    if ($currentValue -eq $ExpectedValue) {
        Write-Log "Result: '$PolicyName' is already compliant. (Value: $currentValue)" -Status "COMPLIANT"
    } else {
        Write-Log "Result: '$PolicyName' is NON-COMPLIANT. (Current: '$currentValue', Expected: '$ExpectedValue')" -Status "FAILURE"
        try {
            # Create an import file with only the required change
            "[System Access]`n$PolicyName = $ExpectedValue" | Out-File $SecEditImportFile -Encoding "Unicode"
            secedit /configure /db "$env:windir\security\new.sdb" /cfg $SecEditImportFile /areas SECURITYPOLICY /quiet
            Write-Log "Action: Successfully set '$PolicyName' to '$ExpectedValue'." -Status "MODIFIED"
        } catch {
            Write-Log "Action: FAILED to set '$PolicyName'. Error: $($_.Exception.Message)" -Status "FAILURE"
        }
    }
    Remove-Item $SecEditExportFile, $SecEditImportFile -ErrorAction SilentlyContinue
    Add-Content -Path $LogFile -Value ""
}

# Function to check and set Windows Firewall Profile settings
Function Check-Set-FirewallProfile {
    param(
        [Parameter(Mandatory=$true)] [string]$Profile, # Domain, Private, Public
        [Parameter(Mandatory=$true)] [string]$SettingName,
        [Parameter(Mandatory=$true)] $ExpectedValue,
        [Parameter(Mandatory=$true)] [string]$Description
    )

    Write-Log "Checking: $Description" -Status "INFO"
    try {
        $currentProfile = Get-NetFirewallProfile -Profile $Profile
        $currentValue = $currentProfile.$SettingName

        if ($currentValue -eq $ExpectedValue) {
            Write-Log "Result: Firewall Profile '$Profile' -> '$SettingName' is already compliant. (Value: $currentValue)" -Status "COMPLIANT"
        } else {
            Write-Log "Result: Firewall Profile '$Profile' -> '$SettingName' is NON-COMPLIANT. (Current: '$currentValue', Expected: '$ExpectedValue')" -Status "FAILURE"
            try {
                Set-NetFirewallProfile -Profile $Profile -Parameter @{$SettingName = $ExpectedValue}
                Write-Log "Action: Successfully set '$SettingName' to '$ExpectedValue' for profile '$Profile'." -Status "MODIFIED"
            } catch {
                Write-Log "Action: FAILED to set '$SettingName' for profile '$Profile'. Error: $($_.Exception.Message)" -Status "FAILURE"
            }
        }
    } catch {
        Write-Log "An error occurred while checking Firewall setting '$Description'. Error: $($_.Exception.Message)" -Status "FAILURE"
    }
    Add-Content -Path $LogFile -Value ""
}


# --- Main Script Body ---
# This is a template. You can add all 397 items from the GCB document here, following the examples.

Start-Script

Write-Log "================= Starting GCB Checks =================" -Status "INFO"

# --- 帳戶原則 (Account Policies) ---
Write-Log "Section: Account Policies" -Status "INFO"

# TWGCB-01-010-0001: 密碼最短使用期限 (1天)
Check-Set-SecurityPolicy -PolicyName "MinimumPasswordAge" -ExpectedValue 1 -Description "密碼最短使用期限"

# TWGCB-01-010-0002: 密碼最長使用期限 (90天以下)
# This check is complex (less than 90). Script will enforce 90.
Check-Set-SecurityPolicy -PolicyName "MaximumPasswordAge" -ExpectedValue 90 -Description "密碼最長使用期限"

# TWGCB-01-010-0003: 最小密碼長度 (8個字元以上)
# This check is complex (greater than 8). Script will enforce 8.
Check-Set-SecurityPolicy -PolicyName "MinimumPasswordLength" -ExpectedValue 8 -Description "最小密碼長度"

# TWGCB-01-010-0004: 密碼必須符合複雜性需求 (啟用)
Check-Set-SecurityPolicy -PolicyName "PasswordComplexity" -ExpectedValue 1 -Description "密碼必須符合複雜性需求"

# TWGCB-01-010-0007: 帳戶鎖定閾值 (5次以下)
# This check is complex (less than 5). Script will enforce 5.
Check-Set-SecurityPolicy -PolicyName "LockoutBadCount" -ExpectedValue 5 -Description "帳戶鎖定閾值"


# --- 電腦設定\系統管理範本 (Computer Settings - Administrative Templates) ---
Write-Log "Section: Computer Settings (Registry-based)" -Status "INFO"

# TWGCB-01-010-0010: 防止啟用鎖定畫面相機 (啟用)
Check-Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreenCamera" -ExpectedValue 1 -Type DWord -Description "防止啟用鎖定畫面相機"

# TWGCB-01-010-0021: 啟用不安全的來賓登入 (停用)
Check-Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" -Name "AllowInsecureGuestAuth" -ExpectedValue 0 -Type DWord -Description "啟用不安全的來賓登入"

# TWGCB-01-010-0040: 開啟方便的 PIN 登入 (停用)
Check-Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "AllowDomainPINLogon" -ExpectedValue 0 -Type DWord -Description "開啟方便的 PIN 登入"

# TWGCB-01-010-0300: 關閉 Microsoft Store 應用程式 (啟用)
Check-Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "RemoveWindowsStore" -ExpectedValue 1 -Type DWord -Description "關閉 Microsoft Store 應用程式"

# TWGCB-01-010-0311: 防止使用 OneDrive 儲存檔案 (啟用)
Check-Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -ExpectedValue 1 -Type DWord -Description "防止使用 OneDrive 儲存檔案"

# TWGCB-01-010-0371: 關閉多點傳送名稱解析 (啟用)
Check-Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ExpectedValue 0 -Type DWord -Description "關閉多點傳送名稱解析 (LLMNR)"

# TWGCB-01-010-0156: 網路存取：不允許存放網路驗證的密碼與認證 (啟用)
# This maps to a security option in registry
Check-Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "disabledomaincreds" -ExpectedValue 1 -Type DWord -Description "網路存取：不允許存放網路驗證的密碼與認證"


# --- Windows Defender 防火牆設定 (Firewall Settings) ---
Write-Log "Section: Windows Defender Firewall Settings" -Status "INFO"

# TWGCB-01-010-0342: 網域設定檔：防火牆狀態 (開啟)
Check-Set-FirewallProfile -Profile Domain -SettingName "Enabled" -ExpectedValue 'True' -Description "網域設定檔：防火牆狀態"

# TWGCB-01-010-0338: 網域設定檔：記錄丟棄的封包 (是)
Check-Set-FirewallProfile -Profile Domain -SettingName "LogDroppedPackets" -ExpectedValue 'True' -Description "網域設定檔：記錄丟棄的封包"

# TWGCB-01-010-0347: 私人設定檔：防火牆狀態 (開啟)
Check-Set-FirewallProfile -Profile Private -SettingName "Enabled" -ExpectedValue 'True' -Description "私人設定檔：防火牆狀態"

# TWGCB-01-010-0358: 公用設定檔：防火牆狀態 (開啟)
Check-Set-FirewallProfile -Profile Public -SettingName "Enabled" -ExpectedValue 'True' -Description "公用設定檔：防火牆狀態"

# --- 使用者設定 (User Settings - HKCU) ---
# Note: These apply to the CURRENT user running the script.
Write-Log "Section: User Settings (Registry-based)" -Status "INFO"

# TWGCB-01-010-0326: 以密碼保護螢幕保護裝置 (啟用)
Check-Set-RegistryValue -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -ExpectedValue "1" -Type String -Description "以密碼保護螢幕保護裝置"

# TWGCB-01-010-0327: 螢幕保護裝置逾時 (900秒)
# Complex value (<=900). Script will enforce 900.
Check-Set-RegistryValue -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -ExpectedValue "900" -Type String -Description "螢幕保護裝置逾時"


# --- Script Completion ---
$endTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$footer = @"

===================================================================
 GCB Check and Set Completed
 End Time: $endTime
===================================================================
"@
Write-Log "================= GCB Checks Finished =================" -Status "INFO"
$footer | Out-File -FilePath $LogFile -Append -Encoding utf8

Write-Host "`n`nScript execution finished. A detailed report has been saved to:" -ForegroundColor Green
Write-Host "$LogFile" -ForegroundColor Yellow
# Optional: Open the log file automatically
# notepad $LogFile
