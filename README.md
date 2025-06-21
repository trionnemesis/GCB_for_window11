# Windows 11 政府組態基準 (GCB) 自動化檢測與修正指令碼

## 摘要

本 PowerShell 指令碼旨在協助系統管理員根據國家資通安全研究院發布的「**Microsoft Windows 11 政府組態基準說明文件 (TWGCB-01-010)**」，自動化地檢測與修正本機設定。

指令碼會逐項檢查系統的帳戶原則、安全性選項、登錄檔設定與防火牆規則，並將結果與 GCB 的建議值進行比對。若發現不符合的項目，指令碼會嘗試自動進行修正，並將所有操作的詳細過程記錄下來。

## ⚠️ 重要聲明

* **系統風險**: 此指令碼會直接修改系統核心的安全性原則、登錄檔及防火牆設定。不當使用可能會導致系統不穩定、功能異常或產生非預期的錯誤。
* **務必備份**: 在執行此指令碼前，**強烈建議您建立完整的系統備份或系統還原點**。
* **測試環境優先**: 請務必先在非生產環境的電腦上進行完整測試，驗證指令碼的行為符合預期後，再部署至正式環境中。
* **系統管理員權限**: 此指令碼必須在 **PowerShell (系統管理員)** 環境下執行，否則將因權限不足而無法讀取或修改系統設定。
* **範本性質**: GCB 文件包含數百項設定。此指令碼是一個涵蓋主要設定類型的**範本與框架**，並未包含所有項目。使用者需根據自身需求，依照下文的擴充說明自行新增其餘檢查項目。

## ✨ 功能

* **自動化檢測**: 自動比對目前系統設定與 GCB 文件中的建議值。
* **自動化修正**: 對於不符合 GCB 要求的設定，嘗試自動更新為建議值。
* **詳細日誌**: 產生一份名為 `wondows11_gcb_checkandset.txt` 的日誌檔案，詳細記錄每項檢查的結果，包含：
    * 已符合的項目 (`COMPLIANT`)
    * 已成功修改的項目 (`MODIFIED`)
    * 修改失敗的項目 (`FAILURE`)

## 🚀 如何使用

1.  **儲存指令碼**: 將提供的 PowerShell 程式碼儲存為 `GCB_Checker.ps1`。
2.  **執行 PowerShell (系統管理員)**:
    * 點擊「開始」功能表。
    * 輸入 `PowerShell`。
    * 在「Windows PowerShell」上按一下右鍵，選擇「**以系統管理員身分執行**」。
3.  **設定執行原則 (若需要)**: 為了允許本機指令碼執行，請在 PowerShell 視窗中輸入以下命令，並按下 `Y` 確認：
    ```powershell
    Set-ExecutionPolicy RemoteSigned
    ```
4.  **導覽至指令碼目錄**: 使用 `cd` 命令切換到您儲存 `GCB_Checker.ps1` 檔案的資料夾。
    ```powershell
    # 範例：如果檔案在 D:\Scripts
    cd D:\Scripts
    ```
5.  **執行指令碼**: 在 PowerShell 中輸入以下命令執行：
    ```powershell
    .\GCB_Checker.ps1
    ```
6.  **檢視結果**:
    * 指令碼會在主控台畫面上即時顯示執行進度與結果。
    * 執行完畢後，請開啟與指令碼位於相同資料夾的 `wondows11_gcb_checkandset.txt` 檔案，以檢視完整的執行報告。

## 📄 日誌檔案說明

日誌檔案會記錄指令碼的每一步操作，方便您追蹤與稽核。狀態標籤的意義如下：

* `[INFO]`: 執行流程中的提示訊息。
* `[COMPLIANT]`: 該項設定**已符合** GCB 要求，未做任何變更。
* `[FAILURE]`: 該項設定**不符合** GCB 要求。後續會有 `[MODIFIED]` 或另一筆 `[FAILURE]` 記錄。
* `[MODIFIED]`: 指令碼已成功將設定**修改**為 GCB 的要求值。

**日誌範例:**
[2025-06-22 01:20:31] [INFO] - Checking: 密碼最短使用期限
[2025-06-22 01:20:31] [COMPLIANT] - Result: 'MinimumPasswordAge' is already compliant. (Value: 1)

[2025-06-22 01:20:32] [INFO] - Checking: 防止啟用鎖定畫面相機
[2025-06-22 01:20:32] [FAILURE] - Result: 'NoLockScreenCamera' is NON-COMPLIANT. (Current: '', Expected: '1')
[2025-06-22 01:20:32] [MODIFIED] - Action: Successfully set 'NoLockScreenCamera' to '1'.

## 🔧 指令碼擴充說明

您可以依照 GCB 文件的內容，輕鬆地擴充此指令碼。以下是不同設定類型的擴充方法：

### 1. 帳戶原則 / 安全性選項 (使用 `secedit`)

這類設定（如密碼長度、帳戶鎖定等）透過 `Check-Set-SecurityPolicy` 函式處理 。

* **範例**: 新增一項檢查「帳戶鎖定期間 (Account lockout duration)」，要求設定為 15 分鐘以上（此處設為 15） 。
* **方法**: 在指令碼主體中加入以下程式碼：
    ```powershell
    # TWGCB-01-010-0009: 帳戶鎖定期間 (15分鐘以上)
    # Script enforces 15 minutes
    Check-Set-SecurityPolicy -PolicyName "LockoutDuration" -ExpectedValue 15 -Description "帳戶鎖定期間"
    ```
* `PolicyName` 需對應 `.inf` 設定檔中的關鍵字，常見的對應可參考網路文件或匯出的 `$env:temp\secedit_export.inf` 檔案。

### 2. 系統管理範本設定 (使用登錄檔)

大部分的系統管理範本設定都對應到登錄檔。這些設定透過 `Check-Set-RegistryValue` 函式處理 。

* **範例**: 新增一項檢查「關閉自動播放 (Turn off Autoplay)」，要求在所有磁碟機上啟用（停用自動播放） 。
* **方法**: 查詢 GPO 對應的登錄檔位置後，在指令碼主體中加入：
    ```powershell
    # TWGCB-01-010-0236: 關閉自動播放 (啟用, 所有磁碟機)
    Check-Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ExpectedValue 255 -Type DWord -Description "關閉自動播放"
    ```
* **參數說明**:
    * `Path`: GPO 對應的登錄檔路徑。電腦設定通常在 `HKLM:\SOFTWARE\Policies\...`，使用者設定在 `HKCU:\SOFTWARE\Policies\...`。
    * `Name`: 登錄檔值的名稱。
    * `ExpectedValue`: GCB 文件要求的設定值（`啟用` 通常為 `1`，`停用` 為 `0`，但有例外）。
    * `Type`: 登錄檔值的類型，通常是 `DWord` 或 `String`。

### 3. Windows Defender 防火牆設定

防火牆設定透過 `Check-Set-FirewallProfile` 函式處理 。

* **範例**: 新增一項檢查「網域設定檔的輸出連線 (Domain Profile Outbound connections)」，要求設定為「允許 (預設)」 。
* **方法**: 在指令碼主體中加入：
    ```powershell
    # TWGCB-01-010-0336: 網域設定檔：輸出連線 (允許(預設))
    Check-Set-FirewallProfile -Profile Domain -SettingName "DefaultOutboundAction" -ExpectedValue 'Allow' -Description "網域設定檔：輸出連線"
    ```
* **參數說明**:
    * `Profile`: 防火牆設定檔，可為 `Domain`, `Private`, 或 `Public`。
    * `SettingName`: 要修改的設定名稱，例如 `Enabled`, `DefaultInboundAction`, `LogDroppedPackets` 等。
    * `ExpectedValue`: GCB 文件要求的設定值。

---
## 參考文件

* **政府組態基準 (GCB) 文件**: `TWGCB-01-010_Microsoft Windows 11政府組態基準說明文件v1.0_1121201.pdf` 
