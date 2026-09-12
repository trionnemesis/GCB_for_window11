# Windows 11 政府組態基準 (GCB) 自動化檢測與修正指令碼

一鍵掃描並修復 Windows 11 是否符合台灣政府組態基準（TWGCB-01-010），並自動產生稽核日誌。

![Platform](https://img.shields.io/badge/Platform-Windows%2011-0078D6?logo=windows11&logoColor=white)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?logo=powershell&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green.svg)

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
* **詳細日誌**: 產生一份名為 `windows11_gcb_checkandset.txt` 的日誌檔案，詳細記錄每項檢查的結果，包含：
    * 已符合的項目 (`COMPLIANT`)
    * 已成功修改的項目 (`MODIFIED`)
    * 修改失敗的項目 (`FAILURE`)

## 🚀 如何使用

1.  **取得程式碼並導覽至目錄**:
    ```powershell
    git clone https://github.com/trionnemesis/GCB_for_window11.git
    cd GCB_for_window11
    ```
2.  **執行 PowerShell (系統管理員)**:
    * 點擊「開始」功能表。
    * 輸入 `PowerShell`。
    * 在「Windows PowerShell」上按一下右鍵，選擇「**以系統管理員身分執行**」。
3.  **設定執行原則 (若需要)**: 為了允許本機指令碼執行，請在 PowerShell 視窗中輸入以下命令：
    ```powershell
    Set-ExecutionPolicy RemoteSigned -Scope Process
    ```
4.  **執行指令碼**: 確認目前所在目錄為 clone 下來的 `GCB_for_window11` 資料夾後，輸入以下命令執行：
    ```powershell
    .\GCB_for_windows11.ps1
    ```
5.  **檢視結果**:
    * 指令碼會在主控台畫面上即時顯示執行進度與結果。
    * 執行完畢後，請開啟與指令碼位於相同資料夾的 `windows11_gcb_checkandset.txt` 檔案，以檢視完整的執行報告。

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
    Check-Set-SecurityPolicy -PolicyName "LockoutDuration" -ExpectedValue 15 -Comparison AtLeast -Description "帳戶鎖定期間"
    ```
* `PolicyName` 需對應 `.inf` 設定檔中的關鍵字，常見的對應可參考網路文件或匯出的 `$env:temp\secedit_export.inf` 檔案。
* `-Comparison` 參數請依該項目的實際規則語意選擇 `Equal`（固定值/開關）、`AtLeast`（下限，數值需大於等於門檻）或 `AtMostNonZero`（上限且不可為 0，數值需大於 0 且小於等於門檻）；詳見下方「變更紀錄」。

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
* **目前採用版本**：TWGCB-01-010 **v1.0**（中華民國112年12月1日 / 1121201）。截至 2026-09-12，經多次複核（2026-07-17、2026-08-19、2026-09-10、2026-09-12）皆未發現官方已發布更新版本，詳見下方「變更紀錄」。

## 變更紀錄

* **2026-09-12（複核，無規則異動）**：依排程任務再次核對 NICS（國家資通安全研究院）現行公告之 Windows 11 GCB 版本。
    * 本工作階段的網路政策同樣封鎖直接連線 `www.nics.nat.gov.tw` / `download.nics.nat.gov.tw`（egress 被擋），改以公開網路搜尋交叉比對官方文件檔名與發布資訊。
    * 確認 **`TWGCB-01-010` 現行仍為 v1.0**（中華民國112年12月1日 / 1121201），與先前歷次複核（2026-07-17、2026-08-19、2026-09-10）結論一致；搜尋結果中仍持續出現「v1.1（1141105，2025年11月）」的說法，但每次追查皆查無任何可驗證、可點擊的官方下載連結或公告佐證（實際搜尋回傳的連結清單僅有 v1.0 `_1121201.pdf`），研判為 AI 搜尋摘要或非官方轉載內容循環傳播所致，本次同樣**不予採用**。
    * 進一步查證 NICS 網站「115年政府組態基準GCB說明文件（預告版）」頁面（`/core_business/cybersecurity_defense/GCB/gcbreview/`）之公開報導內容，115年度新增項目為 **Apple macOS 15.x（TWGCB-01-015，預告版）** 與 **Fortinet FortiGate（TWGCB-03-006，預告版）**，並未見 Windows 11 基準被列入本次預告更新範圍，故本次**不**調整任何規則期望值或版本標示。
    * 因此本次**未修改** `GCB_for_windows11.ps1` 之任何檢測邏輯或期望值，僅更新本文件之複核紀錄。
* **2026-07-17**：修正帳戶原則檢查的比對邏輯錯誤，並複核目前基準版本。
    * **邏輯修正（Bug fix）**：`Check-Set-SecurityPolicy` 先前一律以完全相等 (`-eq`) 判斷帳戶原則是否合規，但 TWGCB-01-010 對應的帳戶原則項目實際規定為「範圍／門檻」而非單一固定值。這導致：
        1. 已符合、甚至**更嚴格**的既有設定（例如最小密碼長度已設為 14、帳戶鎖定閾值已設為 3）被誤判為 `NON-COMPLIANT`；
        2. 觸發修正動作後，反而把原本更嚴格的設定**弱化**至門檻值（例如密碼長度 14 → 8）；
        3. 未正確判斷「0」在部分項目中代表「永不過期／永不鎖定」的不合規特殊值。

      修正方式：為 `Check-Set-SecurityPolicy` 新增 `-Comparison` 參數（`Equal` / `AtLeast` / `AtMostNonZero`），並依各項目的正確規則語意套用：

      | TWGCB-ID | 項目 | 規則語意 | 修正前 | 修正後 (`-Comparison`) |
      |---|---|---|---|---|
      | 0001 | 密碼最短使用期限 | ≥ 1 天 | `-eq 1` | `AtLeast 1` |
      | 0002 | 密碼最長使用期限 | 1~90 天（不可為 0/永不過期） | `-eq 90` | `AtMostNonZero 90` |
      | 0003 | 最小密碼長度 | ≥ 8 字元（保留既有更嚴格設定） | `-eq 8` | `AtLeast 8` |
      | 0004 | 密碼必須符合複雜性需求 | 啟用（布林開關，維持精確比對） | `-eq 1` | `Equal 1`（行為不變） |
      | 0007 | 帳戶鎖定閾值 | 1~5 次（不可為 0/永不鎖定） | `-eq 5` | `AtMostNonZero 5` |

      指令碼自身版本號由 `1.0` 提升為 `1.1`（見 `GCB_for_windows11.ps1` 檔頭），此版本號僅代表**本指令碼**的修正版次，與下方 GCB 基準版本無關。

    * **基準版本複核**：本次同時複核 NICS（國家資通安全研究院）目前公告之 Windows 11 GCB 基準版本。本工作階段的網路政策封鎖 `www.nics.nat.gov.tw` 與 `download.nics.nat.gov.tw`（連線回應 403），故改以公開網路搜尋交叉比對官方檔名與發布資訊。確認結果：現行基準仍為 **TWGCB-01-010 v1.0**（中華民國112年12月1日 / 1121201）。搜尋過程中曾出現「v1.1（1141105）」的說法，但**查無任何可驗證、可點擊的官方來源**佐證，判斷為不可靠資訊，故**不予採用**，本專案亦**不**調整 GCB 基準文件版本號。

---
## Related projects

* [GCB_for_rockylinux](https://github.com/trionnemesis/GCB_for_rockylinux) — 同系列的 Rocky Linux 政府組態基準自動化檢測與修正指令碼。

## License

本專案採用 [MIT License](LICENSE) 授權。
