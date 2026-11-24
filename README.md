# 🛡️ Secure USB Vault Manager (`IS918` Pure Rust Win32 Edition)

![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011%20%7C%20WinPE-0078D4?style=flat-square&logo=windows)
![Version](https://img.shields.io/badge/Release-v2.5.7-8B5CF6?style=flat-square)
![Language](https://img.shields.io/badge/Language-Rust%20(2021%20Edition)-DEA584?style=flat-square&logo=rust)
![Dependencies](https://img.shields.io/badge/Dependencies-Zero%20External%20Crates-10B981?style=flat-square)
![CRT](https://img.shields.io/badge/CRT-Static%20(%2Bcrt--static)-3B82F6?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-F59E0B?style=flat-square)

> **[ 🇰🇷 한국어 안내](#-한국어-안내-korean) | [ 🇺🇸 English Documentation](#-english-documentation)**

<p align="center">
  <img src="./preview.png" alt="Secure USB Vault Manager Preview" width="700" />
</p>

---

# 🇰🇷 한국어 안내 (Korean)

**Secure USB Vault Manager**(`SecureUSBManager.exe`)는 **Innostor `IS918` 시리즈(`IS918M_GA` 등) USB 컨트롤러**의 하드웨어 보안 파티션(Dual-LUN: `CD-ROM + Security`)을 제어하는 초경량 네이티브 보안 런처 및 볼트 관리 프로그램입니다.

기존 제조사 번들 프로그램(`IS918SecurityPack.exe`)의 투박한 UI, 다국어 글자 깨짐, 재포맷 없이는 비밀번호 변경이 불가능했던 한계를 해결하기 위해 **외부 크레이트 의존성 없이(`Zero External Dependencies`) 순수 Rust 표준 라이브러리와 Win32 GDI / SCSI Pass-Through FFI만으로 제작**되었습니다.

---

## ✨ 주요 특징 (Key Features)

### 1. 🔒 하드웨어 레벨 SCSI 보안 파티션 잠금 / 해제 & 빈 이동식 디스크 자동 숨김
- Windows `IOCTL_SCSI_PASS_THROUGH_DIRECT` (64바이트 DMA 정렬 및 표준 6바이트 `INQUIRY` 호환)를 통해 컨트롤러 펌웨어와 직접 통신합니다.
- **32-Round Big-Endian TEA(Tiny Encryption Algorithm)** 및 **1회용 동적 챌린지 토큰(`0xE0 0x32`)** 인증을 통해 하드웨어 보안 영역(`LUN1`)을 마운트하거나 즉시 숨김(Dismount & Lock) 처리합니다.
- **잠금 상태에서 빈 `이동식 디스크` 자동 숨김 (`DeleteVolumeMountPointW`)**: 보안 영역이 잠겨 있을 때는 탐색기(`내 PC`)에서 0바이트 빈 `이동식 디스크` 드라이브 문자를 자동으로 마운트 해제하여 **`CD 드라이브 (SECURE_USB)`만 깔끔하게 표시**하며, 잠금 해제 시 `SetVolumeMountPointW`로 **`Secure USB`** 보안 드라이브를 즉시 자동 마운트합니다.
- **실시간 `Caps Lock` 켜짐 경고**: 비밀번호 입력 시 `Caps Lock`이 켜져 있으면 카드 상단에 즉시 **`⚠️ Caps Lock 켜짐`** 경고를 띄워 입력 실수로 인한 인증 횟수 차감을 방지합니다.

### 2. 🔑 포맷 없는 비밀번호 & 힌트 변경 (Portable Vault System)
- 기존 번들 툴에서는 비밀번호를 바꾸려면 MPTool로 USB 전체를 초기화해야 했으나, 본 프로그램은 **순수 Rust로 구현된 SHA-256 솔트 해시 기반 포터블 볼트(`.is918_vault.cfg`)**를 보안 파티션 내부에 동기화하여 **데이터 손실 없이 언제든 비밀번호와 힌트를 변경**할 수 있습니다.
- 설정 정보(변경된 비밀번호 해시, 힌트, 자동 잠금 타이머, 테마)가 **USB 보안 영역 내부에 직접 저장**되므로 다른 PC에 꽂아도 동일한 설정과 비밀번호로 동작합니다.

### 3. 🛡️ 포맷 후 보안 영역 아이콘(`Secure USB`) & `autorun.inf` 자동 / 원클릭 복구
- 사용자가 윈도우에서 보안 영역(`LUN1`)을 포맷하더라도, 다음 잠금 해제 시(또는 **`[아이콘·Autorun 복구]`** 버튼 클릭 시) 실행 파일 내부에 내장된 에메랄드 보안 볼트 전용 아이콘(`logo.ico`)과 `autorun.inf`(`label=Secure USB`)를 **읽기 전용(`+r`) 및 숨김(`+h`) 속성**으로 즉시 자동 복원합니다.

### 4. 🚨 10회 연속 오류 시 데이터 완전 파기 (Self-Destruct Wipe — Mode B)
- 비밀번호를 틀릴 때마다 남은 인증 기회(`9 / 10` → `1 / 10`)와 데이터 파기 경고 팝업을 표시합니다.
- 남은 기회가 3회 이하일 때는 **`🚨 [위험: 데이터 영구 파기 직전!]`** 강력 경고가 활성화됩니다.
- **10회 연속 인증 실패(`0 / 10`) 시 자폭 프로토콜 작동**:
  1. 보안 영역 내부의 모든 파일을 **3단계 덮어쓰기(`0x00` → `0xFF` → `PRNG 난수`)**로 세단(Shred)
  2. MFT 및 디렉터리 메타데이터 흔적까지 제거하기 위해 볼륨을 **즉시 클린 포맷(`NTFS`)**
  3. 볼트 초기화 후 하드웨어 보안 영역 재잠금

### 5. ⏱️ 자리 비움 자동 잠금 타이머 & 📥 시스템 트레이 상주 (중복 실행 방지)
- **자동 잠금 타이머 (`사용 안 함` / `5분` / `10분` / `15분` / `30분`)**: 지정된 시간 동안 마우스·키보드 입력이 없으면 열려 있는 볼륨 핸들을 안전하게 분리(`FlushFileBuffers` + `FSCTL_DISMOUNT_VOLUME`)한 뒤 보안 영역을 자동으로 잠그고 트레이 알림을 띄웁니다.
- **시스템 트레이(System Tray) 및 단일 인스턴스 지원**: 창을 최소화(`_`)하거나 `[트레이로 숨기기]`를 누르면 트레이 아이콘으로 상주하며, 트레이에 숨겨진 상태에서 프로그램을 다시 실행하면 중복 실행 대신 **기존 창을 즉시 화면 앞으로 복원**합니다.

### 6. 🗑️ 파일 완전 삭제(DoD 3-Pass 보안 세단기) & 잠금 후 안전 제거
- **`[파일 완전 삭제]`**: 선택한 중요 파일을 DoD 방식 3단계 덮어쓰기 후 삭제하여 포렌식/복구 프로그램으로도 절대 복원할 수 없게 파기합니다.
- **`[잠금 후 안전 제거]`**: 파일시스템 캐시 플러시 → 볼륨 잠금 및 마운트 해제 → 하드웨어 보안 잠금(`0xE0 0x33 0x11`) → 미디어 추출(`IOCTL_STORAGE_EJECT_MEDIA`)을 원클릭으로 수행합니다.

### 7. 🌓 Microsoft Fluent 2 (WinUI 3 Mica) 디자인 · 3개 국어(KO / EN / JA) · WinPE 완벽 호환
- **Fluent 2 / WinUI 3 인터페이스**: 라이트 / 다크 모드 실시간 전환, 60fps 마우스 호버 리빌 하이라이트(Reveal Highlight), 하드웨어 및 프로그램 제원을 한눈에 볼 수 있는 **`프로그램 정보`** 탭을 제공합니다.
- **정적 CRT(`+crt-static`) 및 동적 DWM 로딩**: `vcruntime140.dll`이나 `dwmapi.dll`이 없는 **Windows PE (WinPE) 복구 환경**부터 Windows 10 / 11까지 단일 실행 파일 하나로 100% 동작합니다.

---

## 🛠️ Innostor IS918 MPTool 다운로드 및 하드웨어 보안 파티션 제작 가이드

일반 IS918 컨트롤러 USB를 하드웨어 보안 USB(`CD-ROM + Security` Dual-LUN 구조)로 변환하거나, 가상 CD-ROM 영역(`LUN0`)에 본 프로젝트의 `secure_launcher.iso`를 구우려면 **Innostor IS918 Mass Production Tool (`IS918MPTool`)**이 필요합니다.

### 1. IS918 MPTool 다운로드
- **공식 아카이브 (USBDev.ru)**: **[https://www.usbdev.ru/files/innostor/is918mpt/](https://www.usbdev.ru/files/innostor/is918mpt/)**
- USB 컨트롤러의 리비전(예: `IS918M_GA` 등)에 맞는 버전을 다운로드하여 압축을 해제합니다. (예: `IS918MPTool_GA_221206`)

### 2. `MPTool.ini` 설정 및 보안 파티션 굽기
1. `IS918MPTool` 폴더 내 `Configuration\MPTool.ini` 파일을 열거나, MPTool 실행 후 `Setting` (초기 비밀번호는 보통 공란 또는 `IS0024`)으로 들어갑니다.
2. **`[Partition]`** 섹션을 아래와 같이 설정하여 **`LUN0` = 가상 CD-ROM 런처 (`secure_launcher.iso`)**, **`LUN1` = 하드웨어 보안 파티션 (`100%` 데이터 영역)**으로 지정합니다:
   ```ini
   [Partition]
   PartitionNum=2
   PartitionType=5
   Lun0SizeRatio=0
   Lun1SizeRatio=100
   Lun0CDROMPath=C:\path\to\secure_launcher.iso
   Password=1234
   PwdHint=Admin Inquiry
   NoPWDPwrOnLogin=1
   PwdRetryTimes=10
   ```
   - `PartitionType=5`: **CD-ROM + Security** 모드 (`0`=Public 단일, `3`=Public+Security, `4`=CD-ROM+Public, `5`=CD-ROM+Security)
   - `Lun0CDROMPath`: 본 저장소에 포함된 `secure_launcher.iso` 경로를 지정합니다.
3. MPTool 메인 화면에서 **`Start`**를 클릭해 양산(MP) 작업을 완료한 뒤 USB를 재연결하면, 가상 CD-ROM 드라이브에서 `SecureUSBManager.exe`를 즉시 실행할 수 있습니다.

---

## 🚀 빌드 및 CLI 사용 방법 (Build & CLI Usage)

### 1. Rust 네이티브 빌드
```powershell
cd rust_secure_usb
cargo build --release
```
- 빌드 결과물: `rust_secure_usb/target/release/secure_usb_manager.exe`

### 2. CLI(명령줄) 모드
```powershell
SecureUSBManager.exe status                              # 상태 및 파티션/실사용 용량 조회
SecureUSBManager.exe unlock <비밀번호>                    # 보안 영역 잠금 해제
SecureUSBManager.exe lock                                # 보안 영역 즉시 잠금
SecureUSBManager.exe eject                               # 잠금 후 안전 제거 (Safe Eject)
SecureUSBManager.exe passwd <현재_암호> <새_암호> [새_힌트] # 비밀번호 및 힌트 변경
```

---
---

# 🇺🇸 English Documentation

**Secure USB Vault Manager** (`SecureUSBManager.exe`) is an ultra-lightweight, native Win32 hardware security partition launcher and vault manager designed for **Innostor `IS918` series (`IS918M_GA`, etc.) USB flash drive controllers**.

It replaces the legacy vendor utility (`IS918SecurityPack.exe`), which suffered from outdated UI, broken CJK character encoding, and the inability to change passwords without reformatting the entire drive. Written in **100% pure Rust (`Zero External Crates`)** using direct Win32 GDI double-buffering and `IOCTL_SCSI_PASS_THROUGH_DIRECT`, it compiles into a single **`~360 KB` standalone executable** with zero runtime dependencies.

---

## ✨ Key Features

### 1. 🔒 Hardware-Level SCSI Security Partition Unlock/Lock & Ghost Drive Auto-Hide
- Communicates directly with the Innostor `IS918` controller firmware via Windows `IOCTL_SCSI_PASS_THROUGH_DIRECT` (with 64-byte DMA buffer alignment and standard 6-byte `INQUIRY` CDB compatibility for strict xHCI/UASP controllers).
- Uses **32-Round Big-Endian TEA (Tiny Encryption Algorithm)** combined with a **one-time dynamic challenge token (`0xE0 0x32`)** to mount (`0xE0 0x33 0x00 0x01`) or dismount & lock (`0xE0 0x33 0x11`) the hardware-hidden security partition (`LUN1`).
- **Auto-Hide Empty Removable Drive While Locked**: Automatically dismounts and unmounts the empty `LUN1` removable drive letter via `DeleteVolumeMountPointW` while locked so only the `SECURE_USB` CD-ROM appears in Windows Explorer, and automatically re-mounts `Secure USB` via `SetVolumeMountPointW` upon unlock.
- **Live Caps Lock Alert**: Displays a real-time `⚠️ Caps Lock is ON` indicator on password tabs to prevent accidental failed authentication attempts.

### 2. 🔑 Password & Hint Change Without Reformatting (Portable Vault)
- Legacy IS918 tools required a full mass-production reformat to change the password. **Secure USB Vault Manager** implements a **salted SHA-256 portable vault (`.is918_vault.cfg`)** stored directly inside the hidden security partition.
- Your custom password, password hint, auto-lock timer setting, and UI theme travel **inside the USB drive itself**, working seamlessly across any Windows PC.

### 3. 🛡️ Automatic & 1-Click Security Drive Icon (`Secure USB`) & `autorun.inf` Repair
- Even after formatting the security partition (`LUN1`), the manager automatically (or via the **`[Repair Autorun]`** button) restores the custom emerald vault drive icon (`logo.ico`), `autorun.inf` (`label=Secure USB`), and volume label with **Read-Only (`+r`) and Hidden (`+h`)** attributes.

### 4. 🚨 10-Attempt Self-Destruct Data Wipe (Mode B)
- Displays a clear warning dialog with remaining attempts (`9 / 10` down to `1 / 10`) on every failed password entry.
- Escalates to a **`🚨 [CRITICAL: DATA WIPE IMMINENT!]`** alert when 3 or fewer attempts remain.
- **Upon 10 consecutive failed attempts (`0 / 10`), the self-destruct protocol executes automatically**:
  1. Recursively shreds all files inside the security partition using a **3-Pass DoD overwrite (`0x00` → `0xFF` → `PRNG Random`)**.
  2. Performs a silent **clean `NTFS` quick format** to purge MFT and directory metadata traces.
  3. Resets the vault to factory state and immediately re-locks the hardware partition.

### 5. ⏱️ Inactivity Auto-Lock Timer & 📥 System Tray Integration (Single-Instance)
- **Idle Auto-Lock (`Disabled` / `5 Minutes` / `10 Minutes` / `15 Minutes` / `30 Minutes`)**: Monitors system-wide keyboard/mouse idle time (`GetLastInputInfo`), safely flushes and dismounts open volume handles, and automatically locks the security drive when you step away.
- **System Tray Resident & Single-Instance Restore**: Minimize (`_`) or click `[Hide to Tray]` to keep the manager in the system tray with state-aware right-click actions. Launching the executable again automatically restores and focuses the existing window.

### 6. 🗑️ 3-Pass File Shredder & Safe Hardware Eject
- **`[File Shredder]`**: Permanently destroys sensitive files on the security drive via 3-pass overwrite before unlinking so forensic recovery tools cannot restore them.
- **`[Lock & Safe Eject]`**: Flushes volumes, dismounts and locks the security partition, and issues `IOCTL_STORAGE_EJECT_MEDIA` for safe USB removal in one click.

### 7. 🌓 Microsoft Fluent 2 (WinUI 3 Mica) Design · Multi-Language (`KO` / `EN` / `JA`) · WinPE Ready
- **Fluent 2 / WinUI 3 Interface**: Features instant Light / Dark mode switching, 60fps mouse-tracked Reveal Highlight borders, and an **About / Specifications** tab with live hardware details.
- **Static CRT (`+crt-static`) & Dynamic DWM Loading**: Runs out-of-the-box on **Windows PE (WinPE)** recovery environments as well as Windows 10 and Windows 11 with zero external DLL dependencies.

---

## 🛠️ Downloading IS918 MPTool & Creating a Hardware Secure USB

To configure an Innostor IS918 USB drive into Dual-LUN **`CD-ROM + Security`** mode and embed `secure_launcher.iso` into the read-only virtual CD-ROM partition (`LUN0`), you need the **Innostor IS918 Mass Production Tool (`IS918MPTool`)**.

### 1. Download Innostor IS918 MPTool
- **Official Archive (USBDev.ru)**: **[https://www.usbdev.ru/files/innostor/is918mpt/](https://www.usbdev.ru/files/innostor/is918mpt/)**
- Download the MPTool package matching your controller revision (e.g., `IS918M_GA` -> `IS918MPTool_GA_221206`).

### 2. Configure `MPTool.ini` & Flash the Drive
1. Open `Configuration\MPTool.ini` inside the MPTool folder (or open `Setting` in the MPTool GUI; default password is blank or `IS0024`).
2. Configure the **`[Partition]`** section for **`PartitionType=5` (`CD-ROM + Security`)**:
   ```ini
   [Partition]
   PartitionNum=2
   PartitionType=5
   Lun0SizeRatio=0
   Lun1SizeRatio=100
   Lun0CDROMPath=C:\path\to\secure_launcher.iso
   Password=1234
   PwdHint=Admin Inquiry
   NoPWDPwrOnLogin=1
   PwdRetryTimes=10
   ```
   - `PartitionType=5`: Sets **LUN0 = Virtual CD-ROM** and **LUN1 = Hardware Security Partition** (`100%` capacity).
   - `Lun0CDROMPath`: Point this to `secure_launcher.iso` included in this repository.
3. Click **`Start`** in `IS918MPTool.exe`. Once completed, replug the USB drive to access `SecureUSBManager.exe` directly from the hardware read-only CD-ROM drive.

---

## 🔬 Reverse-Engineered IS918 Hardware Security SCSI Protocol

Below is the vendor-specific SCSI command specification (`IOCTL_SCSI_PASS_THROUGH_DIRECT`) verified on live Innostor `IS918M_GA` hardware:

| Operation | SCSI CDB (10 Bytes) | Direction / Size | Description |
| :--- | :--- | :--- | :--- |
| **Identify Controller** | `12 00 00 00 60 00 00 00 00 00` | `DATA_IN` (`96B`) | Standard `INQUIRY`. Bytes `40..44` must equal `"BWSE"`. |
| **Read Flash ID** | `E0 10 06 90 00 0E 00 00 00 00` | `DATA_IN` (`512B`) | Returns 6-byte physical NAND Flash ID at offset `0..6`. |
| **Read Partition Table** | `E0 30 00 00 00 00 00 00 01 00` | `DATA_IN` (`512B`) | Big-Endian `u32` sector counts for `LUN0..3` at `0x10 + i*4`; LUN flags at `0x30 + i`. |
| **Read Security Info** | `E0 32 00 00 00 00 00 01 06 00` | `DATA_IN` (`48B` / `0x30`) | **[CRITICAL]** Transfer length must be `0x30` (48 bytes).<br>`buf[0]`: One-time dynamic challenge token<br>`buf[1]`: Remaining retry count<br>`buf[2] & 1`: Unlock state (`1`=Unlocked, `0`=Locked)<br>`buf[15]`: Max retry limit<br>`buf[32..48]`: ASCII password hint |
| **Hardware Unlock** | `E0 33 00 01 00 00 00 01 00 00` | `DATA_OUT` (`512B`) | Encrypts 16-byte password (`plain32[0..16]`) using 32-round Big-Endian TEA with 128-bit key `[token + 0x266EC300, 0x36D9C77D, 0xE48D5124, 0xAD7275C8]` where `token` is `buf[0]` from the immediately preceding `0xE0 0x32` call. |
| **Hardware Lock** | `E0 33 11 00 00 00 00 00 01 00` | `UNSPECIFIED` (`0B`) | Dismount `LUN1` (`FSCTL_LOCK_VOLUME` + `FSCTL_DISMOUNT_VOLUME`) first, then send `0xE0 0x33 0x11`. |

---

## 📂 Repository Structure

```text
├── README.md                       # Bilingual Project Documentation (KO / EN)
├── preview.png                     # Application UI Preview Screenshot
├── .gitignore                      # Git ignore rules
├── secure_shield.ico               # Multi-resolution (16/32/48px) shield icon
├── SecureUSBManager.exe            # Prebuilt Pure Rust Win32 executable (~360 KB)
├── secure_launcher.iso             # Ready-to-flash CD-ROM (LUN0) ISO image (~424 KB)
├── rust_secure_usb/                # Pure Rust Native Win32 Source Project
│   ├── Cargo.toml                  # Zero dependencies, size-optimized release profile
│   ├── build.rs                    # Windows RC resource compiler script
│   ├── app.rc                      # PerMonitorV2 High-DPI manifest & VERSIONINFO
│   └── src/
│       └── main.rs                 # SCSI engine, TEA/SHA-256, GDI UI, 3-pass shredder
└── preload_lun0/                   # Source files for CD-ROM (LUN0) ISO image
    ├── SecureUSBManager.exe        # Bundled launcher executable
    ├── logo.ico                    # Volume icon
    └── autorun.inf                 # CD-ROM icon & label definition
```

---

## 📜 License

This project is licensed under the **MIT License**.
