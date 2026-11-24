#![windows_subsystem = "windows"]

use std::env;
use std::ffi::c_void;
use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::os::windows::process::CommandExt;
use std::ptr::{null, null_mut};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ============================================================================
// Pure Rust SHA-256 Implementation
// ============================================================================
const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256_hex(data: &[u8]) -> String {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[i * 4], chunk[i * 4 + 1], chunk[i * 4 + 2], chunk[i * 4 + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(SHA256_K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = String::with_capacity(64);
    for val in &h {
        out.push_str(&format!("{:08X}", val));
    }
    out
}

// ============================================================================
// Win32 FFI Declarations
// ============================================================================
type HANDLE = *mut c_void;
type HWND = *mut c_void;
type HDC = *mut c_void;
type HMENU = *mut c_void;
type HINSTANCE = *mut c_void;
type HICON = *mut c_void;
type HCURSOR = *mut c_void;
type HBRUSH = *mut c_void;
type HFONT = *mut c_void;
type HGDIOBJ = *mut c_void;
type HPEN = *mut c_void;
type HBITMAP = *mut c_void;
type WPARAM = usize;
type LPARAM = isize;
type LRESULT = isize;
type ATOM = u16;
type BOOL = i32;
type DWORD = u32;
type UINT = u32;
type COLORREF = u32;

const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;
const GENERIC_READ: DWORD = 0x80000000;
const GENERIC_WRITE: DWORD = 0x40000000;
const FILE_SHARE_READ: DWORD = 0x00000001;
const FILE_SHARE_WRITE: DWORD = 0x00000002;
const FILE_SHARE_DELETE: DWORD = 0x00000004;
const OPEN_EXISTING: DWORD = 3;
const FILE_ATTRIBUTE_READONLY: DWORD = 0x00000001;
const FILE_ATTRIBUTE_HIDDEN: DWORD = 0x00000002;
const FILE_ATTRIBUTE_SYSTEM: DWORD = 0x00000004;
const FILE_ATTRIBUTE_NORMAL: DWORD = 0x00000080;

const IOCTL_SCSI_PASS_THROUGH_DIRECT: DWORD = 0x0004D014;
const FSCTL_LOCK_VOLUME: DWORD = 0x00090018;
const FSCTL_DISMOUNT_VOLUME: DWORD = 0x00090020;
const IOCTL_STORAGE_EJECT_MEDIA: DWORD = 0x002D4808;
const IOCTL_STORAGE_LOAD_MEDIA: DWORD = 0x002D480C;
const IOCTL_STORAGE_LOAD_MEDIA2: DWORD = 0x002D080C;
const IOCTL_STORAGE_GET_DEVICE_NUMBER: DWORD = 0x002D1080;
const IOCTL_STORAGE_FIND_NEW_DEVICES: DWORD = 0x002D5018;
const IOCTL_DISK_UPDATE_PROPERTIES: DWORD = 0x00070140;
const IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS: DWORD = 0x00560000;
const IOCTL_VOLUME_ONLINE: DWORD = 0x0056C008;
const IOCTL_VOLUME_OFFLINE: DWORD = 0x0056C00C;
const IOCTL_MOUNTMGR_CHECK_UNPROCESSED_VOLUMES: DWORD = 0x006D0030;

const SHCNE_MEDIAINSERTED: i32 = 0x00000020;
const SHCNE_MEDIAREMOVED: i32 = 0x00000040;
const SHCNE_DRIVEREMOVED: i32 = 0x00000080;
const SHCNE_DRIVEADD: i32 = 0x00000100;
const SHCNF_PATHW: UINT = 0x0005;
const SHCNF_FLUSHNOWAIT: UINT = 0x3000;

const SCSI_IOCTL_DATA_OUT: u8 = 0;
const SCSI_IOCTL_DATA_IN: u8 = 1;
const SCSI_IOCTL_DATA_UNSPECIFIED: u8 = 2;

const WS_OVERLAPPED: DWORD = 0x00000000;
const WS_CAPTION: DWORD = 0x00C00000;
const WS_SYSMENU: DWORD = 0x00080000;
const WS_MINIMIZEBOX: DWORD = 0x00020000;
const WS_VISIBLE: DWORD = 0x10000000;
const WS_CHILD: DWORD = 0x40000000;
const WS_TABSTOP: DWORD = 0x00010000;
const WS_BORDER: DWORD = 0x00800000;
const WS_CLIPCHILDREN: DWORD = 0x02000000;
const WS_CLIPSIBLINGS: DWORD = 0x04000000;

const CBS_DROPDOWNLIST: DWORD = 0x0003;
const BS_PUSHBUTTON: DWORD = 0x0000;
const BS_AUTOCHECKBOX: DWORD = 0x0003;
const BS_OWNERDRAW: DWORD = 0x000B;
const ES_PASSWORD: DWORD = 0x0020;
const ES_AUTOHSCROLL: DWORD = 0x0080;

const WM_DESTROY: UINT = 0x0002;
const WM_SIZE: UINT = 0x0005;
const WM_CLOSE: UINT = 0x0010;
const WM_PAINT: UINT = 0x000F;
const WM_ERASEBKGND: UINT = 0x0014;
const WM_SETFONT: UINT = 0x0030;
const WM_DRAWITEM: UINT = 0x002B;
const WM_COMMAND: UINT = 0x0111;
const WM_SYSCOMMAND: UINT = 0x0112;
const WM_TIMER: UINT = 0x0113;
const WM_CTLCOLOREDIT: UINT = 0x0133;
const WM_CTLCOLORBTN: UINT = 0x0135;
const WM_CTLCOLORSTATIC: UINT = 0x0138;
const WM_DEVICECHANGE: UINT = 0x0219;
const WM_DPICHANGED: UINT = 0x02E0;
const WM_USER: UINT = 0x0400;
const WM_TRAYICON: UINT = WM_USER + 55;

const CS_VREDRAW: UINT = 0x0001;
const CS_HREDRAW: UINT = 0x0002;
const SWP_NOZORDER: UINT = 0x0004;
const SWP_NOACTIVATE: UINT = 0x0010;

const WM_LBUTTONDBLCLK: usize = 0x0203;
const WM_RBUTTONUP: usize = 0x0205;
const SC_MINIMIZE: usize = 0xF020;

const DBT_DEVICEARRIVAL: usize = 0x8000;
const DBT_DEVICEREMOVECOMPLETE: usize = 0x8004;

const CB_ADDSTRING: UINT = 0x0143;
const CB_RESETCONTENT: UINT = 0x014B;
const CB_SETCURSEL: UINT = 0x014E;
const CB_GETCURSEL: UINT = 0x0147;
const CBN_SELCHANGE: u16 = 1;

const BM_GETCHECK: UINT = 0x00F0;
const BM_SETCHECK: UINT = 0x00F1;
const BST_CHECKED: usize = 1;
const EM_SETPASSWORDCHAR: UINT = 0x00CC;
const EM_SETMARGINS: UINT = 0x00D3;

const TRANSPARENT: i32 = 1;
const DT_LEFT: UINT = 0x0000;
const DT_CENTER: UINT = 0x0001;
const DT_RIGHT: UINT = 0x0002;
const DT_VCENTER: UINT = 0x0004;
const DT_SINGLELINE: UINT = 0x0020;
const DT_END_ELLIPSIS: UINT = 0x8000;
const VK_CAPITAL: i32 = 0x14;

const MB_OK: UINT = 0x00000000;
const MB_YESNO: UINT = 0x00000004;
const MB_ICONINFORMATION: UINT = 0x00000040;
const MB_ICONWARNING: UINT = 0x00000030;
const MB_ICONERROR: UINT = 0x00000010;
const IDYES: i32 = 6;

const SRCCOPY: DWORD = 0x00CC0020;
const PS_SOLID: i32 = 0;

// Tray & Menu constants
const NIM_ADD: DWORD = 0x00000000;
const NIM_MODIFY: DWORD = 0x00000001;
const NIM_DELETE: DWORD = 0x00000002;
const NIF_MESSAGE: UINT = 0x00000001;
const NIF_ICON: UINT = 0x00000002;
const NIF_TIP: UINT = 0x00000004;
const NIF_INFO: UINT = 0x00000010;
const NIIF_INFO: DWORD = 0x00000001;
const NIIF_WARNING: DWORD = 0x00000002;

const MF_STRING: UINT = 0x00000000;
const MF_GRAYED: UINT = 0x00000003;
const MF_CHECKED: UINT = 0x00000008;
const MF_SEPARATOR: UINT = 0x00000800;
const TPM_RIGHTBUTTON: UINT = 0x0002;
const TPM_RETURNCMD: UINT = 0x0100;
const TPM_NONOTIFY: UINT = 0x0080;

const OFN_FILEMUSTEXIST: DWORD = 0x00001000;
const OFN_PATHMUSTEXIST: DWORD = 0x00000800;
const OFN_NOCHANGEDIR: DWORD = 0x00000008;
const OFN_HIDEREADONLY: DWORD = 0x00000004;

#[repr(C)]
struct ScsiPassThroughDirect {
    length: u16,
    scsi_status: u8,
    path_id: u8,
    target_id: u8,
    lun: u8,
    cdb_length: u8,
    sense_info_length: u8,
    data_in: u8,
    data_transfer_length: u32,
    time_out_value: u32,
    data_buffer: *mut c_void,
    sense_info_offset: u32,
    cdb: [u8; 16],
}

#[repr(C)]
struct ScsiPassThroughDirectWithBuffer {
    sptd: ScsiPassThroughDirect,
    filler: u32,
    sense_buf: [u8; 32],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RECT {
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
}

#[repr(C)]
struct PAINTSTRUCT {
    hdc: HDC,
    f_erase: BOOL,
    rc_paint: RECT,
    f_restore: BOOL,
    f_inc_update: BOOL,
    rgb_reserved: [u8; 32],
}

#[repr(C)]
struct DRAWITEMSTRUCT {
    ctl_type: UINT,
    ctl_id: UINT,
    item_id: UINT,
    item_action: UINT,
    item_state: UINT,
    hwnd_item: HWND,
    hdc: HDC,
    rc_item: RECT,
    item_data: usize,
}

#[repr(C)]
struct WNDCLASSEXW {
    cb_size: UINT,
    style: UINT,
    lpfn_wnd_proc: unsafe extern "system" fn(HWND, UINT, WPARAM, LPARAM) -> LRESULT,
    cb_cls_extra: i32,
    cb_wnd_extra: i32,
    h_instance: HINSTANCE,
    h_icon: HICON,
    h_cursor: HCURSOR,
    hbr_background: HBRUSH,
    lpsz_menu_name: *const u16,
    lpsz_class_name: *const u16,
    h_icon_sm: HICON,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct POINT {
    x: i32,
    y: i32,
}

#[repr(C)]
struct BITMAPINFOHEADER {
    bi_size: DWORD,
    bi_width: i32,
    bi_height: i32,
    bi_planes: u16,
    bi_bit_count: u16,
    bi_compression: DWORD,
    bi_size_image: DWORD,
    bi_x_pels_per_meter: i32,
    bi_y_pels_per_meter: i32,
    bi_clr_used: DWORD,
    bi_clr_important: DWORD,
}

#[repr(C)]
struct BITMAPINFO {
    bmi_header: BITMAPINFOHEADER,
    bmi_colors: [u32; 1],
}

#[repr(C)]
struct MSG {
    hwnd: HWND,
    message: UINT,
    w_param: WPARAM,
    l_param: LPARAM,
    time: DWORD,
    pt: POINT,
}

#[repr(C)]
struct LASTINPUTINFO {
    cb_size: UINT,
    dw_time: DWORD,
}

#[repr(C)]
struct SYSTEMTIME {
    w_year: u16,
    w_month: u16,
    w_day_of_week: u16,
    w_day: u16,
    w_hour: u16,
    w_minute: u16,
    w_second: u16,
    w_milliseconds: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct GUID {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

#[repr(C)]
struct NOTIFYICONDATAW {
    cb_size: DWORD,
    h_wnd: HWND,
    u_id: UINT,
    u_flags: UINT,
    u_callback_message: UINT,
    h_icon: HICON,
    sz_tip: [u16; 128],
    dw_state: DWORD,
    dw_state_mask: DWORD,
    sz_info: [u16; 256],
    u_timeout_or_version: UINT,
    sz_info_title: [u16; 64],
    dw_info_flags: DWORD,
    guid_item: GUID,
    h_balloon_icon: HICON,
}

#[repr(C)]
struct OPENFILENAMEW {
    l_struct_size: DWORD,
    hwnd_owner: HWND,
    h_instance: HINSTANCE,
    lpstr_filter: *const u16,
    lpstr_custom_filter: *mut u16,
    n_max_cust_filter: DWORD,
    n_filter_index: DWORD,
    lpstr_file: *mut u16,
    n_max_file: DWORD,
    lpstr_file_title: *mut u16,
    n_max_file_title: DWORD,
    lpstr_initial_dir: *const u16,
    lpstr_title: *const u16,
    flags: DWORD,
    n_file_offset: u16,
    n_file_extension: u16,
    lpstr_def_ext: *const u16,
    l_cust_data: LPARAM,
    lpfn_hook: *mut c_void,
    lp_template_name: *const u16,
    pv_reserved: *mut c_void,
    dw_reserved: DWORD,
    flags_ex: DWORD,
}

#[link(name = "kernel32")]
extern "system" {
    fn CreateFileW(
        lp_file_name: *const u16,
        dw_desired_access: DWORD,
        dw_share_mode: DWORD,
        lp_security_attributes: *mut c_void,
        dw_creation_disposition: DWORD,
        dw_flags_and_attributes: DWORD,
        h_template_file: HANDLE,
    ) -> HANDLE;
    fn DeviceIoControl(
        h_device: HANDLE,
        dw_io_control_code: DWORD,
        lp_in_buffer: *mut c_void,
        n_in_buffer_size: DWORD,
        lp_out_buffer: *mut c_void,
        n_out_buffer_size: DWORD,
        lp_bytes_returned: *mut DWORD,
        lp_overlapped: *mut c_void,
    ) -> BOOL;
    fn CloseHandle(h_object: HANDLE) -> BOOL;
    fn GetModuleHandleW(lp_module_name: *const u16) -> HINSTANCE;
    fn GetUserDefaultUILanguage() -> u16;
    fn SetFileAttributesW(lp_file_name: *const u16, dw_file_attributes: DWORD) -> BOOL;
    fn SetVolumeLabelW(lp_root_path_name: *const u16, lp_volume_name: *const u16) -> BOOL;
    fn GetVolumeInformationW(
        lp_root_path_name: *const u16,
        lp_volume_name_buffer: *mut u16,
        n_volume_name_size: DWORD,
        lp_volume_serial_number: *mut DWORD,
        lp_maximum_component_length: *mut DWORD,
        lp_file_system_flags: *mut DWORD,
        lp_file_system_name_buffer: *mut u16,
        n_file_system_name_size: DWORD,
    ) -> BOOL;
    fn GetDriveTypeW(lp_root_path_name: *const u16) -> UINT;
    fn GetLogicalDrives() -> DWORD;
    fn GetDiskFreeSpaceExW(
        lp_directory_name: *const u16,
        lp_free_bytes_available: *mut u64,
        lp_total_number_of_bytes: *mut u64,
        lp_total_number_of_free_bytes: *mut u64,
    ) -> BOOL;
    fn GetTickCount() -> DWORD;
    fn GetLocalTime(lp_system_time: *mut SYSTEMTIME);
    fn LoadLibraryW(lp_lib_file_name: *const u16) -> HINSTANCE;
    fn GetProcAddress(h_module: HINSTANCE, lp_proc_name: *const u8) -> *mut c_void;
    fn FindFirstVolumeW(lpsz_volume_name: *mut u16, cch_buffer_length: DWORD) -> HANDLE;
    fn FindNextVolumeW(h_find_volume: HANDLE, lpsz_volume_name: *mut u16, cch_buffer_length: DWORD) -> BOOL;
    fn FindVolumeClose(h_find_volume: HANDLE) -> BOOL;
    fn GetVolumePathNamesForVolumeNameW(
        lpsz_volume_name: *const u16,
        lpsz_volume_path_names: *mut u16,
        cch_buffer_length: DWORD,
        lpcch_return_length: *mut DWORD,
    ) -> BOOL;
    fn SetVolumeMountPointW(
        lpsz_volume_mount_point: *const u16,
        lpsz_volume_name: *const u16,
    ) -> BOOL;
    fn DeleteVolumeMountPointW(lpsz_volume_mount_point: *const u16) -> BOOL;
    fn FlushFileBuffers(h_file: HANDLE) -> BOOL;
}

#[link(name = "user32")]
extern "system" {
    fn FindWindowW(lp_class_name: *const u16, lp_window_name: *const u16) -> HWND;
    fn GetKeyState(n_virt_key: i32) -> i16;
    fn RegisterClassExW(lpwcx: *const WNDCLASSEXW) -> ATOM;
    fn CreateWindowExW(
        dw_ex_style: DWORD,
        lp_class_name: *const u16,
        lp_window_name: *const u16,
        dw_style: DWORD,
        x: i32,
        y: i32,
        n_width: i32,
        n_height: i32,
        h_wnd_parent: HWND,
        h_menu: HMENU,
        h_instance: HINSTANCE,
        lp_param: *mut c_void,
    ) -> HWND;
    fn MoveWindow(h_wnd: HWND, x: i32, y: i32, n_width: i32, n_height: i32, b_repaint: BOOL) -> BOOL;
    fn SetWindowPos(h_wnd: HWND, h_wnd_insert_after: HWND, x: i32, y: i32, cx: i32, cy: i32, u_flags: UINT) -> BOOL;
    fn ShowWindow(h_wnd: HWND, n_cmd_show: i32) -> BOOL;
    fn UpdateWindow(h_wnd: HWND) -> BOOL;
    fn GetMessageW(lp_msg: *mut MSG, h_wnd: HWND, w_msg_filter_min: UINT, w_msg_filter_max: UINT) -> BOOL;
    fn TranslateMessage(lp_msg: *const MSG) -> BOOL;
    fn DispatchMessageW(lp_msg: *const MSG) -> LRESULT;
    fn IsDialogMessageW(h_dlg: HWND, lp_msg: *mut MSG) -> BOOL;
    fn DefWindowProcW(h_wnd: HWND, msg: UINT, w_param: WPARAM, l_param: LPARAM) -> LRESULT;
    fn PostQuitMessage(n_exit_code: i32);
    fn DestroyWindow(h_wnd: HWND) -> BOOL;
    fn SendMessageW(h_wnd: HWND, msg: UINT, w_param: WPARAM, l_param: LPARAM) -> LRESULT;
    fn SetWindowTextW(h_wnd: HWND, lp_string: *const u16) -> BOOL;
    fn GetWindowTextW(h_wnd: HWND, lp_string: *mut u16, n_max_count: i32) -> i32;
    fn EnableWindow(h_wnd: HWND, b_enable: BOOL) -> BOOL;
    fn IsWindowEnabled(h_wnd: HWND) -> BOOL;
    fn IsWindowVisible(h_wnd: HWND) -> BOOL;
    fn InvalidateRect(h_wnd: HWND, lp_rect: *const RECT, b_erase: BOOL) -> BOOL;
    fn GetClientRect(h_wnd: HWND, lp_rect: *mut RECT) -> BOOL;
    fn GetWindowRect(h_wnd: HWND, lp_rect: *mut RECT) -> BOOL;
    fn AdjustWindowRectEx(lp_rect: *mut RECT, dw_style: DWORD, b_menu: BOOL, dw_ex_style: DWORD) -> BOOL;
    fn BeginPaint(h_wnd: HWND, lp_paint: *mut PAINTSTRUCT) -> HDC;
    fn EndPaint(h_wnd: HWND, lp_paint: *const PAINTSTRUCT) -> BOOL;
    fn FillRect(h_dc: HDC, lprc: *const RECT, hbr: HBRUSH) -> i32;
    fn DrawTextW(h_dc: HDC, lpch_text: *const u16, cch_text: i32, lprc: *mut RECT, format: UINT) -> i32;
    fn MessageBoxW(h_wnd: HWND, lp_text: *const u16, lp_caption: *const u16, u_type: UINT) -> i32;
    fn LoadIconW(h_instance: HINSTANCE, lp_icon_name: *const u16) -> HICON;
    fn LoadCursorW(h_instance: HINSTANCE, lp_cursor_name: *const u16) -> HCURSOR;
    fn DrawIconEx(
        hdc: HDC,
        x_left: i32,
        y_top: i32,
        h_icon: HICON,
        cx_width: i32,
        cy_width: i32,
        istep_if_ani_cur: UINT,
        hbr_flicker_free_draw: HBRUSH,
        di_flags: UINT,
    ) -> BOOL;
    fn GetSystemMetrics(n_index: i32) -> i32;
    fn SetFocus(h_wnd: HWND) -> HWND;
    fn GetFocus() -> HWND;
    fn GetDC(h_wnd: HWND) -> HDC;
    fn ReleaseDC(h_wnd: HWND, h_dc: HDC) -> i32;
    fn SetTimer(h_wnd: HWND, n_id_event: usize, u_elapse: UINT, lp_timer_func: *mut c_void) -> usize;
    fn KillTimer(h_wnd: HWND, u_id_event: usize) -> BOOL;
    fn GetLastInputInfo(plii: *mut LASTINPUTINFO) -> BOOL;
    fn CreatePopupMenu() -> HMENU;
    fn AppendMenuW(h_menu: HMENU, u_flags: UINT, u_id_new_item: usize, lp_new_item: *const u16) -> BOOL;
    fn TrackPopupMenu(h_menu: HMENU, u_flags: UINT, x: i32, y: i32, n_reserved: i32, h_wnd: HWND, prc_rect: *const RECT) -> BOOL;
    fn DestroyMenu(h_menu: HMENU) -> BOOL;
    fn GetCursorPos(lp_point: *mut POINT) -> BOOL;
    fn ScreenToClient(h_wnd: HWND, lp_point: *mut POINT) -> BOOL;
    fn SetForegroundWindow(h_wnd: HWND) -> BOOL;
    fn SetLayeredWindowAttributes(h_wnd: HWND, cr_key: COLORREF, b_alpha: u8, dw_flags: DWORD) -> BOOL;
}

#[link(name = "gdi32")]
extern "system" {
    fn CreateFontW(
        c_height: i32,
        c_width: i32,
        c_escapement: i32,
        c_orientation: i32,
        c_weight: i32,
        b_italic: DWORD,
        b_underline: DWORD,
        b_strike_out: DWORD,
        i_char_set: DWORD,
        i_out_precision: DWORD,
        i_clip_precision: DWORD,
        i_quality: DWORD,
        i_pitch_and_family: DWORD,
        psz_face_name: *const u16,
    ) -> HFONT;
    fn CreateSolidBrush(color: COLORREF) -> HBRUSH;
    fn CreatePen(i_style: i32, c_width: i32, color: COLORREF) -> HPEN;
    fn RoundRect(hdc: HDC, left: i32, top: i32, right: i32, bottom: i32, width: i32, height: i32) -> BOOL;
    fn Ellipse(hdc: HDC, left: i32, top: i32, right: i32, bottom: i32) -> BOOL;
    fn Pie(hdc: HDC, left: i32, top: i32, right: i32, bottom: i32, xr1: i32, yr1: i32, xr2: i32, yr2: i32) -> BOOL;
    fn MoveToEx(hdc: HDC, x: i32, y: i32, lppt: *mut POINT) -> BOOL;
    fn LineTo(hdc: HDC, x: i32, y: i32) -> BOOL;
    fn DeleteObject(ho: HGDIOBJ) -> BOOL;
    fn SelectObject(hdc: HDC, h: HGDIOBJ) -> HGDIOBJ;
    fn SetBkMode(hdc: HDC, mode: i32) -> i32;
    fn SetBkColor(hdc: HDC, color: COLORREF) -> COLORREF;
    fn SetTextColor(hdc: HDC, color: COLORREF) -> COLORREF;
    fn GetStockObject(i: i32) -> HGDIOBJ;
    fn CreateCompatibleDC(hdc: HDC) -> HDC;
    fn CreateCompatibleBitmap(hdc: HDC, cx: i32, cy: i32) -> HBITMAP;
    fn BitBlt(hdc: HDC, x: i32, y: i32, cx: i32, cy: i32, hdc_src: HDC, x1: i32, y1: i32, rop: DWORD) -> BOOL;
    fn StretchDIBits(
        hdc: HDC,
        x_dest: i32,
        y_dest: i32,
        dest_width: i32,
        dest_height: i32,
        x_src: i32,
        y_src: i32,
        src_width: i32,
        src_height: i32,
        lp_bits: *const c_void,
        lpbmi: *const BITMAPINFO,
        i_usage: UINT,
        rop: DWORD,
    ) -> i32;
    fn DeleteDC(hdc: HDC) -> BOOL;
    fn GetDeviceCaps(hdc: HDC, index: i32) -> i32;
}

#[link(name = "advapi32")]
extern "system" {
    fn RegGetValueW(
        hkey: HANDLE,
        lp_sub_key: *const u16,
        lp_value: *const u16,
        dw_flags: DWORD,
        pdw_type: *mut DWORD,
        pv_data: *mut c_void,
        pcb_data: *mut DWORD,
    ) -> i32;
}

#[link(name = "shell32")]
extern "system" {
    fn Shell_NotifyIconW(dw_message: DWORD, lp_data: *mut NOTIFYICONDATAW) -> BOOL;
    fn SHChangeNotify(w_event_id: i32, u_flags: UINT, dw_item1: *const c_void, dw_item2: *const c_void);
}

#[link(name = "comdlg32")]
extern "system" {
    fn GetOpenFileNameW(lpofn: *mut OPENFILENAMEW) -> BOOL;
}

const fn rgb(r: u8, g: u8, b: u8) -> COLORREF {
    (r as u32) | ((g as u32) << 8) | ((b as u32) << 16)
}

fn to_wide(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}

fn copy_to_wide_fixed(dst: &mut [u16], src: &str) {
    for x in dst.iter_mut() {
        *x = 0;
    }
    for (i, ch) in src.encode_utf16().take(dst.len().saturating_sub(1)).enumerate() {
        dst[i] = ch;
    }
}

fn get_now_timestamp_str() -> String {
    unsafe {
        let mut st: SYSTEMTIME = std::mem::zeroed();
        GetLocalTime(&mut st);
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            st.w_year, st.w_month, st.w_day, st.w_hour, st.w_minute, st.w_second
        )
    }
}

fn get_idle_seconds() -> u32 {
    unsafe {
        let mut lii = LASTINPUTINFO {
            cb_size: std::mem::size_of::<LASTINPUTINFO>() as UINT,
            dw_time: 0,
        };
        if GetLastInputInfo(&mut lii) != 0 {
            let now = GetTickCount();
            now.wrapping_sub(lii.dw_time) / 1000
        } else {
            0
        }
    }
}

// ============================================================================
// Multi-Language Support (KO / EN / JA)
// ============================================================================
#[derive(Clone, Copy, PartialEq, Eq)]
enum AppLang {
    KO = 0,
    EN = 1,
    JA = 2,
}

static mut CURRENT_LANG: AppLang = AppLang::KO;

fn detect_default_lang() -> AppLang {
    unsafe {
        let lang_id = GetUserDefaultUILanguage() & 0xFF;
        if lang_id == 0x11 {
            AppLang::JA
        } else if lang_id == 0x09 {
            AppLang::EN
        } else {
            AppLang::KO
        }
    }
}

fn tr<'a>(ko: &'a str, en: &'a str, ja: &'a str) -> &'a str {
    unsafe {
        match CURRENT_LANG {
            AppLang::KO => ko,
            AppLang::EN => en,
            AppLang::JA => ja,
        }
    }
}

// ============================================================================
// Hardware SCSI & Vault Logic (with Intrusion Audit & Disk Space Usage)
// ============================================================================
#[derive(Clone)]
struct DeviceInfo {
    drive_letter: String,
    vendor: String,
    product: String,
    flash_id: [u8; 6],
    lun_sectors: [u32; 4],
    lun_flags: [u8; 4],
    has_security_lun: bool,
    challenge_token: u8,
    retry_remain: u8,
    retry_limit: u8,
    is_unlocked: bool,
    status_code: u8,
    password_hint: String,
    security_drive_letter: Option<String>,
    effective_hint: String,
    effective_retry_remain: i32,
    effective_retry_limit: i32,
    sec_used_bytes: u64,
    sec_free_bytes: u64,
    sec_total_bytes: u64,
    last_intrusion_count: i32,
    last_intrusion_time: String,
    vault_idle_mins: Option<u32>,
    vault_dark_mode: Option<bool>,
}

impl DeviceInfo {
    fn lun_gb(&self, idx: usize) -> f64 {
        (self.lun_sectors[idx] as f64 * 512.0) / 1073741824.0
    }
    fn total_gb(&self) -> f64 {
        let mut s = 0u64;
        for &sec in &self.lun_sectors {
            s += sec as u64;
        }
        (s as f64 * 512.0) / 1073741824.0
    }
    fn display_title(&self) -> String {
        let st = if !self.has_security_lun {
            tr("일반 단일 파티션", "Public Partition Only", "通常単一パーティション")
        } else if self.is_unlocked {
            tr("잠금 해제됨 (Unlocked)", "Unlocked", "ロック解除済")
        } else {
            tr("잠김 (Locked)", "Locked", "ロック中")
        };
        format!("[{}] {} {} ({:.1} GB) — {}", self.drive_letter, self.vendor, self.product, self.total_gb(), st)
    }
}

#[derive(Clone)]
struct VaultConfig {
    salt_hex: String,
    hash_hex: String,
    hint: String,
    max_retries: i32,
    fail_count: i32,
    last_fail_time: String,
    idle_lock_mins: u32,
    dark_mode: Option<bool>,
}

const VAULT_FILENAME: &str = ".is918_vault.cfg";
const HARDWARE_MASTER_KEYS: [&str; 4] = ["sptdnjzmdls1!", "1234", "0000", "admin"];
const EMBEDDED_LOGO_ICO: &[u8] = include_bytes!("../../secure_vault_drive.ico");
const EMBEDDED_AUTORUN_INF: &[u8] = b"[autorun]\r\nicon=logo.ico\r\nlabel=Secure USB\r\n";

fn restore_security_autorun_and_icon(sec_drv: &str, force: bool) -> bool {
    if !is_drive_ready(sec_drv) {
        return false;
    }
    let root_str = format!("{}\\", sec_drv);
    let root = Path::new(&root_str);
    let ico_path = root.join("logo.ico");
    let inf_path = root.join("autorun.inf");
    let need_restore = force || !ico_path.exists() || !inf_path.exists();

    if need_restore {
        let wroot = to_wide(&root_str);
        let wlabel = to_wide("Secure USB");
        unsafe {
            SetVolumeLabelW(wroot.as_ptr(), wlabel.as_ptr());
        }
    }

    let wico = to_wide(&ico_path.to_string_lossy());
    if force || !ico_path.exists() {
        unsafe {
            SetFileAttributesW(wico.as_ptr(), FILE_ATTRIBUTE_NORMAL);
        }
        let _ = fs::write(&ico_path, EMBEDDED_LOGO_ICO);
    }
    if ico_path.exists() {
        unsafe {
            SetFileAttributesW(wico.as_ptr(), FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN);
        }
    }

    let winf = to_wide(&inf_path.to_string_lossy());
    if force || !inf_path.exists() {
        unsafe {
            SetFileAttributesW(winf.as_ptr(), FILE_ATTRIBUTE_NORMAL);
        }
        let _ = fs::write(&inf_path, EMBEDDED_AUTORUN_INF);
    }
    if inf_path.exists() {
        unsafe {
            SetFileAttributesW(winf.as_ptr(), FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN);
        }
    }

    ico_path.exists() && inf_path.exists()
}

fn compute_vault_hash(password: &str, salt_hex: &str) -> String {
    let input = format!("{}:{}:IS918_VAULT_V1", salt_hex, password);
    sha256_hex(input.as_bytes())
}

fn get_local_vault_path(dev: &DeviceInfo) -> PathBuf {
    let fid = format!(
        "{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        dev.flash_id[0], dev.flash_id[1], dev.flash_id[2], dev.flash_id[3], dev.flash_id[4], dev.flash_id[5]
    );
    let appdata = env::var("APPDATA").unwrap_or_else(|_| ".".to_string());
    let dir = Path::new(&appdata).join("IS918SecurityManager");
    let _ = fs::create_dir_all(&dir);
    dir.join(format!("vault_{}.cfg", fid))
}

fn get_app_prefs_path() -> PathBuf {
    let appdata = env::var("APPDATA").unwrap_or_else(|_| ".".to_string());
    let dir = Path::new(&appdata).join("IS918SecurityManager");
    let _ = fs::create_dir_all(&dir);
    dir.join("ui_prefs.cfg")
}

fn detect_system_dark_mode() -> bool {
    unsafe {
        let hkey_cu = 0x80000001usize as HANDLE;
        let subkey = to_wide("Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize");
        let val_name = to_wide("AppsUseLightTheme");
        let mut data: DWORD = 1;
        let mut size: DWORD = std::mem::size_of::<DWORD>() as DWORD;
        let mut rtype: DWORD = 0;
        let status = RegGetValueW(
            hkey_cu,
            subkey.as_ptr(),
            val_name.as_ptr(),
            0x00000010, // RRF_RT_REG_DWORD
            &mut rtype,
            &mut data as *mut _ as *mut c_void,
            &mut size,
        );
        status == 0 && data == 0
    }
}

fn apply_window_dark_titlebar(hwnd: HWND, dark: bool) {
    unsafe {
        type DwmSetWindowAttributeFn = unsafe extern "system" fn(HWND, DWORD, *const c_void, DWORD) -> i32;
        let dwm_name = to_wide("dwmapi.dll");
        let h_mod = LoadLibraryW(dwm_name.as_ptr());
        if !h_mod.is_null() {
            let fn_ptr = GetProcAddress(h_mod, b"DwmSetWindowAttribute\0".as_ptr());
            if !fn_ptr.is_null() {
                let f: DwmSetWindowAttributeFn = std::mem::transmute(fn_ptr);
                let val: BOOL = if dark { 1 } else { 0 };
                let _ = f(hwnd, 20, &val as *const _ as *const c_void, 4);
                let _ = f(hwnd, 19, &val as *const _ as *const c_void, 4);
                // Windows 11 native rounded corners (DWMWA_WINDOW_CORNER_PREFERENCE = 33, DWMWCP_ROUND = 2)
                let corner_pref: DWORD = 2;
                let _ = f(hwnd, 33, &corner_pref as *const _ as *const c_void, 4);
                // Windows 11 Fluent Mica Backdrop (DWMWA_SYSTEMBACKDROP_TYPE = 38, DWMSBT_MAINWINDOW = 2)
                let backdrop_type: DWORD = 2;
                let _ = f(hwnd, 38, &backdrop_type as *const _ as *const c_void, 4);
                // Seamless dark/light titlebar caption color (DWMWA_CAPTION_COLOR = 35)
                let cap_col: COLORREF = if dark { rgb(32, 32, 32) } else { rgb(243, 243, 243) };
                let _ = f(hwnd, 35, &cap_col as *const _ as *const c_void, 4);
            }
        }
    }
}

fn load_app_prefs() -> (Option<AppLang>, u32, Option<bool>) {
    let p = get_app_prefs_path();
    let mut lang: Option<AppLang> = None;
    let mut idle_mins: u32 = 10;
    let mut dark_mode: Option<bool> = None;
    if let Ok(txt) = fs::read_to_string(&p) {
        for line in txt.lines() {
            if let Some(idx) = line.find('=') {
                let k = line[..idx].trim();
                let v = line[idx + 1..].trim();
                match k {
                    "Lang" => {
                        lang = match v {
                            "EN" => Some(AppLang::EN),
                            "JA" => Some(AppLang::JA),
                            "KO" => Some(AppLang::KO),
                            _ => None,
                        };
                    }
                    "IdleLockMinutes" => {
                        if let Ok(m) = v.parse::<u32>() {
                            if IDLE_TIMEOUT_MINS.contains(&m) {
                                idle_mins = m;
                            }
                        }
                    }
                    "Theme" => {
                        dark_mode = match v {
                            "Dark" | "1" | "true" => Some(true),
                            "Light" | "0" | "false" => Some(false),
                            _ => None,
                        };
                    }
                    _ => {}
                }
            }
        }
    }
    (lang, idle_mins, dark_mode)
}

fn save_app_prefs(lang: AppLang, idle_mins: u32, dark_mode: bool) {
    let l_str = match lang {
        AppLang::KO => "KO",
        AppLang::EN => "EN",
        AppLang::JA => "JA",
    };
    let t_str = if dark_mode { "Dark" } else { "Light" };
    let content = format!("Lang={}\r\nIdleLockMinutes={}\r\nTheme={}\r\n", l_str, idle_mins, t_str);
    let _ = fs::write(get_app_prefs_path(), content.as_bytes());
}

fn query_drive_space(drv: &str) -> Option<(u64, u64, u64)> {
    let root = to_wide(&format!("{}\\", drv));
    let mut free_avail = 0u64;
    let mut total_bytes = 0u64;
    let mut total_free = 0u64;
    unsafe {
        if GetDiskFreeSpaceExW(root.as_ptr(), &mut free_avail, &mut total_bytes, &mut total_free) != 0 && total_bytes > 0 {
            let used = total_bytes.saturating_sub(total_free);
            Some((used, total_free, total_bytes))
        } else {
            None
        }
    }
}

fn is_drive_ready(drv: &str) -> bool {
    query_drive_space(drv).is_some()
}

fn load_vault(sec_drv: Option<&str>, dev: &DeviceInfo) -> Option<VaultConfig> {
    let mut paths = Vec::new();
    if let Some(d) = sec_drv {
        if is_drive_ready(d) {
            paths.push(Path::new(&format!("{}\\", d)).join(VAULT_FILENAME));
        }
    }
    paths.push(get_local_vault_path(dev));

    for p in paths {
        if let Ok(text) = fs::read_to_string(&p) {
            let mut cfg = VaultConfig {
                salt_hex: String::new(),
                hash_hex: String::new(),
                hint: "Admin Inquiry".to_string(),
                max_retries: 10,
                fail_count: 0,
                last_fail_time: String::new(),
                idle_lock_mins: 10,
                dark_mode: None,
            };
            for line in text.lines() {
                if let Some(idx) = line.find('=') {
                    let k = line[..idx].trim();
                    let v = line[idx + 1..].trim();
                    match k {
                        "Salt" => cfg.salt_hex = v.to_string(),
                        "Hash" => cfg.hash_hex = v.to_string(),
                        "Hint" => cfg.hint = v.to_string(),
                        "MaxRetries" => cfg.max_retries = v.parse().unwrap_or(10),
                        "FailCount" => cfg.fail_count = v.parse().unwrap_or(0),
                        "LastFailTime" => cfg.last_fail_time = v.to_string(),
                        "IdleLockMinutes" => {
                            if let Ok(m) = v.parse::<u32>() {
                                if IDLE_TIMEOUT_MINS.contains(&m) {
                                    cfg.idle_lock_mins = m;
                                }
                            }
                        }
                        "Theme" => {
                            cfg.dark_mode = match v {
                                "Dark" | "1" | "true" => Some(true),
                                "Light" | "0" | "false" => Some(false),
                                _ => None,
                            };
                        }
                        _ => {}
                    }
                }
            }
            if !cfg.salt_hex.is_empty() && !cfg.hash_hex.is_empty() {
                return Some(cfg);
            }
        }
    }
    None
}

fn save_vault(sec_drv: Option<&str>, dev: &DeviceInfo, cfg: &VaultConfig) -> bool {
    let theme_line = match cfg.dark_mode {
        Some(true) => "Theme=Dark\r\n",
        Some(false) => "Theme=Light\r\n",
        None => "",
    };
    let content = format!(
        "Salt={}\r\nHash={}\r\nHint={}\r\nMaxRetries={}\r\nFailCount={}\r\nLastFailTime={}\r\nIdleLockMinutes={}\r\n{}",
        cfg.salt_hex, cfg.hash_hex, cfg.hint, cfg.max_retries, cfg.fail_count, cfg.last_fail_time, cfg.idle_lock_mins, theme_line
    );
    let mut saved = false;

    if let Some(d) = sec_drv {
        if is_drive_ready(d) {
            let usb_path = Path::new(&format!("{}\\", d)).join(VAULT_FILENAME);
            let wpath = to_wide(&usb_path.to_string_lossy());
            unsafe {
                SetFileAttributesW(wpath.as_ptr(), FILE_ATTRIBUTE_NORMAL);
            }
            if fs::write(&usb_path, content.as_bytes()).is_ok() {
                unsafe {
                    SetFileAttributesW(wpath.as_ptr(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
                }
                saved = true;
            }
        }
    }

    let local_path = get_local_vault_path(dev);
    if fs::write(&local_path, content.as_bytes()).is_ok() {
        saved = true;
    }
    saved
}

fn create_new_vault(new_password: &str, new_hint: &str, max_retries: i32, idle_mins: u32, dark_mode: Option<bool>) -> VaultConfig {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0x123456789ABCDEF0);
    let salt_hex = sha256_hex(format!("SALT_SEED_{}", nanos).as_bytes())[..32].to_string();
    let hash_hex = compute_vault_hash(new_password, &salt_hex);
    VaultConfig {
        salt_hex,
        hash_hex,
        hint: if new_hint.is_empty() { "-".to_string() } else { new_hint.to_string() },
        max_retries: if max_retries > 0 { max_retries } else { 10 },
        fail_count: 0,
        last_fail_time: String::new(),
        idle_lock_mins: if IDLE_TIMEOUT_MINS.contains(&idle_mins) { idle_mins } else { 10 },
        dark_mode,
    }
}

#[repr(align(64))]
struct AlignedScsiBuf([u8; 4096]);

fn execute_scsi(h_dev: HANDLE, cdb: &[u8], direction: u8, buffer: &mut [u8]) -> bool {
    let mut aligned = AlignedScsiBuf([0u8; 4096]);
    let use_aligned = !buffer.is_empty() && buffer.len() <= 4096;
    if use_aligned && direction == SCSI_IOCTL_DATA_OUT {
        aligned.0[..buffer.len()].copy_from_slice(buffer);
    }
    let data_ptr = if buffer.is_empty() {
        null_mut()
    } else if use_aligned {
        aligned.0.as_mut_ptr() as *mut c_void
    } else {
        buffer.as_mut_ptr() as *mut c_void
    };

    let mut swb = ScsiPassThroughDirectWithBuffer {
        sptd: ScsiPassThroughDirect {
            length: std::mem::size_of::<ScsiPassThroughDirect>() as u16,
            scsi_status: 0,
            path_id: 0,
            target_id: 0,
            lun: 0,
            cdb_length: cdb.len() as u8,
            sense_info_length: 18,
            data_in: direction,
            data_transfer_length: buffer.len() as u32,
            time_out_value: 10,
            data_buffer: data_ptr,
            sense_info_offset: std::mem::size_of::<ScsiPassThroughDirect>() as u32 + 4,
            cdb: [0u8; 16],
        },
        filler: 0,
        sense_buf: [0u8; 32],
    };

    for (i, &b) in cdb.iter().take(16).enumerate() {
        swb.sptd.cdb[i] = b;
    }

    let mut returned: DWORD = 0;
    let ok = unsafe {
        DeviceIoControl(
            h_dev,
            IOCTL_SCSI_PASS_THROUGH_DIRECT,
            &mut swb as *mut _ as *mut c_void,
            std::mem::size_of::<ScsiPassThroughDirectWithBuffer>() as DWORD,
            &mut swb as *mut _ as *mut c_void,
            std::mem::size_of::<ScsiPassThroughDirectWithBuffer>() as DWORD,
            &mut returned,
            null_mut(),
        )
    };
    let success = ok != 0 && swb.sptd.scsi_status == 0;
    if success && use_aligned && direction == SCSI_IOCTL_DATA_IN {
        buffer.copy_from_slice(&aligned.0[..buffer.len()]);
    }
    success
}

fn encrypt_password_tea(password: &str, dynamic_token: u8) -> [u8; 32] {
    let mut plain32 = [0u8; 32];
    let pwd_bytes = password.as_bytes();
    let copy_len = pwd_bytes.len().min(16);
    plain32[..copy_len].copy_from_slice(&pwd_bytes[..copy_len]);

    let seed = (dynamic_token as u32).wrapping_add(0x266EC300);
    let key: [u32; 4] = [seed, 0x36D9C77D, 0xE48D5124, 0xAD7275C8];

    let mut cipher32 = [0u8; 32];
    for blk in 0..4 {
        let off = blk * 8;
        let mut v0 = u32::from_be_bytes([plain32[off], plain32[off + 1], plain32[off + 2], plain32[off + 3]]);
        let mut v1 = u32::from_be_bytes([plain32[off + 4], plain32[off + 5], plain32[off + 6], plain32[off + 7]]);
        let mut sum = 0u32;
        for _ in 0..32 {
            sum = sum.wrapping_sub(0x61C88647);
            let t0 = ((v1 >> 5).wrapping_add(key[1])) ^ ((v1 << 4).wrapping_add(key[0])) ^ (sum.wrapping_add(v1));
            v0 = v0.wrapping_add(t0);
            let t1 = ((v0 >> 5).wrapping_add(key[3])) ^ ((v0 << 4).wrapping_add(key[2])) ^ (sum.wrapping_add(v0));
            v1 = v1.wrapping_add(t1);
        }
        cipher32[off..off + 4].copy_from_slice(&v0.to_be_bytes());
        cipher32[off + 4..off + 8].copy_from_slice(&v1.to_be_bytes());
    }
    cipher32
}

fn open_drive_handle(drive_letter: &str) -> HANDLE {
    let path = to_wide(&format!("\\\\.\\{}", drive_letter));
    let share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    unsafe {
        let mut h = CreateFileW(
            path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            share,
            null_mut(),
            OPEN_EXISTING,
            0,
            null_mut(),
        );
        if h == INVALID_HANDLE_VALUE {
            h = CreateFileW(
                path.as_ptr(),
                GENERIC_READ,
                share,
                null_mut(),
                OPEN_EXISTING,
                0,
                null_mut(),
            );
        }
        if h == INVALID_HANDLE_VALUE {
            h = CreateFileW(
                path.as_ptr(),
                0,
                share,
                null_mut(),
                OPEN_EXISTING,
                0,
                null_mut(),
            );
        }
        h
    }
}

fn refresh_security_status(h_dev: HANDLE, dev: &mut DeviceInfo) -> bool {
    let mut sec_buf = [0u8; 0x30];
    let cdb = [0xE0, 0x32, 0, 0, 0, 0, 0, 1, 6, 0];
    if !execute_scsi(h_dev, &cdb, SCSI_IOCTL_DATA_IN, &mut sec_buf) {
        return false;
    }
    dev.challenge_token = sec_buf[0];
    dev.retry_remain = sec_buf[1];
    dev.retry_limit = if sec_buf[15] > 0 { sec_buf[15] } else { sec_buf[1] };
    dev.is_unlocked = (sec_buf[2] & 0x01) == 0x01;
    dev.status_code = sec_buf[4];

    let mut hint_len = 0;
    while hint_len < 16 && sec_buf[32 + hint_len] != 0 {
        hint_len += 1;
    }
    dev.password_hint = if hint_len > 0 {
        String::from_utf8_lossy(&sec_buf[32..32 + hint_len]).to_string()
    } else {
        "-".to_string()
    };
    true
}

fn query_volume_label(drv: &str) -> String {
    let root = to_wide(&format!("{}\\", drv));
    let mut vol_name = [0u16; 64];
    let ok = unsafe {
        GetVolumeInformationW(
            root.as_ptr(),
            vol_name.as_mut_ptr(),
            vol_name.len() as DWORD,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            0,
        )
    };
    if ok != 0 {
        let len = vol_name.iter().position(|&c| c == 0).unwrap_or(vol_name.len());
        String::from_utf16_lossy(&vol_name[..len]).trim().to_string()
    } else {
        String::new()
    }
}

fn drive_type_of(drv: &str) -> UINT {
    let root = to_wide(&format!("{}\\", drv));
    unsafe { GetDriveTypeW(root.as_ptr()) }
}

fn query_drive(drive_letter: &str) -> Option<DeviceInfo> {
    let h_dev = open_drive_handle(drive_letter);
    if h_dev == INVALID_HANDLE_VALUE {
        return None;
    }

    // Standard 6-byte SCSI INQUIRY (CDB6) first, with fallback to 10-byte and 36-byte INQUIRY
    // so strict UASP / USB 3.0 xHCI filter drivers never reject opcode 0x12 due to CDB length.
    let mut inq = [0u8; 0x60];
    let inq_ok = execute_scsi(h_dev, &[0x12, 0, 0, 0, 0x60, 0], SCSI_IOCTL_DATA_IN, &mut inq)
        || execute_scsi(h_dev, &[0x12, 0, 0, 0, 0x60, 0, 0, 0, 0, 0], SCSI_IOCTL_DATA_IN, &mut inq)
        || execute_scsi(h_dev, &[0x12, 0, 0, 0, 0x24, 0], SCSI_IOCTL_DATA_IN, &mut inq[..0x24]);
    if !inq_ok {
        unsafe { CloseHandle(h_dev); }
        return None;
    }

    let has_bwse = &inq[40..44] == b"BWSE";

    let mut flash_id = [0u8; 6];
    let mut fid_buf = [0u8; 512];
    let fid_ok = execute_scsi(h_dev, &[0xE0, 0x10, 0x06, 0x90, 0x00, 0x0E, 0, 0, 0, 0], SCSI_IOCTL_DATA_IN, &mut fid_buf);
    if fid_ok {
        flash_id.copy_from_slice(&fid_buf[0..6]);
    }

    let mut lun_sectors = [0u32; 4];
    let mut lun_flags = [0u8; 4];
    let mut has_security_lun = false;
    let mut part_buf = [0u8; 512];
    let part_ok = execute_scsi(h_dev, &[0xE0, 0x30, 0, 0, 0, 0, 0, 0, 1, 0], SCSI_IOCTL_DATA_IN, &mut part_buf);
    if part_ok {
        for i in 0..4 {
            let off = 0x10 + i * 4;
            lun_sectors[i] = u32::from_be_bytes([part_buf[off], part_buf[off + 1], part_buf[off + 2], part_buf[off + 3]]);
            lun_flags[i] = part_buf[0x30 + i];
            if lun_sectors[i] > 0 && ((lun_flags[i] & 0x40) != 0 || (lun_flags[i] & 0x80) != 0) {
                has_security_lun = true;
            }
        }
        if lun_sectors[1] > 0 {
            has_security_lun = true;
        }
    }

    let vendor = String::from_utf8_lossy(&inq[8..16]).trim().to_string();
    let product = String::from_utf8_lossy(&inq[16..32]).trim().to_string();

    let mut dev = DeviceInfo {
        drive_letter: drive_letter.to_string(),
        vendor,
        product,
        flash_id,
        lun_sectors,
        lun_flags,
        has_security_lun,
        challenge_token: 0,
        retry_remain: 10,
        retry_limit: 10,
        is_unlocked: false,
        status_code: 0,
        password_hint: "-".to_string(),
        security_drive_letter: None,
        effective_hint: "-".to_string(),
        effective_retry_remain: 10,
        effective_retry_limit: 10,
        sec_used_bytes: 0,
        sec_free_bytes: 0,
        sec_total_bytes: 0,
        last_intrusion_count: 0,
        last_intrusion_time: String::new(),
        vault_idle_mins: None,
        vault_dark_mode: None,
    };

    let sec_ok = refresh_security_status(h_dev, &mut dev);
    unsafe { CloseHandle(h_dev); }

    // Accept the drive if it has the "BWSE" Innostor signature OR responds to Innostor vendor commands (0xE0 0x30 / 0xE0 0x32)
    let valid_part = part_ok && (dev.lun_sectors[0] > 0 || dev.lun_sectors[1] > 0) && dev.lun_sectors[0] < 0x7FFF_FFFF;
    let valid_sec = sec_ok && dev.retry_limit > 0 && dev.retry_limit <= 32;
    if !has_bwse && !valid_part && !valid_sec {
        return None;
    }

    if dev.lun_sectors[1] > 0
        || (sec_ok && (dev.retry_limit > 0 || dev.retry_remain > 0))
        || drive_type_of(drive_letter) == 5
    {
        dev.has_security_lun = true;
    }

    Some(dev)
}

fn update_effective_vault_metadata(dev: &mut DeviceInfo) {
    if let Some(v) = load_vault(dev.security_drive_letter.as_deref(), dev) {
        dev.effective_hint = v.hint;
        dev.effective_retry_limit = v.max_retries;
        dev.effective_retry_remain = (v.max_retries - v.fail_count).max(0);
        dev.vault_idle_mins = Some(v.idle_lock_mins);
        dev.vault_dark_mode = v.dark_mode;
        if v.fail_count > 0 {
            dev.last_intrusion_count = v.fail_count;
            dev.last_intrusion_time = v.last_fail_time;
        }
    } else {
        dev.effective_hint = dev.password_hint.clone();
        dev.effective_retry_limit = dev.retry_limit as i32;
        dev.effective_retry_remain = dev.retry_remain as i32;
    }

    dev.sec_used_bytes = 0;
    dev.sec_free_bytes = 0;
    dev.sec_total_bytes = 0;
    if dev.is_unlocked {
        if let Some(ref sd) = dev.security_drive_letter {
            if let Some((u, f, t)) = query_drive_space(sd) {
                dev.sec_used_bytes = u;
                dev.sec_free_bytes = f;
                dev.sec_total_bytes = t;
            }
            // Automatically restore autorun.inf & logo.ico if the security partition was formatted
            let _ = restore_security_autorun_and_icon(sd, false);
            let usb_vault_path = Path::new(&format!("{}\\", sd)).join(VAULT_FILENAME);
            if !usb_vault_path.exists() {
                if let Some(local_v) = load_vault(None, dev) {
                    let _ = save_vault(Some(sd), dev, &local_v);
                }
            }
        }
    }
}

fn is_usb_candidate_drive(drv: &str) -> bool {
    let root = to_wide(&format!("{}\\", drv));
    let dt = unsafe { GetDriveTypeW(root.as_ptr()) };
    // DRIVE_REMOVABLE (2) or DRIVE_CDROM (5)
    dt == 2 || dt == 5
}

fn is_fixed_drive(drv: &str) -> bool {
    let root = to_wide(&format!("{}\\", drv));
    let dt = unsafe { GetDriveTypeW(root.as_ptr()) };
    // DRIVE_FIXED (3)
    dt == 3
}

fn hide_locked_security_drive_letter(sec_drv: &str) {
    if sec_drv.len() != 2 || !sec_drv.ends_with(':') || sec_drv.eq_ignore_ascii_case("C:") {
        return;
    }
    let dt = drive_type_of(sec_drv);
    if dt != 2 && dt != 3 {
        return;
    }
    unsafe {
        let h = open_drive_handle(sec_drv);
        if h != INVALID_HANDLE_VALUE {
            let mut dummy: DWORD = 0;
            DeviceIoControl(h, FSCTL_DISMOUNT_VOLUME, null_mut(), 0, null_mut(), 0, &mut dummy, null_mut());
            DeviceIoControl(h, IOCTL_VOLUME_OFFLINE, null_mut(), 0, null_mut(), 0, &mut dummy, null_mut());
            CloseHandle(h);
        }
        let mount_pt = to_wide(&format!("{}\\", sec_drv));
        if DeleteVolumeMountPointW(mount_pt.as_ptr()) != 0 {
            SHChangeNotify(
                SHCNE_MEDIAREMOVED,
                SHCNF_PATHW | SHCNF_FLUSHNOWAIT,
                mount_pt.as_ptr() as *const c_void,
                null(),
            );
            SHChangeNotify(
                SHCNE_DRIVEREMOVED,
                SHCNF_PATHW | SHCNF_FLUSHNOWAIT,
                mount_pt.as_ptr() as *const c_void,
                null(),
            );
        }
    }
}

fn hide_all_locked_innostor_removable_drives(public_drv: &str) {
    let mask = unsafe { GetLogicalDrives() };
    for i in 2..26 {
        if (mask & (1 << i)) != 0 {
            let drv = format!("{}:", (b'A' + i as u8) as char);
            if drv.eq_ignore_ascii_case("C:") || drv.eq_ignore_ascii_case(public_drv) {
                continue;
            }
            if drive_type_of(&drv) == 2 && !is_drive_ready(&drv) {
                if query_drive(&drv).is_some() {
                    hide_locked_security_drive_letter(&drv);
                }
            }
        }
    }
}

fn wake_and_rescan_security_lun(public_drv: &str) {
    unsafe {
        let mut dummy: DWORD = 0;
        let mut innostor_disks: Vec<u32> = Vec::new();
        // 1. Poke PhysicalDrive1..12 so Windows disk.sys / partmgr.sys immediately re-reads LUN1 partition table
        for p in 1..=12u32 {
            let pdrv = format!("PhysicalDrive{}", p);
            let h = open_drive_handle(&pdrv);
            if h != INVALID_HANDLE_VALUE {
                let mut inq = [0u8; 0x60];
                let inq_ok = execute_scsi(h, &[0x12, 0, 0, 0, 0x60, 0], SCSI_IOCTL_DATA_IN, &mut inq)
                    || execute_scsi(h, &[0x12, 0, 0, 0, 0x60, 0, 0, 0, 0, 0], SCSI_IOCTL_DATA_IN, &mut inq);
                let mut sec_buf = [0u8; 0x30];
                let sec_ok = execute_scsi(h, &[0xE0, 0x32, 0, 0, 0, 0, 0, 1, 6, 0], SCSI_IOCTL_DATA_IN, &mut sec_buf);
                let is_innostor = (inq_ok && &inq[40..44] == b"BWSE") || sec_ok;
                if is_innostor {
                    innostor_disks.push(p);
                    let mut tur_empty = [];
                    let _ = execute_scsi(h, &[0x00, 0, 0, 0, 0, 0], SCSI_IOCTL_DATA_UNSPECIFIED, &mut tur_empty);
                    let mut cap_buf = [0u8; 8];
                    let _ = execute_scsi(h, &[0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0], SCSI_IOCTL_DATA_IN, &mut cap_buf);
                }
                DeviceIoControl(h, IOCTL_STORAGE_LOAD_MEDIA, null_mut(), 0, null_mut(), 0, &mut dummy, null_mut());
                DeviceIoControl(h, IOCTL_STORAGE_LOAD_MEDIA2, null_mut(), 0, null_mut(), 0, &mut dummy, null_mut());
                DeviceIoControl(h, IOCTL_DISK_UPDATE_PROPERTIES, null_mut(), 0, null_mut(), 0, &mut dummy, null_mut());
                DeviceIoControl(h, IOCTL_STORAGE_FIND_NEW_DEVICES, null_mut(), 0, null_mut(), 0, &mut dummy, null_mut());
                CloseHandle(h);
            }
        }

        // 2. Ask Windows MountPointManager to process any newly arrived volumes and assign drive letters
        let mpm = to_wide("\\\\.\\MountPointManager");
        let h_mpm = CreateFileW(
            mpm.as_ptr(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null_mut(),
            OPEN_EXISTING,
            0,
            null_mut(),
        );
        if h_mpm != INVALID_HANDLE_VALUE {
            DeviceIoControl(
                h_mpm,
                IOCTL_MOUNTMGR_CHECK_UNPROCESSED_VOLUMES,
                null_mut(),
                0,
                null_mut(),
                0,
                &mut dummy,
                null_mut(),
            );
            CloseHandle(h_mpm);
        }

        // 3. Enumerate \\?\Volume{...}\ volumes: if an Innostor LUN1 volume has no drive letter
        //    (e.g. unmounted while locked to hide the empty Removable Disk icon, or automount disabled),
        //    bring it online and assign D:..Z:
        let mut vol_buf = [0u16; 260];
        let h_find = FindFirstVolumeW(vol_buf.as_mut_ptr(), vol_buf.len() as DWORD);
        if h_find != INVALID_HANDLE_VALUE {
            loop {
                let vlen = vol_buf.iter().position(|&c| c == 0).unwrap_or(0);
                if vlen > 1 {
                    let vol_dt = GetDriveTypeW(vol_buf.as_ptr());
                    // Only consider Removable (2) or Fixed (3) volumes, never CD-ROM (5)
                    if vol_dt == 2 || vol_dt == 3 {
                        let vol_str = String::from_utf16_lossy(&vol_buf[..vlen]);
                        let dev_str = vol_str.trim_end_matches('\\');
                        let dev_wide = to_wide(dev_str);
                        let h_vol = CreateFileW(
                            dev_wide.as_ptr(),
                            0,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            null_mut(),
                            OPEN_EXISTING,
                            0,
                            null_mut(),
                        );
                        if h_vol != INVALID_HANDLE_VALUE {
                            let mut matches_innostor_lun1 = false;

                            // Check A: IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS
                            let mut ext_buf = [0u8; 64];
                            let mut bytes_ret: DWORD = 0;
                            let ext_ok = DeviceIoControl(
                                h_vol,
                                IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                                null_mut(),
                                0,
                                ext_buf.as_mut_ptr() as *mut c_void,
                                ext_buf.len() as DWORD,
                                &mut bytes_ret,
                                null_mut(),
                            );
                            if ext_ok != 0 && bytes_ret >= 12 {
                                let num_extents = u32::from_le_bytes([ext_buf[0], ext_buf[1], ext_buf[2], ext_buf[3]]);
                                let disk_num = u32::from_le_bytes([ext_buf[8], ext_buf[9], ext_buf[10], ext_buf[11]]);
                                if num_extents >= 1 && innostor_disks.contains(&disk_num) {
                                    matches_innostor_lun1 = true;
                                }
                            }

                            // Check B: IOCTL_STORAGE_GET_DEVICE_NUMBER (works on DRIVE_REMOVABLE volumes)
                            if !matches_innostor_lun1 {
                                let mut sdn_buf = [0u8; 16];
                                let mut sdn_ret: DWORD = 0;
                                let sdn_ok = DeviceIoControl(
                                    h_vol,
                                    IOCTL_STORAGE_GET_DEVICE_NUMBER,
                                    null_mut(),
                                    0,
                                    sdn_buf.as_mut_ptr() as *mut c_void,
                                    sdn_buf.len() as DWORD,
                                    &mut sdn_ret,
                                    null_mut(),
                                );
                                if sdn_ok != 0 && sdn_ret >= 12 {
                                    let dev_type = u32::from_le_bytes([sdn_buf[0], sdn_buf[1], sdn_buf[2], sdn_buf[3]]);
                                    let dev_num = u32::from_le_bytes([sdn_buf[4], sdn_buf[5], sdn_buf[6], sdn_buf[7]]);
                                    // FILE_DEVICE_DISK == 7
                                    if dev_type == 7 && innostor_disks.contains(&dev_num) {
                                        matches_innostor_lun1 = true;
                                    }
                                }
                            }

                            // Check C: Direct SCSI INQUIRY / 0xE0 0x32 on removable volume handle
                            if !matches_innostor_lun1 && vol_dt == 2 {
                                let mut inq = [0u8; 0x60];
                                let inq_ok = execute_scsi(h_vol, &[0x12, 0, 0, 0, 0x60, 0], SCSI_IOCTL_DATA_IN, &mut inq)
                                    || execute_scsi(h_vol, &[0x12, 0, 0, 0, 0x60, 0, 0, 0, 0, 0], SCSI_IOCTL_DATA_IN, &mut inq);
                                if inq_ok && &inq[40..44] == b"BWSE" {
                                    matches_innostor_lun1 = true;
                                }
                            }

                            if matches_innostor_lun1 {
                                DeviceIoControl(h_vol, IOCTL_STORAGE_LOAD_MEDIA, null_mut(), 0, null_mut(), 0, &mut dummy, null_mut());
                                DeviceIoControl(h_vol, IOCTL_DISK_UPDATE_PROPERTIES, null_mut(), 0, null_mut(), 0, &mut dummy, null_mut());
                                DeviceIoControl(h_vol, IOCTL_VOLUME_ONLINE, null_mut(), 0, null_mut(), 0, &mut dummy, null_mut());
                                let mut paths_buf = [0u16; 260];
                                let mut ret_len: DWORD = 0;
                                let has_mount = GetVolumePathNamesForVolumeNameW(
                                    vol_buf.as_ptr(),
                                    paths_buf.as_mut_ptr(),
                                    paths_buf.len() as DWORD,
                                    &mut ret_len,
                                ) != 0
                                    && paths_buf[0] != 0;
                                if !has_mount {
                                    let used_mask = GetLogicalDrives();
                                    for d in 3..26 {
                                        if (used_mask & (1 << d)) == 0 {
                                            let mount_pt = to_wide(&format!("{}:\\", (b'A' + d as u8) as char));
                                            if SetVolumeMountPointW(mount_pt.as_ptr(), vol_buf.as_ptr()) != 0 {
                                                SHChangeNotify(
                                                    SHCNE_DRIVEADD,
                                                    SHCNF_PATHW | SHCNF_FLUSHNOWAIT,
                                                    mount_pt.as_ptr() as *const c_void,
                                                    null(),
                                                );
                                                SHChangeNotify(
                                                    SHCNE_MEDIAINSERTED,
                                                    SHCNF_PATHW | SHCNF_FLUSHNOWAIT,
                                                    mount_pt.as_ptr() as *const c_void,
                                                    null(),
                                                );
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                            CloseHandle(h_vol);
                        }
                    }
                }
                vol_buf = [0u16; 260];
                if FindNextVolumeW(h_find, vol_buf.as_mut_ptr(), vol_buf.len() as DWORD) == 0 {
                    break;
                }
            }
            FindVolumeClose(h_find);
        }

        // 4. Bring any logical drive letters online and update their disk properties
        let mask = GetLogicalDrives();
        for i in 2..26 {
            if (mask & (1 << i)) != 0 {
                let drv = format!("{}:", (b'A' + i as u8) as char);
                if drv.eq_ignore_ascii_case("C:") || drv.eq_ignore_ascii_case(public_drv) {
                    continue;
                }
                let dt = drive_type_of(&drv);
                if dt == 2 || dt == 3 {
                    let h = open_drive_handle(&drv);
                    if h != INVALID_HANDLE_VALUE {
                        DeviceIoControl(h, IOCTL_STORAGE_LOAD_MEDIA, null_mut(), 0, null_mut(), 0, &mut dummy, null_mut());
                        DeviceIoControl(h, IOCTL_DISK_UPDATE_PROPERTIES, null_mut(), 0, null_mut(), 0, &mut dummy, null_mut());
                        DeviceIoControl(h, IOCTL_VOLUME_ONLINE, null_mut(), 0, null_mut(), 0, &mut dummy, null_mut());
                        CloseHandle(h);
                    }
                }
            }
        }
    }
}

fn is_matching_security_volume(drv: &str, public_drv: &str, expected_sec_sectors: u32) -> bool {
    if drv.eq_ignore_ascii_case("C:") || drv.eq_ignore_ascii_case(public_drv) {
        return false;
    }
    let dt = drive_type_of(drv);
    if dt != 2 && dt != 3 {
        return false;
    }
    let Some((_, _, total_bytes)) = query_drive_space(drv) else {
        return false;
    };
    // 1. Direct Innostor SCSI inquiry match
    if query_drive(drv).is_some() {
        return true;
    }
    // 2. Existing vault file on the drive
    if Path::new(&format!("{}\\", drv)).join(VAULT_FILENAME).exists() {
        return true;
    }
    // 3. Matching volume label ("Secure USB", "SECURITY", "SECURE_VAULT")
    let lbl = query_volume_label(drv);
    if lbl.eq_ignore_ascii_case("Secure USB")
        || lbl.eq_ignore_ascii_case("SECURITY")
        || lbl.eq_ignore_ascii_case("SECURE_VAULT")
    {
        return true;
    }
    // 4. Matching LUN1 byte capacity (within 15% tolerance for filesystem overhead)
    if expected_sec_sectors > 0 {
        let exp_bytes = (expected_sec_sectors as u64) * 512;
        let diff = if total_bytes > exp_bytes {
            total_bytes - exp_bytes
        } else {
            exp_bytes - total_bytes
        };
        if diff <= exp_bytes / 7 && dt == 2 {
            return true;
        }
    }
    false
}

fn find_mounted_security_drive(primary: &DeviceInfo) -> Option<String> {
    let mask = unsafe { GetLogicalDrives() };
    for i in 2..26 {
        if (mask & (1 << i)) != 0 {
            let drv = format!("{}:", (b'A' + i as u8) as char);
            if is_matching_security_volume(&drv, &primary.drive_letter, primary.lun_sectors[1]) {
                return Some(drv);
            }
        }
    }
    None
}

fn scan_devices() -> Vec<DeviceInfo> {
    let mut raw_list: Vec<DeviceInfo> = Vec::new();
    let mask = unsafe { GetLogicalDrives() };

    // Unified Pass: Scan Removable (2), CD-ROM (5), and Fixed (3, skipping C:) drives together
    // so LUN1 (even when Windows classifies it as DRIVE_FIXED) is never skipped when LUN0 is DRIVE_CDROM!
    for i in 2..26 {
        if (mask & (1 << i)) != 0 {
            let drv = format!("{}:", (b'A' + i as u8) as char);
            if drv.eq_ignore_ascii_case("C:") {
                continue;
            }
            if !is_usb_candidate_drive(&drv) && !is_fixed_drive(&drv) {
                continue;
            }
            if let Some(info) = query_drive(&drv) {
                raw_list.push(info);
            }
        }
    }

    // Also query PhysicalDrive1..12:
    // - If no logical drive letter matched at all, use PhysicalDriveN
    // - If a logical drive (e.g. CD-ROM H:) blocked 0xE0 0x30 / 0xE0 0x32 so its lun_sectors are 0,
    //   enrich it from the matching Innostor PhysicalDriveN!
    let mut phys_devs: Vec<DeviceInfo> = Vec::new();
    for p in 1..=12 {
        let pdrv = format!("PhysicalDrive{}", p);
        if let Some(pinfo) = query_drive(&pdrv) {
            phys_devs.push(pinfo);
        }
    }

    if raw_list.is_empty() {
        raw_list = phys_devs;
    } else if !phys_devs.is_empty() {
        let pd = &phys_devs[0];
        for d in &mut raw_list {
            if d.lun_sectors[0] == 0 && d.lun_sectors[1] == 0 {
                d.lun_sectors = pd.lun_sectors;
                d.lun_flags = pd.lun_flags;
            }
            if d.flash_id == [0u8; 6] && pd.flash_id != [0u8; 6] {
                d.flash_id = pd.flash_id;
            }
            if pd.has_security_lun {
                d.has_security_lun = true;
            }
            if pd.is_unlocked {
                d.is_unlocked = true;
            }
        }
    }

    if raw_list.len() >= 2 {
        // Distinguish LUN0 (CD-ROM / small launcher) from LUN1 (Security data volume) regardless of drive-letter order!
        raw_list.sort_by_key(|d| {
            let dt = drive_type_of(&d.drive_letter);
            let is_cd = dt == 5;
            let sz = query_drive_space(&d.drive_letter).map(|(_, _, t)| t).unwrap_or(0);
            (!is_cd, sz)
        });
        let sec_drv = raw_list[1].drive_letter.clone();
        let sec_unlocked = raw_list[1].is_unlocked;
        let mut primary = raw_list.remove(0);
        let sec_ready = is_drive_ready(&sec_drv);
        if (primary.is_unlocked || sec_unlocked) && sec_ready {
            primary.security_drive_letter = Some(sec_drv);
            primary.is_unlocked = true;
        } else {
            // Security LUN is locked (0-byte empty Removable Disk slot) -> hide/unmount its drive letter from Explorer!
            hide_locked_security_drive_letter(&sec_drv);
            primary.security_drive_letter = None;
            primary.is_unlocked = false;
        }
        update_effective_vault_metadata(&mut primary);
        vec![primary]
    } else {
        if let Some(first) = raw_list.first_mut() {
            // If only 1 drive responded to query_drive, check if it is actually LUN1 or if LUN1 is mounted on another letter
            if first.is_unlocked && first.security_drive_letter.is_none() {
                if drive_type_of(&first.drive_letter) != 5 {
                    let sz = query_drive_space(&first.drive_letter).map(|(_, _, t)| t).unwrap_or(0);
                    if sz > 1_073_741_824 {
                        first.security_drive_letter = Some(first.drive_letter.clone());
                    }
                }
                if first.security_drive_letter.is_none() {
                    first.security_drive_letter = find_mounted_security_drive(first);
                }
            } else if !first.is_unlocked {
                // Ensure any empty locked removable LUN1 drive letter is unmounted so it doesn't clutter Explorer
                hide_all_locked_innostor_removable_drives(&first.drive_letter);
                first.security_drive_letter = None;
            }
            update_effective_vault_metadata(first);
        }
        raw_list
    }
}

fn raw_hardware_unlock(h_dev: HANDLE, dev: &mut DeviceInfo, hw_password: &str) -> bool {
    let cipher32 = encrypt_password_tea(hw_password, dev.challenge_token);
    let mut payload = [0u8; 512];
    payload[0..32].copy_from_slice(&cipher32);
    let cdb = [0xE0, 0x33, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00];
    if !execute_scsi(h_dev, &cdb, SCSI_IOCTL_DATA_OUT, &mut payload) {
        return false;
    }
    refresh_security_status(h_dev, dev);
    dev.is_unlocked || dev.status_code == 0
}

fn snapshot_ready_drives_mask() -> DWORD {
    let mask = unsafe { GetLogicalDrives() };
    let mut ready_mask: DWORD = 0;
    for i in 2..26 {
        if (mask & (1 << i)) != 0 {
            let drv = format!("{}:", (b'A' + i as u8) as char);
            if is_drive_ready(&drv) {
                ready_mask |= 1 << i;
            }
        }
    }
    ready_mask
}

fn wait_for_security_drive_letter(
    public_drv: &str,
    known_sec_drv: Option<&str>,
    expected_sec_sectors: u32,
    pre_ready_mask: DWORD,
    timeout_ms: u64,
) -> Option<String> {
    wake_and_rescan_security_lun(public_drv);
    let mut elapsed = 0u64;
    let mut rescanned_midway = false;
    while elapsed < timeout_ms {
        if elapsed >= 900 && !rescanned_midway {
            wake_and_rescan_security_lun(public_drv);
            rescanned_midway = true;
        }
        if let Some(kd) = known_sec_drv {
            if !kd.eq_ignore_ascii_case(public_drv) && is_drive_ready(kd) {
                return Some(kd.to_string());
            }
        }
        let mask = unsafe { GetLogicalDrives() };
        for i in 2..26 {
            if (mask & (1 << i)) != 0 {
                let drv = format!("{}:", (b'A' + i as u8) as char);
                if drv.eq_ignore_ascii_case("C:") || drv.eq_ignore_ascii_case(public_drv) {
                    continue;
                }
                let dt = drive_type_of(&drv);
                if dt != 2 && dt != 3 {
                    continue;
                }
                if !is_drive_ready(&drv) {
                    continue;
                }
                // Newly mounted after unlock OR matches security volume signature/capacity
                let newly_ready = (pre_ready_mask & (1 << i)) == 0;
                if newly_ready || is_matching_security_volume(&drv, public_drv, expected_sec_sectors) {
                    return Some(drv);
                }
            }
        }
        thread::sleep(Duration::from_millis(120));
        elapsed += 120;
    }
    None
}

fn find_innostor_physical_drive_handle() -> HANDLE {
    for p in 1..=12 {
        let pdrv = format!("PhysicalDrive{}", p);
        let h = open_drive_handle(&pdrv);
        if h != INVALID_HANDLE_VALUE {
            let mut inq = [0u8; 0x60];
            let inq_ok = execute_scsi(h, &[0x12, 0, 0, 0, 0x60, 0], SCSI_IOCTL_DATA_IN, &mut inq)
                || execute_scsi(h, &[0x12, 0, 0, 0, 0x60, 0, 0, 0, 0, 0], SCSI_IOCTL_DATA_IN, &mut inq);
            let mut sec_buf = [0u8; 0x30];
            let sec_ok = execute_scsi(h, &[0xE0, 0x32, 0, 0, 0, 0, 0, 1, 6, 0], SCSI_IOCTL_DATA_IN, &mut sec_buf);
            if (inq_ok && &inq[40..44] == b"BWSE") || sec_ok {
                return h;
            }
            unsafe { CloseHandle(h); }
        }
    }
    INVALID_HANDLE_VALUE
}

fn dismount_security_volume_for_lock(sec_drv: &str) {
    let h_sec = open_drive_handle(sec_drv);
    if h_sec != INVALID_HANDLE_VALUE {
        let mut dummy: DWORD = 0;
        unsafe {
            FlushFileBuffers(h_sec);
            for _ in 0..3 {
                if DeviceIoControl(h_sec, FSCTL_LOCK_VOLUME, null_mut(), 0, null_mut(), 0, &mut dummy, null_mut()) != 0 {
                    break;
                }
                thread::sleep(Duration::from_millis(50));
            }
            DeviceIoControl(h_sec, FSCTL_DISMOUNT_VOLUME, null_mut(), 0, null_mut(), 0, &mut dummy, null_mut());
            DeviceIoControl(h_sec, IOCTL_VOLUME_OFFLINE, null_mut(), 0, null_mut(), 0, &mut dummy, null_mut());
            CloseHandle(h_sec);
        }
    }
}

fn lock_device(dev: &mut DeviceInfo) -> (bool, String) {
    if let Some(ref sec_drv) = dev.security_drive_letter {
        dismount_security_volume_for_lock(sec_drv);
    }

    let target_drv = dev.security_drive_letter.as_deref().unwrap_or(&dev.drive_letter);
    let mut h_dev = open_drive_handle(target_drv);
    if h_dev == INVALID_HANDLE_VALUE {
        h_dev = open_drive_handle(&dev.drive_letter);
    }
    if h_dev == INVALID_HANDLE_VALUE {
        h_dev = find_innostor_physical_drive_handle();
    }
    if h_dev == INVALID_HANDLE_VALUE {
        return (false, tr("드라이브 핸들을 열 수 없습니다.", "Cannot open drive handle.", "ドライブを開けません。").to_string());
    }

    let cdb = [0xE0, 0x33, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00];
    let mut empty = [];
    let mut ok_cmd = execute_scsi(h_dev, &cdb, SCSI_IOCTL_DATA_UNSPECIFIED, &mut empty);
    refresh_security_status(h_dev, dev);
    unsafe { CloseHandle(h_dev); }

    if !ok_cmd || dev.is_unlocked {
        if let Some(ref sec_drv) = dev.security_drive_letter {
            dismount_security_volume_for_lock(sec_drv);
        }
        let h_phys = find_innostor_physical_drive_handle();
        if h_phys != INVALID_HANDLE_VALUE {
            if execute_scsi(h_phys, &cdb, SCSI_IOCTL_DATA_UNSPECIFIED, &mut empty) {
                ok_cmd = true;
            }
            refresh_security_status(h_phys, dev);
            unsafe { CloseHandle(h_phys); }
        }
    }

    if !ok_cmd {
        return (
            false,
            tr(
                "잠금 실패 (열려 있는 파일을 모두 닫고 다시 시도해 주세요.)",
                "Lock failed (Please close any open files and try again).",
                "ロック失敗 (開いているファイルを閉じてから再試行してください。)",
            )
            .to_string(),
        );
    }

    let locked = !dev.is_unlocked;
    if locked {
        if let Some(ref sec_drv) = dev.security_drive_letter.clone() {
            if !sec_drv.eq_ignore_ascii_case(&dev.drive_letter) {
                hide_locked_security_drive_letter(sec_drv);
            }
        }
        hide_all_locked_innostor_removable_drives(&dev.drive_letter);
        dev.security_drive_letter = None;
        dev.sec_used_bytes = 0;
        dev.sec_free_bytes = 0;
        dev.sec_total_bytes = 0;
    }
    let msg = if locked {
        tr("보안 영역이 안전하게 잠겼습니다. (Locked)", "Security partition locked.", "セキュリティ領域が安全にロックされました。").to_string()
    } else {
        tr("잠금 명령을 보냈으나 아직 열려 있습니다.", "Lock command sent, but still unlocked.", "ロックコマンドを送信しましたがまだ開いています。").to_string()
    };
    (locked, msg)
}

fn safe_eject_device(dev: &mut DeviceInfo) -> (bool, String) {
    if dev.has_security_lun && dev.is_unlocked {
        let (lok, lmsg) = lock_device(dev);
        if !lok {
            return (false, lmsg);
        }
    }
    let h_pub = open_drive_handle(&dev.drive_letter);
    if h_pub != INVALID_HANDLE_VALUE {
        let mut dummy: DWORD = 0;
        unsafe {
            DeviceIoControl(h_pub, IOCTL_STORAGE_EJECT_MEDIA, null_mut(), 0, null_mut(), 0, &mut dummy, null_mut());
            CloseHandle(h_pub);
        }
    }
    (
        true,
        tr(
            "보안 영역이 잠기고 안전 제거 준비가 완료되었습니다.\n이제 USB를 포트에서 안전하게 뽑으셔도 됩니다.",
            "Security partition locked and ready for safe removal.\nYou may now safely unplug the USB drive.",
            "セキュリティ領域がロックされ、安全な取り外し準備が完了しました。\nUSBを安全に取り外せます。",
        )
        .to_string(),
    )
}

fn format_password_fail_warning(remain: i32, limit: i32) -> String {
    let header = if remain <= 3 {
        tr(
            "🚨 [위험: 데이터 영구 파기 직전!]",
            "🚨 [CRITICAL: DATA WIPE IMMINENT!]",
            "🚨 [危険: データ完全消去の直前です！]",
        )
    } else {
        tr(
            "❌ 비밀번호가 일치하지 않습니다.",
            "❌ Incorrect password.",
            "❌ パスワードが正しくありません。",
        )
    };
    format!(
        "{}\n({}: {} / {})\n\n⚠️ {}\n{}",
        header,
        tr("남은 인증 기회", "Remaining Attempts", "残り試行回数"),
        remain,
        limit,
        tr(
            "남은 횟수가 0이 되면 보안 영역의 모든 데이터가 복구 불가능하게 완전 파기(포맷)됩니다!",
            "When remaining attempts reach 0, ALL data in the security partition will be permanently shredded and formatted!",
            "残り回数が0になると、セキュリティ領域の全データが復元不可能な状態で完全消去(フォーマット)されます！",
        ),
        tr(
            "비밀번호(대·소문자, 한/영 키, Caps Lock)를 정확히 확인한 후 다시 입력해 주세요.",
            "Please carefully check Caps Lock and your password before trying again.",
            "Caps Lockや入力文字をよくご確認の上、再度入力してください。",
        )
    )
}

fn unlock_device(dev: &mut DeviceInfo, user_password: &str) -> (bool, String, Option<(i32, String)>) {
    let mut vault = load_vault(dev.security_drive_letter.as_deref(), dev);
    let mut prior_intrusion: Option<(i32, String)> = None;

    if let Some(ref mut v) = vault {
        if v.fail_count >= v.max_retries {
            let wipe_msg = execute_self_destruct_wipe(dev);
            return (false, wipe_msg, None);
        }
        let input_hash = compute_vault_hash(user_password, &v.salt_hex);
        if !input_hash.eq_ignore_ascii_case(&v.hash_hex) {
            v.fail_count += 1;
            v.last_fail_time = get_now_timestamp_str();
            if v.fail_count >= v.max_retries {
                let wipe_msg = execute_self_destruct_wipe(dev);
                return (false, wipe_msg, None);
            }
            save_vault(dev.security_drive_letter.as_deref(), dev, v);
            let remain = (v.max_retries - v.fail_count).max(0);
            let limit = v.max_retries;
            update_effective_vault_metadata(dev);
            return (false, format_password_fail_warning(remain, limit), None);
        }
        if v.fail_count > 0 {
            prior_intrusion = Some((v.fail_count, v.last_fail_time.clone()));
        }
    }

    let pre_ready_mask = snapshot_ready_drives_mask();

    let target_drv = dev.security_drive_letter.as_deref().unwrap_or(&dev.drive_letter).to_string();
    let mut h_dev = open_drive_handle(&target_drv);
    if h_dev == INVALID_HANDLE_VALUE {
        h_dev = open_drive_handle(&dev.drive_letter);
    }
    if h_dev == INVALID_HANDLE_VALUE {
        h_dev = find_innostor_physical_drive_handle();
    }
    if h_dev == INVALID_HANDLE_VALUE {
        return (false, tr("드라이브 핸들을 열 수 없습니다.", "Cannot open drive handle.", "ドライブを開けません。").to_string(), None);
    }

    if !refresh_security_status(h_dev, dev) {
        let h_phys = find_innostor_physical_drive_handle();
        if h_phys != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(h_dev); }
            h_dev = h_phys;
            refresh_security_status(h_dev, dev);
        }
    }
    let mut hw_opened = dev.is_unlocked;
    let mut opened_by_key: Option<String> = None;

    let mut keys_to_try = vec![user_password.to_string()];
    for &mk in &HARDWARE_MASTER_KEYS {
        if !keys_to_try.iter().any(|k| k == mk) {
            keys_to_try.push(mk.to_string());
        }
    }

    if !hw_opened {
        for k in &keys_to_try {
            refresh_security_status(h_dev, dev);
            if raw_hardware_unlock(h_dev, dev, k) {
                hw_opened = true;
                opened_by_key = Some(k.clone());
                break;
            }
        }
    }
    unsafe { CloseHandle(h_dev); }

    // Fallback: If CD-ROM class driver blocked vendor unlock CDB (0xE0 0x33), retry directly on PhysicalDriveN (disk.sys)
    if !hw_opened {
        let h_phys = find_innostor_physical_drive_handle();
        if h_phys != INVALID_HANDLE_VALUE {
            for k in &keys_to_try {
                refresh_security_status(h_phys, dev);
                if raw_hardware_unlock(h_phys, dev, k) {
                    hw_opened = true;
                    opened_by_key = Some(k.clone());
                    break;
                }
            }
            unsafe { CloseHandle(h_phys); }
        }
    }

    if !hw_opened {
        if dev.retry_remain == 0 {
            let wipe_msg = execute_self_destruct_wipe(dev);
            return (false, wipe_msg, None);
        }
        return (
            false,
            format_password_fail_warning(dev.retry_remain as i32, dev.retry_limit as i32),
            None,
        );
    }

    let sec_drv = wait_for_security_drive_letter(
        &dev.drive_letter,
        dev.security_drive_letter.as_deref(),
        dev.lun_sectors[1],
        pre_ready_mask,
        4200,
    );
    if sec_drv.is_some() {
        dev.security_drive_letter = sec_drv.clone();
    }

    if vault.is_none() {
        if let Some(ref sd) = sec_drv {
            if let Some(mut usb_vault) = load_vault(Some(sd), dev) {
                let input_hash = compute_vault_hash(user_password, &usb_vault.salt_hex);
                if !input_hash.eq_ignore_ascii_case(&usb_vault.hash_hex) {
                    usb_vault.fail_count += 1;
                    usb_vault.last_fail_time = get_now_timestamp_str();
                    if usb_vault.fail_count >= usb_vault.max_retries {
                        let wipe_msg = execute_self_destruct_wipe(dev);
                        return (false, wipe_msg, None);
                    }
                    save_vault(Some(sd), dev, &usb_vault);
                    let _ = lock_device(dev);
                    let remain = (usb_vault.max_retries - usb_vault.fail_count).max(0);
                    let limit = usb_vault.max_retries;
                    update_effective_vault_metadata(dev);
                    return (false, format_password_fail_warning(remain, limit), None);
                }
                if usb_vault.fail_count > 0 {
                    prior_intrusion = Some((usb_vault.fail_count, usb_vault.last_fail_time.clone()));
                }
                vault = Some(usb_vault);
            } else {
                if let Some(ref ok_key) = opened_by_key {
                    if ok_key != user_password {
                        let _ = lock_device(dev);
                        return (
                            false,
                            tr("비밀번호가 일치하지 않습니다.", "Incorrect password.", "パスワードが正しくありません。").to_string(),
                            None,
                        );
                    }
                }
                vault = Some(create_new_vault(
                    user_password,
                    &dev.password_hint,
                    dev.retry_limit as i32,
                    dev.vault_idle_mins.unwrap_or(10),
                    dev.vault_dark_mode,
                ));
            }
        }
    }

    if let Some(ref mut v) = vault {
        v.fail_count = 0;
        v.last_fail_time.clear();
        // Sync current active UI preferences (Theme & Idle Timer) TO the unlocked USB vault
        // so an outdated Theme=Dark inside the locked partition never reverts the user's Light mode on unlock!
        if let Some(dm) = dev.vault_dark_mode {
            v.dark_mode = Some(dm);
        }
        if let Some(im) = dev.vault_idle_mins {
            v.idle_lock_mins = im;
        }
        save_vault(dev.security_drive_letter.as_deref(), dev, v);
    }

    update_effective_vault_metadata(dev);
    if let Some((cnt, ref tm)) = prior_intrusion {
        dev.last_intrusion_count = cnt;
        dev.last_intrusion_time = tm.clone();
    } else {
        dev.last_intrusion_count = 0;
        dev.last_intrusion_time.clear();
    }

    let msg = if let Some(ref sd) = sec_drv {
        format!(
            "{} [{}]",
            tr("잠금 해제 성공! 보안 드라이브 마운트됨", "Unlocked successfully! Security drive mounted", "ロック解除成功！セキュリティドライブがマウントされました"),
            sd
        )
    } else {
        tr("잠금 해제 성공!", "Unlocked successfully!", "ロック解除成功！").to_string()
    };
    (true, msg, prior_intrusion)
}

fn change_password(dev: &mut DeviceInfo, current_pwd: &str, new_pwd: &str, new_hint: &str) -> (bool, String) {
    if new_pwd.len() < 4 || new_pwd.len() > 15 {
        return (
            false,
            tr("새 비밀번호는 4~15자로 입력해 주세요.", "New password must be 4 to 15 characters.", "新しいパスワードは4〜15文字で入力してください。").to_string(),
        );
    }

    let mut cur_idle = dev.vault_idle_mins.unwrap_or(10);
    let mut cur_dark = dev.vault_dark_mode;
    if !dev.is_unlocked {
        let (ok, msg, _) = unlock_device(dev, current_pwd);
        if !ok {
            return (false, msg);
        }
        cur_idle = dev.vault_idle_mins.unwrap_or(cur_idle);
        cur_dark = dev.vault_dark_mode.or(cur_dark);
    } else if let Some(existing) = load_vault(dev.security_drive_letter.as_deref(), dev) {
        let curr_hash = compute_vault_hash(current_pwd, &existing.salt_hex);
        if !curr_hash.eq_ignore_ascii_case(&existing.hash_hex) {
            return (
                false,
                tr("현재 비밀번호가 일치하지 않습니다.", "Current password is incorrect.", "現在のパスワードが正しくありません。").to_string(),
            );
        }
        cur_idle = existing.idle_lock_mins;
        cur_dark = existing.dark_mode;
    }

    let max_r = if dev.effective_retry_limit > 0 { dev.effective_retry_limit } else { 10 };
    let new_vault = create_new_vault(new_pwd, new_hint, max_r, cur_idle, cur_dark);
    if !save_vault(dev.security_drive_letter.as_deref(), dev, &new_vault) {
        return (
            false,
            tr("비밀번호 정보를 저장하지 못했습니다.", "Failed to save password.", "パスワード情報の保存に失敗しました。").to_string(),
        );
    }

    update_effective_vault_metadata(dev);
    (
        true,
        tr("비밀번호 및 힌트가 성공적으로 변경되었습니다!", "Password and hint updated successfully!", "パスワードとヒントが正常に変更されました！").to_string(),
    )
}

fn update_vault_preferences(dev: &mut DeviceInfo, new_idle_mins: u32, dark_mode: bool) {
    dev.vault_idle_mins = Some(new_idle_mins);
    dev.vault_dark_mode = Some(dark_mode);
    if let Some(mut v) = load_vault(dev.security_drive_letter.as_deref(), dev) {
        v.idle_lock_mins = new_idle_mins;
        v.dark_mode = Some(dark_mode);
        save_vault(dev.security_drive_letter.as_deref(), dev, &v);
    }
}

// ============================================================================
// Secure File Shredder (3-Pass DoD Overwrite: 0x00 -> 0xFF -> Pseudo-Random -> Unlink)
// ============================================================================
fn shred_file_permanently(path: &Path) -> Result<u64, String> {
    let meta = fs::metadata(path).map_err(|e| e.to_string())?;
    if !meta.is_file() {
        return Err("Not a regular file".to_string());
    }
    let len = meta.len();
    let wpath = to_wide(&path.to_string_lossy());
    unsafe {
        SetFileAttributesW(wpath.as_ptr(), FILE_ATTRIBUTE_NORMAL);
    }

    if len > 0 {
        let mut file = OpenOptions::new().write(true).open(path).map_err(|e| e.to_string())?;
        let chunk_size = 65536usize;
        let mut buf = vec![0u8; chunk_size];

        // Pass 1: 0x00, Pass 2: 0xFF, Pass 3: PRNG stream
        for pass in 0..3 {
            file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
            let mut rem = len;
            let mut seed = (SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0xA5A5_5A5A))
                ^ ((pass as u64) * 0x9E3779B97F4A7C15);

            while rem > 0 {
                let to_write = (rem as usize).min(chunk_size);
                match pass {
                    0 => buf[..to_write].fill(0x00),
                    1 => buf[..to_write].fill(0xFF),
                    _ => {
                        for b in &mut buf[..to_write] {
                            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                            *b = (seed >> 32) as u8;
                        }
                    }
                }
                file.write_all(&buf[..to_write]).map_err(|e| e.to_string())?;
                rem -= to_write as u64;
            }
            let _ = file.sync_all();
        }
    }

    fs::remove_file(path).map_err(|e| e.to_string())?;
    Ok(len)
}

fn shred_directory_tree(dir: &Path) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if name.eq_ignore_ascii_case("System Volume Information") || name.eq_ignore_ascii_case(VAULT_FILENAME) {
                continue;
            }
            let wpath = to_wide(&p.to_string_lossy());
            unsafe {
                SetFileAttributesW(wpath.as_ptr(), FILE_ATTRIBUTE_NORMAL);
            }
            if p.is_dir() {
                shred_directory_tree(&p);
                let _ = fs::remove_dir_all(&p);
            } else {
                let _ = shred_file_permanently(&p);
            }
        }
    }
}

fn execute_self_destruct_wipe(dev: &mut DeviceInfo) -> String {
    let pre_ready_mask = snapshot_ready_drives_mask();
    // 1. Mount security partition silently using hardware master key if currently locked
    let target_drv = dev.security_drive_letter.as_deref().unwrap_or(&dev.drive_letter).to_string();
    let mut h_dev = open_drive_handle(&target_drv);
    if h_dev == INVALID_HANDLE_VALUE {
        h_dev = open_drive_handle(&dev.drive_letter);
    }
    if h_dev == INVALID_HANDLE_VALUE {
        h_dev = find_innostor_physical_drive_handle();
    }
    let mut hw_opened = dev.is_unlocked;
    if h_dev != INVALID_HANDLE_VALUE {
        refresh_security_status(h_dev, dev);
        hw_opened = dev.is_unlocked;
        if !hw_opened {
            for &mk in &HARDWARE_MASTER_KEYS {
                refresh_security_status(h_dev, dev);
                if raw_hardware_unlock(h_dev, dev, mk) {
                    hw_opened = true;
                    break;
                }
            }
        }
        unsafe { CloseHandle(h_dev); }
    }

    if hw_opened {
        if let Some(sec_drv) = wait_for_security_drive_letter(
            &dev.drive_letter,
            dev.security_drive_letter.as_deref(),
            dev.lun_sectors[1],
            pre_ready_mask,
            4200,
        ) {
            dev.security_drive_letter = Some(sec_drv.clone());
            let root_path = PathBuf::from(format!("{}\\", sec_drv));

            // 2. Shred all files and directories inside the security partition (3-Pass DoD overwrite)
            shred_directory_tree(&root_path);

            // 3. Remove USB vault file and perform a silent quick NTFS format to wipe MFT/directory metadata
            let usb_vault_path = root_path.join(VAULT_FILENAME);
            let wv = to_wide(&usb_vault_path.to_string_lossy());
            unsafe {
                SetFileAttributesW(wv.as_ptr(), FILE_ATTRIBUTE_NORMAL);
            }
            let _ = fs::remove_file(&usb_vault_path);

            let _ = Command::new("cmd.exe")
                .args(["/C", &format!("format {} /FS:NTFS /V:SECURE_VAULT /Q /Y", sec_drv)])
                .creation_flags(0x08000000) // CREATE_NO_WINDOW
                .status();

            // 4. Re-initialize clean factory vault + autorun.inf + logo.ico on wiped partition and immediately re-lock hardware
            let _ = restore_security_autorun_and_icon(&sec_drv, true);
            let reset_vault = create_new_vault(
                HARDWARE_MASTER_KEYS[0],
                &dev.password_hint,
                dev.retry_limit as i32,
                dev.vault_idle_mins.unwrap_or(10),
                dev.vault_dark_mode,
            );
            save_vault(Some(&sec_drv), dev, &reset_vault);
        }
        let _ = lock_device(dev);
    }

    // 5. Reset local vault cache to factory default as well
    let reset_local = create_new_vault(
        HARDWARE_MASTER_KEYS[0],
        &dev.password_hint,
        dev.retry_limit as i32,
        dev.vault_idle_mins.unwrap_or(10),
        dev.vault_dark_mode,
    );
    let _ = fs::remove_file(get_local_vault_path(dev));
    save_vault(None, dev, &reset_local);
    update_effective_vault_metadata(dev);

    tr(
        "🚨 [보안 데이터 완전 파기 완료]\n\n비밀번호 오류 허용 횟수(10회)를 초과하여 보안 영역의 모든 파일이 3단계 덮어쓰기 및 포맷으로 영구 파기(초기화)되었습니다.",
        "🚨 [SECURITY SELF-DESTRUCT EXECUTED]\n\nMaximum password attempts (10) exceeded. All files in the security partition have been permanently shredded and formatted.",
        "🚨 [セキュリティ領域データ完全破棄完了]\n\nパスワード試行回数上限(10回)を超えたため、セキュリティ領域の全データが完全消去・初期化されました。",
    )
    .to_string()
}

fn select_and_shred_file(hwnd: HWND, initial_drive: Option<&str>) -> Option<(bool, String)> {
    unsafe {
        let mut file_buf = [0u16; 520];
        let filter_str = tr(
            "모든 파일 (*.*)\0*.*\0\0",
            "All Files (*.*)\0*.*\0\0",
            "すべてのファイル (*.*)\0*.*\0\0",
        );
        let filter_w: Vec<u16> = filter_str.encode_utf16().collect();
        let init_dir_str = initial_drive.map(|d| format!("{}\\", d)).unwrap_or_default();
        let init_dir_w = to_wide(&init_dir_str);
        let title_w = to_wide(tr(
            "복구 불가능하게 완전 삭제(세단)할 파일 선택",
            "Select File to Permanently Shred (3-Pass Overwrite)",
            "完全削除（シュレッダー）するファイルを選択",
        ));

        let mut ofn: OPENFILENAMEW = std::mem::zeroed();
        ofn.l_struct_size = std::mem::size_of::<OPENFILENAMEW>() as DWORD;
        ofn.hwnd_owner = hwnd;
        ofn.lpstr_filter = filter_w.as_ptr();
        ofn.lpstr_file = file_buf.as_mut_ptr();
        ofn.n_max_file = file_buf.len() as DWORD;
        ofn.lpstr_initial_dir = if initial_drive.is_some() { init_dir_w.as_ptr() } else { null() };
        ofn.lpstr_title = title_w.as_ptr();
        ofn.flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR | OFN_HIDEREADONLY;

        if GetOpenFileNameW(&mut ofn) == 0 {
            return None;
        }

        let end = file_buf.iter().position(|&c| c == 0).unwrap_or(file_buf.len());
        let selected_path = String::from_utf16_lossy(&file_buf[..end]);
        let path_obj = Path::new(&selected_path);

        let confirm_msg = format!(
            "{}\n\n[ {} ]\n\n{}",
            tr(
                "선택한 파일을 3단계 덮어쓰기(0x00 → 0xFF → 난수) 방식으로 완전 파기하시겠습니까?",
                "Permanently shred the selected file with 3-pass overwrite (0x00 -> 0xFF -> Random)?",
                "選択したファイルを3段階上書き方式で完全に破棄しますか？",
            ),
            selected_path,
            tr(
                "※ 주의: 완전 삭제된 파일은 어떤 복구 프로그램으로도 절대 살릴 수 없습니다!",
                "* WARNING: Shredded files can NEVER be recovered by any recovery tool!",
                "※ 注意: 完全削除されたファイルはいかなる復元ソフトでも絶対に復元できません！",
            )
        );
        let cm_w = to_wide(&confirm_msg);
        let ct_w = to_wide(tr("파일 보안 완전 삭제 확인", "Confirm Permanent File Shredding", "ファイルの完全削除確認"));
        if MessageBoxW(hwnd, cm_w.as_ptr(), ct_w.as_ptr(), MB_YESNO | MB_ICONWARNING) != IDYES {
            return None;
        }

        match shred_file_permanently(path_obj) {
            Ok(bytes) => {
                let kb = (bytes as f64) / 1024.0;
                Some((
                    true,
                    format!(
                        "{}\n({:.1} KB — 3-Pass Overwrite Completed)",
                        tr(
                            "파일이 복구 불가능하게 완전 삭제(세단)되었습니다.",
                            "File permanently shredded beyond recovery.",
                            "ファイルが復元不可能な状態で完全に削除されました。",
                        ),
                        kb
                    ),
                ))
            }
            Err(e) => Some((
                false,
                format!(
                    "{}: {}",
                    tr("파일 완전 삭제 실패", "Failed to shred file", "ファイル完全削除に失敗しました"),
                    e
                ),
            )),
        }
    }
}

// ============================================================================
// High-DPI Aware Double-Buffered Custom Canvas & Controls
// ============================================================================
const ID_CMB_LANG: usize = 101;
const ID_CMB_DEV: usize = 102;
const ID_BTN_REFRESH: usize = 103;
const ID_TXT_PWD: usize = 104;
const ID_CHK_SHOW_PWD: usize = 105;
const ID_BTN_UNLOCK: usize = 106;
const ID_BTN_LOCK: usize = 107;
const ID_BTN_CHANGE_PWD: usize = 108;
const ID_BTN_OPEN_DRV: usize = 111;
const ID_CMB_IDLE_TIMER: usize = 112;
const ID_BTN_SHRED: usize = 113;
const ID_BTN_SAFE_EJECT: usize = 114;
const ID_BTN_TO_TRAY: usize = 115;
const ID_BTN_THEME: usize = 116;
const ID_BTN_GITHUB: usize = 117;
const ID_BTN_RESTORE_AUTORUN: usize = 118;

const ID_NAV_HOME: usize = 120;
const ID_NAV_PWD: usize = 121;
const ID_NAV_SHRED: usize = 122;
const ID_NAV_SETTINGS: usize = 123;
const ID_NAV_ABOUT: usize = 124;
const ID_TXT_CURR_PWD: usize = 130;
const ID_TXT_NEW_PWD: usize = 131;
const ID_TXT_CONF_PWD: usize = 132;
const ID_TXT_NEW_HINT: usize = 133;

const ID_TRAY_SHOW: usize = 301;
const ID_TRAY_OPEN_FOLDER: usize = 302;
const ID_TRAY_LOCK_NOW: usize = 303;
const ID_TRAY_SAFE_EJECT: usize = 304;
const ID_TRAY_EXIT: usize = 305;
const ID_TRAY_RESTORE_AUTORUN: usize = 306;

const TIMER_IDLE_CHECK: usize = 777;
const TIMER_HOVER_CHECK: usize = 778;
const IDLE_TIMEOUT_MINS: [u32; 5] = [0, 5, 10, 15, 30];
const GITHUB_REPO_URL: &str = "https://github.com/q20021410/ISP918-Secure-USB";

struct AppUiState {
    hwnd_main: HWND,
    dpi_scale: f32,
    active_tab: usize,
    h_icon: HICON,
    font_title: HFONT,
    font_card_hdr: HFONT,
    font_bold: HFONT,
    font_reg: HFONT,
    font_small_bold: HFONT,
    font_small: HFONT,
    br_card: HBRUSH,
    br_card_dark: HBRUSH,
    br_edit_dark: HBRUSH,
    br_edit_light_dis: HBRUSH,
    nav_home: HWND,
    nav_pwd: HWND,
    nav_shred: HWND,
    nav_settings: HWND,
    nav_about: HWND,
    btn_github: HWND,
    btn_restore_autorun: HWND,
    btn_theme: HWND,
    cmb_lang: HWND,
    cmb_dev: HWND,
    btn_refresh: HWND,
    txt_pwd: HWND,
    chk_show_pwd: HWND,
    btn_unlock: HWND,
    btn_lock: HWND,
    txt_curr_pwd: HWND,
    txt_new_pwd: HWND,
    txt_conf_pwd: HWND,
    txt_new_hint: HWND,
    btn_change_pwd: HWND,
    cmb_idle_timer: HWND,
    btn_open_drv: HWND,
    btn_shred: HWND,
    btn_safe_eject: HWND,
    btn_to_tray: HWND,
    hovered_ctrl: HWND,
    focused_ctrl: HWND,
    cursor_client: POINT,
    devices: Vec<DeviceInfo>,
    selected_idx: usize,
    part_info_str: String,
    sec_state_str: String,
    hint_str: String,
    retry_str: String,
    idle_limit_minutes: u32,
    dark_mode: bool,
    show_pwd: bool,
    caps_lock_on: bool,
    tray_active: bool,
    bg_pixels: Vec<u32>,
    bg_w: i32,
    bg_h: i32,
}

static mut APP_STATE: Option<AppUiState> = None;

#[inline]
unsafe fn get_state<'a>() -> Option<&'a AppUiState> {
    let ptr = &raw const APP_STATE;
    (*ptr).as_ref()
}

#[inline]
unsafe fn get_state_mut<'a>() -> Option<&'a mut AppUiState> {
    let ptr = &raw mut APP_STATE;
    (*ptr).as_mut()
}

fn sc(val: i32, scale: f32) -> i32 {
    ((val as f32) * scale).round() as i32
}

fn set_ctrl_text(hwnd: HWND, text: &str) {
    if !hwnd.is_null() {
        let w = to_wide(text);
        unsafe { SetWindowTextW(hwnd, w.as_ptr()); }
    }
}

fn get_ctrl_text(hwnd: HWND) -> String {
    if hwnd.is_null() {
        return String::new();
    }
    let mut buf = [0u16; 256];
    let len = unsafe { GetWindowTextW(hwnd, buf.as_mut_ptr(), 255) };
    if len <= 0 {
        String::new()
    } else {
        String::from_utf16_lossy(&buf[..len as usize])
    }
}

fn fill_solid_rect(hdc: HDC, rc: &RECT, color: COLORREF) {
    unsafe {
        let br = CreateSolidBrush(color);
        FillRect(hdc, rc, br);
        DeleteObject(br as HGDIOBJ);
    }
}

fn draw_rounded_box(hdc: HDC, rc: &RECT, fill_col: COLORREF, border_col: COLORREF, radius: i32) {
    unsafe {
        let br = CreateSolidBrush(fill_col);
        let pen = CreatePen(PS_SOLID, 1, border_col);
        let old_br = SelectObject(hdc, br as HGDIOBJ);
        let old_pen = SelectObject(hdc, pen as HGDIOBJ);
        RoundRect(hdc, rc.left, rc.top, rc.right, rc.bottom, radius, radius);
        SelectObject(hdc, old_br);
        SelectObject(hdc, old_pen);
        DeleteObject(br as HGDIOBJ);
        DeleteObject(pen as HGDIOBJ);
    }
}

fn draw_text_rect(hdc: HDC, text: &str, mut rc: RECT, font: HFONT, color: COLORREF, flags: UINT) {
    unsafe {
        let old_f = SelectObject(hdc, font as HGDIOBJ);
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, color);
        let w = to_wide(text);
        DrawTextW(hdc, w.as_ptr(), (w.len() - 1) as i32, &mut rc, flags | 0x0800);
        SelectObject(hdc, old_f);
    }
}

// ============================================================================
// Microsoft Fluent Design 32-Bit BGRA Pixel Shader (Acrylic Glass, SDF & Glow)
// ============================================================================
#[inline]
fn pack_bgra(r: u8, g: u8, b: u8) -> u32 {
    (b as u32) | ((g as u32) << 8) | ((r as u32) << 16) | 0xFF000000
}

#[inline]
fn unpack_rgb(px: u32) -> (f32, f32, f32) {
    let b = (px & 0xFF) as f32;
    let g = ((px >> 8) & 0xFF) as f32;
    let r = ((px >> 16) & 0xFF) as f32;
    (r, g, b)
}

#[inline]
fn colorref_to_f32(c: COLORREF) -> (f32, f32, f32) {
    let r = (c & 0xFF) as f32;
    let g = ((c >> 8) & 0xFF) as f32;
    let b = ((c >> 16) & 0xFF) as f32;
    (r, g, b)
}

#[inline]
fn blend_pixel(dst: u32, sr: f32, sg: f32, sb: f32, alpha: f32) -> u32 {
    if alpha <= 0.001 {
        return dst;
    }
    let a = alpha.clamp(0.0, 1.0);
    let inv = 1.0 - a;
    let (dr, dg, db) = unpack_rgb(dst);
    let r = (dr * inv + sr * a).clamp(0.0, 255.0) as u8;
    let g = (dg * inv + sg * a).clamp(0.0, 255.0) as u8;
    let b = (db * inv + sb * a).clamp(0.0, 255.0) as u8;
    pack_bgra(r, g, b)
}

#[inline]
fn add_glow_pixel(dst: u32, gr: f32, gg: f32, gb: f32, intensity: f32) -> u32 {
    if intensity <= 0.001 {
        return dst;
    }
    let k = intensity.clamp(0.0, 1.0);
    let (dr, dg, db) = unpack_rgb(dst);
    // Soft additive screen light bloom
    let r = (dr + (255.0 - dr * 0.65) * (gr / 255.0) * k).clamp(0.0, 255.0) as u8;
    let g = (dg + (255.0 - dg * 0.65) * (gg / 255.0) * k).clamp(0.0, 255.0) as u8;
    let b = (db + (255.0 - db * 0.65) * (gb / 255.0) * k).clamp(0.0, 255.0) as u8;
    pack_bgra(r, g, b)
}

#[inline]
fn sdf_round_rect(px: f32, py: f32, l: f32, t: f32, r: f32, b: f32, rad: f32) -> f32 {
    let cx = (l + r) * 0.5;
    let cy = (t + b) * 0.5;
    let hx = ((r - l) * 0.5 - rad).max(0.0);
    let hy = ((b - t) * 0.5 - rad).max(0.0);
    let dx = (px - cx).abs() - hx;
    let dy = (py - cy).abs() - hy;
    let out_x = dx.max(0.0);
    let out_y = dy.max(0.0);
    let out_dist = (out_x * out_x + out_y * out_y).sqrt();
    let in_dist = dx.max(dy).min(0.0);
    out_dist + in_dist - rad
}

unsafe fn blit_bgra_buffer(hdc: HDC, bw: i32, bh: i32, pixels: &[u32]) {
    if bw <= 0 || bh <= 0 || pixels.len() < (bw * bh) as usize {
        return;
    }
    let bmi = BITMAPINFO {
        bmi_header: BITMAPINFOHEADER {
            bi_size: std::mem::size_of::<BITMAPINFOHEADER>() as DWORD,
            bi_width: bw,
            bi_height: -bh, // Top-down DIB
            bi_planes: 1,
            bi_bit_count: 32,
            bi_compression: 0, // BI_RGB
            bi_size_image: (bw * bh * 4) as DWORD,
            bi_x_pels_per_meter: 0,
            bi_y_pels_per_meter: 0,
            bi_clr_used: 0,
            bi_clr_important: 0,
        },
        bmi_colors: [0],
    };
    StretchDIBits(
        hdc,
        0,
        0,
        bw,
        bh,
        0,
        0,
        bw,
        bh,
        pixels.as_ptr() as *const c_void,
        &bmi,
        0,
        SRCCOPY,
    );
}

fn fill_fluent_ambient_backdrop(
    buf: &mut [u32],
    bw: i32,
    bh: i32,
    sb_w: i32,
    s: f32,
    dark: bool,
    status_glow: COLORREF,
) {
    let fw = (bw as f32).max(1.0);
    let fh = (bh as f32).max(1.0);
    let (sr, sg, sb) = colorref_to_f32(status_glow);

    // Subtle Mica ambient tint blooms behind the right LayerFillColorDefault pane
    let c1x = fw * 0.78;
    let c1y = fh * 0.14;
    let r1_inv = 1.0 / (fw * 0.50).max(1.0);

    let c2x = fw * 0.36;
    let c2y = fh * 0.22;
    let r2_inv = 1.0 / (fw * 0.45).max(1.0);

    let c3x = fw * 0.60;
    let c3y = fh * 0.82;
    let r3_inv = 1.0 / (fw * 0.48).max(1.0);

    let pane_l = sb_w as f32;
    let pane_t = sc(4, s) as f32;
    let pane_r = (bw + sc(24, s)) as f32;
    let pane_b = (bh + sc(24, s)) as f32;
    let pane_rad = sc(12, s) as f32;

    for y in 0..bh {
        let fy = y as f32 + 0.5;
        let row_idx = (y * bw) as usize;

        for x in 0..bw {
            let fx = x as f32 + 0.5;
            // Official WinUI 3 SolidBackgroundFillColorBase (#202020 Dark / #F3F3F3 Light)
            let mut px = if dark {
                pack_bgra(32, 32, 32)
            } else {
                pack_bgra(243, 243, 243)
            };

            // Subtle Mica wallpaper tint sampling simulation
            let d1 = ((fx - c1x) * (fx - c1x) + (fy - c1y) * (fy - c1y)).sqrt() * r1_inv;
            if d1 < 1.0 {
                let t = (1.0 - d1) * (1.0 - d1);
                if dark {
                    px = add_glow_pixel(px, 124.0, 58.0, 237.0, t * 0.14);
                } else {
                    px = blend_pixel(px, 237.0, 233.0, 254.0, t * 0.45);
                }
            }
            let d2 = ((fx - c2x) * (fx - c2x) + (fy - c2y) * (fy - c2y)).sqrt() * r2_inv;
            if d2 < 1.0 {
                let t = (1.0 - d2) * (1.0 - d2);
                if dark {
                    px = add_glow_pixel(px, 0.0, 120.0, 212.0, t * 0.14);
                } else {
                    px = blend_pixel(px, 224.0, 242.0, 254.0, t * 0.45);
                }
            }
            let d3 = ((fx - c3x) * (fx - c3x) + (fy - c3y) * (fy - c3y)).sqrt() * r3_inv;
            if d3 < 1.0 {
                let t = (1.0 - d3) * (1.0 - d3);
                if dark {
                    px = add_glow_pixel(px, sr, sg, sb, t * 0.10);
                } else {
                    px = blend_pixel(px, sr, sg, sb, t * 0.08);
                }
            }

            // Official WinUI 3 NavigationView Content Frame Layer:
            // LayerFillColorDefault (#4C3A3A3A in dark mode, #80FFFFFF in light mode)
            // with a rounded top-left corner (12px) and 1px CardStrokeColorDefault border!
            let d_pane = sdf_round_rect(fx, fy, pane_l, pane_t, pane_r, pane_b, pane_rad);
            if d_pane < 0.75 {
                let cov = (0.5 - d_pane).clamp(0.0, 1.0);
                if dark {
                    px = blend_pixel(px, 44.0, 44.0, 44.0, 0.45 * cov);
                } else {
                    px = blend_pixel(px, 255.0, 255.0, 255.0, 0.65 * cov);
                }
            }
            if d_pane > -1.35 && d_pane < 0.75 {
                let rim_w = (1.0 - (d_pane + 0.3).abs() * 1.05).clamp(0.0, 1.0);
                if dark {
                    px = blend_pixel(px, 255.0, 255.0, 255.0, 0.09 * rim_w);
                } else {
                    px = blend_pixel(px, 0.0, 0.0, 0.0, 0.07 * rim_w);
                }
            }

            buf[row_idx + x as usize] = px;
        }
    }
}

fn fluent_apply_acrylic_noise(buf: &mut [u32], bw: i32, bh: i32, rc: &RECT, rad: f32, strength: f32) {
    if strength <= 0.001 {
        return;
    }
    let x0 = rc.left.max(0);
    let x1 = rc.right.min(bw);
    let y0 = rc.top.max(0);
    let y1 = rc.bottom.min(bh);
    let l = rc.left as f32;
    let t = rc.top as f32;
    let r = rc.right as f32;
    let b = rc.bottom as f32;

    for y in y0..y1 {
        let fy = y as f32 + 0.5;
        let row_idx = (y * bw) as usize;
        for x in x0..x1 {
            let fx = x as f32 + 0.5;
            if sdf_round_rect(fx, fy, l, t, r, b, rad) < -0.5 {
                let mut h = (x as u32).wrapping_mul(374761393).wrapping_add((y as u32).wrapping_mul(668265263));
                h = (h ^ (h >> 13)).wrapping_mul(1274126177);
                let n = ((h & 0xFF) as f32 / 255.0 - 0.5) * 2.0 * strength;
                let idx = row_idx + x as usize;
                let (dr, dg, db) = unpack_rgb(buf[idx]);
                buf[idx] = pack_bgra(
                    (dr + n).clamp(0.0, 255.0) as u8,
                    (dg + n).clamp(0.0, 255.0) as u8,
                    (db + n).clamp(0.0, 255.0) as u8,
                );
            }
        }
    }
}

fn fluent_apply_reveal_highlight(
    buf: &mut [u32],
    bw: i32,
    bh: i32,
    rc: &RECT,
    rad: f32,
    mx: f32,
    my: f32,
    reveal_radius: f32,
    glow_col: COLORREF,
    fill_boost: f32,
    rim_boost: f32,
) {
    if reveal_radius <= 1.0 {
        return;
    }
    let pad = 2;
    let x0 = (rc.left - pad).max(0);
    let x1 = (rc.right + pad).min(bw);
    let y0 = (rc.top - pad).max(0);
    let y1 = (rc.bottom + pad).min(bh);

    if mx < (x0 as f32 - reveal_radius)
        || mx > (x1 as f32 + reveal_radius)
        || my < (y0 as f32 - reveal_radius)
        || my > (y1 as f32 + reveal_radius)
    {
        return;
    }

    let (gr, gg, gb) = colorref_to_f32(glow_col);
    let l = rc.left as f32;
    let t = rc.top as f32;
    let r = rc.right as f32;
    let b = rc.bottom as f32;
    let inv_rad = 1.0 / reveal_radius;

    for y in y0..y1 {
        let fy = y as f32 + 0.5;
        let dy_m = fy - my;
        let row_idx = (y * bw) as usize;
        for x in x0..x1 {
            let fx = x as f32 + 0.5;
            let dx_m = fx - mx;
            let dist_m = (dx_m * dx_m + dy_m * dy_m).sqrt() * inv_rad;
            if dist_m >= 1.0 {
                continue;
            }
            let att = (1.0 - dist_m) * (1.0 - dist_m);
            let d = sdf_round_rect(fx, fy, l, t, r, b, rad);
            let idx = row_idx + x as usize;
            if d < 0.5 && fill_boost > 0.001 {
                let cov = (0.5 - d).clamp(0.0, 1.0);
                buf[idx] = add_glow_pixel(buf[idx], gr, gg, gb, att * fill_boost * cov);
            }
            if d > -1.8 && d < 0.75 && rim_boost > 0.001 {
                let rim_w = (1.0 - (d + 0.45).abs() * 0.85).clamp(0.0, 1.0);
                buf[idx] = add_glow_pixel(buf[idx], gr, gg, gb, att * rim_boost * rim_w);
            }
        }
    }
}

fn fluent_draw_bottom_focus_pill(
    buf: &mut [u32],
    bw: i32,
    bh: i32,
    rc_box: &RECT,
    rad: f32,
    s: f32,
    pill_col: COLORREF,
    is_focused: bool,
) {
    let pill_h = if is_focused { sc(2, s).max(2) } else { sc(1, s).max(1) };
    let inset = if is_focused { sc(3, s) } else { sc(6, s) };
    let rc_p = RECT {
        left: rc_box.left + inset,
        top: rc_box.bottom - pill_h,
        right: rc_box.right - inset,
        bottom: rc_box.bottom,
    };
    let (pr, pg, pb) = colorref_to_f32(pill_col);
    let x0 = rc_p.left.max(0);
    let x1 = rc_p.right.min(bw);
    let y0 = rc_p.top.max(0);
    let y1 = rc_p.bottom.min(bh);
    let l = rc_box.left as f32;
    let t = rc_box.top as f32;
    let r = rc_box.right as f32;
    let b = rc_box.bottom as f32;

    for y in y0..y1 {
        let fy = y as f32 + 0.5;
        let row_idx = (y * bw) as usize;
        for x in x0..x1 {
            let fx = x as f32 + 0.5;
            if sdf_round_rect(fx, fy, l, t, r, b, rad) < 0.5 {
                let idx = row_idx + x as usize;
                buf[idx] = blend_pixel(buf[idx], pr, pg, pb, if is_focused { 0.98 } else { 0.45 });
            }
        }
    }
}

fn fluent_add_rect_glow(
    buf: &mut [u32],
    bw: i32,
    bh: i32,
    rc: &RECT,
    rad: f32,
    glow_col: COLORREF,
    spread: f32,
    intensity: f32,
) {
    if spread <= 0.5 || intensity <= 0.001 {
        return;
    }
    let (gr, gg, gb) = colorref_to_f32(glow_col);
    let pad = (spread.ceil() as i32) + 2;
    let x0 = (rc.left - pad).max(0);
    let x1 = (rc.right + pad).min(bw);
    let y0 = (rc.top - pad).max(0);
    let y1 = (rc.bottom + pad).min(bh);

    let l = rc.left as f32;
    let t = rc.top as f32;
    let r = rc.right as f32;
    let b = rc.bottom as f32;

    for y in y0..y1 {
        let fy = y as f32 + 0.5;
        let row_idx = (y * bw) as usize;
        for x in x0..x1 {
            let fx = x as f32 + 0.5;
            let d = sdf_round_rect(fx, fy, l, t, r, b, rad);
            if d > -2.0 && d < spread {
                let norm = (1.0 - d.max(0.0) / spread).clamp(0.0, 1.0);
                let k = norm * norm * intensity;
                let idx = row_idx + x as usize;
                buf[idx] = add_glow_pixel(buf[idx], gr, gg, gb, k);
            }
        }
    }
}

fn fluent_draw_glass_box(
    buf: &mut [u32],
    bw: i32,
    bh: i32,
    rc: &RECT,
    rad: f32,
    fill_top: COLORREF,
    fill_bot: COLORREF,
    fill_alpha: f32,
    rim_top: COLORREF,
    rim_bot: COLORREF,
    rim_alpha: f32,
    glow_col: COLORREF,
    glow_spread: f32,
    glow_intensity: f32,
    drop_shadow: f32,
) {
    let pad = (glow_spread.max(12.0).ceil() as i32) + 4;
    let x0 = (rc.left - pad).max(0);
    let x1 = (rc.right + pad).min(bw);
    let y0 = (rc.top - pad).max(0);
    let y1 = (rc.bottom + pad).min(bh);

    let l = rc.left as f32;
    let t = rc.top as f32;
    let r = rc.right as f32;
    let b = rc.bottom as f32;
    let w_inv = 1.0 / (r - l).max(1.0);
    let h_inv = 1.0 / (b - t).max(1.0);

    let (ftr, ftg, ftb) = colorref_to_f32(fill_top);
    let (fbr, fbg, fbb) = colorref_to_f32(fill_bot);
    let (rtr, rtg, rtb) = colorref_to_f32(rim_top);
    let (rbr, rbg, rbb) = colorref_to_f32(rim_bot);
    let (gr, gg, gb) = colorref_to_f32(glow_col);

    for y in y0..y1 {
        let fy = y as f32 + 0.5;
        let vy = ((fy - t) * h_inv).clamp(0.0, 1.0);
        let row_idx = (y * bw) as usize;

        for x in x0..x1 {
            let fx = x as f32 + 0.5;
            let vx = ((fx - l) * w_inv).clamp(0.0, 1.0);
            let idx = row_idx + x as usize;
            let mut px = buf[idx];

            // 1. Soft Vertical Drop Shadow
            if drop_shadow > 0.001 {
                let ds = sdf_round_rect(fx, fy - 4.0, l + 1.0, t + 1.0, r - 1.0, b, rad);
                if ds > -1.0 && ds < 10.0 {
                    let st = (1.0 - ds.max(0.0) / 10.0).clamp(0.0, 1.0);
                    px = blend_pixel(px, 2.0, 4.0, 10.0, st * st * drop_shadow);
                }
            }

            let d = sdf_round_rect(fx, fy, l, t, r, b, rad);

            // 2. Soft Outer Translucent Glow Halo
            if glow_intensity > 0.001 && glow_spread > 0.5 && d > -1.5 && d < glow_spread {
                let gt = (1.0 - d.max(0.0) / glow_spread).clamp(0.0, 1.0);
                px = add_glow_pixel(px, gr, gg, gb, gt * gt * glow_intensity);
            }

            // 3. Anti-Aliased Frosted Acrylic Interior Fill
            if d < 0.75 {
                let cov = (0.5 - d).clamp(0.0, 1.0);
                let cr = ftr + (fbr - ftr) * vy;
                let cg = ftg + (fbg - ftg) * vy;
                let cb = ftb + (fbb - ftb) * vy;
                px = blend_pixel(px, cr, cg, cb, fill_alpha * cov);

                // Subtle top-left diagonal glass sheen inside card/button
                let sheen = ((1.0 - vy * 1.6).max(0.0)) * (1.0 - vx * 0.45);
                if sheen > 0.01 && d < -0.5 {
                    px = add_glow_pixel(px, 220.0, 240.0, 255.0, sheen * 0.07 * cov);
                }
            }

            // 4. Anti-Aliased 1.3px Directional Specular Glass Rim Border
            if rim_alpha > 0.001 && d > -1.6 && d < 0.75 {
                let rim_w = (1.0 - (d + 0.45).abs() * 0.95).clamp(0.0, 1.0);
                let diag = ((vx * 0.45) + (vy * 0.55)).clamp(0.0, 1.0);
                let rr = rtr + (rbr - rtr) * diag;
                let rg = rtg + (rbg - rtg) * diag;
                let rb = rtb + (rbb - rtb) * diag;
                px = blend_pixel(px, rr, rg, rb, rim_alpha * rim_w);
            }

            buf[idx] = px;
        }
    }
}

fn fluent_draw_hero_wave_card(buf: &mut [u32], bw: i32, bh: i32, rc: &RECT, rad: f32, s: f32) {
    // First add an outer violet-cyan glow halo around the hero card
    fluent_add_rect_glow(buf, bw, bh, rc, rad, rgb(139, 92, 246), sc(16, s) as f32, 0.35);

    let pad = 4;
    let x0 = (rc.left - pad).max(0);
    let x1 = (rc.right + pad).min(bw);
    let y0 = (rc.top - pad).max(0);
    let y1 = (rc.bottom + pad).min(bh);

    let l = rc.left as f32;
    let t = rc.top as f32;
    let r = rc.right as f32;
    let b = rc.bottom as f32;
    let w_inv = 1.0 / (r - l).max(1.0);
    let h_inv = 1.0 / (b - t).max(1.0);

    for y in y0..y1 {
        let fy = y as f32 + 0.5;
        let vy = ((fy - t) * h_inv).clamp(0.0, 1.0);
        let row_idx = (y * bw) as usize;

        for x in x0..x1 {
            let fx = x as f32 + 0.5;
            let vx = ((fx - l) * w_inv).clamp(0.0, 1.0);
            let d = sdf_round_rect(fx, fy, l, t, r, b, rad);
            if d >= 0.75 {
                continue;
            }
            let cov = (0.5 - d).clamp(0.0, 1.0);
            let idx = row_idx + x as usize;

            // Deep midnight base inside hero card
            let mut hr = 7.0 + vx * 14.0;
            let mut hg = 11.0 + (1.0 - vy) * 12.0;
            let mut hb = 28.0 + vx * 26.0;

            // Flowing 3D Fluent Violet/Magenta Wave Ribbon (like WPF Gallery Hero Wave!)
            let wave1_y = 0.72 - 0.48 * ((vx * 3.6 - 0.7).sin() * 0.5 + 0.5);
            let dist1 = ((vy - wave1_y).abs() * 2.1).min(1.0);
            let w1 = (1.0 - dist1) * (1.0 - dist1) * (0.25 + 0.75 * vx);
            hr += w1 * 145.0;
            hg += w1 * 38.0;
            hb += w1 * 215.0;

            // Secondary Electric Cyan/Azure Flowing Wave Ribbon
            let wave2_y = 0.30 + 0.45 * ((vx * 4.2 + 0.4).cos() * 0.5 + 0.5);
            let dist2 = ((vy - wave2_y).abs() * 2.3).min(1.0);
            let w2 = (1.0 - dist2) * (1.0 - dist2) * (0.35 + 0.65 * (1.0 - vx * 0.4));
            hr += w2 * 18.0;
            hg += w2 * 155.0;
            hb += w2 * 235.0;

            // Specular Wave Crest Highlight
            let crest = (1.0 - ((vy - wave1_y + 0.05).abs() * 7.5).min(1.0)).powi(2) * vx;
            hr += crest * 95.0;
            hg += crest * 75.0;
            hb += crest * 120.0;

            let mut px = blend_pixel(
                buf[idx],
                hr.clamp(0.0, 255.0),
                hg.clamp(0.0, 255.0),
                hb.clamp(0.0, 255.0),
                0.92 * cov,
            );

            // Glowing Specular Glass Rim on Hero Card
            if d > -1.6 && d < 0.75 {
                let rim_w = (1.0 - (d + 0.45).abs() * 0.95).clamp(0.0, 1.0);
                let rr = 125.0 + vx * 90.0;
                let rg = 211.0 - vx * 70.0;
                let rb = 252.0;
                px = blend_pixel(px, rr, rg, rb, 0.85 * rim_w);
            }

            buf[idx] = px;
        }
    }
}

fn fluent_extract_sub_buffer(
    src: &[u32],
    src_w: i32,
    src_h: i32,
    ox: i32,
    oy: i32,
    w: i32,
    h: i32,
    fallback_col: COLORREF,
) -> Vec<u32> {
    let (fr, fg, fb) = colorref_to_f32(fallback_col);
    let fb_px = pack_bgra(fr as u8, fg as u8, fb as u8);
    let mut out = vec![fb_px; (w.max(1) * h.max(1)) as usize];
    if src.is_empty() || src_w <= 0 || src_h <= 0 {
        return out;
    }
    for y in 0..h {
        let sy = oy + y;
        if sy < 0 || sy >= src_h {
            continue;
        }
        let dst_row = (y * w) as usize;
        let src_row = (sy * src_w) as usize;
        for x in 0..w {
            let sx = ox + x;
            if sx >= 0 && sx < src_w {
                let idx = src_row + sx as usize;
                if idx < src.len() {
                    out[dst_row + x as usize] = src[idx];
                }
            }
        }
    }
    out
}

unsafe fn draw_flag_icon(hdc: HDC, x: i32, y: i32, w: i32, h: i32, lang: AppLang) {
    let rc_flag = RECT { left: x, top: y, right: x + w, bottom: y + h };
    // White flag base with subtle slate border
    draw_rounded_box(hdc, &rc_flag, rgb(255, 255, 255), rgb(148, 163, 184), 2);

    match lang {
        AppLang::KO => {
            // South Korea Flag (Taegeukgi)
            let cx = x + w / 2;
            let cy = y + h / 2;
            let r = (h / 4).max(3);

            // Trigrams (4 corner black diagonal bars)
            let pen_blk = CreatePen(PS_SOLID, 1, rgb(15, 23, 42));
            let old_p = SelectObject(hdc, pen_blk as HGDIOBJ);
            // Top-left (Geon)
            MoveToEx(hdc, x + 3, y + 4, null_mut());
            LineTo(hdc, x + 6, y + 2);
            // Top-right (Gam)
            MoveToEx(hdc, x + w - 6, y + 2, null_mut());
            LineTo(hdc, x + w - 3, y + 4);
            // Bottom-left (Ri)
            MoveToEx(hdc, x + 3, y + h - 5, null_mut());
            LineTo(hdc, x + 6, y + h - 3);
            // Bottom-right (Gon)
            MoveToEx(hdc, x + w - 6, y + h - 3, null_mut());
            LineTo(hdc, x + w - 3, y + h - 5);
            SelectObject(hdc, old_p);
            DeleteObject(pen_blk as HGDIOBJ);

            // Blue bottom circle
            let br_blue = CreateSolidBrush(rgb(0, 71, 160));
            let pen_blue = CreatePen(PS_SOLID, 1, rgb(0, 71, 160));
            let ob = SelectObject(hdc, br_blue as HGDIOBJ);
            let op = SelectObject(hdc, pen_blue as HGDIOBJ);
            Ellipse(hdc, cx - r, cy - r, cx + r, cy + r);
            SelectObject(hdc, ob);
            SelectObject(hdc, op);
            DeleteObject(br_blue as HGDIOBJ);
            DeleteObject(pen_blue as HGDIOBJ);

            // Red top semicircle (Pie from right to left counter-clockwise = top half)
            let br_red = CreateSolidBrush(rgb(205, 46, 58));
            let pen_red = CreatePen(PS_SOLID, 1, rgb(205, 46, 58));
            let ob2 = SelectObject(hdc, br_red as HGDIOBJ);
            let op2 = SelectObject(hdc, pen_red as HGDIOBJ);
            Pie(hdc, cx - r, cy - r, cx + r, cy + r, cx + r, cy, cx - r, cy);
            SelectObject(hdc, ob2);
            SelectObject(hdc, op2);
            DeleteObject(br_red as HGDIOBJ);
            DeleteObject(pen_red as HGDIOBJ);
        }
        AppLang::EN => {
            // US Flag (Stars & Stripes)
            let inner_l = x + 1;
            let inner_r = x + w - 1;
            let inner_t = y + 1;
            let inner_b = y + h - 1;
            let ih = (inner_b - inner_t).max(7);

            for s in 0..7 {
                if s % 2 == 0 {
                    let st_top = inner_t + (s * ih) / 7;
                    let st_bot = inner_t + ((s + 1) * ih) / 7;
                    let rc_s = RECT {
                        left: inner_l,
                        top: st_top,
                        right: inner_r,
                        bottom: st_bot.max(st_top + 1),
                    };
                    fill_solid_rect(hdc, &rc_s, rgb(191, 10, 48));
                }
            }
            // Blue Canton
            let rc_canton = RECT {
                left: inner_l,
                top: inner_t,
                right: inner_l + (w * 48) / 100,
                bottom: inner_t + (ih * 4) / 7,
            };
            fill_solid_rect(hdc, &rc_canton, rgb(0, 40, 104));

            // Tiny white stars inside canton
            let c_w = rc_canton.right - rc_canton.left;
            let c_h = rc_canton.bottom - rc_canton.top;
            for sx in &[1, 3] {
                for sy in &[1, 2] {
                    let px = rc_canton.left + (c_w * sx) / 4;
                    let py = rc_canton.top + (c_h * sy) / 3;
                    let rc_dot = RECT { left: px, top: py, right: px + 1, bottom: py + 1 };
                    fill_solid_rect(hdc, &rc_dot, rgb(255, 255, 255));
                }
            }
        }
        AppLang::JA => {
            // Japan Flag (Hinomaru)
            let cx = x + w / 2;
            let cy = y + h / 2;
            let r = (h / 4).max(3);
            let br_red = CreateSolidBrush(rgb(188, 0, 45));
            let pen_red = CreatePen(PS_SOLID, 1, rgb(188, 0, 45));
            let ob = SelectObject(hdc, br_red as HGDIOBJ);
            let op = SelectObject(hdc, pen_red as HGDIOBJ);
            Ellipse(hdc, cx - r, cy - r, cx + r, cy + r);
            SelectObject(hdc, ob);
            SelectObject(hdc, op);
            DeleteObject(br_red as HGDIOBJ);
            DeleteObject(pen_red as HGDIOBJ);
        }
    }
}

unsafe fn draw_theme_icon(hdc: HDC, cx: i32, cy: i32, s: f32, is_dark: bool, bg_col: COLORREF) {
    if is_dark {
        // Golden Crescent Moon
        let r = sc(6, s).max(4);
        let br_moon = CreateSolidBrush(rgb(251, 191, 36));
        let pen_moon = CreatePen(PS_SOLID, 1, rgb(251, 191, 36));
        let ob = SelectObject(hdc, br_moon as HGDIOBJ);
        let op = SelectObject(hdc, pen_moon as HGDIOBJ);
        Ellipse(hdc, cx - r, cy - r, cx + r, cy + r);
        SelectObject(hdc, ob);
        SelectObject(hdc, op);
        DeleteObject(br_moon as HGDIOBJ);
        DeleteObject(pen_moon as HGDIOBJ);

        // Cutout circle shifted upper-right to form crescent
        let ox = sc(3, s).max(2);
        let oy = sc(2, s).max(1);
        let br_cut = CreateSolidBrush(bg_col);
        let pen_cut = CreatePen(PS_SOLID, 1, bg_col);
        let ob2 = SelectObject(hdc, br_cut as HGDIOBJ);
        let op2 = SelectObject(hdc, pen_cut as HGDIOBJ);
        Ellipse(hdc, cx - r + ox, cy - r - oy, cx + r + ox, cy + r - oy);
        SelectObject(hdc, ob2);
        SelectObject(hdc, op2);
        DeleteObject(br_cut as HGDIOBJ);
        DeleteObject(pen_cut as HGDIOBJ);
    } else {
        // Amber Sun with 8 Rays
        let r_core = sc(4, s).max(3);
        let r_ray = sc(7, s).max(5);
        let r_diag = sc(5, s).max(4);
        let pen_sun = CreatePen(PS_SOLID, sc(2, s).max(1), rgb(245, 158, 11));
        let op = SelectObject(hdc, pen_sun as HGDIOBJ);
        MoveToEx(hdc, cx - r_ray, cy, null_mut());
        LineTo(hdc, cx + r_ray, cy);
        MoveToEx(hdc, cx, cy - r_ray, null_mut());
        LineTo(hdc, cx, cy + r_ray);
        MoveToEx(hdc, cx - r_diag, cy - r_diag, null_mut());
        LineTo(hdc, cx + r_diag, cy + r_diag);
        MoveToEx(hdc, cx - r_diag, cy + r_diag, null_mut());
        LineTo(hdc, cx + r_diag, cy - r_diag);
        SelectObject(hdc, op);
        DeleteObject(pen_sun as HGDIOBJ);

        let br_sun = CreateSolidBrush(rgb(245, 158, 11));
        let pen_core = CreatePen(PS_SOLID, 1, rgb(245, 158, 11));
        let ob = SelectObject(hdc, br_sun as HGDIOBJ);
        let op2 = SelectObject(hdc, pen_core as HGDIOBJ);
        Ellipse(hdc, cx - r_core, cy - r_core, cx + r_core, cy + r_core);
        SelectObject(hdc, ob);
        SelectObject(hdc, op2);
        DeleteObject(br_sun as HGDIOBJ);
        DeleteObject(pen_core as HGDIOBJ);
    }
}

unsafe fn draw_circle_dot(hdc: HDC, cx: i32, cy: i32, r: i32, col: COLORREF) {
    let br = CreateSolidBrush(col);
    let pen = CreatePen(PS_SOLID, 1, col);
    let ob = SelectObject(hdc, br as HGDIOBJ);
    let op = SelectObject(hdc, pen as HGDIOBJ);
    Ellipse(hdc, cx - r, cy - r, cx + r, cy + r);
    SelectObject(hdc, ob);
    SelectObject(hdc, op);
    DeleteObject(br as HGDIOBJ);
    DeleteObject(pen as HGDIOBJ);
}

unsafe fn draw_elevated_card(hdc: HDC, rc: &RECT, bg_col: COLORREF, border_col: COLORREF, s: f32, dark: bool) {
    let rad = sc(12, s);
    // Subtle outer bottom drop shadow
    let shadow_col = if dark { rgb(2, 6, 23) } else { rgb(203, 213, 225) };
    let rc_shadow = RECT {
        left: rc.left + sc(1, s),
        top: rc.top + sc(2, s),
        right: rc.right - sc(1, s),
        bottom: rc.bottom + sc(2, s),
    };
    draw_rounded_box(hdc, &rc_shadow, shadow_col, shadow_col, rad);
    draw_rounded_box(hdc, rc, bg_col, border_col, rad);

    // Top inner specular highlight line
    let hi_col = if dark { rgb(71, 85, 105) } else { rgb(255, 255, 255) };
    let pen_hi = CreatePen(PS_SOLID, 1, hi_col);
    let op = SelectObject(hdc, pen_hi as HGDIOBJ);
    MoveToEx(hdc, rc.left + sc(10, s), rc.top + 1, null_mut());
    LineTo(hdc, rc.right - sc(10, s), rc.top + 1);
    SelectObject(hdc, op);
    DeleteObject(pen_hi as HGDIOBJ);
}

unsafe fn draw_button_icon(hdc: HDC, id: usize, cx: i32, cy: i32, s: f32, col: COLORREF, bg_col: COLORREF) {
    let pw = sc(2, s).max(1);
    let pen = CreatePen(PS_SOLID, pw, col);
    let op = SelectObject(hdc, pen as HGDIOBJ);

    match id {
        ID_BTN_UNLOCK => {
            // Open Padlock
            let rc_body = RECT {
                left: cx - sc(6, s),
                top: cy - sc(1, s),
                right: cx + sc(6, s),
                bottom: cy + sc(7, s),
            };
            draw_rounded_box(hdc, &rc_body, col, col, sc(3, s));
            // Shackle (shifted open on right)
            MoveToEx(hdc, cx - sc(3, s), cy - sc(1, s), null_mut());
            LineTo(hdc, cx - sc(3, s), cy - sc(6, s));
            LineTo(hdc, cx + sc(4, s), cy - sc(6, s));
            LineTo(hdc, cx + sc(4, s), cy - sc(4, s));
            // Keyhole cutout dot
            draw_circle_dot(hdc, cx, cy + sc(3, s), sc(1, s).max(1), bg_col);
        }
        ID_BTN_LOCK => {
            // Closed Padlock
            let rc_body = RECT {
                left: cx - sc(6, s),
                top: cy - sc(1, s),
                right: cx + sc(6, s),
                bottom: cy + sc(7, s),
            };
            draw_rounded_box(hdc, &rc_body, col, col, sc(3, s));
            // Closed shackle
            MoveToEx(hdc, cx - sc(3, s), cy - sc(1, s), null_mut());
            LineTo(hdc, cx - sc(3, s), cy - sc(6, s));
            LineTo(hdc, cx + sc(3, s), cy - sc(6, s));
            LineTo(hdc, cx + sc(3, s), cy - sc(1, s));
            draw_circle_dot(hdc, cx, cy + sc(3, s), sc(1, s).max(1), bg_col);
        }
        ID_BTN_CHANGE_PWD | ID_NAV_PWD => {
            // Key Icon
            let r = sc(4, s);
            draw_circle_dot(hdc, cx - sc(3, s), cy, r, col);
            draw_circle_dot(hdc, cx - sc(3, s), cy, (r - sc(2, s)).max(1), bg_col);
            MoveToEx(hdc, cx + sc(1, s), cy, null_mut());
            LineTo(hdc, cx + sc(7, s), cy);
            MoveToEx(hdc, cx + sc(4, s), cy, null_mut());
            LineTo(hdc, cx + sc(4, s), cy + sc(3, s));
            MoveToEx(hdc, cx + sc(6, s), cy, null_mut());
            LineTo(hdc, cx + sc(6, s), cy + sc(4, s));
        }
        ID_NAV_HOME => {
            // Home House Icon
            MoveToEx(hdc, cx - sc(6, s), cy, null_mut());
            LineTo(hdc, cx, cy - sc(6, s));
            LineTo(hdc, cx + sc(6, s), cy);
            MoveToEx(hdc, cx - sc(4, s), cy - sc(1, s), null_mut());
            LineTo(hdc, cx - sc(4, s), cy + sc(5, s));
            LineTo(hdc, cx + sc(4, s), cy + sc(5, s));
            LineTo(hdc, cx + sc(4, s), cy - sc(1, s));
        }
        ID_NAV_SETTINGS => {
            // Settings Sliders Icon (3 horizontal tracks with circular knobs)
            MoveToEx(hdc, cx - sc(6, s), cy - sc(4, s), null_mut());
            LineTo(hdc, cx + sc(6, s), cy - sc(4, s));
            draw_circle_dot(hdc, cx - sc(2, s), cy - sc(4, s), sc(2, s).max(2), col);

            MoveToEx(hdc, cx - sc(6, s), cy, null_mut());
            LineTo(hdc, cx + sc(6, s), cy);
            draw_circle_dot(hdc, cx + sc(3, s), cy, sc(2, s).max(2), col);

            MoveToEx(hdc, cx - sc(6, s), cy + sc(4, s), null_mut());
            LineTo(hdc, cx + sc(6, s), cy + sc(4, s));
            draw_circle_dot(hdc, cx - sc(1, s), cy + sc(4, s), sc(2, s).max(2), col);
        }
        ID_NAV_ABOUT => {
            // Info Circle (i) Icon
            let r = sc(6, s);
            draw_circle_dot(hdc, cx, cy, r, col);
            draw_circle_dot(hdc, cx, cy, (r - sc(2, s)).max(1), bg_col);
            draw_circle_dot(hdc, cx, cy - sc(3, s), sc(1, s).max(1), col);
            MoveToEx(hdc, cx, cy - sc(1, s), null_mut());
            LineTo(hdc, cx, cy + sc(4, s));
        }
        ID_BTN_GITHUB => {
            // External Link / Launch Box Icon
            MoveToEx(hdc, cx - sc(1, s), cy - sc(5, s), null_mut());
            LineTo(hdc, cx - sc(5, s), cy - sc(5, s));
            LineTo(hdc, cx - sc(5, s), cy + sc(5, s));
            LineTo(hdc, cx + sc(5, s), cy + sc(5, s));
            LineTo(hdc, cx + sc(5, s), cy + sc(1, s));
            MoveToEx(hdc, cx - sc(1, s), cy + sc(1, s), null_mut());
            LineTo(hdc, cx + sc(5, s), cy - sc(5, s));
            MoveToEx(hdc, cx + sc(1, s), cy - sc(5, s), null_mut());
            LineTo(hdc, cx + sc(5, s), cy - sc(5, s));
            LineTo(hdc, cx + sc(5, s), cy - sc(1, s));
        }
        ID_BTN_OPEN_DRV => {
            // Folder Icon
            let rc_tab = RECT {
                left: cx - sc(6, s),
                top: cy - sc(5, s),
                right: cx - sc(1, s),
                bottom: cy - sc(2, s),
            };
            let rc_folder = RECT {
                left: cx - sc(6, s),
                top: cy - sc(3, s),
                right: cx + sc(6, s),
                bottom: cy + sc(5, s),
            };
            draw_rounded_box(hdc, &rc_tab, col, col, sc(2, s));
            draw_rounded_box(hdc, &rc_folder, col, col, sc(2, s));
        }
        ID_BTN_SHRED | ID_NAV_SHRED => {
            // Shredder Document + Strips Icon
            let rc_doc = RECT {
                left: cx - sc(5, s),
                top: cy - sc(6, s),
                right: cx + sc(5, s),
                bottom: cy + sc(1, s),
            };
            draw_rounded_box(hdc, &rc_doc, bg_col, col, sc(2, s));
            MoveToEx(hdc, cx - sc(3, s), cy + sc(2, s), null_mut());
            LineTo(hdc, cx - sc(3, s), cy + sc(6, s));
            MoveToEx(hdc, cx, cy + sc(2, s), null_mut());
            LineTo(hdc, cx, cy + sc(6, s));
            MoveToEx(hdc, cx + sc(3, s), cy + sc(2, s), null_mut());
            LineTo(hdc, cx + sc(3, s), cy + sc(6, s));
        }
        ID_BTN_SAFE_EJECT => {
            // Eject Symbol (Up Triangle + Base Bar)
            MoveToEx(hdc, cx, cy - sc(5, s), null_mut());
            LineTo(hdc, cx - sc(5, s), cy + sc(1, s));
            LineTo(hdc, cx + sc(5, s), cy + sc(1, s));
            LineTo(hdc, cx, cy - sc(5, s));
            MoveToEx(hdc, cx - sc(5, s), cy + sc(4, s), null_mut());
            LineTo(hdc, cx + sc(5, s), cy + sc(4, s));
        }
        ID_BTN_TO_TRAY => {
            // Tray Box + Down Arrow
            MoveToEx(hdc, cx - sc(5, s), cy + sc(1, s), null_mut());
            LineTo(hdc, cx - sc(5, s), cy + sc(5, s));
            LineTo(hdc, cx + sc(5, s), cy + sc(5, s));
            LineTo(hdc, cx + sc(5, s), cy + sc(1, s));
            MoveToEx(hdc, cx, cy - sc(5, s), null_mut());
            LineTo(hdc, cx, cy + sc(2, s));
            MoveToEx(hdc, cx - sc(3, s), cy - sc(1, s), null_mut());
            LineTo(hdc, cx, cy + sc(2, s));
            LineTo(hdc, cx + sc(3, s), cy - sc(1, s));
        }
        ID_BTN_REFRESH | ID_BTN_RESTORE_AUTORUN => {
            // Circular Refresh / Restore Arrow
            let r = sc(5, s);
            draw_circle_dot(hdc, cx, cy, r, col);
            draw_circle_dot(hdc, cx, cy, (r - sc(2, s)).max(1), bg_col);
            // Arrow head on top-right
            MoveToEx(hdc, cx + sc(2, s), cy - sc(5, s), null_mut());
            LineTo(hdc, cx + sc(5, s), cy - sc(4, s));
            LineTo(hdc, cx + sc(4, s), cy - sc(1, s));
        }
        _ => {}
    }

    SelectObject(hdc, op);
    DeleteObject(pen as HGDIOBJ);
}

// ============================================================================
// System Tray Management
// ============================================================================
unsafe fn init_or_update_tray_icon(state: &mut AppUiState, balloon: Option<(&str, &str, DWORD)>) {
    let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
    nid.cb_size = std::mem::size_of::<NOTIFYICONDATAW>() as DWORD;
    nid.h_wnd = state.hwnd_main;
    nid.u_id = 1;
    nid.u_flags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    nid.u_callback_message = WM_TRAYICON;
    nid.h_icon = state.h_icon;

    let status_tip = if state.devices.is_empty() {
        "Secure USB Manager (No Device)"
    } else if state.devices[state.selected_idx].is_unlocked {
        "Secure USB Manager — UNLOCKED"
    } else {
        "Secure USB Manager — LOCKED"
    };
    copy_to_wide_fixed(&mut nid.sz_tip, status_tip);

    if let Some((title, info, flags)) = balloon {
        nid.u_flags |= NIF_INFO;
        copy_to_wide_fixed(&mut nid.sz_info_title, title);
        copy_to_wide_fixed(&mut nid.sz_info, info);
        nid.dw_info_flags = flags;
    }

    if !state.tray_active {
        Shell_NotifyIconW(NIM_ADD, &mut nid);
        state.tray_active = true;
    } else {
        Shell_NotifyIconW(NIM_MODIFY, &mut nid);
    }
}

unsafe fn remove_tray_icon(state: &mut AppUiState) {
    if state.tray_active {
        let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
        nid.cb_size = std::mem::size_of::<NOTIFYICONDATAW>() as DWORD;
        nid.h_wnd = state.hwnd_main;
        nid.u_id = 1;
        Shell_NotifyIconW(NIM_DELETE, &mut nid);
        state.tray_active = false;
    }
}

unsafe fn show_tray_context_menu(hwnd: HWND) {
    let h_menu = CreatePopupMenu();
    if h_menu.is_null() {
        return;
    }

    let (has_dev, is_unlocked, can_lock) = if let Some(s) = get_state() {
        let hd = !s.devices.is_empty();
        let unl = hd && (!s.devices[s.selected_idx].has_security_lun || s.devices[s.selected_idx].is_unlocked);
        let clk = hd && s.devices[s.selected_idx].has_security_lun && s.devices[s.selected_idx].is_unlocked;
        (hd, unl, clk)
    } else {
        (false, false, false)
    };

    let t_show = to_wide(tr("보안 관리 창 열기", "Open Manager Window", "管理画面を開く"));
    let t_open = to_wide(tr("보안 드라이브 폴더 열기", "Open Security Drive Folder", "セキュリティフォルダを開く"));
    let t_restore = to_wide(tr("보안 영역 아이콘·Autorun 복구", "Repair Drive Icon & Autorun", "アイコン・Autorunの修復"));
    let t_lock = to_wide(tr("즉시 보안 영역 잠금 (Lock)", "Lock Security Partition Now", "直ちにロックする (Lock)"));
    let t_eject = to_wide(tr("잠금 후 안전 제거 (Safe Eject)", "Lock & Safe Eject USB", "ロックして安全に取り外す"));
    let t_exit = to_wide(tr("프로그램 종료", "Exit Program", "プログラム終了"));

    let fl_open = MF_STRING | if is_unlocked { 0 } else { MF_GRAYED };
    let fl_lock = MF_STRING | if can_lock { 0 } else { MF_GRAYED };
    let fl_eject = MF_STRING | if has_dev { 0 } else { MF_GRAYED };

    AppendMenuW(h_menu, MF_STRING, ID_TRAY_SHOW, t_show.as_ptr());
    AppendMenuW(h_menu, fl_open, ID_TRAY_OPEN_FOLDER, t_open.as_ptr());
    AppendMenuW(h_menu, fl_open, ID_TRAY_RESTORE_AUTORUN, t_restore.as_ptr());
    AppendMenuW(h_menu, MF_SEPARATOR, 0, null());
    AppendMenuW(h_menu, fl_lock, ID_TRAY_LOCK_NOW, t_lock.as_ptr());
    AppendMenuW(h_menu, fl_eject, ID_TRAY_SAFE_EJECT, t_eject.as_ptr());
    AppendMenuW(h_menu, MF_SEPARATOR, 0, null());
    AppendMenuW(h_menu, MF_STRING, ID_TRAY_EXIT, t_exit.as_ptr());

    let mut pt = POINT { x: 0, y: 0 };
    GetCursorPos(&mut pt);
    SetForegroundWindow(hwnd);
    let cmd = TrackPopupMenu(
        h_menu,
        TPM_RIGHTBUTTON | TPM_RETURNCMD | TPM_NONOTIFY,
        pt.x,
        pt.y,
        0,
        hwnd,
        null(),
    ) as usize;
    DestroyMenu(h_menu);

    match cmd {
        ID_TRAY_SHOW => {
            ShowWindow(hwnd, 5);
            ShowWindow(hwnd, 9); // SW_RESTORE
            SetForegroundWindow(hwnd);
        }
        ID_TRAY_OPEN_FOLDER => {
            SendMessageW(hwnd, WM_COMMAND, ID_BTN_OPEN_DRV, 0);
        }
        ID_TRAY_RESTORE_AUTORUN => {
            SendMessageW(hwnd, WM_COMMAND, ID_BTN_RESTORE_AUTORUN, 0);
        }
        ID_TRAY_LOCK_NOW => {
            SendMessageW(hwnd, WM_COMMAND, ID_BTN_LOCK, 0);
        }
        ID_TRAY_SAFE_EJECT => {
            SendMessageW(hwnd, WM_COMMAND, ID_BTN_SAFE_EJECT, 0);
        }
        ID_TRAY_EXIT => {
            DestroyWindow(hwnd);
        }
        _ => {}
    }
}

fn get_lang_button_label() -> &'static str {
    unsafe {
        match CURRENT_LANG {
            AppLang::KO => "한국어",
            AppLang::EN => "English",
            AppLang::JA => "日本語",
        }
    }
}

fn get_theme_button_label(dark: bool) -> &'static str {
    if dark {
        tr("다크", "Dark", "ダーク")
    } else {
        tr("라이트", "Light", "ライト")
    }
}

fn get_idle_button_label(mins: u32) -> &'static str {
    match mins {
        5 => tr("5분", "5 Minutes", "5分"),
        10 => tr("10분", "10 Minutes", "10分"),
        15 => tr("15분", "15 Minutes", "15分"),
        30 => tr("30분", "30 Minutes", "30分"),
        _ => tr("사용 안 함", "Disabled", "無効"),
    }
}

unsafe fn show_dropdown_popup(hwnd_parent: HWND, btn_hwnd: HWND, items: &[String], current_sel: usize) -> Option<usize> {
    let h_menu = CreatePopupMenu();
    if h_menu.is_null() {
        return None;
    }
    for (i, text) in items.iter().enumerate() {
        let w = to_wide(text);
        let flags = MF_STRING | if i == current_sel { MF_CHECKED } else { 0 };
        AppendMenuW(h_menu, flags, 1000 + i, w.as_ptr());
    }
    let mut rc = RECT { left: 0, top: 0, right: 0, bottom: 0 };
    GetWindowRect(btn_hwnd, &mut rc);
    SetForegroundWindow(hwnd_parent);
    let cmd = TrackPopupMenu(
        h_menu,
        TPM_RIGHTBUTTON | TPM_RETURNCMD | TPM_NONOTIFY,
        rc.left,
        rc.bottom + 2,
        0,
        hwnd_parent,
        null(),
    ) as usize;
    DestroyMenu(h_menu);
    if cmd >= 1000 && (cmd - 1000) < items.len() {
        Some(cmd - 1000)
    } else {
        None
    }
}

unsafe fn update_tab_visibility(state: &mut AppUiState) {
    let tab = state.active_tab;
    let s = state.dpi_scale;
    let show_home = if tab == 0 { 5 } else { 0 };
    let show_pwd = if tab == 1 { 5 } else { 0 };
    let show_shred = if tab == 2 { 5 } else { 0 };
    let show_set = if tab == 3 { 5 } else { 0 };
    let show_about = if tab == 4 { 5 } else { 0 };
    let show_restore = if tab == 0 || tab == 3 { 5 } else { 0 };

    if tab == 0 {
        set_ctrl_text(
            state.btn_restore_autorun,
            tr("아이콘·Autorun 복구", "Repair Autorun", "アイコン修復"),
        );
        MoveWindow(state.btn_restore_autorun, sc(436, s), sc(472, s), sc(188, s), sc(36, s), 1);
    } else if tab == 3 {
        set_ctrl_text(
            state.btn_restore_autorun,
            tr("즉시 복구", "Repair", "今すぐ修復"),
        );
        MoveWindow(state.btn_restore_autorun, sc(664, s), sc(397, s), sc(148, s), sc(32, s), 1);
    }

    ShowWindow(state.txt_pwd, show_home);
    ShowWindow(state.chk_show_pwd, show_home);
    ShowWindow(state.btn_unlock, show_home);
    ShowWindow(state.btn_lock, show_home);
    ShowWindow(state.btn_open_drv, show_home);
    ShowWindow(state.btn_safe_eject, show_home);
    ShowWindow(state.btn_restore_autorun, show_restore);

    ShowWindow(state.txt_curr_pwd, show_pwd);
    ShowWindow(state.txt_new_pwd, show_pwd);
    ShowWindow(state.txt_conf_pwd, show_pwd);
    ShowWindow(state.txt_new_hint, show_pwd);
    ShowWindow(state.btn_change_pwd, show_pwd);

    ShowWindow(state.btn_shred, show_shred);

    ShowWindow(state.cmb_idle_timer, show_set);
    ShowWindow(state.btn_theme, show_set);
    ShowWindow(state.cmb_lang, show_set);

    ShowWindow(state.btn_github, show_about);

    if tab == 1 && !state.devices.is_empty() && state.selected_idx < state.devices.len() {
        let h = &state.devices[state.selected_idx].effective_hint;
        if get_ctrl_text(state.txt_new_hint).is_empty() && h != "-" {
            set_ctrl_text(state.txt_new_hint, h);
        }
    }

    InvalidateRect(state.nav_home, null(), 0);
    InvalidateRect(state.nav_pwd, null(), 0);
    InvalidateRect(state.nav_shred, null(), 0);
    InvalidateRect(state.nav_settings, null(), 0);
    InvalidateRect(state.nav_about, null(), 0);
    InvalidateRect(state.hwnd_main, null(), 1);
}

fn apply_language_and_refresh(state: &mut AppUiState, rescan: bool) {
    set_ctrl_text(
        state.hwnd_main,
        tr(
            "Secure USB Manager (보안 USB 통합 관리)",
            "Secure USB Manager",
            "Secure USB Manager (セキュリティUSB統合管理)",
        ),
    );
    set_ctrl_text(state.nav_home, tr("홈 / 잠금 제어", "Home & Lock", "ホーム / ロック"));
    set_ctrl_text(state.nav_pwd, tr("비밀번호 변경", "Password", "パスワード変更"));
    set_ctrl_text(state.nav_shred, tr("파일 완전 삭제", "File Shredder", "ファイル完全削除"));
    set_ctrl_text(state.nav_settings, tr("환경 설정", "Settings", "環境設定"));
    set_ctrl_text(state.nav_about, tr("프로그램 정보", "About / Info", "プログラム情報"));
    set_ctrl_text(state.btn_github, tr("GitHub 열기", "Open GitHub", "GitHubを開く"));
    set_ctrl_text(state.btn_restore_autorun, tr("아이콘·Autorun 복구", "Repair Autorun", "アイコン修復"));

    set_ctrl_text(state.btn_theme, get_theme_button_label(state.dark_mode));
    set_ctrl_text(state.cmb_lang, get_lang_button_label());
    set_ctrl_text(state.btn_refresh, tr("새로고침", "Refresh", "更新"));
    set_ctrl_text(state.chk_show_pwd, tr("표시", "Show", "表示"));
    set_ctrl_text(state.btn_unlock, tr("잠금 해제 (Unlock)", "Unlock Partition", "ロック解除 (Unlock)"));
    set_ctrl_text(state.btn_lock, tr("보안 영역 잠금 (Lock)", "Lock Partition", "ロック (Lock)"));
    set_ctrl_text(
        state.btn_change_pwd,
        tr("비밀번호 및 힌트 변경 저장", "Save New Password & Hint", "パスワードとヒントを保存"),
    );
    set_ctrl_text(state.btn_open_drv, tr("보안 폴더 열기", "Open Security Folder", "セキュリティフォルダを開く"));
    set_ctrl_text(
        state.btn_shred,
        tr(
            "영구 삭제할 파일 선택 (3-Pass 완전 삭제)",
            "Select File to Permanently Shred (3-Pass)",
            "ファイルを選択して3-Pass完全削除",
        ),
    );
    set_ctrl_text(state.btn_safe_eject, tr("잠금 후 안전 제거", "Lock & Safe Eject", "ロックして安全に取り外す"));
    set_ctrl_text(state.btn_to_tray, tr("트레이로 숨기기", "Hide to Tray", "トレイに隠す"));
    set_ctrl_text(state.cmb_idle_timer, get_idle_button_label(state.idle_limit_minutes));

    if rescan {
        let prev_intrusion = if !state.devices.is_empty() && state.selected_idx < state.devices.len() {
            let d = &state.devices[state.selected_idx];
            Some((d.last_intrusion_count, d.last_intrusion_time.clone()))
        } else {
            None
        };

        state.devices = scan_devices();
        state.selected_idx = 0;

        if let Some((cnt, tm)) = prev_intrusion {
            if cnt > 0 && !state.devices.is_empty() && state.devices[0].last_intrusion_count == 0 {
                state.devices[0].last_intrusion_count = cnt;
                state.devices[0].last_intrusion_time = tm;
            }
        }
    }

    if state.devices.is_empty() {
        set_ctrl_text(
            state.cmb_dev,
            tr(
                "연결된 보안 USB 장치가 없습니다.",
                "No Secure USB device found.",
                "接続されているセキュリティUSBがありません。",
            ),
        );
    } else {
        if state.selected_idx >= state.devices.len() {
            state.selected_idx = 0;
        }
        if let Some(usb_idle) = state.devices[state.selected_idx].vault_idle_mins {
            state.idle_limit_minutes = usb_idle;
            set_ctrl_text(state.cmb_idle_timer, get_idle_button_label(state.idle_limit_minutes));
        }
        let title = state.devices[state.selected_idx].display_title();
        set_ctrl_text(state.cmb_dev, &title);
    }

    update_selected_device_ui(state);
    unsafe {
        update_tab_visibility(state);
        InvalidateRect(state.btn_theme, null(), 0);
        InvalidateRect(state.cmb_lang, null(), 0);
        InvalidateRect(state.cmb_dev, null(), 0);
        InvalidateRect(state.cmb_idle_timer, null(), 0);
        InvalidateRect(state.chk_show_pwd, null(), 1);
        InvalidateRect(state.txt_pwd, null(), 1);
        init_or_update_tray_icon(state, None);
    }
}

fn update_selected_device_ui(state: &mut AppUiState) {
    if state.devices.is_empty() {
        state.part_info_str = tr("파티션 구조: -", "Partitions: -", "パーティション構成: -").to_string();
        state.sec_state_str = tr(
            "보안 상태: 연결된 보안 USB 장치가 없습니다.",
            "Status: No Secure USB device connected.",
            "状態: セキュリティUSBが接続されていません。",
        )
        .to_string();
        state.hint_str = tr("비밀번호 힌트: -", "Password Hint: -", "パスワードヒント: -").to_string();
        state.retry_str = tr("남은 인증 기회: -", "Retries Left: -", "残り試行回数: -").to_string();
        unsafe {
            EnableWindow(state.txt_pwd, 0);
            EnableWindow(state.btn_unlock, 0);
            EnableWindow(state.btn_lock, 0);
            EnableWindow(state.txt_curr_pwd, 0);
            EnableWindow(state.txt_new_pwd, 0);
            EnableWindow(state.txt_conf_pwd, 0);
            EnableWindow(state.txt_new_hint, 0);
            EnableWindow(state.btn_change_pwd, 0);
            EnableWindow(state.btn_open_drv, 0);
            EnableWindow(state.btn_shred, 0);
            EnableWindow(state.btn_safe_eject, 0);
            EnableWindow(state.btn_restore_autorun, 0);
            InvalidateRect(state.hwnd_main, null(), 0);
        }
        return;
    }

    let dev = &state.devices[state.selected_idx];
    let mut parts = Vec::new();
    for i in 0..4 {
        if dev.lun_sectors[i] > 0 {
            let gb = dev.lun_gb(i);
            let mb = (dev.lun_sectors[i] as f64 * 512.0) / 1048576.0;
            let is_sec = (dev.lun_flags[i] & 0x40) != 0 || (dev.lun_flags[i] & 0x80) != 0 || (i == 1 && dev.has_security_lun);
            let is_ro = (dev.lun_flags[i] & 0x04) != 0 || (dev.lun_flags[i] & 0x02) != 0;
            let sz = if gb >= 1.0 { format!("{:.2} GB", gb) } else { format!("{:.2} MB", mb) };
            let role = if is_sec {
                tr("보안 영역", "Security", "セキュリティ")
            } else {
                tr("런처 영역", "Launcher", "ランチャー")
            };
            let ro = if is_ro { tr(", 읽기 전용", ", Read-Only", ", 読取専用") } else { "" };
            parts.push(format!("{} ({}{})", sz, role, ro));
        }
    }

    if dev.is_unlocked && dev.sec_total_bytes > 0 {
        let used_gb = (dev.sec_used_bytes as f64) / 1073741824.0;
        let free_gb = (dev.sec_free_bytes as f64) / 1073741824.0;
        let pct = ((dev.sec_used_bytes as f64 / dev.sec_total_bytes as f64) * 100.0).round() as u32;
        state.part_info_str = format!(
            "{}  |  {}: {:.2} GB ({}%) / {}: {:.2} GB",
            parts.join(" + "),
            tr("사용", "Used", "使用"),
            used_gb,
            pct,
            tr("여유", "Free", "空き"),
            free_gb
        );
    } else {
        state.part_info_str = format!(
            "{}{}",
            tr("파티션: ", "Partitions: ", "構成: "),
            if parts.is_empty() { "-".to_string() } else { parts.join("  +  ") }
        );
    }

    unsafe {
        EnableWindow(state.btn_open_drv, 1);
        EnableWindow(state.btn_safe_eject, 1);
        EnableWindow(state.btn_restore_autorun, 1);
    }

    if !dev.has_security_lun {
        state.sec_state_str = tr(
            "보안 상태: 일반 단일 파티션 모드",
            "Status: Single Public Partition Mode",
            "状態: 通常単一パーティションモード",
        )
        .to_string();
        state.hint_str = tr("비밀번호 힌트: 해당 없음", "Password Hint: N/A", "パスワードヒント: 該当なし").to_string();
        state.retry_str = tr("남은 인증 기회: 해당 없음", "Retries Left: N/A", "残り試行回数: 該当なし").to_string();
        unsafe {
            EnableWindow(state.txt_pwd, 0);
            EnableWindow(state.btn_unlock, 0);
            EnableWindow(state.btn_lock, 0);
            EnableWindow(state.txt_curr_pwd, 0);
            EnableWindow(state.txt_new_pwd, 0);
            EnableWindow(state.txt_conf_pwd, 0);
            EnableWindow(state.txt_new_hint, 0);
            EnableWindow(state.btn_change_pwd, 0);
            EnableWindow(state.btn_shred, 1);
        }
    } else {
        state.hint_str = format!("{}{}", tr("비밀번호 힌트: ", "Hint: ", "ヒント: "), dev.effective_hint);
        if dev.is_unlocked && dev.last_intrusion_count > 0 {
            state.retry_str = format!(
                "⚠️ {} {} ({})",
                tr("오류 감지:", "Failed:", "失敗検知:"),
                dev.last_intrusion_count,
                if dev.last_intrusion_time.is_empty() { "-" } else { &dev.last_intrusion_time }
            );
        } else if !dev.is_unlocked && dev.effective_retry_remain < dev.effective_retry_limit {
            state.retry_str = format!(
                "⚠️ {}{} / {} ({})",
                tr("남은 기회: ", "Retries: ", "残り回数: "),
                dev.effective_retry_remain,
                dev.effective_retry_limit,
                tr("0회 시 데이터 파기", "Wipe at 0", "0でデータ消去")
            );
        } else {
            state.retry_str = format!(
                "{}{} / {}",
                tr("남은 인증 기회: ", "Retries Left: ", "残り試行回数: "),
                dev.effective_retry_remain,
                dev.effective_retry_limit
            );
        }
        unsafe {
            EnableWindow(state.txt_curr_pwd, 1);
            EnableWindow(state.txt_new_pwd, 1);
            EnableWindow(state.txt_conf_pwd, 1);
            EnableWindow(state.txt_new_hint, 1);
            EnableWindow(state.btn_change_pwd, 1);
        }

        if dev.is_unlocked {
            let sec_d = dev
                .security_drive_letter
                .as_ref()
                .map(|s| format!(" [{}]", s))
                .unwrap_or_default();
            state.sec_state_str = format!(
                "{}{}",
                tr("보안 상태: 잠금 해제됨 (Unlocked)", "Status: Unlocked", "状態: ロック解除済 (Unlocked)"),
                sec_d
            );
            unsafe {
                EnableWindow(state.txt_pwd, 0);
                EnableWindow(state.btn_unlock, 0);
                EnableWindow(state.btn_lock, 1);
                EnableWindow(state.btn_open_drv, 1);
                EnableWindow(state.btn_restore_autorun, 1);
                EnableWindow(state.btn_shred, 1);
            }
        } else {
            state.sec_state_str = tr(
                "보안 상태: 잠김 (Locked)",
                "Status: Locked",
                "状態: ロック中 (Locked)",
            )
            .to_string();
            unsafe {
                EnableWindow(state.txt_pwd, 1);
                EnableWindow(state.btn_unlock, 1);
                EnableWindow(state.btn_lock, 0);
                EnableWindow(state.btn_open_drv, 0);
                EnableWindow(state.btn_restore_autorun, 0);
                EnableWindow(state.btn_shred, 0);
                if state.active_tab == 0 {
                    SetFocus(state.txt_pwd);
                }
            }
        }
    }

    unsafe {
        InvalidateRect(state.hwnd_main, null(), 0);
        InvalidateRect(state.btn_unlock, null(), 0);
        InvalidateRect(state.btn_lock, null(), 0);
        InvalidateRect(state.btn_change_pwd, null(), 0);
        InvalidateRect(state.btn_open_drv, null(), 0);
        InvalidateRect(state.btn_restore_autorun, null(), 0);
        InvalidateRect(state.btn_refresh, null(), 0);
        InvalidateRect(state.btn_open_drv, null(), 0);
        InvalidateRect(state.btn_shred, null(), 0);
        InvalidateRect(state.btn_safe_eject, null(), 0);
        InvalidateRect(state.btn_to_tray, null(), 0);
    }
}

unsafe fn get_ctrl_client_rect(hwnd_main: HWND, ctrl: HWND) -> Option<RECT> {
    if ctrl.is_null() || IsWindowEnabled(ctrl) == 0 || IsWindowVisible(ctrl) == 0 {
        return None;
    }
    let mut rc = RECT { left: 0, top: 0, right: 0, bottom: 0 };
    if GetWindowRect(ctrl, &mut rc) == 0 {
        return None;
    }
    if rc.right <= rc.left || rc.bottom <= rc.top {
        return None;
    }
    let mut pt_tl = POINT { x: rc.left, y: rc.top };
    let mut pt_br = POINT { x: rc.right, y: rc.bottom };
    ScreenToClient(hwnd_main, &mut pt_tl);
    ScreenToClient(hwnd_main, &mut pt_br);
    Some(RECT {
        left: pt_tl.x,
        top: pt_tl.y,
        right: pt_br.x,
        bottom: pt_br.y,
    })
}

fn fluent_draw_elevated_glass_card(
    buf: &mut [u32],
    bw: i32,
    bh: i32,
    rc: &RECT,
    s: f32,
    dark: bool,
    accent_glow: COLORREF,
    glow_int: f32,
    mx: f32,
    my: f32,
) {
    let rad = sc(8, s) as f32;
    if dark {
        // Official WinUI 3 CardBackgroundFillColorDefault (#0DFFFFFF over LayerFillColorDefault)
        // + CardStrokeColorDefault (top specular highlight #16FFFFFF, side/bottom #0F000000)
        fluent_draw_glass_box(
            buf,
            bw,
            bh,
            rc,
            rad,
            rgb(56, 56, 56),
            rgb(45, 45, 45),
            0.74,
            rgb(115, 115, 115),
            rgb(62, 62, 62),
            0.52,
            accent_glow,
            sc(14, s) as f32,
            glow_int * 0.45,
            0.36,
        );
        fluent_apply_acrylic_noise(buf, bw, bh, rc, rad, 1.8);
        fluent_apply_reveal_highlight(
            buf,
            bw,
            bh,
            rc,
            rad,
            mx,
            my,
            sc(175, s) as f32,
            rgb(96, 205, 255),
            0.035,
            0.32,
        );
    } else {
        fluent_draw_glass_box(
            buf,
            bw,
            bh,
            rc,
            rad,
            rgb(255, 255, 255),
            rgb(251, 251, 251),
            0.84,
            rgb(255, 255, 255),
            rgb(218, 218, 218),
            0.85,
            accent_glow,
            sc(12, s) as f32,
            glow_int * 0.25,
            0.10,
        );
        fluent_apply_reveal_highlight(
            buf,
            bw,
            bh,
            rc,
            rad,
            mx,
            my,
            sc(175, s) as f32,
            rgb(0, 120, 212),
            0.025,
            0.22,
        );
    }
}

fn fluent_draw_recessed_glass_tile(
    buf: &mut [u32],
    bw: i32,
    bh: i32,
    rc: &RECT,
    rad: f32,
    dark: bool,
) {
    if dark {
        // Official WinUI 3 CardBackgroundFillColorSecondary (#08FFFFFF / #232323 recessed Expander row)
        fluent_draw_glass_box(
            buf,
            bw,
            bh,
            rc,
            rad,
            rgb(35, 35, 35),
            rgb(31, 31, 31),
            0.78,
            rgb(76, 76, 76),
            rgb(48, 48, 48),
            0.46,
            rgb(96, 205, 255),
            0.0,
            0.0,
            0.0,
        );
    } else {
        fluent_draw_glass_box(
            buf,
            bw,
            bh,
            rc,
            rad,
            rgb(246, 246, 246),
            rgb(242, 242, 242),
            0.85,
            rgb(229, 229, 229),
            rgb(216, 216, 216),
            0.78,
            rgb(0, 120, 212),
            0.0,
            0.0,
            0.0,
        );
    }
}

// ============================================================================
// Main Window Paint & Event Handling (Microsoft Fluent 2 / WinUI 3 Design)
// ============================================================================
unsafe fn paint_main_canvas(hdc: HDC, rc_client: &RECT, state: &mut AppUiState) {
    let s = state.dpi_scale;
    let cw = sc(860, s);
    let ch = sc(540, s);
    let sb_w = sc(200, s);
    let dark = state.dark_mode;
    let mx = state.cursor_client.x as f32;
    let my = state.cursor_client.y as f32;

    let bw = (rc_client.right - rc_client.left).max(cw);
    let bh = (rc_client.bottom - rc_client.top).max(ch);
    let total_px = (bw * bh) as usize;
    if state.bg_pixels.len() != total_px {
        state.bg_pixels.resize(total_px, 0);
    }
    state.bg_w = bw;
    state.bg_h = bh;

    // Official WinUI 3 TextFillColorPrimary / Secondary / Tertiary
    let col_hdr = if dark { rgb(255, 255, 255) } else { rgb(26, 26, 26) };
    let col_label = if dark { rgb(232, 232, 232) } else { rgb(36, 36, 36) };
    let col_sub = if dark { rgb(166, 166, 166) } else { rgb(96, 96, 96) };

    // Determine Status Badge & Dynamic Ambient Glow Color
    let (badge_txt, badge_top, badge_bot, badge_rim, badge_glow, dot_col) = if state.devices.is_empty() {
        (
            "NO DEVICE",
            rgb(56, 56, 56),
            rgb(42, 42, 42),
            rgb(140, 140, 140),
            rgb(96, 205, 255),
            rgb(166, 166, 166),
        )
    } else {
        let d = &state.devices[state.selected_idx];
        if !d.has_security_lun {
            (
                "PUBLIC MODE",
                rgb(0, 120, 212),
                rgb(0, 95, 184),
                rgb(96, 205, 255),
                rgb(96, 205, 255),
                rgb(152, 224, 255),
            )
        } else if d.is_unlocked {
            (
                "UNLOCKED",
                rgb(16, 137, 62),
                rgb(12, 108, 48),
                rgb(108, 203, 95),
                rgb(108, 203, 95),
                rgb(158, 235, 148),
            )
        } else {
            (
                "LOCKED",
                rgb(196, 43, 28),
                rgb(158, 32, 20),
                rgb(255, 153, 164),
                rgb(255, 153, 164),
                rgb(255, 198, 204),
            )
        }
    };

    // ========================================================================
    // STAGE 1: 32-BIT BGRA FLUENT 2 PIXEL SHADER PASS (Mica, LayerPane, Acrylic, Reveal)
    // ========================================================================
    fill_fluent_ambient_backdrop(&mut state.bg_pixels, bw, bh, sb_w, s, dark, badge_glow);

    // Sidebar Top Brand Emblem Tile
    let rc_ico_tile = RECT {
        left: sc(14, s),
        top: sc(16, s),
        right: sc(54, s),
        bottom: sc(56, s),
    };
    fluent_draw_glass_box(
        &mut state.bg_pixels,
        bw,
        bh,
        &rc_ico_tile,
        sc(8, s) as f32,
        if dark { rgb(46, 46, 46) } else { rgb(255, 255, 255) },
        if dark { rgb(34, 34, 34) } else { rgb(244, 244, 244) },
        0.92,
        rgb(96, 205, 255),
        rgb(72, 72, 72),
        0.65,
        rgb(96, 205, 255),
        sc(10, s) as f32,
        if dark { 0.25 } else { 0.10 },
        0.25,
    );

    // Sidebar Version Badge Pill
    let rc_ver = RECT {
        left: sc(62, s),
        top: sc(39, s),
        right: sc(118, s),
        bottom: sc(56, s),
    };
    fluent_draw_glass_box(
        &mut state.bg_pixels,
        bw,
        bh,
        &rc_ver,
        sc(4, s) as f32,
        if dark { rgb(45, 45, 45) } else { rgb(228, 240, 252) },
        if dark { rgb(36, 36, 36) } else { rgb(214, 232, 250) },
        0.90,
        rgb(96, 205, 255),
        if dark { rgb(64, 64, 64) } else { rgb(0, 120, 212) },
        0.55,
        rgb(96, 205, 255),
        0.0,
        0.0,
        0.0,
    );

    // Sidebar Horizontal Divider Lines (WinUI 3 DividerStrokeColorDefaultBrush #14FFFFFF)
    for &dy in &[sc(70, s), sc(424, s)] {
        if dy >= 0 && dy < bh {
            let row = (dy * bw) as usize;
            for x in sc(14, s)..sc(186, s).min(bw) {
                let idx = row + x as usize;
                state.bg_pixels[idx] = if dark {
                    blend_pixel(state.bg_pixels[idx], 255.0, 255.0, 255.0, 0.08)
                } else {
                    blend_pixel(state.bg_pixels[idx], 0.0, 0.0, 0.0, 0.08)
                };
            }
        }
    }

    // Active Sidebar Navigation Item subtle ambient glow
    let active_nav_hwnd = match state.active_tab {
        0 => state.nav_home,
        1 => state.nav_pwd,
        2 => state.nav_shred,
        3 => state.nav_settings,
        _ => state.nav_about,
    };
    if let Some(rc_nav) = get_ctrl_client_rect(state.hwnd_main, active_nav_hwnd) {
        fluent_add_rect_glow(
            &mut state.bg_pixels,
            bw,
            bh,
            &rc_nav,
            sc(6, s) as f32,
            rgb(96, 205, 255),
            sc(10, s) as f32,
            if dark { 0.16 } else { 0.08 },
        );
    }

    // Right Pane Persistent Hero Header Banner Card with 3D Flowing Violet/Cyan Wave
    let rc_hero = RECT {
        left: sc(220, s),
        top: sc(14, s),
        right: cw - sc(20, s),
        bottom: sc(84, s),
    };
    fluent_draw_hero_wave_card(&mut state.bg_pixels, bw, bh, &rc_hero, sc(8, s) as f32, s);
    fluent_apply_acrylic_noise(&mut state.bg_pixels, bw, bh, &rc_hero, sc(8, s) as f32, 1.6);

    // Status Badge Pill inside Hero Card
    let rc_badge = RECT {
        left: cw - sc(158, s),
        top: sc(35, s),
        right: cw - sc(36, s),
        bottom: sc(63, s),
    };
    fluent_draw_glass_box(
        &mut state.bg_pixels,
        bw,
        bh,
        &rc_badge,
        sc(14, s) as f32,
        badge_top,
        badge_bot,
        0.92,
        badge_rim,
        badge_top,
        0.85,
        badge_glow,
        sc(12, s) as f32,
        0.45,
        0.30,
    );

    if state.active_tab == 0 {
        let rc_card1 = RECT {
            left: sc(220, s),
            top: sc(138, s),
            right: cw - sc(20, s),
            bottom: sc(318, s),
        };
        fluent_draw_elevated_glass_card(
            &mut state.bg_pixels,
            bw,
            bh,
            &rc_card1,
            s,
            dark,
            rgb(96, 205, 255),
            0.14,
            mx,
            my,
        );

        let rc_acc1 = RECT {
            left: sc(236, s),
            top: sc(151, s),
            right: sc(240, s),
            bottom: sc(168, s),
        };
        fluent_draw_glass_box(
            &mut state.bg_pixels,
            bw,
            bh,
            &rc_acc1,
            sc(2, s) as f32,
            rgb(96, 205, 255),
            rgb(0, 120, 212),
            1.0,
            rgb(152, 224, 255),
            rgb(0, 120, 212),
            1.0,
            rgb(96, 205, 255),
            sc(6, s) as f32,
            0.40,
            0.0,
        );

        // Partition Capacity Gauge Bar
        let rc_bar = RECT {
            left: sc(236, s),
            top: sc(177, s),
            right: rc_card1.right - sc(16, s),
            bottom: sc(211, s),
        };
        if state.devices.is_empty() {
            fluent_draw_recessed_glass_tile(&mut state.bg_pixels, bw, bh, &rc_bar, sc(6, s) as f32, dark);
        } else {
            let d = &state.devices[state.selected_idx];
            let l0 = d.lun_gb(0);
            let l1 = d.lun_gb(1);
            let tot = (l0 + l1).max(0.001);
            if !d.has_security_lun || l1 <= 0.001 {
                fluent_draw_glass_box(
                    &mut state.bg_pixels,
                    bw,
                    bh,
                    &rc_bar,
                    sc(6, s) as f32,
                    rgb(0, 120, 212),
                    rgb(0, 95, 184),
                    0.92,
                    rgb(96, 205, 255),
                    rgb(0, 120, 212),
                    0.85,
                    rgb(96, 205, 255),
                    sc(10, s) as f32,
                    0.28,
                    0.18,
                );
            } else {
                let total_w = rc_bar.right - rc_bar.left;
                let w0 = ((total_w as f64 * (l0 / tot)) as i32).max(sc(144, s));
                let (sec_top, sec_bot, sec_rim, sec_glow) = if d.is_unlocked {
                    (rgb(16, 137, 62), rgb(12, 108, 48), rgb(108, 203, 95), rgb(108, 203, 95))
                } else {
                    (rgb(196, 43, 28), rgb(158, 32, 20), rgb(255, 153, 164), rgb(255, 153, 164))
                };

                fluent_draw_glass_box(
                    &mut state.bg_pixels,
                    bw,
                    bh,
                    &rc_bar,
                    sc(6, s) as f32,
                    sec_top,
                    sec_bot,
                    0.90,
                    sec_rim,
                    sec_top,
                    0.80,
                    sec_glow,
                    sc(10, s) as f32,
                    0.28,
                    0.18,
                );

                if d.is_unlocked && d.sec_total_bytes > 0 {
                    let sec_w = rc_bar.right - (rc_bar.left + w0);
                    let used_w = ((sec_w as f64) * (d.sec_used_bytes as f64 / d.sec_total_bytes as f64)) as i32;
                    if used_w > 2 {
                        let rc_used = RECT {
                            left: rc_bar.left + w0,
                            top: rc_bar.top + 1,
                            right: (rc_bar.left + w0 + used_w).min(rc_bar.right - sc(4, s)),
                            bottom: rc_bar.bottom - 1,
                        };
                        fluent_draw_glass_box(
                            &mut state.bg_pixels,
                            bw,
                            bh,
                            &rc_used,
                            sc(5, s) as f32,
                            rgb(10, 92, 42),
                            rgb(8, 72, 32),
                            0.90,
                            rgb(108, 203, 95),
                            rgb(16, 137, 62),
                            0.50,
                            rgb(108, 203, 95),
                            0.0,
                            0.0,
                            0.0,
                        );
                    }
                }

                // Launcher Left Segment Pill
                let rc0_round = RECT {
                    left: rc_bar.left,
                    top: rc_bar.top,
                    right: rc_bar.left + w0,
                    bottom: rc_bar.bottom,
                };
                fluent_draw_glass_box(
                    &mut state.bg_pixels,
                    bw,
                    bh,
                    &rc0_round,
                    sc(6, s) as f32,
                    rgb(0, 120, 212),
                    rgb(0, 95, 184),
                    0.96,
                    rgb(96, 205, 255),
                    rgb(0, 120, 212),
                    0.88,
                    rgb(96, 205, 255),
                    sc(8, s) as f32,
                    0.25,
                    0.0,
                );
            }
        }

        // Tile 2: WinUI 3 InfoBar Semantic Status Banner Row
        let rc_tile2 = RECT {
            left: sc(236, s),
            top: sc(222, s),
            right: rc_card1.right - sc(16, s),
            bottom: sc(256, s),
        };
        if state.devices.is_empty() {
            fluent_draw_recessed_glass_tile(&mut state.bg_pixels, bw, bh, &rc_tile2, sc(4, s) as f32, dark);
        } else {
            let d = &state.devices[state.selected_idx];
            let (t_top, t_bot, t_rim, t_glow) = if !d.has_security_lun {
                if dark {
                    (rgb(28, 44, 62), rgb(24, 38, 54), rgb(96, 205, 255), rgb(96, 205, 255))
                } else {
                    (rgb(240, 246, 255), rgb(228, 240, 252), rgb(0, 120, 212), rgb(0, 120, 212))
                }
            } else if d.is_unlocked {
                if dark {
                    (rgb(28, 52, 36), rgb(24, 44, 30), rgb(108, 203, 95), rgb(108, 203, 95))
                } else {
                    (rgb(223, 246, 221), rgb(208, 238, 205), rgb(16, 137, 62), rgb(16, 137, 62))
                }
            } else if dark {
                // Official WinUI 3 SystemFillColorCriticalBackground (#442726)
                (rgb(68, 39, 38), rgb(56, 32, 31), rgb(255, 153, 164), rgb(255, 153, 164))
            } else {
                (rgb(253, 231, 233), rgb(250, 216, 219), rgb(196, 43, 28), rgb(196, 43, 28))
            };
            fluent_draw_glass_box(
                &mut state.bg_pixels,
                bw,
                bh,
                &rc_tile2,
                sc(4, s) as f32,
                t_top,
                t_bot,
                0.88,
                t_rim,
                t_top,
                0.65,
                t_glow,
                sc(8, s) as f32,
                if dark { 0.18 } else { 0.08 },
                0.0,
            );
        }

        // Tile 3A & 3B (Hint & Remaining Retries)
        let rc_tile3a = RECT {
            left: sc(236, s),
            top: sc(266, s),
            right: sc(524, s),
            bottom: sc(300, s),
        };
        fluent_draw_recessed_glass_tile(&mut state.bg_pixels, bw, bh, &rc_tile3a, sc(4, s) as f32, dark);

        let rc_tile3b = RECT {
            left: sc(532, s),
            top: sc(266, s),
            right: rc_card1.right - sc(16, s),
            bottom: sc(300, s),
        };
        fluent_draw_recessed_glass_tile(&mut state.bg_pixels, bw, bh, &rc_tile3b, sc(4, s) as f32, dark);

        // Card 2: Security Authentication & Quick Drive Controls
        let rc_card2 = RECT {
            left: sc(220, s),
            top: sc(328, s),
            right: cw - sc(20, s),
            bottom: sc(524, s),
        };
        fluent_draw_elevated_glass_card(
            &mut state.bg_pixels,
            bw,
            bh,
            &rc_card2,
            s,
            dark,
            rgb(96, 205, 255),
            0.16,
            mx,
            my,
        );

        let rc_acc2 = RECT {
            left: sc(236, s),
            top: sc(341, s),
            right: sc(240, s),
            bottom: sc(358, s),
        };
        fluent_draw_glass_box(
            &mut state.bg_pixels,
            bw,
            bh,
            &rc_acc2,
            sc(2, s) as f32,
            rgb(96, 205, 255),
            rgb(0, 120, 212),
            1.0,
            rgb(152, 224, 255),
            rgb(0, 120, 212),
            1.0,
            rgb(96, 205, 255),
            sc(6, s) as f32,
            0.40,
            0.0,
        );

        // Official WinUI 3 PasswordBox with Bottom Accent Focus Pill (`TextControlElevationBorderFocusedBrush`)
        let pwd_enabled = !state.devices.is_empty()
            && state.devices[state.selected_idx].has_security_lun
            && !state.devices[state.selected_idx].is_unlocked;
        let pwd_focused = pwd_enabled && (state.focused_ctrl == state.txt_pwd || state.focused_ctrl.is_null());
        let rc_pwd_box = RECT {
            left: sc(320, s),
            top: sc(372, s),
            right: sc(722, s),
            bottom: sc(404, s),
        };
        let (p_bg, p_rim_t, p_rim_b, p_glow_int) = if dark {
            if pwd_enabled {
                (rgb(30, 30, 30), rgb(90, 90, 90), rgb(70, 70, 70), if pwd_focused { 0.25 } else { 0.10 })
            } else {
                (rgb(30, 30, 30), rgb(55, 55, 55), rgb(45, 45, 45), 0.0)
            }
        } else if pwd_enabled {
            (rgb(255, 255, 255), rgb(200, 200, 200), rgb(170, 170, 170), if pwd_focused { 0.14 } else { 0.05 })
        } else {
            (rgb(243, 243, 243), rgb(218, 218, 218), rgb(200, 200, 200), 0.0)
        };
        fluent_draw_glass_box(
            &mut state.bg_pixels,
            bw,
            bh,
            &rc_pwd_box,
            sc(4, s) as f32,
            p_bg,
            p_bg,
            0.98,
            p_rim_t,
            p_rim_b,
            0.85,
            rgb(96, 205, 255),
            sc(10, s) as f32,
            p_glow_int,
            0.0,
        );
        if pwd_enabled {
            let pill_col = if pwd_focused {
                if dark { rgb(96, 205, 255) } else { rgb(0, 120, 212) }
            } else if dark {
                rgb(154, 154, 154)
            } else {
                rgb(138, 138, 138)
            };
            fluent_draw_bottom_focus_pill(
                &mut state.bg_pixels,
                bw,
                bh,
                &rc_pwd_box,
                sc(4, s) as f32,
                s,
                pill_col,
                pwd_focused,
            );
        }

        // Subtle Accent Glow behind Enabled Primary Action Buttons
        if let Some(rc_u) = get_ctrl_client_rect(state.hwnd_main, state.btn_unlock) {
            fluent_add_rect_glow(
                &mut state.bg_pixels,
                bw,
                bh,
                &rc_u,
                sc(4, s) as f32,
                rgb(96, 205, 255),
                sc(12, s) as f32,
                if dark { 0.26 } else { 0.14 },
            );
        }
        if let Some(rc_l) = get_ctrl_client_rect(state.hwnd_main, state.btn_lock) {
            fluent_add_rect_glow(
                &mut state.bg_pixels,
                bw,
                bh,
                &rc_l,
                sc(4, s) as f32,
                rgb(255, 153, 164),
                sc(12, s) as f32,
                if dark { 0.26 } else { 0.14 },
            );
        }
    } else if state.active_tab == 1 {
        let rc_card = RECT {
            left: sc(220, s),
            top: sc(138, s),
            right: cw - sc(20, s),
            bottom: sc(524, s),
        };
        fluent_draw_elevated_glass_card(
            &mut state.bg_pixels,
            bw,
            bh,
            &rc_card,
            s,
            dark,
            rgb(96, 205, 255),
            0.14,
            mx,
            my,
        );

        let rc_acc = RECT {
            left: sc(236, s),
            top: sc(151, s),
            right: sc(240, s),
            bottom: sc(168, s),
        };
        fluent_draw_glass_box(
            &mut state.bg_pixels,
            bw,
            bh,
            &rc_acc,
            sc(2, s) as f32,
            rgb(252, 225, 0),
            rgb(217, 119, 6),
            1.0,
            rgb(254, 240, 138),
            rgb(217, 119, 6),
            1.0,
            rgb(252, 225, 0),
            sc(6, s) as f32,
            0.40,
            0.0,
        );

        // Compact 1-Line Hint & Retry Status Bar
        let rc_pol = RECT {
            left: sc(236, s),
            top: sc(184, s),
            right: rc_card.right - sc(16, s),
            bottom: sc(222, s),
        };
        fluent_draw_recessed_glass_tile(&mut state.bg_pixels, bw, bh, &rc_pol, sc(6, s) as f32, dark);

        let form_enabled = !state.devices.is_empty() && state.devices[state.selected_idx].has_security_lun;
        let tab1_inputs = [
            (250, state.txt_curr_pwd),
            (296, state.txt_new_pwd),
            (342, state.txt_conf_pwd),
            (388, state.txt_new_hint),
        ];

        for &(y_top, ed_hwnd) in &tab1_inputs {
            let is_foc = form_enabled && state.focused_ctrl == ed_hwnd;
            let (inp_bg, inp_rim_t, inp_rim_b, inp_glow) = if dark {
                if form_enabled {
                    (rgb(30, 30, 30), rgb(90, 90, 90), rgb(70, 70, 70), if is_foc { 0.25 } else { 0.08 })
                } else {
                    (rgb(30, 30, 30), rgb(55, 55, 55), rgb(45, 45, 45), 0.0)
                }
            } else if form_enabled {
                (rgb(255, 255, 255), rgb(200, 200, 200), rgb(170, 170, 170), if is_foc { 0.14 } else { 0.04 })
            } else {
                (rgb(243, 243, 243), rgb(218, 218, 218), rgb(200, 200, 200), 0.0)
            };

            let rc_inp = RECT {
                left: sc(418, s),
                top: sc(y_top, s),
                right: sc(820, s),
                bottom: sc(y_top + 34, s),
            };
            fluent_draw_glass_box(
                &mut state.bg_pixels,
                bw,
                bh,
                &rc_inp,
                sc(4, s) as f32,
                inp_bg,
                inp_bg,
                0.98,
                inp_rim_t,
                inp_rim_b,
                0.85,
                rgb(96, 205, 255),
                sc(10, s) as f32,
                inp_glow,
                0.0,
            );
            if form_enabled {
                let pill_col = if is_foc {
                    if dark { rgb(96, 205, 255) } else { rgb(0, 120, 212) }
                } else if dark {
                    rgb(154, 154, 154)
                } else {
                    rgb(138, 138, 138)
                };
                fluent_draw_bottom_focus_pill(
                    &mut state.bg_pixels,
                    bw,
                    bh,
                    &rc_inp,
                    sc(4, s) as f32,
                    s,
                    pill_col,
                    is_foc,
                );
            }
        }

        if let Some(rc_chg) = get_ctrl_client_rect(state.hwnd_main, state.btn_change_pwd) {
            fluent_add_rect_glow(
                &mut state.bg_pixels,
                bw,
                bh,
                &rc_chg,
                sc(4, s) as f32,
                rgb(96, 205, 255),
                sc(12, s) as f32,
                if dark { 0.25 } else { 0.14 },
            );
        }
    } else if state.active_tab == 2 {
        let rc_card = RECT {
            left: sc(220, s),
            top: sc(138, s),
            right: cw - sc(20, s),
            bottom: sc(524, s),
        };
        fluent_draw_elevated_glass_card(
            &mut state.bg_pixels,
            bw,
            bh,
            &rc_card,
            s,
            dark,
            rgb(255, 153, 164),
            0.14,
            mx,
            my,
        );

        let rc_acc = RECT {
            left: sc(236, s),
            top: sc(151, s),
            right: sc(240, s),
            bottom: sc(168, s),
        };
        fluent_draw_glass_box(
            &mut state.bg_pixels,
            bw,
            bh,
            &rc_acc,
            sc(2, s) as f32,
            rgb(255, 153, 164),
            rgb(196, 43, 28),
            1.0,
            rgb(255, 198, 204),
            rgb(196, 43, 28),
            1.0,
            rgb(255, 153, 164),
            sc(6, s) as f32,
            0.40,
            0.0,
        );

        // Compact Status & Warning Banner without textbook fluff
        let rc_warn = RECT {
            left: sc(236, s),
            top: sc(188, s),
            right: rc_card.right - sc(16, s),
            bottom: sc(264, s),
        };
        let (w_top, w_bot, w_rim) = if dark {
            (rgb(68, 39, 38), rgb(56, 32, 31), rgb(255, 153, 164))
        } else {
            (rgb(253, 231, 233), rgb(250, 216, 219), rgb(196, 43, 28))
        };
        fluent_draw_glass_box(
            &mut state.bg_pixels,
            bw,
            bh,
            &rc_warn,
            sc(6, s) as f32,
            w_top,
            w_bot,
            0.88,
            w_rim,
            w_bot,
            0.65,
            rgb(255, 153, 164),
            sc(10, s) as f32,
            if dark { 0.18 } else { 0.08 },
            0.0,
        );

        if let Some(rc_sh) = get_ctrl_client_rect(state.hwnd_main, state.btn_shred) {
            fluent_add_rect_glow(
                &mut state.bg_pixels,
                bw,
                bh,
                &rc_sh,
                sc(4, s) as f32,
                rgb(255, 153, 164),
                sc(14, s) as f32,
                if dark { 0.30 } else { 0.16 },
            );
        }
    } else if state.active_tab == 3 {
        let rc_card = RECT {
            left: sc(220, s),
            top: sc(138, s),
            right: cw - sc(20, s),
            bottom: sc(524, s),
        };
        fluent_draw_elevated_glass_card(
            &mut state.bg_pixels,
            bw,
            bh,
            &rc_card,
            s,
            dark,
            rgb(96, 205, 255),
            0.14,
            mx,
            my,
        );

        let rc_acc = RECT {
            left: sc(236, s),
            top: sc(151, s),
            right: sc(240, s),
            bottom: sc(168, s),
        };
        fluent_draw_glass_box(
            &mut state.bg_pixels,
            bw,
            bh,
            &rc_acc,
            sc(2, s) as f32,
            rgb(96, 205, 255),
            rgb(0, 120, 212),
            1.0,
            rgb(152, 224, 255),
            rgb(0, 120, 212),
            1.0,
            rgb(96, 205, 255),
            sc(6, s) as f32,
            0.40,
            0.0,
        );

        for &y0 in &[188, 254, 320, 386] {
            let rc_r = RECT {
                left: sc(236, s),
                top: sc(y0, s),
                right: rc_card.right - sc(16, s),
                bottom: sc(y0 + 54, s),
            };
            fluent_draw_recessed_glass_tile(&mut state.bg_pixels, bw, bh, &rc_r, sc(6, s) as f32, dark);
            fluent_apply_reveal_highlight(
                &mut state.bg_pixels,
                bw,
                bh,
                &rc_r,
                sc(6, s) as f32,
                mx,
                my,
                sc(140, s) as f32,
                rgb(96, 205, 255),
                0.03,
                0.30,
            );
        }
    } else {
        // TAB 4: ABOUT / PROGRAM & HARDWARE SPECIFICATIONS
        let rc_card = RECT {
            left: sc(220, s),
            top: sc(138, s),
            right: cw - sc(20, s),
            bottom: sc(524, s),
        };
        fluent_draw_elevated_glass_card(
            &mut state.bg_pixels,
            bw,
            bh,
            &rc_card,
            s,
            dark,
            rgb(96, 205, 255),
            0.14,
            mx,
            my,
        );

        let rc_acc = RECT {
            left: sc(236, s),
            top: sc(151, s),
            right: sc(240, s),
            bottom: sc(168, s),
        };
        fluent_draw_glass_box(
            &mut state.bg_pixels,
            bw,
            bh,
            &rc_acc,
            sc(2, s) as f32,
            rgb(96, 205, 255),
            rgb(0, 120, 212),
            1.0,
            rgb(152, 224, 255),
            rgb(0, 120, 212),
            1.0,
            rgb(96, 205, 255),
            sc(6, s) as f32,
            0.40,
            0.0,
        );

        for i in 0..7 {
            let y0 = 182 + (i * 47);
            let rc_r = RECT {
                left: sc(236, s),
                top: sc(y0, s),
                right: rc_card.right - sc(16, s),
                bottom: sc(y0 + 41, s),
            };
            fluent_draw_recessed_glass_tile(&mut state.bg_pixels, bw, bh, &rc_r, sc(5, s) as f32, dark);
            fluent_apply_reveal_highlight(
                &mut state.bg_pixels,
                bw,
                bh,
                &rc_r,
                sc(5, s) as f32,
                mx,
                my,
                sc(140, s) as f32,
                rgb(96, 205, 255),
                0.03,
                0.28,
            );
        }
    }

    // Dynamic Hover Reveal Glow Halo around Currently Hovered Control
    if !state.hovered_ctrl.is_null() {
        if let Some(rc_hov) = get_ctrl_client_rect(state.hwnd_main, state.hovered_ctrl) {
            let hov_col = if state.hovered_ctrl == state.btn_lock || state.hovered_ctrl == state.btn_shred {
                rgb(255, 153, 164)
            } else {
                rgb(96, 205, 255)
            };
            fluent_add_rect_glow(
                &mut state.bg_pixels,
                bw,
                bh,
                &rc_hov,
                sc(4, s) as f32,
                hov_col,
                sc(12, s) as f32,
                if dark { 0.28 } else { 0.16 },
            );
        }
    }

    // Blit the 32-bit Fluent 2 / WinUI 3 Canvas to the Memory DC
    blit_bgra_buffer(hdc, bw, bh, &state.bg_pixels);

    // ========================================================================
    // STAGE 2: CRISP GDI TYPOGRAPHY & VECTOR ICON OVERLAY PASS
    // ========================================================================
    if !state.h_icon.is_null() {
        DrawIconEx(hdc, sc(18, s), sc(20, s), state.h_icon, sc(32, s), sc(32, s), 0, null_mut(), 3);
    }
    draw_text_rect(
        hdc,
        "SECURE VAULT",
        RECT { left: sc(62, s), top: sc(15, s), right: sc(192, s), bottom: sc(37, s) },
        state.font_card_hdr,
        col_hdr,
        DT_LEFT | DT_VCENTER | DT_SINGLELINE,
    );
    draw_text_rect(
        hdc,
        "v2.5.7",
        rc_ver,
        state.font_small_bold,
        if dark { rgb(125, 211, 252) } else { rgb(29, 78, 216) },
        DT_CENTER | DT_VCENTER | DT_SINGLELINE,
    );

    let page_title = match state.active_tab {
        1 => tr("PASSWORD & SECURITY", "PASSWORD & SECURITY", "PASSWORD & SECURITY"),
        2 => tr("DOD 3-PASS FILE SHREDDER", "DOD 3-PASS FILE SHREDDER", "DOD 3-PASS FILE SHREDDER"),
        3 => tr("PREFERENCES", "PREFERENCES", "PREFERENCES"),
        4 => tr("ABOUT & SPECIFICATIONS", "ABOUT & SPECIFICATIONS", "ABOUT & SPECIFICATIONS"),
        _ => tr("SECURE USB VAULT", "SECURE USB VAULT", "SECURE USB VAULT"),
    };

    draw_text_rect(
        hdc,
        page_title,
        RECT { left: sc(238, s), top: sc(14, s), right: sc(685, s), bottom: sc(84, s) },
        state.font_title,
        rgb(255, 255, 255),
        DT_LEFT | DT_VCENTER | DT_SINGLELINE,
    );

    draw_circle_dot(
        hdc,
        rc_badge.left + sc(15, s),
        (rc_badge.top + rc_badge.bottom) / 2,
        sc(4, s),
        dot_col,
    );
    draw_text_rect(
        hdc,
        badge_txt,
        RECT {
            left: rc_badge.left + sc(23, s),
            top: rc_badge.top,
            right: rc_badge.right - sc(6, s),
            bottom: rc_badge.bottom,
        },
        state.font_small_bold,
        rgb(255, 255, 255),
        DT_CENTER | DT_VCENTER | DT_SINGLELINE,
    );

    // ========================================================================
    // TAB 0: HOME & LOCK CONTROL TEXT OVERLAY
    // ========================================================================
    if state.active_tab == 0 {
        let rc_card1_right = cw - sc(20, s);
        draw_text_rect(
            hdc,
            tr(
                "파티션 및 보안 상태",
                "Partition & Security Status",
                "パーティションおよびセキュリティ状態",
            ),
            RECT { left: sc(247, s), top: sc(147, s), right: rc_card1_right - sc(16, s), bottom: sc(171, s) },
            state.font_card_hdr,
            col_hdr,
            DT_LEFT | DT_VCENTER | DT_SINGLELINE,
        );

        let rc_bar = RECT {
            left: sc(236, s),
            top: sc(177, s),
            right: rc_card1_right - sc(16, s),
            bottom: sc(211, s),
        };
        if state.devices.is_empty() {
            draw_text_rect(
                hdc,
                tr("장치가 감지되지 않았습니다.", "No device detected.", "デバイスが検出されていません。"),
                RECT { left: rc_bar.left + sc(14, s), top: rc_bar.top, right: rc_bar.right, bottom: rc_bar.bottom },
                state.font_reg,
                col_sub,
                DT_LEFT | DT_VCENTER | DT_SINGLELINE,
            );
        } else {
            let d = &state.devices[state.selected_idx];
            let l0 = d.lun_gb(0);
            let l1 = d.lun_gb(1);
            let tot = (l0 + l1).max(0.001);
            if !d.has_security_lun || l1 <= 0.001 {
                let txt = format!(
                    "{} ({:.2} GB — 100%)",
                    tr("단일 일반 파티션", "Single Public Partition", "単一通常パーティション"),
                    l0
                );
                draw_text_rect(
                    hdc,
                    &txt,
                    RECT { left: rc_bar.left + sc(14, s), top: rc_bar.top, right: rc_bar.right, bottom: rc_bar.bottom },
                    state.font_small_bold,
                    rgb(255, 255, 255),
                    DT_LEFT | DT_VCENTER | DT_SINGLELINE,
                );
            } else {
                let total_w = rc_bar.right - rc_bar.left;
                let w0 = ((total_w as f64 * (l0 / tot)) as i32).max(sc(144, s));
                let rc0 = RECT { left: rc_bar.left, top: rc_bar.top, right: rc_bar.left + w0, bottom: rc_bar.bottom };
                let rc1 = RECT { left: rc_bar.left + w0, top: rc_bar.top, right: rc_bar.right, bottom: rc_bar.bottom };

                let t0 = if l0 < 1.0 {
                    format!("{} ({:.2} MB)", tr("런처", "Launcher", "ランチャー"), l0 * 1024.0)
                } else {
                    format!("{} ({:.1} GB)", tr("공개", "Public", "公開"), l0)
                };
                let t1 = if d.is_unlocked && d.sec_total_bytes > 0 {
                    let u_gb = (d.sec_used_bytes as f64) / 1073741824.0;
                    let f_gb = (d.sec_free_bytes as f64) / 1073741824.0;
                    format!(
                        "{} ({:.2} GB — {}: {:.2} GB / {}: {:.2} GB)",
                        tr("보안 영역", "Security", "セキュリティ"),
                        l1,
                        tr("사용", "Used", "使用"),
                        u_gb,
                        tr("여유", "Free", "空き"),
                        f_gb
                    )
                } else {
                    let st_str = if d.is_unlocked {
                        tr("잠금 해제됨", "Unlocked", "ロック解除済")
                    } else {
                        tr("암호 잠김", "Locked", "ロック中")
                    };
                    format!("{} ({:.2} GB — {})", tr("보안 영역", "Security", "セキュリティ領域"), l1, st_str)
                };

                draw_text_rect(
                    hdc,
                    &t0,
                    RECT { left: rc0.left + sc(4, s), top: rc0.top, right: rc0.right - sc(4, s), bottom: rc0.bottom },
                    state.font_small_bold,
                    rgb(255, 255, 255),
                    DT_CENTER | DT_VCENTER | DT_SINGLELINE,
                );
                draw_text_rect(
                    hdc,
                    &t1,
                    RECT { left: rc1.left + sc(12, s), top: rc1.top, right: rc1.right - sc(8, s), bottom: rc1.bottom },
                    state.font_small_bold,
                    rgb(255, 255, 255),
                    DT_LEFT | DT_VCENTER | DT_SINGLELINE,
                );
            }
        }

        let sec_col = if state.devices.is_empty() {
            col_sub
        } else {
            let d = &state.devices[state.selected_idx];
            if !d.has_security_lun {
                if dark { rgb(147, 197, 253) } else { rgb(37, 99, 235) }
            } else if d.is_unlocked {
                if dark { rgb(110, 231, 183) } else { rgb(5, 150, 105) }
            } else if dark {
                rgb(253, 164, 175)
            } else {
                rgb(225, 29, 72)
            }
        };
        let rc_tile2 = RECT {
            left: sc(236, s),
            top: sc(222, s),
            right: rc_card1_right - sc(16, s),
            bottom: sc(256, s),
        };
        draw_circle_dot(hdc, rc_tile2.left + sc(11, s), (rc_tile2.top + rc_tile2.bottom) / 2, sc(3, s), sec_col);
        draw_text_rect(
            hdc,
            &state.sec_state_str,
            RECT {
                left: rc_tile2.left + sc(22, s),
                top: rc_tile2.top,
                right: rc_tile2.right - sc(10, s),
                bottom: rc_tile2.bottom,
            },
            state.font_bold,
            sec_col,
            DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS,
        );

        let rc_tile3a = RECT {
            left: sc(236, s),
            top: sc(266, s),
            right: sc(524, s),
            bottom: sc(300, s),
        };
        draw_text_rect(
            hdc,
            &state.hint_str,
            RECT {
                left: rc_tile3a.left + sc(12, s),
                top: rc_tile3a.top,
                right: rc_tile3a.right - sc(8, s),
                bottom: rc_tile3a.bottom,
            },
            state.font_reg,
            col_sub,
            DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS,
        );

        let retry_col = if !state.devices.is_empty() {
            let d = &state.devices[state.selected_idx];
            if !d.is_unlocked && d.effective_retry_remain <= 3 {
                if dark { rgb(251, 113, 133) } else { rgb(225, 29, 72) }
            } else if (!d.is_unlocked && d.effective_retry_remain < d.effective_retry_limit) || d.last_intrusion_count > 0 {
                if dark { rgb(251, 191, 36) } else { rgb(217, 119, 6) }
            } else {
                col_sub
            }
        } else {
            col_sub
        };
        let rc_tile3b = RECT {
            left: sc(532, s),
            top: sc(266, s),
            right: rc_card1_right - sc(16, s),
            bottom: sc(300, s),
        };
        draw_text_rect(
            hdc,
            &state.retry_str,
            RECT {
                left: rc_tile3b.left + sc(12, s),
                top: rc_tile3b.top,
                right: rc_tile3b.right - sc(8, s),
                bottom: rc_tile3b.bottom,
            },
            state.font_bold,
            retry_col,
            DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS,
        );

        draw_text_rect(
            hdc,
            tr(
                "잠금 제어 및 드라이브 작업",
                "Lock Control & Drive Actions",
                "ロック制御およびドライブ操作",
            ),
            RECT { left: sc(247, s), top: sc(337, s), right: rc_card1_right - sc(16, s), bottom: sc(361, s) },
            state.font_card_hdr,
            col_hdr,
            DT_LEFT | DT_VCENTER | DT_SINGLELINE,
        );
        if state.caps_lock_on {
            let caps_col = if dark { rgb(251, 191, 36) } else { rgb(217, 119, 6) };
            draw_text_rect(
                hdc,
                tr("⚠️ Caps Lock 켜짐", "⚠️ Caps Lock is ON", "⚠️ Caps Lock ON"),
                RECT { left: sc(530, s), top: sc(337, s), right: rc_card1_right - sc(18, s), bottom: sc(361, s) },
                state.font_small_bold,
                caps_col,
                DT_RIGHT | DT_VCENTER | DT_SINGLELINE,
            );
        }

        draw_text_rect(
            hdc,
            tr("비밀번호:", "Password:", "パスワード:"),
            RECT { left: sc(236, s), top: sc(372, s), right: sc(316, s), bottom: sc(404, s) },
            state.font_bold,
            col_label,
            DT_LEFT | DT_VCENTER | DT_SINGLELINE,
        );

        let pwd_enabled = !state.devices.is_empty()
            && state.devices[state.selected_idx].has_security_lun
            && !state.devices[state.selected_idx].is_unlocked;
        let (pwd_bg, pwd_ico_col) = if dark {
            if pwd_enabled {
                (rgb(30, 30, 30), rgb(96, 205, 255))
            } else {
                (rgb(30, 30, 30), rgb(90, 90, 90))
            }
        } else if pwd_enabled {
            (rgb(255, 255, 255), rgb(0, 120, 212))
        } else {
            (rgb(243, 243, 243), rgb(160, 160, 160))
        };
        draw_button_icon(hdc, ID_BTN_CHANGE_PWD, sc(335, s), sc(388, s), s, pwd_ico_col, pwd_bg);
    }
    // ========================================================================
    // TAB 1: PASSWORD & VAULT SECURITY TEXT OVERLAY
    // ========================================================================
    else if state.active_tab == 1 {
        let rc_card_right = cw - sc(20, s);
        draw_text_rect(
            hdc,
            tr(
                "비밀번호 및 힌트 변경",
                "Change Password & Hint",
                "パスワードおよびヒントの変更",
            ),
            RECT { left: sc(247, s), top: sc(147, s), right: rc_card_right - sc(16, s), bottom: sc(171, s) },
            state.font_card_hdr,
            col_hdr,
            DT_LEFT | DT_VCENTER | DT_SINGLELINE,
        );
        if state.caps_lock_on {
            let caps_col = if dark { rgb(251, 191, 36) } else { rgb(217, 119, 6) };
            draw_text_rect(
                hdc,
                tr("⚠️ Caps Lock 켜짐", "⚠️ Caps Lock is ON", "⚠️ Caps Lock ON"),
                RECT { left: sc(530, s), top: sc(147, s), right: rc_card_right - sc(18, s), bottom: sc(171, s) },
                state.font_small_bold,
                caps_col,
                DT_RIGHT | DT_VCENTER | DT_SINGLELINE,
            );
        }

        let cur_summary = format!("{}    |    {}", state.hint_str, state.retry_str);
        draw_text_rect(
            hdc,
            &cur_summary,
            RECT { left: sc(250, s), top: sc(184, s), right: rc_card_right - sc(26, s), bottom: sc(222, s) },
            state.font_bold,
            col_label,
            DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS,
        );

        let form_enabled = !state.devices.is_empty() && state.devices[state.selected_idx].has_security_lun;
        let (inp_bg, ico_c) = if dark {
            if form_enabled {
                (rgb(30, 30, 30), rgb(96, 205, 255))
            } else {
                (rgb(30, 30, 30), rgb(90, 90, 90))
            }
        } else if form_enabled {
            (rgb(255, 255, 255), rgb(0, 120, 212))
        } else {
            (rgb(243, 243, 243), rgb(160, 160, 160))
        };

        let labels = [
            (tr("현재 비밀번호:", "Current Password:", "現在のパスワード:"), 250),
            (tr("새 비밀번호 (4~15자):", "New Password (4-15 chars):", "新しいパスワード (4〜15文字):"), 296),
            (tr("새 비밀번호 확인:", "Confirm New Password:", "新しいパスワード (確認):"), 342),
            (tr("새 비밀번호 힌트:", "New Password Hint:", "新しいパスワードヒント:"), 388),
        ];
        for &(lbl, y_top) in &labels {
            draw_text_rect(
                hdc,
                lbl,
                RECT {
                    left: sc(242, s),
                    top: sc(y_top, s),
                    right: sc(412, s),
                    bottom: sc(y_top + 34, s),
                },
                state.font_bold,
                col_label,
                DT_LEFT | DT_VCENTER | DT_SINGLELINE,
            );
            draw_button_icon(hdc, ID_BTN_CHANGE_PWD, sc(433, s), sc(y_top + 17, s), s, ico_c, inp_bg);
        }
    }
    // ========================================================================
    // TAB 2: DOD 3-PASS FILE SHREDDER TEXT OVERLAY
    // ========================================================================
    else if state.active_tab == 2 {
        let rc_card_right = cw - sc(20, s);
        draw_text_rect(
            hdc,
            tr(
                "파일 완전 삭제 (DoD 3-Pass Shredder)",
                "3-Pass DoD File Shredder",
                "ファイル完全削除 (DoD 3-Pass Shredder)",
            ),
            RECT { left: sc(247, s), top: sc(147, s), right: rc_card_right - sc(16, s), bottom: sc(171, s) },
            state.font_card_hdr,
            col_hdr,
            DT_LEFT | DT_VCENTER | DT_SINGLELINE,
        );

        let w_col = if dark { rgb(253, 164, 175) } else { rgb(190, 18, 60) };
        draw_text_rect(
            hdc,
            tr(
                "⚠️ 3-Pass 덮어쓰기 (0x00 → 0xFF → 난수)  ·  삭제된 파일은 복구할 수 없습니다.",
                "⚠️ 3-Pass Overwrite (0x00 → 0xFF → Random)  ·  Deleted files cannot be recovered.",
                "⚠️ 3-Pass 上書き (0x00 → 0xFF → 乱数)  ·  削除されたファイルは復元できません。",
            ),
            RECT { left: sc(248, s), top: sc(196, s), right: rc_card_right - sc(18, s), bottom: sc(226, s) },
            state.font_small_bold,
            w_col,
            DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS,
        );
        draw_text_rect(
            hdc,
            &state.sec_state_str,
            RECT { left: sc(252, s), top: sc(228, s), right: rc_card_right - sc(22, s), bottom: sc(256, s) },
            state.font_small_bold,
            col_label,
            DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS,
        );
    }
    // ========================================================================
    // TAB 3: SETTINGS & PREFERENCES TEXT OVERLAY
    // ========================================================================
    else if state.active_tab == 3 {
        let rc_card_right = cw - sc(20, s);
        draw_text_rect(
            hdc,
            tr(
                "환경 설정",
                "Preferences",
                "環境設定",
            ),
            RECT { left: sc(247, s), top: sc(147, s), right: rc_card_right - sc(16, s), bottom: sc(171, s) },
            state.font_card_hdr,
            col_hdr,
            DT_LEFT | DT_VCENTER | DT_SINGLELINE,
        );

        let rows = [
            (188, tr("자리 비움 자동 잠금 타이머", "Inactivity Auto-Lock Timer", "放置時の自動ロックタイマー")),
            (254, tr("인터페이스 화면 테마", "Appearance Theme", "インターフェース外観テーマ")),
            (320, tr("표시 언어 (Display Language)", "Display Language", "表示言語 (Display Language)")),
            (
                386,
                tr(
                    "보안 영역 아이콘·Autorun 복구",
                    "Repair Security Drive Icon & Autorun",
                    "セキュリティ領域のアイコン・Autorun修復",
                ),
            ),
        ];

        for &(y0, title_s) in &rows {
            draw_text_rect(
                hdc,
                title_s,
                RECT {
                    left: sc(254, s),
                    top: sc(y0, s),
                    right: sc(656, s),
                    bottom: sc(y0 + 54, s),
                },
                state.font_bold,
                col_hdr,
                DT_LEFT | DT_VCENTER | DT_SINGLELINE,
            );
        }
    }
    // ========================================================================
    // TAB 4: ABOUT / PROGRAM & HARDWARE SPECIFICATIONS TEXT OVERLAY
    // ========================================================================
    else {
        let rc_card_right = cw - sc(20, s);
        draw_text_rect(
            hdc,
            tr(
                "프로그램 정보 및 하드웨어 제원",
                "About & Hardware Specifications",
                "プログラム情報およびハードウェア仕様",
            ),
            RECT { left: sc(247, s), top: sc(147, s), right: rc_card_right - sc(16, s), bottom: sc(171, s) },
            state.font_card_hdr,
            col_hdr,
            DT_LEFT | DT_VCENTER | DT_SINGLELINE,
        );

        let hw_live_str = if state.devices.is_empty() {
            tr("연결된 장치 없음 (-)", "No device connected (-)", "未接続 (-)").to_string()
        } else {
            let d = &state.devices[state.selected_idx];
            let l0_mb = d.lun_gb(0) * 1024.0;
            let l1_gb = d.lun_gb(1);
            format!(
                "[{}] {} {}  ·  LUN0: {:.2} MB + LUN1: {:.2} GB",
                d.drive_letter,
                d.vendor,
                d.product,
                l0_mb,
                l1_gb
            )
        };

        let info_rows: [(&str, String); 7] = [
            (
                tr("프로그램 / 버전", "App / Version", "プログラム / 版"),
                "IS918 Secure USB Manager  ·  v2.5.7 (x86_64 Static CRT / WinPE)".to_string(),
            ),
            (
                tr("출처 / 제작자", "Source / Author", "出典 / 制作者"),
                "q20021410  (Open-Source Hardware Security Suite)".to_string(),
            ),
            (
                tr("GitHub 주소", "GitHub Repo", "GitHub URL"),
                GITHUB_REPO_URL.to_string(),
            ),
            (
                tr("대상 컨트롤러", "Controller", "コントローラ"),
                "Innostor IS918 / IS918M_GA (USB 3.0 Dual-LUN Controller)".to_string(),
            ),
            (
                tr("연결된 USB 제원", "Connected USB", "接続USB仕様"),
                hw_live_str,
            ),
            (
                tr("보안 아키텍처", "Security Spec", "セキュリティ仕様"),
                tr(
                    "ISO9660 CD-ROM (LUN0) + SCSI 0xE0 잠금 (LUN1) · SHA-256 볼트",
                    "ISO9660 CD-ROM (LUN0) + SCSI 0xE0 Lock (LUN1) · SHA-256 Vault",
                    "ISO9660 CD-ROM (LUN0) + SCSI 0xE0 ロック (LUN1) · SHA-256",
                )
                .to_string(),
            ),
            (
                tr("방어 정책 / 환경", "Defense / OS", "防御機能 / 環境"),
                tr(
                    "10회 오류 시 자동 파기 · DoD 3-Pass 완전 삭제 · Win10 / 11 / WinPE",
                    "10-Try Self-Destruct · DoD 3-Pass Shredder · Win10 / 11 / WinPE",
                    "10回失敗で自動破棄 · DoD 3-Pass完全削除 · Win10 / 11 / WinPE",
                )
                .to_string(),
            ),
        ];

        let key_col = if dark { rgb(96, 205, 255) } else { rgb(0, 103, 192) };
        for (i, (k_str, v_str)) in info_rows.iter().enumerate() {
            let y0 = 182 + (i as i32 * 47);
            let right_lim = if i == 2 {
                sc(700, s)
            } else {
                rc_card_right - sc(20, s)
            };
            draw_text_rect(
                hdc,
                k_str,
                RECT {
                    left: sc(248, s),
                    top: sc(y0, s),
                    right: sc(350, s),
                    bottom: sc(y0 + 41, s),
                },
                state.font_small_bold,
                key_col,
                DT_LEFT | DT_VCENTER | DT_SINGLELINE,
            );
            draw_text_rect(
                hdc,
                v_str,
                RECT {
                    left: sc(356, s),
                    top: sc(y0, s),
                    right: right_lim,
                    bottom: sc(y0 + 41, s),
                },
                state.font_small,
                col_hdr,
                DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS,
            );
        }
    }
}

unsafe extern "system" fn main_wnd_proc(hwnd: HWND, msg: UINT, w_param: WPARAM, l_param: LPARAM) -> LRESULT {
    match msg {
        WM_ERASEBKGND => 1,
        WM_PAINT => {
            let mut ps: PAINTSTRUCT = std::mem::zeroed();
            let hdc = BeginPaint(hwnd, &mut ps);

            let mut rc_client: RECT = std::mem::zeroed();
            GetClientRect(hwnd, &mut rc_client);
            let w = rc_client.right - rc_client.left;
            let h = rc_client.bottom - rc_client.top;

            let mem_dc = CreateCompatibleDC(hdc);
            let mem_bmp = CreateCompatibleBitmap(hdc, w, h);
            let old_bmp = SelectObject(mem_dc, mem_bmp as HGDIOBJ);

            if let Some(state) = get_state_mut() {
                paint_main_canvas(mem_dc, &rc_client, state);
            }

            BitBlt(hdc, 0, 0, w, h, mem_dc, 0, 0, SRCCOPY);
            SelectObject(mem_dc, old_bmp);
            DeleteObject(mem_bmp as HGDIOBJ);
            DeleteDC(mem_dc);

            EndPaint(hwnd, &ps);
            0
        }
        WM_DRAWITEM => {
            let dis = &*(l_param as *const DRAWITEMSTRUCT);
            let mut txt_buf = [0u16; 128];
            let len = GetWindowTextW(dis.hwnd_item, txt_buf.as_mut_ptr(), 127);
            let text = if len > 0 { String::from_utf16_lossy(&txt_buf[..len as usize]) } else { String::new() };

            let is_disabled = (dis.item_state & 0x0004) != 0;
            let is_pressed = (dis.item_state & 0x0001) != 0;
            let is_hovered = !is_disabled
                && get_state()
                    .map(|s| s.hovered_ctrl == dis.hwnd_item)
                    .unwrap_or(false);

            let id = dis.ctl_id as usize;
            let is_nav = id >= ID_NAV_HOME && id <= ID_NAV_ABOUT;
            let is_dropdown = id == ID_CMB_LANG || id == ID_CMB_DEV || id == ID_CMB_IDLE_TIMER;
            let is_secondary = id == ID_BTN_REFRESH
                || id == ID_BTN_THEME
                || id == ID_BTN_OPEN_DRV
                || id == ID_BTN_SAFE_EJECT
                || id == ID_BTN_TO_TRAY
                || id == ID_BTN_GITHUB
                || id == ID_BTN_RESTORE_AUTORUN;

            let bw = (dis.rc_item.right - dis.rc_item.left).max(1);
            let bh = (dis.rc_item.bottom - dis.rc_item.top).max(1);

            let mut rc_w = RECT { left: 0, top: 0, right: 0, bottom: 0 };
            GetWindowRect(dis.hwnd_item, &mut rc_w);
            let mut pt_tl = POINT { x: rc_w.left, y: rc_w.top };
            ScreenToClient(hwnd, &mut pt_tl);

            let dark = get_state().map(|s| s.dark_mode).unwrap_or(false);
            let fallback_bg = if is_nav || id == ID_BTN_TO_TRAY {
                if dark { rgb(32, 32, 32) } else { rgb(243, 243, 243) }
            } else if dark {
                rgb(44, 44, 44)
            } else {
                rgb(249, 249, 249)
            };

            let mut btn_buf = if let Some(state) = get_state() {
                fluent_extract_sub_buffer(
                    &state.bg_pixels,
                    state.bg_w,
                    state.bg_h,
                    pt_tl.x,
                    pt_tl.y,
                    bw,
                    bh,
                    fallback_bg,
                )
            } else {
                vec![pack_bgra(32, 32, 32); (bw * bh) as usize]
            };

            let rc_local = RECT { left: 0, top: 0, right: bw, bottom: bh };
            let local_mx = get_state().map(|s| (s.cursor_client.x - pt_tl.x) as f32).unwrap_or(-999.0);
            let local_my = get_state().map(|s| (s.cursor_client.y - pt_tl.y) as f32).unwrap_or(-999.0);

            if is_nav {
                if let Some(state) = get_state() {
                    let s = state.dpi_scale;
                    let nav_idx = id - ID_NAV_HOME;
                    let is_active = state.active_tab == nav_idx;

                    // Official WinUI 3 NavigationViewItem tokens:
                    // Selected: SubtleFillColorSecondary (#0Fffffff in dark mode, #09000000 in light mode)
                    // PointerOver: SubtleFillColorTertiary (#0Affffff in dark mode, #06000000 in light mode)
                    let (txt_c, ico_c, ico_bg) = if is_active {
                        if dark {
                            fluent_draw_glass_box(
                                &mut btn_buf,
                                bw,
                                bh,
                                &rc_local,
                                sc(6, s) as f32,
                                rgb(52, 52, 52),
                                rgb(46, 46, 46),
                                0.85,
                                rgb(90, 90, 90),
                                rgb(62, 62, 62),
                                0.50,
                                rgb(96, 205, 255),
                                0.0,
                                0.0,
                                0.0,
                            );
                            fluent_apply_reveal_highlight(
                                &mut btn_buf,
                                bw,
                                bh,
                                &rc_local,
                                sc(6, s) as f32,
                                local_mx,
                                local_my,
                                sc(95, s) as f32,
                                rgb(96, 205, 255),
                                0.08,
                                0.45,
                            );
                            (rgb(255, 255, 255), rgb(96, 205, 255), rgb(48, 48, 48))
                        } else {
                            fluent_draw_glass_box(
                                &mut btn_buf,
                                bw,
                                bh,
                                &rc_local,
                                sc(6, s) as f32,
                                rgb(234, 234, 234),
                                rgb(228, 228, 228),
                                0.90,
                                rgb(210, 210, 210),
                                rgb(200, 200, 200),
                                0.65,
                                rgb(0, 120, 212),
                                0.0,
                                0.0,
                                0.0,
                            );
                            (rgb(26, 26, 26), rgb(0, 120, 212), rgb(232, 232, 232))
                        }
                    } else if is_hovered || is_pressed {
                        if dark {
                            fluent_draw_glass_box(
                                &mut btn_buf,
                                bw,
                                bh,
                                &rc_local,
                                sc(6, s) as f32,
                                rgb(45, 45, 45),
                                rgb(40, 40, 40),
                                0.72,
                                rgb(80, 80, 80),
                                rgb(55, 55, 55),
                                0.40,
                                rgb(96, 205, 255),
                                0.0,
                                0.0,
                                0.0,
                            );
                            fluent_apply_reveal_highlight(
                                &mut btn_buf,
                                bw,
                                bh,
                                &rc_local,
                                sc(6, s) as f32,
                                local_mx,
                                local_my,
                                sc(95, s) as f32,
                                rgb(255, 255, 255),
                                0.07,
                                0.40,
                            );
                            (rgb(255, 255, 255), rgb(96, 205, 255), rgb(42, 42, 42))
                        } else {
                            fluent_draw_glass_box(
                                &mut btn_buf,
                                bw,
                                bh,
                                &rc_local,
                                sc(6, s) as f32,
                                rgb(238, 238, 238),
                                rgb(233, 233, 233),
                                0.78,
                                rgb(215, 215, 215),
                                rgb(205, 205, 205),
                                0.55,
                                rgb(0, 120, 212),
                                0.0,
                                0.0,
                                0.0,
                            );
                            (rgb(26, 26, 26), rgb(0, 120, 212), rgb(235, 235, 235))
                        }
                    } else if dark {
                        (rgb(200, 200, 200), rgb(180, 180, 180), rgb(32, 32, 32))
                    } else {
                        (rgb(92, 92, 92), rgb(92, 92, 92), rgb(243, 243, 243))
                    };

                    if is_active {
                        // Official WinUI 3 NavigationView Selection Indicator Pill (3px wide, 16px tall, #60CDFF / #0078D4)
                        let pill_col = if dark { rgb(96, 205, 255) } else { rgb(0, 120, 212) };
                        let rc_ind = RECT {
                            left: sc(2, s),
                            top: sc(12, s),
                            right: sc(5, s),
                            bottom: bh - sc(12, s),
                        };
                        fluent_draw_glass_box(
                            &mut btn_buf,
                            bw,
                            bh,
                            &rc_ind,
                            sc(2, s) as f32,
                            pill_col,
                            pill_col,
                            1.0,
                            pill_col,
                            pill_col,
                            1.0,
                            pill_col,
                            sc(5, s) as f32,
                            if dark { 0.45 } else { 0.15 },
                            0.0,
                        );
                    }

                    blit_bgra_buffer(dis.hdc, bw, bh, &btn_buf);

                    let cy = bh / 2;
                    let cx = sc(24, s);
                    draw_button_icon(dis.hdc, id, cx, cy, s, ico_c, ico_bg);

                    let rc_txt = RECT {
                        left: sc(42, s),
                        top: 0,
                        right: bw - sc(8, s),
                        bottom: bh,
                    };
                    let f = if is_active { state.font_bold } else { state.font_reg };
                    draw_text_rect(
                        dis.hdc,
                        &text,
                        rc_txt,
                        f,
                        txt_c,
                        DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS,
                    );
                }
                return 1;
            }

            if id == ID_CHK_SHOW_PWD {
                if let Some(state) = get_state() {
                    let s = state.dpi_scale;
                    let box_sz = sc(18, s);
                    let bx = sc(2, s);
                    let by = (bh - box_sz) / 2;
                    let rc_box = RECT {
                        left: bx,
                        top: by,
                        right: bx + box_sz,
                        bottom: by + box_sz,
                    };

                    if state.show_pwd {
                        // WinUI 3 CheckBox Checked state: AccentFillColorDefault (#60CDFF Dark / #0078D4 Light)
                        let acc_c = if dark { rgb(96, 205, 255) } else { rgb(0, 120, 212) };
                        fluent_draw_glass_box(
                            &mut btn_buf,
                            bw,
                            bh,
                            &rc_box,
                            sc(4, s) as f32,
                            acc_c,
                            acc_c,
                            0.98,
                            acc_c,
                            acc_c,
                            0.98,
                            acc_c,
                            sc(5, s) as f32,
                            0.30,
                            0.0,
                        );
                    } else {
                        let (b_top, b_rim) = if is_hovered {
                            if dark {
                                (rgb(52, 52, 52), rgb(160, 160, 160))
                            } else {
                                (rgb(236, 236, 236), rgb(110, 110, 110))
                            }
                        } else if dark {
                            (rgb(36, 36, 36), rgb(138, 138, 138))
                        } else {
                            (rgb(245, 245, 245), rgb(138, 138, 138))
                        };
                        fluent_draw_glass_box(
                            &mut btn_buf,
                            bw,
                            bh,
                            &rc_box,
                            sc(4, s) as f32,
                            b_top,
                            b_top,
                            0.90,
                            b_rim,
                            b_rim,
                            0.90,
                            rgb(96, 205, 255),
                            0.0,
                            0.0,
                            0.0,
                        );
                    }

                    blit_bgra_buffer(dis.hdc, bw, bh, &btn_buf);

                    if state.show_pwd {
                        let chk_col = if dark { rgb(16, 16, 16) } else { rgb(255, 255, 255) };
                        let pen_chk = CreatePen(PS_SOLID, sc(2, s).max(2), chk_col);
                        let op = SelectObject(dis.hdc, pen_chk as HGDIOBJ);
                        MoveToEx(dis.hdc, bx + sc(4, s), by + sc(9, s), null_mut());
                        LineTo(dis.hdc, bx + sc(8, s), by + sc(13, s));
                        LineTo(dis.hdc, bx + sc(14, s), by + sc(5, s));
                        SelectObject(dis.hdc, op);
                        DeleteObject(pen_chk as HGDIOBJ);
                    }

                    let txt_col = if dark { rgb(245, 245, 245) } else { rgb(26, 26, 26) };
                    let rc_txt = RECT {
                        left: bx + box_sz + sc(7, s),
                        top: 0,
                        right: bw,
                        bottom: bh,
                    };
                    draw_text_rect(
                        dis.hdc,
                        &text,
                        rc_txt,
                        state.font_reg,
                        txt_col,
                        DT_LEFT | DT_VCENTER | DT_SINGLELINE,
                    );
                }
                return 1;
            }

            if is_dropdown {
                if let Some(state) = get_state() {
                    let s = state.dpi_scale;
                    // Official WinUI 3 ComboBox / DropDownButton tokens:
                    // ControlFillColorDefault (#0FFFFFFF / #383838 in Dark), ControlElevationBorderBrush
                    let (top_c, bot_c, rim_t, rim_b, txt_col, badge_bg, arrow_col, f_alpha) = if dark {
                        if is_pressed {
                            (
                                rgb(44, 44, 44),
                                rgb(40, 40, 40),
                                rgb(90, 90, 90),
                                rgb(70, 70, 70),
                                rgb(206, 206, 206),
                                rgb(34, 34, 34),
                                rgb(96, 205, 255),
                                0.90,
                            )
                        } else if is_hovered {
                            (
                                rgb(64, 64, 64),
                                rgb(58, 58, 58),
                                rgb(125, 125, 125),
                                rgb(82, 82, 82),
                                rgb(255, 255, 255),
                                rgb(48, 48, 48),
                                rgb(96, 205, 255),
                                0.88,
                            )
                        } else {
                            (
                                rgb(55, 55, 55),
                                rgb(49, 49, 49),
                                rgb(105, 105, 105),
                                rgb(68, 68, 68),
                                rgb(255, 255, 255),
                                rgb(38, 38, 38),
                                rgb(200, 200, 200),
                                0.84,
                            )
                        }
                    } else if is_pressed {
                        (
                            rgb(242, 242, 242),
                            rgb(236, 236, 236),
                            rgb(195, 195, 195),
                            rgb(175, 175, 175),
                            rgb(96, 96, 96),
                            rgb(228, 228, 228),
                            rgb(0, 120, 212),
                            0.94,
                        )
                    } else if is_hovered {
                        (
                            rgb(252, 252, 252),
                            rgb(246, 246, 246),
                            rgb(205, 205, 205),
                            rgb(165, 165, 165),
                            rgb(26, 26, 26),
                            rgb(236, 236, 236),
                            rgb(0, 120, 212),
                            0.94,
                        )
                    } else {
                        (
                            rgb(255, 255, 255),
                            rgb(250, 250, 250),
                            rgb(218, 218, 218),
                            rgb(180, 180, 180),
                            rgb(26, 26, 26),
                            rgb(243, 243, 243),
                            rgb(96, 96, 96),
                            0.90,
                        )
                    };

                    fluent_draw_glass_box(
                        &mut btn_buf,
                        bw,
                        bh,
                        &rc_local,
                        sc(4, s) as f32,
                        top_c,
                        bot_c,
                        f_alpha,
                        rim_t,
                        rim_b,
                        0.78,
                        rgb(96, 205, 255),
                        0.0,
                        0.0,
                        0.0,
                    );
                    if is_hovered {
                        fluent_apply_reveal_highlight(
                            &mut btn_buf,
                            bw,
                            bh,
                            &rc_local,
                            sc(4, s) as f32,
                            local_mx,
                            local_my,
                            sc(110, s) as f32,
                            rgb(96, 205, 255),
                            0.06,
                            0.45,
                        );
                    }

                    let arrow_w = sc(28, s);
                    let rc_badge = RECT {
                        left: bw - arrow_w,
                        top: sc(3, s),
                        right: bw - sc(3, s),
                        bottom: bh - sc(3, s),
                    };
                    fluent_draw_glass_box(
                        &mut btn_buf,
                        bw,
                        bh,
                        &rc_badge,
                        sc(3, s) as f32,
                        badge_bg,
                        badge_bg,
                        0.75,
                        rim_t,
                        rim_b,
                        0.25,
                        rgb(96, 205, 255),
                        0.0,
                        0.0,
                        0.0,
                    );

                    blit_bgra_buffer(dis.hdc, bw, bh, &btn_buf);

                    draw_text_rect(
                        dis.hdc,
                        "▾",
                        rc_badge,
                        state.font_bold,
                        arrow_col,
                        DT_CENTER | DT_VCENTER | DT_SINGLELINE,
                    );

                    let mut txt_left = sc(10, s);
                    if id == ID_CMB_LANG {
                        let fw = sc(22, s);
                        let fh = sc(15, s);
                        let fx = sc(11, s);
                        let fy = (bh - fh) / 2;
                        draw_flag_icon(dis.hdc, fx, fy, fw, fh, CURRENT_LANG);
                        txt_left = fx + fw + sc(6, s);
                    } else if id == ID_CMB_DEV {
                        let dot_col = if state.devices.is_empty() {
                            rgb(148, 163, 184)
                        } else if state.devices[state.selected_idx].is_unlocked {
                            rgb(108, 203, 95)
                        } else {
                            rgb(255, 153, 164)
                        };
                        let cy = bh / 2;
                        draw_circle_dot(dis.hdc, sc(14, s), cy, sc(4, s), dot_col);
                        txt_left = sc(26, s);
                    }

                    let rc_txt = RECT {
                        left: txt_left,
                        top: 0,
                        right: bw - arrow_w - sc(2, s),
                        bottom: bh,
                    };
                    let f = state.font_small_bold;
                    let align = if id == ID_CMB_DEV {
                        DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS
                    } else {
                        DT_CENTER | DT_VCENTER | DT_SINGLELINE
                    };
                    draw_text_rect(dis.hdc, &text, rc_txt, f, txt_col, align);
                }
                return 1;
            }

            // Official WinUI 3 Standard Button vs AccentButtonStyle
            let (top_c, bot_c, rim_t, rim_b, txt_col, f_alpha, r_alpha) = if is_secondary {
                if is_disabled {
                    if dark {
                        (rgb(42, 42, 42), rgb(38, 38, 38), rgb(64, 64, 64), rgb(52, 52, 52), rgb(110, 110, 110), 0.55, 0.40)
                    } else {
                        (rgb(245, 245, 245), rgb(240, 240, 240), rgb(218, 218, 218), rgb(210, 210, 210), rgb(160, 160, 160), 0.70, 0.55)
                    }
                } else if dark {
                    if is_pressed {
                        (rgb(45, 45, 45), rgb(41, 41, 41), rgb(86, 86, 86), rgb(68, 68, 68), rgb(206, 206, 206), 0.88, 0.75)
                    } else if is_hovered {
                        (rgb(64, 64, 64), rgb(58, 58, 58), rgb(125, 125, 125), rgb(82, 82, 82), rgb(255, 255, 255), 0.86, 0.82)
                    } else {
                        (rgb(55, 55, 55), rgb(49, 49, 49), rgb(105, 105, 105), rgb(68, 68, 68), rgb(255, 255, 255), 0.82, 0.72)
                    }
                } else if is_pressed {
                    (rgb(240, 240, 240), rgb(235, 235, 235), rgb(195, 195, 195), rgb(175, 175, 175), rgb(96, 96, 96), 0.92, 0.80)
                } else if is_hovered {
                    (rgb(250, 250, 250), rgb(244, 244, 244), rgb(205, 205, 205), rgb(165, 165, 165), rgb(26, 26, 26), 0.92, 0.85)
                } else {
                    (rgb(255, 255, 255), rgb(250, 250, 250), rgb(218, 218, 218), rgb(180, 180, 180), rgb(26, 26, 26), 0.88, 0.78)
                }
            } else if is_disabled {
                if dark {
                    (rgb(45, 45, 45), rgb(40, 40, 40), rgb(68, 68, 68), rgb(54, 54, 54), rgb(115, 115, 115), 0.60, 0.45)
                } else {
                    (rgb(236, 236, 236), rgb(230, 230, 230), rgb(212, 212, 212), rgb(198, 198, 198), rgb(160, 160, 160), 0.75, 0.55)
                }
            } else {
                match id {
                    ID_BTN_UNLOCK | ID_BTN_CHANGE_PWD => {
                        // Official WinUI 3 AccentButtonStyle:
                        // Dark Theme uses bright AccentLight2 (#60CDFF) with dark text (#101010)!
                        // Light Theme uses AccentBase (#0078D4) with white text (#FFFFFF)!
                        if dark {
                            if is_pressed {
                                (rgb(62, 168, 224), rgb(52, 152, 208), rgb(130, 215, 255), rgb(44, 138, 192), rgb(18, 24, 32), 0.96, 0.92)
                            } else if is_hovered {
                                (rgb(122, 215, 255), rgb(98, 205, 255), rgb(198, 240, 255), rgb(74, 184, 240), rgb(12, 18, 26), 0.96, 0.96)
                            } else {
                                (rgb(96, 205, 255), rgb(76, 190, 245), rgb(172, 230, 255), rgb(56, 168, 225), rgb(12, 18, 26), 0.94, 0.92)
                            }
                        } else if is_pressed {
                            (rgb(0, 95, 170), rgb(0, 82, 150), rgb(60, 145, 220), rgb(0, 68, 128), rgb(255, 255, 255), 0.96, 0.92)
                        } else if is_hovered {
                            (rgb(16, 132, 224), rgb(0, 114, 204), rgb(110, 188, 255), rgb(0, 95, 175), rgb(255, 255, 255), 0.95, 0.95)
                        } else {
                            (rgb(0, 120, 212), rgb(0, 103, 192), rgb(82, 168, 242), rgb(0, 86, 164), rgb(255, 255, 255), 0.94, 0.90)
                        }
                    }
                    ID_BTN_LOCK | ID_BTN_SHRED => {
                        if is_pressed {
                            (rgb(164, 34, 22), rgb(138, 28, 18), rgb(245, 130, 140), rgb(120, 22, 14), rgb(255, 255, 255), 0.96, 0.92)
                        } else if is_hovered {
                            (rgb(220, 58, 42), rgb(196, 43, 28), rgb(255, 178, 186), rgb(164, 34, 22), rgb(255, 255, 255), 0.95, 0.95)
                        } else {
                            (rgb(196, 43, 28), rgb(168, 35, 22), rgb(255, 153, 164), rgb(142, 28, 18), rgb(255, 255, 255), 0.92, 0.90)
                        }
                    }
                    _ => (rgb(64, 64, 64), rgb(52, 52, 52), rgb(120, 120, 120), rgb(72, 72, 72), rgb(255, 255, 255), 0.85, 0.80),
                }
            };

            if let Some(state) = get_state() {
                let s = state.dpi_scale;
                fluent_draw_glass_box(
                    &mut btn_buf,
                    bw,
                    bh,
                    &rc_local,
                    sc(4, s) as f32,
                    top_c,
                    bot_c,
                    f_alpha,
                    rim_t,
                    rim_b,
                    r_alpha,
                    top_c,
                    0.0,
                    0.0,
                    0.0,
                );
                if is_hovered && !is_disabled {
                    fluent_apply_reveal_highlight(
                        &mut btn_buf,
                        bw,
                        bh,
                        &rc_local,
                        sc(4, s) as f32,
                        local_mx,
                        local_my,
                        sc(120, s) as f32,
                        rgb(255, 255, 255),
                        0.08,
                        0.50,
                    );
                }
                blit_bgra_buffer(dis.hdc, bw, bh, &btn_buf);

                let f = if is_secondary { state.font_small_bold } else { state.font_bold };
                let cy = bh / 2;

                if id == ID_BTN_THEME {
                    let cx = sc(16, s);
                    draw_theme_icon(dis.hdc, cx, cy, s, state.dark_mode, bot_c);
                    let rc_t = RECT {
                        left: sc(26, s),
                        top: 0,
                        right: bw - sc(4, s),
                        bottom: bh,
                    };
                    draw_text_rect(
                        dis.hdc,
                        &text,
                        rc_t,
                        f,
                        txt_col,
                        DT_CENTER | DT_VCENTER | DT_SINGLELINE,
                    );
                } else {
                    let ico_x = if is_secondary { sc(17, s) } else { sc(24, s) };
                    draw_button_icon(dis.hdc, id, ico_x, cy, s, txt_col, bot_c);
                    let rc_t = RECT {
                        left: if is_secondary { sc(25, s) } else { sc(32, s) },
                        top: 0,
                        right: bw - sc(4, s),
                        bottom: bh,
                    };
                    draw_text_rect(
                        dis.hdc,
                        &text,
                        rc_t,
                        f,
                        txt_col,
                        DT_CENTER | DT_VCENTER | DT_SINGLELINE,
                    );
                }
            }
            1
        }
        WM_CTLCOLOREDIT => {
            let hdc = w_param as HDC;
            if let Some(state) = get_state() {
                if state.dark_mode {
                    SetBkColor(hdc, rgb(30, 30, 30));
                    SetTextColor(hdc, rgb(255, 255, 255));
                    return state.br_edit_dark as LRESULT;
                } else {
                    SetBkColor(hdc, rgb(255, 255, 255));
                    SetTextColor(hdc, rgb(26, 26, 26));
                    return state.br_card as LRESULT;
                }
            }
            GetStockObject(0) as LRESULT
        }
        WM_CTLCOLORSTATIC | WM_CTLCOLORBTN => {
            let hdc = w_param as HDC;
            let ctrl_hwnd = l_param as HWND;
            if let Some(state) = get_state() {
                let is_edit_ctrl = !ctrl_hwnd.is_null()
                    && (ctrl_hwnd == state.txt_pwd
                        || ctrl_hwnd == state.txt_curr_pwd
                        || ctrl_hwnd == state.txt_new_pwd
                        || ctrl_hwnd == state.txt_conf_pwd
                        || ctrl_hwnd == state.txt_new_hint);
                if is_edit_ctrl {
                    if state.dark_mode {
                        SetBkColor(hdc, rgb(30, 30, 30));
                        SetTextColor(hdc, rgb(130, 130, 130));
                        return state.br_edit_dark as LRESULT;
                    } else {
                        SetBkColor(hdc, rgb(243, 243, 243));
                        SetTextColor(hdc, rgb(150, 150, 150));
                        return state.br_edit_light_dis as LRESULT;
                    }
                }
                SetBkMode(hdc, TRANSPARENT);
                if state.dark_mode {
                    SetTextColor(hdc, rgb(232, 232, 232));
                    return state.br_card_dark as LRESULT;
                } else {
                    SetTextColor(hdc, rgb(26, 26, 26));
                    return state.br_card as LRESULT;
                }
            }
            GetStockObject(0) as LRESULT
        }
        WM_SYSCOMMAND => {
            if (w_param & 0xFFF0) == SC_MINIMIZE {
                ShowWindow(hwnd, 0); // Hide to system tray on minimize
                if let Some(state) = get_state_mut() {
                    init_or_update_tray_icon(
                        state,
                        Some((
                            tr("시스템 트레이 실행 중", "Running in System Tray", "システムトレイで実行中"),
                            tr(
                                "보안 USB 관리자가 트레이로 숨겨졌습니다. 아이콘을 더블클릭하면 다시 열립니다.",
                                "Secure USB Manager is minimized to tray. Double-click the icon to restore.",
                                "トレイに最小化されました。アイコンをダブルクリックすると開きます。",
                            ),
                            NIIF_INFO,
                        )),
                    );
                }
                return 0;
            }
            DefWindowProcW(hwnd, msg, w_param, l_param)
        }
        WM_TRAYICON => {
            let ev = (l_param as usize) & 0xFFFF;
            if ev == WM_LBUTTONDBLCLK {
                ShowWindow(hwnd, 5);
                ShowWindow(hwnd, 9);
                SetForegroundWindow(hwnd);
            } else if ev == WM_RBUTTONUP {
                show_tray_context_menu(hwnd);
            }
            0
        }
        WM_TIMER => {
            if w_param == TIMER_HOVER_CHECK {
                if let Some(state) = get_state_mut() {
                    let mut pt = POINT { x: 0, y: 0 };
                    GetCursorPos(&mut pt);
                    let mut pt_cl = pt;
                    ScreenToClient(hwnd, &mut pt_cl);
                    let cur_focus = GetFocus();

                    let ctrls = [
                        state.nav_home,
                        state.nav_pwd,
                        state.nav_shred,
                        state.nav_settings,
                        state.nav_about,
                        state.btn_github,
                        state.btn_restore_autorun,
                        state.btn_theme,
                        state.cmb_lang,
                        state.cmb_dev,
                        state.btn_refresh,
                        state.chk_show_pwd,
                        state.cmb_idle_timer,
                        state.btn_unlock,
                        state.btn_lock,
                        state.btn_change_pwd,
                        state.btn_open_drv,
                        state.btn_shred,
                        state.btn_safe_eject,
                        state.btn_to_tray,
                    ];
                    let mut new_hover: HWND = null_mut();
                    for &c in &ctrls {
                        if !c.is_null() && IsWindowVisible(c) != 0 {
                            let mut rc = RECT { left: 0, top: 0, right: 0, bottom: 0 };
                            GetWindowRect(c, &mut rc);
                            if pt.x >= rc.left && pt.x < rc.right && pt.y >= rc.top && pt.y < rc.bottom {
                                new_hover = c;
                                break;
                            }
                        }
                    }

                    let mut need_canvas_repaint = false;
                    let dx = (pt_cl.x - state.cursor_client.x).abs();
                    let dy = (pt_cl.y - state.cursor_client.y).abs();
                    if (dx >= 3 || dy >= 3) && pt_cl.x >= 0 && pt_cl.x < state.bg_w && pt_cl.y >= 0 && pt_cl.y < state.bg_h {
                        state.cursor_client = pt_cl;
                        need_canvas_repaint = true;
                    }
                    if cur_focus != state.focused_ctrl {
                        state.focused_ctrl = cur_focus;
                        need_canvas_repaint = true;
                    }
                    let caps = (GetKeyState(VK_CAPITAL) & 1) != 0;
                    if caps != state.caps_lock_on {
                        state.caps_lock_on = caps;
                        need_canvas_repaint = true;
                    }

                    if new_hover != state.hovered_ctrl {
                        let old = state.hovered_ctrl;
                        state.hovered_ctrl = new_hover;
                        need_canvas_repaint = true;
                        if !old.is_null() {
                            InvalidateRect(old, null(), 0);
                        }
                        if !new_hover.is_null() {
                            InvalidateRect(new_hover, null(), 0);
                        }
                    } else if need_canvas_repaint && !state.hovered_ctrl.is_null() {
                        InvalidateRect(state.hovered_ctrl, null(), 0);
                    }

                    if need_canvas_repaint {
                        InvalidateRect(hwnd, null(), 0);
                    }
                }
                return 0;
            }
            if w_param == TIMER_IDLE_CHECK {
                if let Some(state) = get_state_mut() {
                    if state.idle_limit_minutes > 0 && !state.devices.is_empty() {
                        let idx = state.selected_idx;
                        if state.devices[idx].has_security_lun && state.devices[idx].is_unlocked {
                            let idle_secs = get_idle_seconds();
                            if idle_secs >= state.idle_limit_minutes * 60 {
                                let (lok, _) = lock_device(&mut state.devices[idx]);
                                if lok {
                                    apply_language_and_refresh(state, true);
                                    init_or_update_tray_icon(
                                        state,
                                        Some((
                                            tr("자리 비움 자동 잠금 완료", "Auto-Locked due to Inactivity", "放置による自動ロック完了"),
                                            tr(
                                                "지정된 시간 동안 입력이 없어 보안 영역을 자동으로 잠갔습니다.",
                                                "Security partition was automatically locked due to user inactivity.",
                                                "一定時間操作がなかったため、セキュリティ領域を自動ロックしました。",
                                            ),
                                            NIIF_WARNING,
                                        )),
                                    );
                                }
                            }
                        }
                    }
                }
            }
            0
        }
        WM_DEVICECHANGE => {
            if w_param == DBT_DEVICEARRIVAL || w_param == DBT_DEVICEREMOVECOMPLETE {
                if let Some(state) = get_state_mut() {
                    apply_language_and_refresh(state, true);
                }
            }
            0
        }
        WM_COMMAND => {
            let id = w_param & 0xFFFF;
            let _code = ((w_param >> 16) & 0xFFFF) as u16;

            if id >= ID_NAV_HOME && id <= ID_NAV_ABOUT {
                let target_tab = id - ID_NAV_HOME;
                if let Some(state) = get_state_mut() {
                    if state.active_tab != target_tab {
                        state.active_tab = target_tab;
                        update_tab_visibility(state);
                    }
                }
                return 0;
            }

            if id == ID_BTN_GITHUB {
                let _ = Command::new("explorer.exe").arg(GITHUB_REPO_URL).spawn();
                return 0;
            }

            if id == ID_BTN_RESTORE_AUTORUN {
                let mut restore_res: Option<(bool, String)> = None;
                if let Some(state) = get_state_mut() {
                    if !state.devices.is_empty() {
                        let d = &mut state.devices[state.selected_idx];
                        if d.has_security_lun && !d.is_unlocked {
                            restore_res = Some((
                                false,
                                tr(
                                    "보안 영역이 현재 잠겨 있습니다.\n\n먼저 [홈 / 잠금 제어]에서 비밀번호를 입력해 잠금을 해제하면 아이콘(logo.ico)과 autorun.inf가 자동으로 복구되며, 해제된 상태에서 이 버튼으로 언제든 수동 복구할 수 있습니다.",
                                    "Security partition is currently locked.\n\nPlease unlock the security partition first; logo.ico and autorun.inf will be repaired automatically, or can be repaired manually while unlocked.",
                                    "セキュリティ領域は現在ロックされています。\n\n先にロックを解除するとアイコン(logo.ico)とautorun.infが自動修復されます。",
                                )
                                .to_string(),
                            ));
                        } else {
                            let target = d
                                .security_drive_letter
                                .clone()
                                .unwrap_or_else(|| d.drive_letter.clone());
                            let ok = restore_security_autorun_and_icon(&target, true);
                            if let Some(local_v) = load_vault(None, d) {
                                let _ = save_vault(Some(&target), d, &local_v);
                            }
                            if ok {
                                restore_res = Some((
                                    true,
                                    format!(
                                        "✅ [{}] {}",
                                        target,
                                        tr(
                                            "보안 드라이브에 autorun.inf 및 아이콘(logo.ico) 복구가 완료되었습니다!\n(읽기 전용·숨김 속성 및 'Secure USB' 라벨 적용 완료)",
                                            "Successfully repaired autorun.inf and drive icon (logo.ico) with Read-Only & Hidden attributes!",
                                            "autorun.inf およびドライブアイコン (logo.ico) の修復が完了しました！(読み取り専用・隠しファイル属性適用)"
                                        )
                                    ),
                                ));
                            } else {
                                restore_res = Some((
                                    false,
                                    tr(
                                        "드라이브에 파일을 기록할 수 없습니다. 쓰기 권한이나 마운트 상태를 확인해 주세요.",
                                        "Could not write autorun.inf or logo.ico to the drive. Please check write permissions.",
                                        "ドライブにファイルを書き込めませんでした。書き込み権限を確認してください。",
                                    )
                                    .to_string(),
                                ));
                            }
                        }
                    }
                }
                if let Some((ok, msg)) = restore_res {
                    let m = to_wide(&msg);
                    let t = to_wide(if ok {
                        tr("아이콘·Autorun 복구 완료", "Autorun & Icon Repaired", "アイコン・Autorun 修復完了")
                    } else {
                        tr("알림", "Notice", "確認")
                    });
                    MessageBoxW(
                        hwnd,
                        m.as_ptr(),
                        t.as_ptr(),
                        MB_OK | if ok { MB_ICONINFORMATION } else { MB_ICONWARNING },
                    );
                }
                return 0;
            }

            if id == ID_BTN_THEME {
                if let Some(state) = get_state_mut() {
                    state.dark_mode = !state.dark_mode;
                    apply_window_dark_titlebar(hwnd, state.dark_mode);
                    if !state.devices.is_empty() && state.selected_idx < state.devices.len() {
                        let idx = state.selected_idx;
                        update_vault_preferences(&mut state.devices[idx], state.idle_limit_minutes, state.dark_mode);
                    }
                    save_app_prefs(CURRENT_LANG, state.idle_limit_minutes, state.dark_mode);
                    apply_language_and_refresh(state, false);
                }
                return 0;
            }

            if id == ID_CMB_LANG {
                let mut btn_hw = null_mut();
                let mut cur_idx = 0usize;
                if let Some(state) = get_state() {
                    btn_hw = state.cmb_lang;
                    cur_idx = CURRENT_LANG as usize;
                }
                let items = vec![
                    "한국어".to_string(),
                    "English".to_string(),
                    "日本語".to_string(),
                ];
                if let Some(sel) = show_dropdown_popup(hwnd, btn_hw, &items, cur_idx) {
                    CURRENT_LANG = match sel {
                        1 => AppLang::EN,
                        2 => AppLang::JA,
                        _ => AppLang::KO,
                    };
                    if let Some(state) = get_state_mut() {
                        save_app_prefs(CURRENT_LANG, state.idle_limit_minutes, state.dark_mode);
                        apply_language_and_refresh(state, false);
                    }
                }
                return 0;
            }

            if id == ID_CMB_DEV {
                let mut btn_hw = null_mut();
                let mut items = Vec::new();
                let mut cur_idx = 0usize;
                if let Some(state) = get_state() {
                    btn_hw = state.cmb_dev;
                    cur_idx = state.selected_idx;
                    for d in &state.devices {
                        items.push(d.display_title());
                    }
                }
                if !items.is_empty() {
                    if let Some(sel) = show_dropdown_popup(hwnd, btn_hw, &items, cur_idx) {
                        if let Some(state) = get_state_mut() {
                            if sel < state.devices.len() {
                                state.selected_idx = sel;
                                let title = state.devices[sel].display_title();
                                set_ctrl_text(state.cmb_dev, &title);
                                InvalidateRect(state.cmb_dev, null(), 0);
                                update_selected_device_ui(state);
                            }
                        }
                    }
                }
                return 0;
            }

            if id == ID_CMB_IDLE_TIMER {
                let mut btn_hw = null_mut();
                let mut cur_idx = 0usize;
                if let Some(state) = get_state() {
                    btn_hw = state.cmb_idle_timer;
                    cur_idx = IDLE_TIMEOUT_MINS.iter().position(|&m| m == state.idle_limit_minutes).unwrap_or(0);
                }
                let items = vec![
                    tr("사용 안 함", "Disabled", "無効").to_string(),
                    tr("5분", "5 Minutes", "5分").to_string(),
                    tr("10분", "10 Minutes", "10分").to_string(),
                    tr("15분", "15 Minutes", "15分").to_string(),
                    tr("30분", "30 Minutes", "30分").to_string(),
                ];
                if let Some(sel) = show_dropdown_popup(hwnd, btn_hw, &items, cur_idx) {
                    if let Some(state) = get_state_mut() {
                        state.idle_limit_minutes = IDLE_TIMEOUT_MINS[sel];
                        if !state.devices.is_empty() && state.selected_idx < state.devices.len() {
                            let idx = state.selected_idx;
                            update_vault_preferences(&mut state.devices[idx], state.idle_limit_minutes, state.dark_mode);
                        }
                        save_app_prefs(CURRENT_LANG, state.idle_limit_minutes, state.dark_mode);
                        set_ctrl_text(state.cmb_idle_timer, get_idle_button_label(state.idle_limit_minutes));
                        InvalidateRect(state.cmb_idle_timer, null(), 0);
                    }
                }
                return 0;
            }

            if id == ID_BTN_REFRESH {
                if let Some(state) = get_state_mut() {
                    apply_language_and_refresh(state, true);
                }
                return 0;
            }

            if id == ID_CHK_SHOW_PWD {
                if let Some(state) = get_state_mut() {
                    state.show_pwd = !state.show_pwd;
                    let ch = if state.show_pwd { 0 } else { '●' as usize };
                    SendMessageW(state.txt_pwd, EM_SETPASSWORDCHAR, ch, 0);
                    InvalidateRect(state.chk_show_pwd, null(), 0);
                    InvalidateRect(state.txt_pwd, null(), 1);
                }
                return 0;
            }

            if id == ID_BTN_TO_TRAY {
                ShowWindow(hwnd, 0);
                if let Some(state) = get_state_mut() {
                    init_or_update_tray_icon(
                        state,
                        Some((
                            tr("시스템 트레이 실행 중", "Running in System Tray", "システムトレイで実行中"),
                            tr(
                                "우측 하단 트레이 아이콘을 더블클릭하거나 우클릭하여 제어할 수 있습니다.",
                                "Double-click or right-click the tray icon to control your Secure USB.",
                                "右下のトレイアイコンからいつでも操作できます。",
                            ),
                            NIIF_INFO,
                        )),
                    );
                }
                return 0;
            }

            if id == ID_BTN_OPEN_DRV {
                if let Some(state) = get_state() {
                    if !state.devices.is_empty() {
                        let d = &state.devices[state.selected_idx];
                        let target = d.security_drive_letter.as_deref().unwrap_or(&d.drive_letter);
                        let _ = Command::new("explorer.exe").arg(format!("{}\\", target)).spawn();
                    }
                }
                return 0;
            }

            if id == ID_BTN_SHRED {
                let sec_drv = if let Some(state) = get_state() {
                    if !state.devices.is_empty() {
                        let d = &state.devices[state.selected_idx];
                        Some(d.security_drive_letter.clone().unwrap_or_else(|| d.drive_letter.clone()))
                    } else {
                        None
                    }
                } else {
                    None
                };

                if let Some((ok, msg)) = select_and_shred_file(hwnd, sec_drv.as_deref()) {
                    let m = to_wide(&msg);
                    let t = to_wide(if ok {
                        tr("파일 완전 삭제 완료", "File Shredding Complete", "完全削除完了")
                    } else {
                        tr("오류", "Error", "エラー")
                    });
                    MessageBoxW(hwnd, m.as_ptr(), t.as_ptr(), MB_OK | if ok { MB_ICONINFORMATION } else { MB_ICONERROR });
                    if let Some(state) = get_state_mut() {
                        apply_language_and_refresh(state, true);
                    }
                }
                return 0;
            }

            if id == ID_BTN_SAFE_EJECT {
                let mut eject_res: Option<(bool, String)> = None;
                if let Some(state) = get_state_mut() {
                    if !state.devices.is_empty() {
                        let idx = state.selected_idx;
                        eject_res = Some(safe_eject_device(&mut state.devices[idx]));
                    }
                }
                if let Some((ok, msg)) = eject_res {
                    if let Some(state) = get_state_mut() {
                        apply_language_and_refresh(state, true);
                    }
                    let m = to_wide(&msg);
                    let t = to_wide(if ok {
                        tr("안전 제거 준비 완료", "Safe to Remove Hardware", "安全な取り外し完了")
                    } else {
                        tr("안전 제거 실패", "Safe Eject Failed", "取り外し失敗")
                    });
                    MessageBoxW(hwnd, m.as_ptr(), t.as_ptr(), MB_OK | if ok { MB_ICONINFORMATION } else { MB_ICONERROR });
                }
                return 0;
            }

            if id == ID_BTN_UNLOCK {
                let mut action_result: Option<(bool, String, Option<(i32, String)>)> = None;
                if let Some(state) = get_state_mut() {
                    if !state.devices.is_empty() && state.devices[state.selected_idx].has_security_lun {
                        let pwd = get_ctrl_text(state.txt_pwd);
                        if pwd.is_empty() {
                            let m = to_wide(tr("비밀번호를 입력해 주세요.", "Please enter your password.", "パスワードを入力してください。"));
                            let t = to_wide(tr("알림", "Notice", "確認"));
                            MessageBoxW(hwnd, m.as_ptr(), t.as_ptr(), MB_OK | MB_ICONWARNING);
                            return 0;
                        }
                        let idx = state.selected_idx;
                        state.devices[idx].vault_idle_mins = Some(state.idle_limit_minutes);
                        state.devices[idx].vault_dark_mode = Some(state.dark_mode);
                        let (ok, msg, intrusion) = unlock_device(&mut state.devices[idx], &pwd);
                        if ok {
                            set_ctrl_text(state.txt_pwd, "");
                        }
                        action_result = Some((ok, msg, intrusion));
                    }
                }
                if let Some((ok, msg, intrusion)) = action_result {
                    if let Some(state) = get_state_mut() {
                        apply_language_and_refresh(state, true);
                    }
                    let full_msg = if let Some((cnt, tm)) = intrusion {
                        format!(
                            "{}\n\n⚠️ [{}] {}\n({}: {} / {}: {})",
                            msg,
                            tr("보안 경고", "Security Alert", "セキュリティ警告"),
                            tr(
                                "이전에 잘못된 비밀번호 입력 시도가 감지되었습니다!",
                                "Previous failed password attempts were detected on this USB!",
                                "以前に誤ったパスワード試行が検知されました！",
                            ),
                            tr("실패 횟수", "Failed Attempts", "失敗回数"),
                            cnt,
                            tr("마지막 시도 시각", "Last Attempt Time", "最終試行時刻"),
                            if tm.is_empty() { "-" } else { &tm }
                        )
                    } else {
                        msg
                    };
                    let m = to_wide(&full_msg);
                    let t = to_wide(if ok {
                        tr("잠금 해제 완료", "Unlocked", "ロック解除完了")
                    } else {
                        tr("인증 오류", "Authentication Failed", "認証エラー")
                    });
                    MessageBoxW(hwnd, m.as_ptr(), t.as_ptr(), MB_OK | if ok { MB_ICONINFORMATION } else { MB_ICONERROR });
                }
                return 0;
            }

            if id == ID_BTN_LOCK {
                let mut lock_res: Option<(bool, String)> = None;
                if let Some(state) = get_state_mut() {
                    if !state.devices.is_empty() && state.devices[state.selected_idx].has_security_lun {
                        let idx = state.selected_idx;
                        lock_res = Some(lock_device(&mut state.devices[idx]));
                    }
                }
                if let Some((ok, msg)) = lock_res {
                    if let Some(state) = get_state_mut() {
                        apply_language_and_refresh(state, true);
                    }
                    let m = to_wide(&msg);
                    let t = to_wide(if ok {
                        tr("잠금 완료", "Locked", "ロック完了")
                    } else {
                        tr("잠금 실패", "Lock Failed", "ロック失敗")
                    });
                    MessageBoxW(hwnd, m.as_ptr(), t.as_ptr(), MB_OK | if ok { MB_ICONINFORMATION } else { MB_ICONERROR });
                }
                return 0;
            }

            if id == ID_BTN_CHANGE_PWD {
                let mut chg_res: Option<(bool, String)> = None;
                if let Some(state) = get_state_mut() {
                    if !state.devices.is_empty() && state.devices[state.selected_idx].has_security_lun {
                        let curr_p = get_ctrl_text(state.txt_curr_pwd);
                        let new_p = get_ctrl_text(state.txt_new_pwd);
                        let conf_p = get_ctrl_text(state.txt_conf_pwd);
                        let new_h = get_ctrl_text(state.txt_new_hint);

                        if curr_p.is_empty() {
                            let m = to_wide(tr("현재 비밀번호를 입력해 주세요.", "Please enter your current password.", "現在のパスワードを入力してください。"));
                            let t = to_wide(tr("알림", "Notice", "確認"));
                            MessageBoxW(hwnd, m.as_ptr(), t.as_ptr(), MB_OK | MB_ICONWARNING);
                            return 0;
                        }
                        if new_p.len() < 4 || new_p.len() > 15 {
                            let m = to_wide(tr("새 비밀번호는 4~15자로 입력해 주세요.", "New password must be 4 to 15 characters long.", "新しいパスワードは4〜15文字で入力してください。"));
                            let t = to_wide(tr("알림", "Notice", "確認"));
                            MessageBoxW(hwnd, m.as_ptr(), t.as_ptr(), MB_OK | MB_ICONWARNING);
                            return 0;
                        }
                        if new_p != conf_p {
                            let m = to_wide(tr("새 비밀번호와 확인란이 일치하지 않습니다.", "New passwords do not match.", "新しいパスワードと確認欄が一致しません。"));
                            let t = to_wide(tr("알림", "Notice", "確認"));
                            MessageBoxW(hwnd, m.as_ptr(), t.as_ptr(), MB_OK | MB_ICONWARNING);
                            return 0;
                        }

                        let idx = state.selected_idx;
                        let (ok, msg) = change_password(&mut state.devices[idx], &curr_p, &new_p, &new_h);
                        if ok {
                            set_ctrl_text(state.txt_curr_pwd, "");
                            set_ctrl_text(state.txt_new_pwd, "");
                            set_ctrl_text(state.txt_conf_pwd, "");
                        }
                        chg_res = Some((ok, msg));
                    }
                }
                if let Some((ok, msg)) = chg_res {
                    if let Some(state) = get_state_mut() {
                        apply_language_and_refresh(state, true);
                    }
                    let m = to_wide(&msg);
                    let t = to_wide(if ok {
                        tr("변경 완료", "Success", "変更完了")
                    } else {
                        tr("변경 실패", "Failed", "変更失敗")
                    });
                    MessageBoxW(hwnd, m.as_ptr(), t.as_ptr(), MB_OK | if ok { MB_ICONINFORMATION } else { MB_ICONERROR });
                }
                return 0;
            }

            DefWindowProcW(hwnd, msg, w_param, l_param)
        }
        WM_SIZE => {
            InvalidateRect(hwnd, null(), 1);
            0
        }
        WM_DPICHANGED => {
            let new_dpi = (w_param & 0xFFFF) as i32;
            let sug_rc = if l_param != 0 {
                Some(&*(l_param as *const RECT))
            } else {
                None
            };
            if let Some(state) = get_state_mut() {
                apply_dpi_scale(state, new_dpi, sug_rc);
            }
            0
        }
        WM_DESTROY => {
            KillTimer(hwnd, TIMER_IDLE_CHECK);
            KillTimer(hwnd, TIMER_HOVER_CHECK);
            if let Some(state) = get_state_mut() {
                remove_tray_icon(state);
                // Always auto-lock security partition on program exit
                if !state.devices.is_empty() {
                    let idx = state.selected_idx;
                    if state.devices[idx].has_security_lun && state.devices[idx].is_unlocked {
                        let _ = lock_device(&mut state.devices[idx]);
                    }
                }
            }
            PostQuitMessage(0);
            0
        }
        _ => DefWindowProcW(hwnd, msg, w_param, l_param),
    }
}

fn create_app_font(height: i32, weight: i32) -> HFONT {
    let face = to_wide("Malgun Gothic");
    unsafe {
        CreateFontW(height, 0, 0, 0, weight, 0, 0, 0, 1, 0, 0, 5, 0, face.as_ptr())
    }
}

unsafe fn get_window_dpi(hwnd: HWND, fallback_dpi: i32) -> i32 {
    type GetDpiForWindowFn = unsafe extern "system" fn(HWND) -> UINT;
    let u32_name = to_wide("user32.dll");
    let h_mod = GetModuleHandleW(u32_name.as_ptr());
    if !h_mod.is_null() {
        let fn_ptr = GetProcAddress(h_mod, b"GetDpiForWindow\0".as_ptr());
        if !fn_ptr.is_null() {
            let f: GetDpiForWindowFn = std::mem::transmute(fn_ptr);
            let dpi = f(hwnd) as i32;
            if dpi >= 96 {
                return dpi;
            }
        }
    }
    fallback_dpi.max(96)
}

unsafe fn adjust_window_rect_dpi(rc: &mut RECT, style: DWORD, ex_style: DWORD, dpi: i32) {
    type AdjustWindowRectExForDpiFn = unsafe extern "system" fn(*mut RECT, DWORD, BOOL, DWORD, UINT) -> BOOL;
    let u32_name = to_wide("user32.dll");
    let h_mod = GetModuleHandleW(u32_name.as_ptr());
    if !h_mod.is_null() {
        let fn_ptr = GetProcAddress(h_mod, b"AdjustWindowRectExForDpi\0".as_ptr());
        if !fn_ptr.is_null() {
            let f: AdjustWindowRectExForDpiFn = std::mem::transmute(fn_ptr);
            if f(rc, style, 0, ex_style, dpi as UINT) != 0 {
                return;
            }
        }
    }
    AdjustWindowRectEx(rc, style, 0, ex_style);
}

unsafe fn apply_dpi_scale(state: &mut AppUiState, new_dpi: i32, suggested_rc: Option<&RECT>) {
    let scale = if new_dpi > 96 { (new_dpi as f32) / 96.0 } else { 1.0 };
    state.dpi_scale = scale;

    let old_f1 = state.font_title;
    let old_f2 = state.font_card_hdr;
    let old_f3 = state.font_bold;
    let old_f4 = state.font_reg;
    let old_f5 = state.font_small_bold;
    let old_f6 = state.font_small;

    state.font_title = create_app_font(-sc(20, scale), 700);
    state.font_card_hdr = create_app_font(-sc(15, scale), 700);
    state.font_bold = create_app_font(-sc(14, scale), 700);
    state.font_reg = create_app_font(-sc(14, scale), 400);
    state.font_small_bold = create_app_font(-sc(13, scale), 700);
    state.font_small = create_app_font(-sc(13, scale), 400);

    let win_style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_CLIPCHILDREN;
    let mut rc_win = RECT {
        left: 0,
        top: 0,
        right: sc(860, scale),
        bottom: sc(540, scale),
    };
    adjust_window_rect_dpi(&mut rc_win, win_style, 0, new_dpi);
    let win_w = rc_win.right - rc_win.left;
    let win_h = rc_win.bottom - rc_win.top;

    if let Some(sug) = suggested_rc {
        SetWindowPos(
            state.hwnd_main,
            null_mut(),
            sug.left,
            sug.top,
            win_w,
            win_h,
            SWP_NOZORDER | SWP_NOACTIVATE,
        );
    } else {
        let mut cur_rc = RECT { left: 0, top: 0, right: 0, bottom: 0 };
        GetWindowRect(state.hwnd_main, &mut cur_rc);
        SetWindowPos(
            state.hwnd_main,
            null_mut(),
            cur_rc.left,
            cur_rc.top,
            win_w,
            win_h,
            SWP_NOZORDER | SWP_NOACTIVATE,
        );
    }

    // Sidebar Navigation Controls
    MoveWindow(state.nav_home, sc(12, scale), sc(82, scale), sc(176, scale), sc(42, scale), 1);
    MoveWindow(state.nav_pwd, sc(12, scale), sc(130, scale), sc(176, scale), sc(42, scale), 1);
    MoveWindow(state.nav_shred, sc(12, scale), sc(178, scale), sc(176, scale), sc(42, scale), 1);
    MoveWindow(state.nav_settings, sc(12, scale), sc(226, scale), sc(176, scale), sc(42, scale), 1);
    MoveWindow(state.nav_about, sc(12, scale), sc(274, scale), sc(176, scale), sc(42, scale), 1);
    MoveWindow(state.btn_to_tray, sc(12, scale), sc(480, scale), sc(176, scale), sc(40, scale), 1);

    // Persistent Top Device Selector Bar
    MoveWindow(state.cmb_dev, sc(220, scale), sc(94, scale), sc(502, scale), sc(32, scale), 1);
    MoveWindow(state.btn_refresh, sc(730, scale), sc(94, scale), sc(110, scale), sc(32, scale), 1);

    // Tab 0 (Home & Lock) Controls
    MoveWindow(state.txt_pwd, sc(350, scale), sc(378, scale), sc(362, scale), sc(19, scale), 1);
    SendMessageW(state.txt_pwd, WM_SETFONT, state.font_reg as WPARAM, 1);
    SendMessageW(
        state.txt_pwd,
        EM_SETMARGINS,
        3,
        (((sc(4, scale) as isize) << 16) | (sc(4, scale) as isize)) as LPARAM,
    );
    MoveWindow(state.chk_show_pwd, sc(732, scale), sc(376, scale), sc(84, scale), sc(24, scale), 1);
    SendMessageW(state.chk_show_pwd, WM_SETFONT, state.font_reg as WPARAM, 1);

    MoveWindow(state.btn_unlock, sc(236, scale), sc(416, scale), sc(288, scale), sc(46, scale), 1);
    MoveWindow(state.btn_lock, sc(536, scale), sc(416, scale), sc(288, scale), sc(46, scale), 1);
    MoveWindow(state.btn_open_drv, sc(236, scale), sc(472, scale), sc(188, scale), sc(36, scale), 1);
    MoveWindow(state.btn_safe_eject, sc(636, scale), sc(472, scale), sc(188, scale), sc(36, scale), 1);
    if state.active_tab == 3 {
        MoveWindow(state.btn_restore_autorun, sc(664, scale), sc(397, scale), sc(148, scale), sc(32, scale), 1);
    } else {
        MoveWindow(state.btn_restore_autorun, sc(436, scale), sc(472, scale), sc(188, scale), sc(36, scale), 1);
    }

    // Tab 1 (Password & Security) Controls
    let edits = [
        (state.txt_curr_pwd, 256),
        (state.txt_new_pwd, 302),
        (state.txt_conf_pwd, 348),
        (state.txt_new_hint, 394),
    ];
    for &(ed, y_ed) in &edits {
        MoveWindow(ed, sc(448, scale), sc(y_ed, scale), sc(362, scale), sc(19, scale), 1);
        SendMessageW(ed, WM_SETFONT, state.font_reg as WPARAM, 1);
        SendMessageW(
            ed,
            EM_SETMARGINS,
            3,
            (((sc(4, scale) as isize) << 16) | (sc(4, scale) as isize)) as LPARAM,
        );
    }
    MoveWindow(state.btn_change_pwd, sc(418, scale), sc(446, scale), sc(402, scale), sc(48, scale), 1);

    // Tab 2 (File Shredder) Controls
    MoveWindow(state.btn_shred, sc(276, scale), sc(292, scale), sc(508, scale), sc(52, scale), 1);

    // Tab 3 (Settings) Controls
    MoveWindow(state.cmb_idle_timer, sc(664, scale), sc(199, scale), sc(148, scale), sc(32, scale), 1);
    MoveWindow(state.btn_theme, sc(664, scale), sc(265, scale), sc(148, scale), sc(32, scale), 1);
    MoveWindow(state.cmb_lang, sc(664, scale), sc(331, scale), sc(148, scale), sc(32, scale), 1);

    // Tab 4 (About / Info) Controls
    MoveWindow(state.btn_github, sc(702, scale), sc(281, scale), sc(114, scale), sc(31, scale), 1);

    if !old_f1.is_null() { DeleteObject(old_f1 as HGDIOBJ); }
    if !old_f2.is_null() { DeleteObject(old_f2 as HGDIOBJ); }
    if !old_f3.is_null() { DeleteObject(old_f3 as HGDIOBJ); }
    if !old_f4.is_null() { DeleteObject(old_f4 as HGDIOBJ); }
    if !old_f5.is_null() { DeleteObject(old_f5 as HGDIOBJ); }
    if !old_f6.is_null() { DeleteObject(old_f6 as HGDIOBJ); }

    InvalidateRect(state.hwnd_main, null(), 1);
    InvalidateRect(state.nav_home, null(), 1);
    InvalidateRect(state.nav_pwd, null(), 1);
    InvalidateRect(state.nav_shred, null(), 1);
    InvalidateRect(state.nav_settings, null(), 1);
    InvalidateRect(state.nav_about, null(), 1);
    InvalidateRect(state.btn_github, null(), 1);
    InvalidateRect(state.btn_restore_autorun, null(), 1);
    InvalidateRect(state.btn_theme, null(), 1);
    InvalidateRect(state.cmb_lang, null(), 1);
    InvalidateRect(state.cmb_dev, null(), 1);
    InvalidateRect(state.btn_refresh, null(), 1);
    InvalidateRect(state.txt_pwd, null(), 1);
    InvalidateRect(state.chk_show_pwd, null(), 1);
    InvalidateRect(state.cmb_idle_timer, null(), 1);
    InvalidateRect(state.btn_unlock, null(), 1);
    InvalidateRect(state.btn_lock, null(), 1);
    InvalidateRect(state.btn_change_pwd, null(), 1);
    InvalidateRect(state.btn_open_drv, null(), 1);
    InvalidateRect(state.btn_shred, null(), 1);
    InvalidateRect(state.btn_safe_eject, null(), 1);
    InvalidateRect(state.btn_to_tray, null(), 1);
}

fn run_gui() {
    unsafe {
        let (saved_lang, saved_idle_mins, saved_dark_mode) = load_app_prefs();
        CURRENT_LANG = saved_lang.unwrap_or_else(detect_default_lang);
        let init_dark = saved_dark_mode.unwrap_or_else(detect_system_dark_mode);
        let h_inst = GetModuleHandleW(null());
        let h_icon = LoadIconW(h_inst, 1 as *const u16);

        let screen_dc = GetDC(null_mut());
        let dpi_x = GetDeviceCaps(screen_dc, 88);
        ReleaseDC(null_mut(), screen_dc);
        let scale = if dpi_x > 96 { (dpi_x as f32) / 96.0 } else { 1.0 };

        let cls_name = to_wide("SecureUSBManagerRustClassV3");
        let existing_hwnd = FindWindowW(cls_name.as_ptr(), null());
        if !existing_hwnd.is_null() {
            ShowWindow(existing_hwnd, 5);
            ShowWindow(existing_hwnd, 9);
            SetForegroundWindow(existing_hwnd);
            return;
        }
        let br_card = CreateSolidBrush(rgb(255, 255, 255));
        let br_card_dark = CreateSolidBrush(rgb(45, 45, 45));
        let br_edit_dark = CreateSolidBrush(rgb(30, 30, 30));
        let br_edit_light_dis = CreateSolidBrush(rgb(243, 243, 243));

        let wc = WNDCLASSEXW {
            cb_size: std::mem::size_of::<WNDCLASSEXW>() as UINT,
            style: CS_HREDRAW | CS_VREDRAW,
            lpfn_wnd_proc: main_wnd_proc,
            cb_cls_extra: 0,
            cb_wnd_extra: 0,
            h_instance: h_inst,
            h_icon,
            h_cursor: LoadCursorW(null_mut(), 32512 as *const u16),
            hbr_background: null_mut(),
            lpsz_menu_name: null(),
            lpsz_class_name: cls_name.as_ptr(),
            h_icon_sm: h_icon,
        };
        RegisterClassExW(&wc);

        let win_style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_CLIPCHILDREN;
        let mut rc_win = RECT {
            left: 0,
            top: 0,
            right: sc(860, scale),
            bottom: sc(540, scale),
        };
        adjust_window_rect_dpi(&mut rc_win, win_style, 0, dpi_x);
        let win_w = rc_win.right - rc_win.left;
        let win_h = rc_win.bottom - rc_win.top;

        let scr_w = GetSystemMetrics(0);
        let scr_h = GetSystemMetrics(1);
        let win_title = to_wide("Secure USB Manager");

        let hwnd = CreateWindowExW(
            0,
            cls_name.as_ptr(),
            win_title.as_ptr(),
            win_style,
            (scr_w - win_w) / 2,
            (scr_h - win_h) / 2,
            win_w,
            win_h,
            null_mut(),
            null_mut(),
            h_inst,
            null_mut(),
        );
        apply_window_dark_titlebar(hwnd, init_dark);

        let font_title = create_app_font(-sc(20, scale), 700);
        let font_card_hdr = create_app_font(-sc(15, scale), 700);
        let font_bold = create_app_font(-sc(14, scale), 700);
        let font_reg = create_app_font(-sc(14, scale), 400);
        let font_small_bold = create_app_font(-sc(13, scale), 700);
        let font_small = create_app_font(-sc(13, scale), 400);

        let c_btn = to_wide("BUTTON");
        let c_edit = to_wide("EDIT");
        let empty = to_wide("");

        // Left Sidebar Navigation Items
        let nav_home = CreateWindowExW(
            0,
            c_btn.as_ptr(),
            empty.as_ptr(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
            sc(12, scale),
            sc(82, scale),
            sc(176, scale),
            sc(42, scale),
            hwnd,
            ID_NAV_HOME as HMENU,
            h_inst,
            null_mut(),
        );
        let nav_pwd = CreateWindowExW(
            0,
            c_btn.as_ptr(),
            empty.as_ptr(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
            sc(12, scale),
            sc(130, scale),
            sc(176, scale),
            sc(42, scale),
            hwnd,
            ID_NAV_PWD as HMENU,
            h_inst,
            null_mut(),
        );
        let nav_shred = CreateWindowExW(
            0,
            c_btn.as_ptr(),
            empty.as_ptr(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
            sc(12, scale),
            sc(178, scale),
            sc(176, scale),
            sc(42, scale),
            hwnd,
            ID_NAV_SHRED as HMENU,
            h_inst,
            null_mut(),
        );
        let nav_settings = CreateWindowExW(
            0,
            c_btn.as_ptr(),
            empty.as_ptr(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
            sc(12, scale),
            sc(226, scale),
            sc(176, scale),
            sc(42, scale),
            hwnd,
            ID_NAV_SETTINGS as HMENU,
            h_inst,
            null_mut(),
        );
        let nav_about = CreateWindowExW(
            0,
            c_btn.as_ptr(),
            empty.as_ptr(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
            sc(12, scale),
            sc(274, scale),
            sc(176, scale),
            sc(42, scale),
            hwnd,
            ID_NAV_ABOUT as HMENU,
            h_inst,
            null_mut(),
        );
        let btn_to_tray = CreateWindowExW(
            0,
            c_btn.as_ptr(),
            empty.as_ptr(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
            sc(12, scale),
            sc(480, scale),
            sc(176, scale),
            sc(40, scale),
            hwnd,
            ID_BTN_TO_TRAY as HMENU,
            h_inst,
            null_mut(),
        );

        // Persistent Right-Pane Device Selector Bar
        let cmb_dev = CreateWindowExW(
            0,
            c_btn.as_ptr(),
            empty.as_ptr(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
            sc(220, scale),
            sc(94, scale),
            sc(502, scale),
            sc(32, scale),
            hwnd,
            ID_CMB_DEV as HMENU,
            h_inst,
            null_mut(),
        );
        let btn_refresh = CreateWindowExW(
            0,
            c_btn.as_ptr(),
            empty.as_ptr(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
            sc(730, scale),
            sc(94, scale),
            sc(110, scale),
            sc(32, scale),
            hwnd,
            ID_BTN_REFRESH as HMENU,
            h_inst,
            null_mut(),
        );

        // Tab 0 (Home & Lock) Controls
        let txt_pwd = CreateWindowExW(
            0,
            c_edit.as_ptr(),
            empty.as_ptr(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_PASSWORD | ES_AUTOHSCROLL,
            sc(350, scale),
            sc(378, scale),
            sc(362, scale),
            sc(19, scale),
            hwnd,
            ID_TXT_PWD as HMENU,
            h_inst,
            null_mut(),
        );
        SendMessageW(txt_pwd, WM_SETFONT, font_reg as WPARAM, 1);
        SendMessageW(txt_pwd, EM_SETMARGINS, 3, (((sc(4, scale) as isize) << 16) | (sc(4, scale) as isize)) as LPARAM);

        let chk_show_pwd = CreateWindowExW(
            0,
            c_btn.as_ptr(),
            empty.as_ptr(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
            sc(732, scale),
            sc(376, scale),
            sc(84, scale),
            sc(24, scale),
            hwnd,
            ID_CHK_SHOW_PWD as HMENU,
            h_inst,
            null_mut(),
        );
        SendMessageW(chk_show_pwd, WM_SETFONT, font_reg as WPARAM, 1);

        let btn_unlock = CreateWindowExW(
            0,
            c_btn.as_ptr(),
            empty.as_ptr(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
            sc(236, scale),
            sc(416, scale),
            sc(288, scale),
            sc(46, scale),
            hwnd,
            ID_BTN_UNLOCK as HMENU,
            h_inst,
            null_mut(),
        );
        let btn_lock = CreateWindowExW(
            0,
            c_btn.as_ptr(),
            empty.as_ptr(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
            sc(536, scale),
            sc(416, scale),
            sc(288, scale),
            sc(46, scale),
            hwnd,
            ID_BTN_LOCK as HMENU,
            h_inst,
            null_mut(),
        );
        let btn_open_drv = CreateWindowExW(
            0,
            c_btn.as_ptr(),
            empty.as_ptr(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
            sc(236, scale),
            sc(472, scale),
            sc(188, scale),
            sc(36, scale),
            hwnd,
            ID_BTN_OPEN_DRV as HMENU,
            h_inst,
            null_mut(),
        );
        let btn_restore_autorun = CreateWindowExW(
            0,
            c_btn.as_ptr(),
            empty.as_ptr(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
            sc(436, scale),
            sc(472, scale),
            sc(188, scale),
            sc(36, scale),
            hwnd,
            ID_BTN_RESTORE_AUTORUN as HMENU,
            h_inst,
            null_mut(),
        );
        let btn_safe_eject = CreateWindowExW(
            0,
            c_btn.as_ptr(),
            empty.as_ptr(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
            sc(636, scale),
            sc(472, scale),
            sc(188, scale),
            sc(36, scale),
            hwnd,
            ID_BTN_SAFE_EJECT as HMENU,
            h_inst,
            null_mut(),
        );

        // Tab 1 (Password & Vault Security) Controls
        let mk_tab1_edit = |id: usize, y_pos: i32, is_pwd: bool| -> HWND {
            let mut st_ed = WS_CHILD | WS_TABSTOP | ES_AUTOHSCROLL;
            if is_pwd {
                st_ed |= ES_PASSWORD;
            }
            let hw = CreateWindowExW(
                0,
                c_edit.as_ptr(),
                empty.as_ptr(),
                st_ed,
                sc(448, scale),
                sc(y_pos, scale),
                sc(362, scale),
                sc(19, scale),
                hwnd,
                id as HMENU,
                h_inst,
                null_mut(),
            );
            SendMessageW(hw, WM_SETFONT, font_reg as WPARAM, 1);
            SendMessageW(hw, EM_SETMARGINS, 3, (((sc(4, scale) as isize) << 16) | (sc(4, scale) as isize)) as LPARAM);
            hw
        };
        let txt_curr_pwd = mk_tab1_edit(ID_TXT_CURR_PWD, 256, true);
        let txt_new_pwd = mk_tab1_edit(ID_TXT_NEW_PWD, 302, true);
        let txt_conf_pwd = mk_tab1_edit(ID_TXT_CONF_PWD, 348, true);
        let txt_new_hint = mk_tab1_edit(ID_TXT_NEW_HINT, 394, false);

        let btn_change_pwd = CreateWindowExW(
            0,
            c_btn.as_ptr(),
            empty.as_ptr(),
            WS_CHILD | WS_TABSTOP | BS_OWNERDRAW,
            sc(418, scale),
            sc(446, scale),
            sc(402, scale),
            sc(48, scale),
            hwnd,
            ID_BTN_CHANGE_PWD as HMENU,
            h_inst,
            null_mut(),
        );

        // Tab 2 (File Shredder) Controls
        let btn_shred = CreateWindowExW(
            0,
            c_btn.as_ptr(),
            empty.as_ptr(),
            WS_CHILD | WS_TABSTOP | BS_OWNERDRAW,
            sc(276, scale),
            sc(292, scale),
            sc(508, scale),
            sc(52, scale),
            hwnd,
            ID_BTN_SHRED as HMENU,
            h_inst,
            null_mut(),
        );

        // Tab 3 (Settings) Controls
        let cmb_idle_timer = CreateWindowExW(
            0,
            c_btn.as_ptr(),
            empty.as_ptr(),
            WS_CHILD | WS_TABSTOP | BS_OWNERDRAW,
            sc(664, scale),
            sc(199, scale),
            sc(148, scale),
            sc(32, scale),
            hwnd,
            ID_CMB_IDLE_TIMER as HMENU,
            h_inst,
            null_mut(),
        );
        let btn_theme = CreateWindowExW(
            0,
            c_btn.as_ptr(),
            empty.as_ptr(),
            WS_CHILD | WS_TABSTOP | BS_OWNERDRAW,
            sc(664, scale),
            sc(265, scale),
            sc(148, scale),
            sc(32, scale),
            hwnd,
            ID_BTN_THEME as HMENU,
            h_inst,
            null_mut(),
        );
        let cmb_lang = CreateWindowExW(
            0,
            c_btn.as_ptr(),
            empty.as_ptr(),
            WS_CHILD | WS_TABSTOP | BS_OWNERDRAW,
            sc(664, scale),
            sc(331, scale),
            sc(148, scale),
            sc(32, scale),
            hwnd,
            ID_CMB_LANG as HMENU,
            h_inst,
            null_mut(),
        );

        // Tab 4 (About / Info) Controls
        let btn_github = CreateWindowExW(
            0,
            c_btn.as_ptr(),
            empty.as_ptr(),
            WS_CHILD | WS_TABSTOP | BS_OWNERDRAW,
            sc(702, scale),
            sc(281, scale),
            sc(114, scale),
            sc(31, scale),
            hwnd,
            ID_BTN_GITHUB as HMENU,
            h_inst,
            null_mut(),
        );

        let st = AppUiState {
            hwnd_main: hwnd,
            dpi_scale: scale,
            active_tab: 0,
            h_icon,
            font_title,
            font_card_hdr,
            font_bold,
            font_reg,
            font_small_bold,
            font_small,
            br_card,
            br_card_dark,
            br_edit_dark,
            br_edit_light_dis,
            nav_home,
            nav_pwd,
            nav_shred,
            nav_settings,
            nav_about,
            btn_github,
            btn_restore_autorun,
            btn_theme,
            cmb_lang,
            cmb_dev,
            btn_refresh,
            txt_pwd,
            chk_show_pwd,
            btn_unlock,
            btn_lock,
            txt_curr_pwd,
            txt_new_pwd,
            txt_conf_pwd,
            txt_new_hint,
            btn_change_pwd,
            cmb_idle_timer,
            btn_open_drv,
            btn_shred,
            btn_safe_eject,
            btn_to_tray,
            hovered_ctrl: null_mut(),
            focused_ctrl: null_mut(),
            cursor_client: POINT { x: 420, y: 200 },
            bg_pixels: Vec::new(),
            bg_w: 0,
            bg_h: 0,
            devices: Vec::new(),
            selected_idx: 0,
            part_info_str: String::new(),
            sec_state_str: String::new(),
            hint_str: String::new(),
            retry_str: String::new(),
            idle_limit_minutes: saved_idle_mins,
            dark_mode: init_dark,
            show_pwd: false,
            caps_lock_on: (GetKeyState(VK_CAPITAL) & 1) != 0,
            tray_active: false,
        };

        let ptr = &raw mut APP_STATE;
        *ptr = Some(st);
        let actual_dpi = get_window_dpi(hwnd, dpi_x);
        if let Some(state) = get_state_mut() {
            if actual_dpi != dpi_x {
                apply_dpi_scale(state, actual_dpi, None);
            }
            apply_language_and_refresh(state, true);
        }

        // Start 5-second background timer for Idle Auto-Lock check & 45ms UI Hover Glow tracker
        SetTimer(hwnd, TIMER_IDLE_CHECK, 5000, null_mut());
        SetTimer(hwnd, TIMER_HOVER_CHECK, 45, null_mut());

        ShowWindow(hwnd, 5);
        UpdateWindow(hwnd);

        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
            if msg.message == 0x0100 && msg.w_param == 0x0D {
                if let Some(s) = get_state() {
                    if msg.hwnd == s.txt_pwd {
                        SendMessageW(hwnd, WM_COMMAND, ID_BTN_UNLOCK, 0);
                        continue;
                    } else if msg.hwnd == s.txt_curr_pwd
                        || msg.hwnd == s.txt_new_pwd
                        || msg.hwnd == s.txt_conf_pwd
                        || msg.hwnd == s.txt_new_hint
                    {
                        SendMessageW(hwnd, WM_COMMAND, ID_BTN_CHANGE_PWD, 0);
                        continue;
                    }
                }
            }
            if IsDialogMessageW(hwnd, &mut msg) == 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        let cmd = args[1].to_lowercase();
        let mut devs = scan_devices();
        if devs.is_empty() {
            println!("No Secure USB device found.");
            std::process::exit(1);
        }
        let target = &mut devs[0];
        match cmd.as_str() {
            "status" => {
                println!("{}", target.display_title());
                for i in 0..4 {
                    if target.lun_sectors[i] > 0 {
                        println!("  LUN{}: {} sectors ({:.2} GB), Flag=0x{:02X}", i, target.lun_sectors[i], target.lun_gb(i), target.lun_flags[i]);
                    }
                }
                if target.has_security_lun {
                    println!(
                        "  Security: Unlocked={}, Hint='{}', Retry={}/{}, SecDrive={}",
                        target.is_unlocked,
                        target.effective_hint,
                        target.effective_retry_remain,
                        target.effective_retry_limit,
                        target.security_drive_letter.as_deref().unwrap_or("Hidden")
                    );
                    if target.sec_total_bytes > 0 {
                        println!(
                            "  Disk Usage: Used={:.2} GB / Free={:.2} GB / Total={:.2} GB",
                            target.sec_used_bytes as f64 / 1073741824.0,
                            target.sec_free_bytes as f64 / 1073741824.0,
                            target.sec_total_bytes as f64 / 1073741824.0
                        );
                    }
                }
            }
            "unlock" if args.len() >= 3 => {
                let (ok, msg, _) = unlock_device(target, &args[2]);
                println!("{}", msg);
                std::process::exit(if ok { 0 } else { 1 });
            }
            "lock" => {
                let (ok, msg) = lock_device(target);
                println!("{}", msg);
                std::process::exit(if ok { 0 } else { 1 });
            }
            "eject" => {
                let (ok, msg) = safe_eject_device(target);
                println!("{}", msg);
                std::process::exit(if ok { 0 } else { 1 });
            }
            "passwd" if args.len() >= 4 => {
                let hint = if args.len() >= 5 { args[4].clone() } else { target.effective_hint.clone() };
                let (ok, msg) = change_password(target, &args[2], &args[3], &hint);
                println!("{}", msg);
                std::process::exit(if ok { 0 } else { 1 });
            }
            _ => {}
        }
        return;
    }

    run_gui();
}
