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
const OPEN_EXISTING: DWORD = 3;
const FILE_ATTRIBUTE_NORMAL: DWORD = 0x00000080;
const FILE_ATTRIBUTE_HIDDEN: DWORD = 0x00000002;
const FILE_ATTRIBUTE_SYSTEM: DWORD = 0x00000004;

const IOCTL_SCSI_PASS_THROUGH_DIRECT: DWORD = 0x0004D014;
const FSCTL_LOCK_VOLUME: DWORD = 0x00090018;
const FSCTL_DISMOUNT_VOLUME: DWORD = 0x00090020;
const IOCTL_STORAGE_EJECT_MEDIA: DWORD = 0x002D4808;

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
const WM_USER: UINT = 0x0400;
const WM_TRAYICON: UINT = WM_USER + 55;

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
}

#[link(name = "user32")]
extern "system" {
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
    fn SetForegroundWindow(h_wnd: HWND) -> BOOL;
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
    fn DeleteDC(hdc: HDC) -> BOOL;
    fn GetDeviceCaps(hdc: HDC, index: i32) -> i32;
}

#[link(name = "dwmapi")]
extern "system" {
    fn DwmSetWindowAttribute(hwnd: HWND, dw_attribute: DWORD, pv_attribute: *const c_void, cb_attribute: DWORD) -> i32;
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
            tr("보안 영역 열림 (Unlocked)", "Security Unlocked", "セキュリティ領域 解除済")
        } else {
            tr("보안 영역 잠김 (Locked)", "Security Locked", "セキュリティ領域 ロック中")
        };
        format!("[{}] {} {} ({:.1} GB)  —  {}", self.drive_letter, self.vendor, self.product, self.total_gb(), st)
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
        let val: BOOL = if dark { 1 } else { 0 };
        let _ = DwmSetWindowAttribute(hwnd, 20, &val as *const _ as *const c_void, 4);
        let _ = DwmSetWindowAttribute(hwnd, 19, &val as *const _ as *const c_void, 4);
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

fn execute_scsi(h_dev: HANDLE, cdb: &[u8], direction: u8, buffer: &mut [u8]) -> bool {
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
            data_buffer: if buffer.is_empty() { null_mut() } else { buffer.as_mut_ptr() as *mut c_void },
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
    ok != 0 && swb.sptd.scsi_status == 0
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
    unsafe {
        let mut h = CreateFileW(
            path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null_mut(),
            OPEN_EXISTING,
            0,
            null_mut(),
        );
        if h == INVALID_HANDLE_VALUE {
            h = CreateFileW(
                path.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
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

fn query_drive(drive_letter: &str) -> Option<DeviceInfo> {
    let h_dev = open_drive_handle(drive_letter);
    if h_dev == INVALID_HANDLE_VALUE {
        return None;
    }

    let mut inq = [0u8; 0x60];
    if !execute_scsi(h_dev, &[0x12, 0, 0, 0, 0x60, 0, 0, 0, 0, 0], SCSI_IOCTL_DATA_IN, &mut inq) {
        unsafe { CloseHandle(h_dev); }
        return None;
    }

    if &inq[40..44] != b"BWSE" {
        unsafe { CloseHandle(h_dev); }
        return None;
    }

    let vendor = String::from_utf8_lossy(&inq[8..16]).trim().to_string();
    let product = String::from_utf8_lossy(&inq[16..32]).trim().to_string();

    let mut flash_id = [0u8; 6];
    let mut fid_buf = [0u8; 512];
    if execute_scsi(h_dev, &[0xE0, 0x10, 0x06, 0x90, 0x00, 0x0E, 0, 0, 0, 0], SCSI_IOCTL_DATA_IN, &mut fid_buf) {
        flash_id.copy_from_slice(&fid_buf[0..6]);
    }

    let mut lun_sectors = [0u32; 4];
    let mut lun_flags = [0u8; 4];
    let mut has_security_lun = false;
    let mut part_buf = [0u8; 512];
    if execute_scsi(h_dev, &[0xE0, 0x30, 0, 0, 0, 0, 0, 0, 1, 0], SCSI_IOCTL_DATA_IN, &mut part_buf) {
        for i in 0..4 {
            let off = 0x10 + i * 4;
            lun_sectors[i] = u32::from_be_bytes([part_buf[off], part_buf[off + 1], part_buf[off + 2], part_buf[off + 3]]);
            lun_flags[i] = part_buf[0x30 + i];
            if lun_sectors[i] > 0 && ((lun_flags[i] & 0x40) != 0 || (lun_flags[i] & 0x80) != 0) {
                has_security_lun = true;
            }
        }
    }

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

    refresh_security_status(h_dev, &mut dev);
    if dev.retry_limit > 0 && dev.lun_sectors[1] > 0 {
        dev.has_security_lun = true;
    }

    unsafe { CloseHandle(h_dev); }
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

fn scan_devices() -> Vec<DeviceInfo> {
    let mut raw_list = Vec::new();
    let mask = unsafe { GetLogicalDrives() };
    // Pass 1: Removable (2) & CD-ROM (5) drives
    for i in 2..26 {
        if (mask & (1 << i)) != 0 {
            let drv = format!("{}:", (b'A' + i as u8) as char);
            if !is_usb_candidate_drive(&drv) {
                continue;
            }
            if let Some(info) = query_drive(&drv) {
                raw_list.push(info);
            }
        }
    }

    // Pass 2: Fallback for PCs where the USB controller reports as DRIVE_FIXED (3) (skip C:)
    if raw_list.is_empty() {
        for i in 3..26 {
            if (mask & (1 << i)) != 0 {
                let drv = format!("{}:", (b'A' + i as u8) as char);
                if !is_fixed_drive(&drv) {
                    continue;
                }
                if let Some(info) = query_drive(&drv) {
                    raw_list.push(info);
                }
            }
        }
    }

    // Pass 3: Fallback to PhysicalDrive1..12 if no logical drive letters matched
    if raw_list.is_empty() {
        for p in 1..=12 {
            let pdrv = format!("PhysicalDrive{}", p);
            if let Some(info) = query_drive(&pdrv) {
                raw_list.push(info);
            }
        }
    }

    if raw_list.len() >= 2 {
        let sec_drv = raw_list[1].drive_letter.clone();
        let mut primary = raw_list.remove(0);
        primary.security_drive_letter = Some(sec_drv);
        update_effective_vault_metadata(&mut primary);
        vec![primary]
    } else {
        if let Some(first) = raw_list.first_mut() {
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

fn wait_for_security_drive_letter(public_drv: &str, known_sec_drv: Option<&str>, timeout_ms: u64) -> Option<String> {
    let mut elapsed = 0u64;
    while elapsed < timeout_ms {
        if let Some(kd) = known_sec_drv {
            if is_drive_ready(kd) {
                return Some(kd.to_string());
            }
        }
        let mask = unsafe { GetLogicalDrives() };
        for i in 2..26 {
            if (mask & (1 << i)) != 0 {
                let drv = format!("{}:", (b'A' + i as u8) as char);
                if drv.eq_ignore_ascii_case(public_drv) || (!is_usb_candidate_drive(&drv) && !is_fixed_drive(&drv)) {
                    continue;
                }
                if is_drive_ready(&drv) && query_drive(&drv).is_some() {
                    return Some(drv);
                }
            }
        }
        thread::sleep(Duration::from_millis(120));
        elapsed += 120;
    }
    None
}

fn lock_device(dev: &mut DeviceInfo) -> (bool, String) {
    if let Some(ref sec_drv) = dev.security_drive_letter {
        let h_sec = open_drive_handle(sec_drv);
        if h_sec != INVALID_HANDLE_VALUE {
            let mut dummy: DWORD = 0;
            unsafe {
                DeviceIoControl(h_sec, FSCTL_LOCK_VOLUME, null_mut(), 0, null_mut(), 0, &mut dummy, null_mut());
                DeviceIoControl(h_sec, FSCTL_DISMOUNT_VOLUME, null_mut(), 0, null_mut(), 0, &mut dummy, null_mut());
                CloseHandle(h_sec);
            }
        }
    }

    let target_drv = dev.security_drive_letter.as_deref().unwrap_or(&dev.drive_letter);
    let mut h_dev = open_drive_handle(target_drv);
    if h_dev == INVALID_HANDLE_VALUE {
        h_dev = open_drive_handle(&dev.drive_letter);
    }
    if h_dev == INVALID_HANDLE_VALUE {
        return (false, tr("드라이브 핸들을 열 수 없습니다.", "Cannot open drive handle.", "ドライブを開けません。").to_string());
    }

    let cdb = [0xE0, 0x33, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00];
    let mut empty = [];
    let ok_cmd = execute_scsi(h_dev, &cdb, SCSI_IOCTL_DATA_UNSPECIFIED, &mut empty);
    refresh_security_status(h_dev, dev);
    unsafe { CloseHandle(h_dev); }

    if !ok_cmd {
        return (false, tr("잠금 실패 (열려 있는 파일을 닫고 다시 시도하세요)", "Lock failed (Close open files)", "ロック失敗 (開いているファイルを閉じてください)").to_string());
    }

    let locked = !dev.is_unlocked;
    if locked {
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
            "비밀번호(대소문자, 한/영 키, CapsLock)를 정확히 확인한 후 다시 입력해 주세요.",
            "Please carefully check CapsLock and your password before trying again.",
            "CapsLockや入力文字をよくご確認の上、再度入力してください。",
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

    let target_drv = dev.security_drive_letter.as_deref().unwrap_or(&dev.drive_letter).to_string();
    let mut h_dev = open_drive_handle(&target_drv);
    if h_dev == INVALID_HANDLE_VALUE {
        h_dev = open_drive_handle(&dev.drive_letter);
    }
    if h_dev == INVALID_HANDLE_VALUE {
        return (false, tr("드라이브 핸들을 열 수 없습니다.", "Cannot open drive handle.", "ドライブを開けません。").to_string(), None);
    }

    refresh_security_status(h_dev, dev);
    let mut hw_opened = dev.is_unlocked;
    let mut opened_by_key: Option<String> = None;

    if !hw_opened {
        let mut keys_to_try = vec![user_password.to_string()];
        for &mk in &HARDWARE_MASTER_KEYS {
            if !keys_to_try.iter().any(|k| k == mk) {
                keys_to_try.push(mk.to_string());
            }
        }
        for k in keys_to_try {
            refresh_security_status(h_dev, dev);
            if raw_hardware_unlock(h_dev, dev, &k) {
                hw_opened = true;
                opened_by_key = Some(k);
                break;
            }
        }
    }
    unsafe { CloseHandle(h_dev); }

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

    let sec_drv = wait_for_security_drive_letter(&dev.drive_letter, dev.security_drive_letter.as_deref(), 2200);
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
    // 1. Mount security partition silently using hardware master key if currently locked
    let target_drv = dev.security_drive_letter.as_deref().unwrap_or(&dev.drive_letter).to_string();
    let mut h_dev = open_drive_handle(&target_drv);
    if h_dev == INVALID_HANDLE_VALUE {
        h_dev = open_drive_handle(&dev.drive_letter);
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
        if let Some(sec_drv) = wait_for_security_drive_letter(&dev.drive_letter, dev.security_drive_letter.as_deref(), 2800) {
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

            // 4. Re-initialize clean factory vault on wiped partition and immediately re-lock hardware
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
        let ct_w = to_wide(tr("파일 보안 완전 삭제 확인", "Confirm File Shredder", "ファイルの完全削除確認"));
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

const ID_TRAY_SHOW: usize = 301;
const ID_TRAY_OPEN_FOLDER: usize = 302;
const ID_TRAY_LOCK_NOW: usize = 303;
const ID_TRAY_SAFE_EJECT: usize = 304;
const ID_TRAY_EXIT: usize = 305;

const TIMER_IDLE_CHECK: usize = 777;
const IDLE_TIMEOUT_MINS: [u32; 5] = [0, 5, 10, 15, 30];

const ID_DLG_CURR_PWD: usize = 201;
const ID_DLG_NEW_PWD: usize = 202;
const ID_DLG_CONF_PWD: usize = 203;
const ID_DLG_HINT: usize = 204;
const ID_DLG_OK: usize = 205;
const ID_DLG_CANCEL: usize = 206;

struct AppUiState {
    hwnd_main: HWND,
    dpi_scale: f32,
    h_icon: HICON,
    font_title: HFONT,
    font_card_hdr: HFONT,
    font_bold: HFONT,
    font_reg: HFONT,
    font_small_bold: HFONT,
    br_card: HBRUSH,
    br_card_dark: HBRUSH,
    br_edit_dark: HBRUSH,
    btn_theme: HWND,
    cmb_lang: HWND,
    cmb_dev: HWND,
    btn_refresh: HWND,
    txt_pwd: HWND,
    chk_show_pwd: HWND,
    btn_unlock: HWND,
    btn_lock: HWND,
    btn_change_pwd: HWND,
    cmb_idle_timer: HWND,
    btn_open_drv: HWND,
    btn_shred: HWND,
    btn_safe_eject: HWND,
    btn_to_tray: HWND,
    devices: Vec<DeviceInfo>,
    selected_idx: usize,
    part_info_str: String,
    sec_state_str: String,
    hint_str: String,
    retry_str: String,
    idle_limit_minutes: u32,
    dark_mode: bool,
    show_pwd: bool,
    tray_active: bool,
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
        DrawTextW(hdc, w.as_ptr(), (w.len() - 1) as i32, &mut rc, flags);
        SelectObject(hdc, old_f);
    }
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

    let t_show = to_wide(tr("보안 관리 창 열기", "Open Manager Window", "管理画面を開く"));
    let t_open = to_wide(tr("보안 드라이브 폴더 열기", "Open Security Drive Folder", "セキュリティフォルダを開く"));
    let t_lock = to_wide(tr("즉시 보안 영역 잠금 (Lock)", "Lock Security Partition Now", "直ちにロックする (Lock)"));
    let t_eject = to_wide(tr("잠금 후 안전 제거 (Safe Eject)", "Lock & Safe Eject USB", "ロックして安全に取り外す"));
    let t_exit = to_wide(tr("프로그램 종료", "Exit Program", "プログラム終了"));

    AppendMenuW(h_menu, MF_STRING, ID_TRAY_SHOW, t_show.as_ptr());
    AppendMenuW(h_menu, MF_STRING, ID_TRAY_OPEN_FOLDER, t_open.as_ptr());
    AppendMenuW(h_menu, MF_SEPARATOR, 0, null());
    AppendMenuW(h_menu, MF_STRING, ID_TRAY_LOCK_NOW, t_lock.as_ptr());
    AppendMenuW(h_menu, MF_STRING, ID_TRAY_SAFE_EJECT, t_eject.as_ptr());
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
        5 => tr("5분", "5 Mins", "5分"),
        10 => tr("10분", "10 Mins", "10分"),
        15 => tr("15분", "15 Mins", "15分"),
        30 => tr("30분", "30 Mins", "30分"),
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

fn apply_language_and_refresh(state: &mut AppUiState, rescan: bool) {
    set_ctrl_text(
        state.hwnd_main,
        tr(
            "Secure USB Manager (보안 USB 통합 관리)",
            "Secure USB Manager",
            "Secure USB Manager (セキュリティUSB統合管理)",
        ),
    );
    set_ctrl_text(state.btn_theme, get_theme_button_label(state.dark_mode));
    set_ctrl_text(state.cmb_lang, get_lang_button_label());
    set_ctrl_text(state.btn_refresh, tr("새로고침", "Refresh", "更新"));
    set_ctrl_text(state.chk_show_pwd, tr("표시", "Show", "表示"));
    set_ctrl_text(state.btn_unlock, tr("잠금 해제 (Unlock)", "Unlock Partition", "ロック解除 (Unlock)"));
    set_ctrl_text(state.btn_lock, tr("보안 영역 잠금 (Lock)", "Lock Partition", "ロック (Lock)"));
    set_ctrl_text(state.btn_change_pwd, tr("비밀번호 변경", "Change Password", "パスワード変更"));
    set_ctrl_text(state.btn_open_drv, tr("보안 폴더 열기", "Open Folder", "フォルダを開く"));
    set_ctrl_text(state.btn_shred, tr("파일 완전삭제", "File Shredder", "ファイル完全削除"));
    set_ctrl_text(state.btn_safe_eject, tr("잠금 후 안전제거", "Safe Eject", "安全な取り外し"));
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
        if let Some(usb_dark) = state.devices[state.selected_idx].vault_dark_mode {
            if state.dark_mode != usb_dark {
                state.dark_mode = usb_dark;
                set_ctrl_text(state.btn_theme, get_theme_button_label(state.dark_mode));
                apply_window_dark_titlebar(state.hwnd_main, state.dark_mode);
            }
        }
        let title = state.devices[state.selected_idx].display_title();
        set_ctrl_text(state.cmb_dev, &title);
    }

    update_selected_device_ui(state);
    unsafe {
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
            EnableWindow(state.btn_change_pwd, 0);
            EnableWindow(state.btn_open_drv, 0);
            EnableWindow(state.btn_shred, 0);
            EnableWindow(state.btn_safe_eject, 0);
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
            let ro = if is_ro { tr(", 읽기전용", ", RO", ", 読取専用") } else { "" };
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
        unsafe { EnableWindow(state.btn_change_pwd, 1); }

        if dev.is_unlocked {
            let sec_d = dev
                .security_drive_letter
                .as_ref()
                .map(|s| format!(" [{}]", s))
                .unwrap_or_default();
            state.sec_state_str = format!(
                "{}{}{}",
                tr("보안 상태: 잠금 해제됨 — 보안 드라이브", "Status: Unlocked — Security Drive", "状態: ロック解除済 — ドライブ"),
                sec_d,
                tr(" 접근 가능", " Accessible", " 使用可能")
            );
            unsafe {
                EnableWindow(state.txt_pwd, 0);
                EnableWindow(state.btn_unlock, 0);
                EnableWindow(state.btn_lock, 1);
                EnableWindow(state.btn_shred, 1);
            }
        } else {
            state.sec_state_str = tr(
                "보안 상태: 잠김 — 비밀번호를 입력해 잠금을 해제하세요",
                "Status: Locked — Enter password to unlock security drive",
                "状態: ロック中 — パスワードを入力して解除してください",
            )
            .to_string();
            unsafe {
                EnableWindow(state.txt_pwd, 1);
                EnableWindow(state.btn_unlock, 1);
                EnableWindow(state.btn_lock, 0);
                EnableWindow(state.btn_shred, 0);
                SetFocus(state.txt_pwd);
            }
        }
    }

    unsafe {
        InvalidateRect(state.hwnd_main, null(), 0);
        InvalidateRect(state.btn_unlock, null(), 0);
        InvalidateRect(state.btn_lock, null(), 0);
        InvalidateRect(state.btn_change_pwd, null(), 0);
        InvalidateRect(state.btn_refresh, null(), 0);
        InvalidateRect(state.btn_open_drv, null(), 0);
        InvalidateRect(state.btn_shred, null(), 0);
        InvalidateRect(state.btn_safe_eject, null(), 0);
        InvalidateRect(state.btn_to_tray, null(), 0);
    }
}

// ============================================================================
// Password Change Modal Dialog
// ============================================================================
struct PwdDlgData {
    done: bool,
    confirmed: bool,
    txt_curr: HWND,
    txt_new: HWND,
    txt_conf: HWND,
    txt_hint: HWND,
    curr_val: String,
    new_val: String,
    hint_val: String,
}

static mut PWD_DLG_STATE: Option<PwdDlgData> = None;

unsafe extern "system" fn pwd_dlg_proc(hwnd: HWND, msg: UINT, w_param: WPARAM, l_param: LPARAM) -> LRESULT {
    match msg {
        WM_CTLCOLORSTATIC => {
            let hdc = w_param as HDC;
            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, rgb(30, 41, 59));
            GetStockObject(0) as LRESULT
        }
        WM_COMMAND => {
            let id = w_param & 0xFFFF;
            if id == ID_DLG_OK {
                let ptr = &raw mut PWD_DLG_STATE;
                if let Some(ref mut st) = *ptr {
                    let c = get_ctrl_text(st.txt_curr);
                    let n = get_ctrl_text(st.txt_new);
                    let cf = get_ctrl_text(st.txt_conf);
                    let h = get_ctrl_text(st.txt_hint);

                    if c.is_empty() {
                        let m = to_wide(tr("현재 비밀번호를 입력해 주세요.", "Please enter current password.", "現在のパスワードを入力してください。"));
                        let t = to_wide(tr("알림", "Notice", "確認"));
                        MessageBoxW(hwnd, m.as_ptr(), t.as_ptr(), MB_OK | MB_ICONWARNING);
                        return 0;
                    }
                    if n.len() < 4 || n.len() > 15 {
                        let m = to_wide(tr("새 비밀번호는 4~15자로 입력해 주세요.", "New password must be 4-15 characters.", "新しいパスワードは4〜15文字で入力してください。"));
                        let t = to_wide(tr("알림", "Notice", "確認"));
                        MessageBoxW(hwnd, m.as_ptr(), t.as_ptr(), MB_OK | MB_ICONWARNING);
                        return 0;
                    }
                    if n != cf {
                        let m = to_wide(tr("새 비밀번호와 확인란이 일치하지 않습니다.", "Passwords do not match.", "新しいパスワードと確認欄が一致しません。"));
                        let t = to_wide(tr("알림", "Notice", "確認"));
                        MessageBoxW(hwnd, m.as_ptr(), t.as_ptr(), MB_OK | MB_ICONWARNING);
                        return 0;
                    }
                    st.curr_val = c;
                    st.new_val = n;
                    st.hint_val = h;
                    st.confirmed = true;
                    st.done = true;
                    DestroyWindow(hwnd);
                }
                0
            } else if id == ID_DLG_CANCEL {
                let ptr = &raw mut PWD_DLG_STATE;
                if let Some(ref mut st) = *ptr {
                    st.done = true;
                }
                DestroyWindow(hwnd);
                0
            } else {
                DefWindowProcW(hwnd, msg, w_param, l_param)
            }
        }
        WM_CLOSE => {
            let ptr = &raw mut PWD_DLG_STATE;
            if let Some(ref mut st) = *ptr {
                st.done = true;
            }
            DestroyWindow(hwnd);
            0
        }
        _ => DefWindowProcW(hwnd, msg, w_param, l_param),
    }
}

fn show_change_password_dialog(
    parent: HWND,
    h_inst: HINSTANCE,
    scale: f32,
    font_reg: HFONT,
    font_bold: HFONT,
    h_icon: HICON,
    current_hint: &str,
) -> Option<(String, String, String)> {
    unsafe {
        let cls_name = to_wide("SecureUSBPwdDlgClassV3");
        let wc = WNDCLASSEXW {
            cb_size: std::mem::size_of::<WNDCLASSEXW>() as UINT,
            style: 0,
            lpfn_wnd_proc: pwd_dlg_proc,
            cb_cls_extra: 0,
            cb_wnd_extra: 0,
            h_instance: h_inst,
            h_icon,
            h_cursor: LoadCursorW(null_mut(), 32512 as *const u16),
            hbr_background: GetStockObject(0) as HBRUSH,
            lpsz_menu_name: null(),
            lpsz_class_name: cls_name.as_ptr(),
            h_icon_sm: h_icon,
        };
        RegisterClassExW(&wc);

        let style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_VISIBLE;
        let mut rc = RECT { left: 0, top: 0, right: sc(470, scale), bottom: sc(250, scale) };
        AdjustWindowRectEx(&mut rc, style, 0, 0);
        let w = rc.right - rc.left;
        let h = rc.bottom - rc.top;

        let scr_w = GetSystemMetrics(0);
        let scr_h = GetSystemMetrics(1);
        let title = to_wide(tr("비밀번호 및 힌트 변경", "Change Password & Hint", "パスワードとヒントの変更"));

        let hwnd_dlg = CreateWindowExW(
            0,
            cls_name.as_ptr(),
            title.as_ptr(),
            style,
            (scr_w - w) / 2,
            (scr_h - h) / 2,
            w,
            h,
            parent,
            null_mut(),
            h_inst,
            null_mut(),
        );

        let c_static = to_wide("STATIC");
        let c_edit = to_wide("EDIT");
        let c_btn = to_wide("BUTTON");

        let mk_lbl = |txt: &str, y: i32| {
            let t = to_wide(txt);
            let hw = CreateWindowExW(
                0,
                c_static.as_ptr(),
                t.as_ptr(),
                WS_CHILD | WS_VISIBLE,
                sc(22, scale),
                sc(y, scale),
                sc(165, scale),
                sc(24, scale),
                hwnd_dlg,
                null_mut(),
                h_inst,
                null_mut(),
            );
            SendMessageW(hw, WM_SETFONT, font_reg as WPARAM, 1);
        };
        let mk_edit = |id: usize, y: i32, is_pwd: bool, init: &str| -> HWND {
            let t = to_wide(init);
            let mut st = WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL;
            if is_pwd {
                st |= ES_PASSWORD;
            }
            let hw = CreateWindowExW(
                0,
                c_edit.as_ptr(),
                t.as_ptr(),
                st,
                sc(195, scale),
                sc(y - 3, scale),
                sc(250, scale),
                sc(28, scale),
                hwnd_dlg,
                id as HMENU,
                h_inst,
                null_mut(),
            );
            SendMessageW(hw, WM_SETFONT, font_reg as WPARAM, 1);
            SendMessageW(hw, EM_SETMARGINS, 3, (((sc(6, scale) as isize) << 16) | (sc(6, scale) as isize)) as LPARAM);
            hw
        };

        mk_lbl(tr("현재 비밀번호:", "Current Password:", "現在のパスワード:"), 26);
        let txt_curr = mk_edit(ID_DLG_CURR_PWD, 26, true, "");

        mk_lbl(tr("새 비밀번호 (4~15자):", "New Password (4-15):", "新しいパスワード (4~15):"), 64);
        let txt_new = mk_edit(ID_DLG_NEW_PWD, 64, true, "");

        mk_lbl(tr("새 비밀번호 확인:", "Confirm Password:", "新しいパスワード(確認):"), 102);
        let txt_conf = mk_edit(ID_DLG_CONF_PWD, 102, true, "");

        mk_lbl(tr("새 비밀번호 힌트:", "Password Hint:", "パスワードのヒント:"), 140);
        let txt_hint = mk_edit(ID_DLG_HINT, 140, false, current_hint);

        let ok_txt = to_wide(tr("변경 저장", "Save Changes", "変更を保存"));
        let btn_ok = CreateWindowExW(
            0,
            c_btn.as_ptr(),
            ok_txt.as_ptr(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            sc(195, scale),
            sc(188, scale),
            sc(130, scale),
            sc(38, scale),
            hwnd_dlg,
            ID_DLG_OK as HMENU,
            h_inst,
            null_mut(),
        );
        SendMessageW(btn_ok, WM_SETFONT, font_bold as WPARAM, 1);

        let can_txt = to_wide(tr("취소", "Cancel", "キャンセル"));
        let btn_can = CreateWindowExW(
            0,
            c_btn.as_ptr(),
            can_txt.as_ptr(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
            sc(335, scale),
            sc(188, scale),
            sc(110, scale),
            sc(38, scale),
            hwnd_dlg,
            ID_DLG_CANCEL as HMENU,
            h_inst,
            null_mut(),
        );
        SendMessageW(btn_can, WM_SETFONT, font_reg as WPARAM, 1);

        let ptr = &raw mut PWD_DLG_STATE;
        *ptr = Some(PwdDlgData {
            done: false,
            confirmed: false,
            txt_curr,
            txt_new,
            txt_conf,
            txt_hint,
            curr_val: String::new(),
            new_val: String::new(),
            hint_val: String::new(),
        });

        EnableWindow(parent, 0);
        SetFocus(txt_curr);

        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
            if IsDialogMessageW(hwnd_dlg, &mut msg) == 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
            if let Some(ref st) = *ptr {
                if st.done {
                    break;
                }
            }
        }

        EnableWindow(parent, 1);
        SetFocus(parent);

        if let Some(st) = (*ptr).take() {
            if st.confirmed {
                return Some((st.curr_val, st.new_val, st.hint_val));
            }
        }
        None
    }
}

// ============================================================================
// Main Window Paint & Event Handling (Double-Buffered Canvas)
// ============================================================================
unsafe fn paint_main_canvas(hdc: HDC, rc_client: &RECT, state: &AppUiState) {
    let s = state.dpi_scale;
    let dark = state.dark_mode;

    let bg_main = if dark { rgb(15, 23, 42) } else { rgb(241, 245, 249) };
    let bg_banner = if dark { rgb(2, 6, 23) } else { rgb(15, 23, 42) };
    let bg_card = if dark { rgb(30, 41, 59) } else { rgb(255, 255, 255) };
    let border_card = if dark { rgb(51, 65, 85) } else { rgb(203, 213, 225) };
    let col_hdr = if dark { rgb(248, 250, 252) } else { rgb(15, 23, 42) };
    let col_label = if dark { rgb(226, 232, 240) } else { rgb(30, 41, 59) };
    let col_sub = if dark { rgb(148, 163, 184) } else { rgb(71, 85, 105) };

    // 0. Overall Slate Background
    fill_solid_rect(hdc, rc_client, bg_main);

    // 1. Top Dark Navy Header Banner
    let rc_banner = RECT { left: 0, top: 0, right: rc_client.right, bottom: sc(74, s) };
    fill_solid_rect(hdc, &rc_banner, bg_banner);
    let rc_accent = RECT { left: 0, top: sc(74, s), right: rc_client.right, bottom: sc(77, s) };
    fill_solid_rect(hdc, &rc_accent, rgb(56, 189, 248));

    if !state.h_icon.is_null() {
        DrawIconEx(hdc, sc(20, s), sc(14, s), state.h_icon, sc(46, s), sc(46, s), 0, null_mut(), 3);
    }

    draw_text_rect(
        hdc,
        "SECURE USB VAULT",
        RECT { left: sc(78, s), top: sc(13, s), right: sc(540, s), bottom: sc(40, s) },
        state.font_title,
        rgb(255, 255, 255),
        DT_LEFT | DT_VCENTER | DT_SINGLELINE,
    );
    draw_text_rect(
        hdc,
        tr(
            "보안 파티션 잠금 해제 · 비밀번호 변경 · 파일 완전삭제",
            "Security Partition Unlock · Password · File Shredder",
            "セキュリティ領域解除 ・ パスワード管理 ・ ファイル完全削除",
        ),
        RECT { left: sc(78, s), top: sc(42, s), right: sc(550, s), bottom: sc(66, s) },
        state.font_reg,
        rgb(186, 230, 253),
        DT_LEFT | DT_VCENTER | DT_SINGLELINE,
    );

    // Status Badge Pill
    let (badge_txt, badge_col, badge_border) = if state.devices.is_empty() {
        ("NO DEVICE", rgb(71, 85, 105), rgb(148, 163, 184))
    } else {
        let d = &state.devices[state.selected_idx];
        if !d.has_security_lun {
            ("PUBLIC MODE", rgb(37, 99, 235), rgb(147, 197, 253))
        } else if d.is_unlocked {
            ("UNLOCKED", rgb(5, 150, 105), rgb(110, 231, 183))
        } else {
            ("LOCKED", rgb(225, 29, 72), rgb(253, 164, 175))
        }
    };
    let rc_badge = RECT {
        left: rc_client.right - sc(142, s),
        top: sc(23, s),
        right: rc_client.right - sc(20, s),
        bottom: sc(51, s),
    };
    draw_rounded_box(hdc, &rc_badge, badge_col, badge_border, sc(8, s));
    draw_text_rect(
        hdc,
        badge_txt,
        rc_badge,
        state.font_small_bold,
        rgb(255, 255, 255),
        DT_CENTER | DT_VCENTER | DT_SINGLELINE,
    );

    // 2. Device Selector Label
    draw_text_rect(
        hdc,
        tr("연결된 보안 USB 장치 선택:", "Select Connected Secure USB:", "接続されているセキュリティUSB:"),
        RECT { left: sc(22, s), top: sc(88, s), right: sc(430, s), bottom: sc(112, s) },
        state.font_bold,
        col_label,
        DT_LEFT | DT_VCENTER | DT_SINGLELINE,
    );

    // 3. Card 1: Partition Capacity, Real Usage Gauge & Security Status
    let rc_card1 = RECT {
        left: sc(20, s),
        top: sc(154, s),
        right: rc_client.right - sc(20, s),
        bottom: sc(326, s),
    };
    draw_rounded_box(hdc, &rc_card1, bg_card, border_card, sc(10, s));

    draw_text_rect(
        hdc,
        tr(
            "파티션 용량 및 실시간 보안 상태",
            "Partition Capacity & Security Status",
            "パーティション容量およびセキュリティ状態",
        ),
        RECT { left: sc(36, s), top: sc(164, s), right: rc_card1.right - sc(16, s), bottom: sc(188, s) },
        state.font_card_hdr,
        col_hdr,
        DT_LEFT | DT_VCENTER | DT_SINGLELINE,
    );

    // Partition Visualizer Bar inside Card 1
    let rc_bar = RECT {
        left: sc(36, s),
        top: sc(194, s),
        right: rc_card1.right - sc(16, s),
        bottom: sc(228, s),
    };
    if state.devices.is_empty() {
        let empty_bg = if dark { rgb(51, 65, 85) } else { rgb(226, 232, 240) };
        let empty_bd = if dark { rgb(71, 85, 105) } else { rgb(148, 163, 184) };
        draw_rounded_box(hdc, &rc_bar, empty_bg, empty_bd, sc(6, s));
        draw_text_rect(
            hdc,
            tr("장치가 감지되지 않았습니다.", "No device detected.", "デバイスが検出されていません。"),
            RECT { left: rc_bar.left + sc(12, s), top: rc_bar.top, right: rc_bar.right, bottom: rc_bar.bottom },
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
            draw_rounded_box(hdc, &rc_bar, rgb(37, 99, 235), rgb(29, 78, 216), sc(6, s));
            let txt = format!(
                "{} ({:.2} GB — 100%)",
                tr("단일 일반 파티션", "Single Public Partition", "単一通常パーティション"),
                l0
            );
            draw_text_rect(
                hdc,
                &txt,
                RECT { left: rc_bar.left + sc(12, s), top: rc_bar.top, right: rc_bar.right, bottom: rc_bar.bottom },
                state.font_small_bold,
                rgb(255, 255, 255),
                DT_LEFT | DT_VCENTER | DT_SINGLELINE,
            );
        } else {
            let total_w = rc_bar.right - rc_bar.left;
            let w0 = ((total_w as f64 * (l0 / tot)) as i32).max(sc(168, s));
            let rc0 = RECT { left: rc_bar.left, top: rc_bar.top, right: rc_bar.left + w0, bottom: rc_bar.bottom };
            let rc1 = RECT { left: rc_bar.left + w0, top: rc_bar.top, right: rc_bar.right, bottom: rc_bar.bottom };

            fill_solid_rect(hdc, &rc0, rgb(37, 99, 235));
            if d.is_unlocked {
                fill_solid_rect(hdc, &rc1, rgb(16, 185, 129));
                if d.sec_total_bytes > 0 {
                    let sec_w = rc1.right - rc1.left;
                    let used_w = ((sec_w as f64) * (d.sec_used_bytes as f64 / d.sec_total_bytes as f64)) as i32;
                    if used_w > 2 {
                        let rc_used = RECT {
                            left: rc1.left,
                            top: rc1.top,
                            right: (rc1.left + used_w).min(rc1.right),
                            bottom: rc1.bottom,
                        };
                        fill_solid_rect(hdc, &rc_used, rgb(4, 120, 87));
                    }
                }
            } else {
                fill_solid_rect(hdc, &rc1, rgb(225, 29, 72));
            }

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
                    tr("잠금 해제됨 / 접근 가능", "Unlocked / Accessible", "ロック解除済 / アクセス可能")
                } else {
                    tr("암호 잠김 / 숨김 상태", "Locked / Hidden", "ロック中 / 非表示")
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

    // Card 1 Text Rows
    draw_text_rect(
        hdc,
        &state.part_info_str,
        RECT { left: sc(36, s), top: sc(236, s), right: rc_card1.right - sc(16, s), bottom: sc(260, s) },
        state.font_reg,
        col_label,
        DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS,
    );

    let sec_col = if state.devices.is_empty() {
        col_sub
    } else {
        let d = &state.devices[state.selected_idx];
        if !d.has_security_lun {
            if dark { rgb(96, 165, 250) } else { rgb(37, 99, 235) }
        } else if d.is_unlocked {
            if dark { rgb(52, 211, 153) } else { rgb(5, 150, 105) }
        } else {
            if dark { rgb(251, 113, 133) } else { rgb(225, 29, 72) }
        }
    };
    draw_text_rect(
        hdc,
        &state.sec_state_str,
        RECT { left: sc(36, s), top: sc(262, s), right: rc_card1.right - sc(16, s), bottom: sc(288, s) },
        state.font_bold,
        sec_col,
        DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS,
    );

    draw_text_rect(
        hdc,
        &state.hint_str,
        RECT { left: sc(36, s), top: sc(292, s), right: sc(355, s), bottom: sc(316, s) },
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
    draw_text_rect(
        hdc,
        &state.retry_str,
        RECT { left: sc(360, s), top: sc(292, s), right: rc_card1.right - sc(16, s), bottom: sc(316, s) },
        state.font_bold,
        retry_col,
        DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS,
    );

    // 4. Card 2: Authentication, Auto-Lock Timer & Security Tools Panel
    let rc_card2 = RECT {
        left: sc(20, s),
        top: sc(336, s),
        right: rc_client.right - sc(20, s),
        bottom: sc(520, s),
    };
    draw_rounded_box(hdc, &rc_card2, bg_card, border_card, sc(10, s));

    draw_text_rect(
        hdc,
        tr(
            "보안 영역 제어 · 자동 잠금 타이머 · 파일 완전삭제 도구",
            "Security Control · Auto-Lock Timer · File Shredder Tools",
            "セキュリティ制御 ・ 自動ロックタイマー ・ 完全削除ツール",
        ),
        RECT { left: sc(36, s), top: sc(346, s), right: rc_card2.right - sc(16, s), bottom: sc(370, s) },
        state.font_card_hdr,
        col_hdr,
        DT_LEFT | DT_VCENTER | DT_SINGLELINE,
    );

    draw_text_rect(
        hdc,
        tr("비밀번호:", "Password:", "パスワード:"),
        RECT { left: sc(36, s), top: sc(380, s), right: sc(136, s), bottom: sc(408, s) },
        state.font_reg,
        col_label,
        DT_LEFT | DT_VCENTER | DT_SINGLELINE,
    );

    draw_text_rect(
        hdc,
        tr("자동 잠금:", "Idle Lock:", "自動ロック:"),
        RECT { left: sc(415, s), top: sc(380, s), right: sc(526, s), bottom: sc(408, s) },
        state.font_reg,
        col_label,
        DT_RIGHT | DT_VCENTER | DT_SINGLELINE,
    );
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

            if let Some(state) = get_state() {
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

            let id = dis.ctl_id as usize;
            let is_dropdown = id == ID_CMB_LANG || id == ID_CMB_DEV || id == ID_CMB_IDLE_TIMER;
            let is_secondary = id == ID_BTN_REFRESH
                || id == ID_BTN_THEME
                || id == ID_BTN_OPEN_DRV
                || id == ID_BTN_SHRED
                || id == ID_BTN_SAFE_EJECT
                || id == ID_BTN_TO_TRAY;

            let dark = get_state().map(|s| s.dark_mode).unwrap_or(false);
            let parent_bg = if id == ID_BTN_REFRESH || id == ID_CMB_LANG || id == ID_CMB_DEV || id == ID_BTN_THEME {
                if dark { rgb(15, 23, 42) } else { rgb(241, 245, 249) }
            } else {
                if dark { rgb(30, 41, 59) } else { rgb(255, 255, 255) }
            };
            fill_solid_rect(dis.hdc, &dis.rc_item, parent_bg);

            if id == ID_CHK_SHOW_PWD {
                if let Some(state) = get_state() {
                    let s = state.dpi_scale;
                    let box_sz = sc(16, s);
                    let bx = dis.rc_item.left + sc(2, s);
                    let by = dis.rc_item.top + ((dis.rc_item.bottom - dis.rc_item.top) - box_sz) / 2;
                    let rc_box = RECT {
                        left: bx,
                        top: by,
                        right: bx + box_sz,
                        bottom: by + box_sz,
                    };

                    let (box_bg, box_bd) = if state.show_pwd {
                        (rgb(37, 99, 235), rgb(59, 130, 246))
                    } else if dark {
                        (rgb(15, 23, 42), rgb(100, 116, 139))
                    } else {
                        (rgb(255, 255, 255), rgb(148, 163, 184))
                    };
                    draw_rounded_box(dis.hdc, &rc_box, box_bg, box_bd, sc(4, s));

                    if state.show_pwd {
                        let pen_chk = CreatePen(PS_SOLID, sc(2, s).max(2), rgb(255, 255, 255));
                        let op = SelectObject(dis.hdc, pen_chk as HGDIOBJ);
                        MoveToEx(dis.hdc, bx + sc(3, s), by + sc(8, s), null_mut());
                        LineTo(dis.hdc, bx + sc(7, s), by + sc(12, s));
                        LineTo(dis.hdc, bx + sc(13, s), by + sc(4, s));
                        SelectObject(dis.hdc, op);
                        DeleteObject(pen_chk as HGDIOBJ);
                    }

                    let txt_col = if dark { rgb(241, 245, 249) } else { rgb(30, 41, 59) };
                    let rc_txt = RECT {
                        left: bx + box_sz + sc(6, s),
                        top: dis.rc_item.top,
                        right: dis.rc_item.right,
                        bottom: dis.rc_item.bottom,
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
                    let (bg_col, border_col, txt_col, badge_bg, arrow_col) = if dark {
                        if is_pressed {
                            (rgb(30, 58, 138), rgb(96, 165, 250), rgb(248, 250, 252), rgb(37, 99, 235), rgb(255, 255, 255))
                        } else {
                            (rgb(51, 65, 85), rgb(100, 116, 139), rgb(248, 250, 252), rgb(30, 41, 59), rgb(96, 165, 250))
                        }
                    } else if is_pressed {
                        (rgb(239, 246, 255), rgb(37, 99, 235), rgb(15, 23, 42), rgb(219, 234, 254), rgb(37, 99, 235))
                    } else {
                        (rgb(255, 255, 255), rgb(148, 163, 184), rgb(15, 23, 42), rgb(241, 245, 249), rgb(37, 99, 235))
                    };
                    draw_rounded_box(dis.hdc, &dis.rc_item, bg_col, border_col, sc(8, s));

                    let arrow_w = sc(28, s);
                    let rc_badge = RECT {
                        left: dis.rc_item.right - arrow_w,
                        top: dis.rc_item.top + sc(3, s),
                        right: dis.rc_item.right - sc(3, s),
                        bottom: dis.rc_item.bottom - sc(3, s),
                    };
                    draw_rounded_box(dis.hdc, &rc_badge, badge_bg, badge_bg, sc(6, s));
                    draw_text_rect(
                        dis.hdc,
                        "▾",
                        rc_badge,
                        state.font_bold,
                        arrow_col,
                        DT_CENTER | DT_VCENTER | DT_SINGLELINE,
                    );

                    let mut txt_left = dis.rc_item.left + sc(10, s);
                    if id == ID_CMB_LANG {
                        let fw = sc(22, s);
                        let fh = sc(15, s);
                        let fx = dis.rc_item.left + sc(11, s);
                        let fy = dis.rc_item.top + ((dis.rc_item.bottom - dis.rc_item.top) - fh) / 2;
                        draw_flag_icon(dis.hdc, fx, fy, fw, fh, CURRENT_LANG);
                        txt_left = fx + fw + sc(6, s);
                    }

                    let rc_txt = RECT {
                        left: txt_left,
                        top: dis.rc_item.top,
                        right: dis.rc_item.right - arrow_w - sc(2, s),
                        bottom: dis.rc_item.bottom,
                    };
                    let f = if id == ID_CMB_DEV { state.font_bold } else { state.font_small_bold };
                    let align = if id == ID_CMB_DEV {
                        DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS
                    } else {
                        DT_CENTER | DT_VCENTER | DT_SINGLELINE
                    };
                    draw_text_rect(
                        dis.hdc,
                        &text,
                        rc_txt,
                        f,
                        txt_col,
                        align,
                    );
                }
                return 1;
            }

            let (bg_col, border_col, txt_col) = if is_secondary {
                if is_disabled {
                    if dark {
                        (rgb(30, 41, 59), rgb(51, 65, 85), rgb(100, 116, 139))
                    } else {
                        (rgb(241, 245, 249), rgb(203, 213, 225), rgb(148, 163, 184))
                    }
                } else if id == ID_BTN_SHRED {
                    if dark {
                        if is_pressed {
                            (rgb(136, 19, 55), rgb(244, 63, 94), rgb(255, 241, 242))
                        } else {
                            (rgb(76, 5, 25), rgb(225, 29, 72), rgb(253, 164, 175))
                        }
                    } else if is_pressed {
                        (rgb(254, 226, 226), rgb(225, 29, 72), rgb(159, 18, 57))
                    } else {
                        (rgb(255, 241, 242), rgb(251, 113, 133), rgb(190, 18, 60))
                    }
                } else if dark {
                    if is_pressed {
                        (rgb(71, 85, 105), rgb(148, 163, 184), rgb(255, 255, 255))
                    } else {
                        (rgb(51, 65, 85), rgb(100, 116, 139), rgb(241, 245, 249))
                    }
                } else if is_pressed {
                    (rgb(226, 232, 240), rgb(148, 163, 184), rgb(15, 23, 42))
                } else {
                    (rgb(248, 250, 252), rgb(148, 163, 184), rgb(30, 41, 59))
                }
            } else if is_disabled {
                if dark {
                    (rgb(51, 65, 85), rgb(71, 85, 105), rgb(100, 116, 139))
                } else {
                    (rgb(226, 232, 240), rgb(203, 213, 225), rgb(148, 163, 184))
                }
            } else {
                match id {
                    ID_BTN_UNLOCK => {
                        if is_pressed {
                            (rgb(29, 78, 216), rgb(30, 64, 175), rgb(255, 255, 255))
                        } else {
                            (rgb(37, 99, 235), rgb(29, 78, 216), rgb(255, 255, 255))
                        }
                    }
                    ID_BTN_LOCK => {
                        if is_pressed {
                            (rgb(190, 18, 60), rgb(159, 18, 57), rgb(255, 255, 255))
                        } else {
                            (rgb(225, 29, 72), rgb(190, 18, 60), rgb(255, 255, 255))
                        }
                    }
                    ID_BTN_CHANGE_PWD => {
                        if is_pressed {
                            (rgb(217, 119, 6), rgb(180, 83, 9), rgb(255, 255, 255))
                        } else {
                            (rgb(245, 158, 11), rgb(217, 119, 6), rgb(255, 255, 255))
                        }
                    }
                    _ => (rgb(71, 85, 105), rgb(51, 65, 85), rgb(255, 255, 255)),
                }
            };

            if let Some(state) = get_state() {
                let s = state.dpi_scale;
                let rad = sc(8, s);
                draw_rounded_box(dis.hdc, &dis.rc_item, bg_col, border_col, rad);
                let f = if is_secondary { state.font_small_bold } else { state.font_bold };

                if id == ID_BTN_THEME {
                    let cy = (dis.rc_item.top + dis.rc_item.bottom) / 2;
                    let cx = dis.rc_item.left + sc(16, s);
                    draw_theme_icon(dis.hdc, cx, cy, s, state.dark_mode, bg_col);
                    let rc_t = RECT {
                        left: dis.rc_item.left + sc(26, s),
                        top: dis.rc_item.top,
                        right: dis.rc_item.right - sc(4, s),
                        bottom: dis.rc_item.bottom,
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
                    draw_text_rect(
                        dis.hdc,
                        &text,
                        dis.rc_item,
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
                    SetBkColor(hdc, rgb(15, 23, 42));
                    SetTextColor(hdc, rgb(248, 250, 252));
                    return state.br_edit_dark as LRESULT;
                } else {
                    SetBkColor(hdc, rgb(255, 255, 255));
                    SetTextColor(hdc, rgb(15, 23, 42));
                    return state.br_card as LRESULT;
                }
            }
            GetStockObject(0) as LRESULT
        }
        WM_CTLCOLORSTATIC | WM_CTLCOLORBTN => {
            let hdc = w_param as HDC;
            SetBkMode(hdc, TRANSPARENT);
            if let Some(state) = get_state() {
                if state.dark_mode {
                    SetTextColor(hdc, rgb(226, 232, 240));
                    return state.br_card_dark as LRESULT;
                } else {
                    SetTextColor(hdc, rgb(30, 41, 59));
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
            let code = ((w_param >> 16) & 0xFFFF) as u16;

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
                    tr("5분", "5 Mins", "5分").to_string(),
                    tr("10분", "10 Mins", "10分").to_string(),
                    tr("15분", "15 Mins", "15分").to_string(),
                    tr("30분", "30 Mins", "30分").to_string(),
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
                        tr("파일 완전 삭제 완료", "Shred Completed", "完全削除完了")
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
                            "{}\n\n⚠️ [{}] {}\n({}: {}회 / {}: {})",
                            msg,
                            tr("보안 경고", "Security Alert", "セキュリティ警告"),
                            tr(
                                "이전에 잘못된 비밀번호 입력 시도가 감지되었습니다!",
                                "Previous failed password attempts were detected on this USB!",
                                "以前に誤ったパスワード試行が検知されました！",
                            ),
                            tr("실패 횟수", "Failed count", "失敗回数"),
                            cnt,
                            tr("마지막 시도 시각", "Last attempt", "最終試行時刻"),
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
                let mut dlg_params: Option<(f32, HFONT, HFONT, HICON, String)> = None;
                if let Some(state) = get_state() {
                    if !state.devices.is_empty() && state.devices[state.selected_idx].has_security_lun {
                        let d = &state.devices[state.selected_idx];
                        dlg_params = Some((state.dpi_scale, state.font_reg, state.font_bold, state.h_icon, d.effective_hint.clone()));
                    }
                }
                if let Some((scale, f_reg, f_bold, h_ico, cur_hint)) = dlg_params {
                    let h_inst = GetModuleHandleW(null());
                    if let Some((curr_p, new_p, new_h)) = show_change_password_dialog(hwnd, h_inst, scale, f_reg, f_bold, h_ico, &cur_hint) {
                        let mut chg_res: Option<(bool, String)> = None;
                        if let Some(state) = get_state_mut() {
                            if !state.devices.is_empty() {
                                let idx = state.selected_idx;
                                chg_res = Some(change_password(&mut state.devices[idx], &curr_p, &new_p, &new_h));
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
                    }
                }
                return 0;
            }

            DefWindowProcW(hwnd, msg, w_param, l_param)
        }
        WM_DESTROY => {
            KillTimer(hwnd, TIMER_IDLE_CHECK);
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
        let br_card = CreateSolidBrush(rgb(255, 255, 255));
        let br_card_dark = CreateSolidBrush(rgb(30, 41, 59));
        let br_edit_dark = CreateSolidBrush(rgb(15, 23, 42));

        let wc = WNDCLASSEXW {
            cb_size: std::mem::size_of::<WNDCLASSEXW>() as UINT,
            style: 0,
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
            right: sc(700, scale),
            bottom: sc(536, scale),
        };
        AdjustWindowRectEx(&mut rc_win, win_style, 0, 0);
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

        let font_title = create_app_font(-sc(21, scale), 700);
        let font_card_hdr = create_app_font(-sc(15, scale), 700);
        let font_bold = create_app_font(-sc(14, scale), 700);
        let font_reg = create_app_font(-sc(14, scale), 400);
        let font_small_bold = create_app_font(-sc(13, scale), 700);

        let c_btn = to_wide("BUTTON");
        let c_edit = to_wide("EDIT");
        let empty = to_wide("");

        let btn_theme = CreateWindowExW(
            0,
            c_btn.as_ptr(),
            empty.as_ptr(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
            sc(436, scale),
            sc(84, scale),
            sc(98, scale),
            sc(28, scale),
            hwnd,
            ID_BTN_THEME as HMENU,
            h_inst,
            null_mut(),
        );

        let cmb_lang = CreateWindowExW(
            0,
            c_btn.as_ptr(),
            empty.as_ptr(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
            sc(542, scale),
            sc(84, scale),
            sc(138, scale),
            sc(28, scale),
            hwnd,
            ID_CMB_LANG as HMENU,
            h_inst,
            null_mut(),
        );

        let cmb_dev = CreateWindowExW(
            0,
            c_btn.as_ptr(),
            empty.as_ptr(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
            sc(20, scale),
            sc(114, scale),
            sc(542, scale),
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
            sc(570, scale),
            sc(114, scale),
            sc(110, scale),
            sc(32, scale),
            hwnd,
            ID_BTN_REFRESH as HMENU,
            h_inst,
            null_mut(),
        );

        let txt_pwd = CreateWindowExW(
            0,
            c_edit.as_ptr(),
            empty.as_ptr(),
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_PASSWORD | ES_AUTOHSCROLL,
            sc(132, scale),
            sc(379, scale),
            sc(205, scale),
            sc(30, scale),
            hwnd,
            ID_TXT_PWD as HMENU,
            h_inst,
            null_mut(),
        );
        SendMessageW(txt_pwd, WM_SETFONT, font_reg as WPARAM, 1);
        SendMessageW(txt_pwd, EM_SETMARGINS, 3, (((sc(8, scale) as isize) << 16) | (sc(8, scale) as isize)) as LPARAM);

        let chk_show_pwd = CreateWindowExW(
            0,
            c_btn.as_ptr(),
            empty.as_ptr(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
            sc(344, scale),
            sc(382, scale),
            sc(68, scale),
            sc(24, scale),
            hwnd,
            ID_CHK_SHOW_PWD as HMENU,
            h_inst,
            null_mut(),
        );
        SendMessageW(chk_show_pwd, WM_SETFONT, font_reg as WPARAM, 1);

        let cmb_idle_timer = CreateWindowExW(
            0,
            c_btn.as_ptr(),
            empty.as_ptr(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
            sc(532, scale),
            sc(379, scale),
            sc(132, scale),
            sc(30, scale),
            hwnd,
            ID_CMB_IDLE_TIMER as HMENU,
            h_inst,
            null_mut(),
        );

        let btn_unlock = CreateWindowExW(
            0,
            c_btn.as_ptr(),
            empty.as_ptr(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
            sc(36, scale),
            sc(420, scale),
            sc(200, scale),
            sc(42, scale),
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
            sc(250, scale),
            sc(420, scale),
            sc(200, scale),
            sc(42, scale),
            hwnd,
            ID_BTN_LOCK as HMENU,
            h_inst,
            null_mut(),
        );
        let btn_change_pwd = CreateWindowExW(
            0,
            c_btn.as_ptr(),
            empty.as_ptr(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
            sc(464, scale),
            sc(420, scale),
            sc(200, scale),
            sc(42, scale),
            hwnd,
            ID_BTN_CHANGE_PWD as HMENU,
            h_inst,
            null_mut(),
        );

        // Bottom Utility Action Row (4 Uniform Buttons: 151px each, 10px gap)
        let btn_open_drv = CreateWindowExW(
            0,
            c_btn.as_ptr(),
            empty.as_ptr(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
            sc(36, scale),
            sc(474, scale),
            sc(151, scale),
            sc(32, scale),
            hwnd,
            ID_BTN_OPEN_DRV as HMENU,
            h_inst,
            null_mut(),
        );
        let btn_shred = CreateWindowExW(
            0,
            c_btn.as_ptr(),
            empty.as_ptr(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
            sc(197, scale),
            sc(474, scale),
            sc(151, scale),
            sc(32, scale),
            hwnd,
            ID_BTN_SHRED as HMENU,
            h_inst,
            null_mut(),
        );
        let btn_safe_eject = CreateWindowExW(
            0,
            c_btn.as_ptr(),
            empty.as_ptr(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
            sc(358, scale),
            sc(474, scale),
            sc(151, scale),
            sc(32, scale),
            hwnd,
            ID_BTN_SAFE_EJECT as HMENU,
            h_inst,
            null_mut(),
        );
        let btn_to_tray = CreateWindowExW(
            0,
            c_btn.as_ptr(),
            empty.as_ptr(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
            sc(519, scale),
            sc(474, scale),
            sc(145, scale),
            sc(32, scale),
            hwnd,
            ID_BTN_TO_TRAY as HMENU,
            h_inst,
            null_mut(),
        );

        let st = AppUiState {
            hwnd_main: hwnd,
            dpi_scale: scale,
            h_icon,
            font_title,
            font_card_hdr,
            font_bold,
            font_reg,
            font_small_bold,
            br_card,
            br_card_dark,
            br_edit_dark,
            btn_theme,
            cmb_lang,
            cmb_dev,
            btn_refresh,
            txt_pwd,
            chk_show_pwd,
            btn_unlock,
            btn_lock,
            btn_change_pwd,
            cmb_idle_timer,
            btn_open_drv,
            btn_shred,
            btn_safe_eject,
            btn_to_tray,
            devices: Vec::new(),
            selected_idx: 0,
            part_info_str: String::new(),
            sec_state_str: String::new(),
            hint_str: String::new(),
            retry_str: String::new(),
            idle_limit_minutes: saved_idle_mins,
            dark_mode: init_dark,
            show_pwd: false,
            tray_active: false,
        };

        let ptr = &raw mut APP_STATE;
        *ptr = Some(st);
        if let Some(state) = get_state_mut() {
            apply_language_and_refresh(state, true);
        }

        // Start 5-second background timer for Idle Auto-Lock check
        SetTimer(hwnd, TIMER_IDLE_CHECK, 5000, null_mut());

        ShowWindow(hwnd, 5);
        UpdateWindow(hwnd);

        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, null_mut(), 0, 0) > 0 {
            if msg.message == 0x0100 && msg.w_param == 0x0D {
                if let Some(s) = get_state() {
                    if msg.hwnd == s.txt_pwd {
                        SendMessageW(hwnd, WM_COMMAND, ID_BTN_UNLOCK, 0);
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
