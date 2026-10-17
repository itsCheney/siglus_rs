//! Mikage host additions to the C API.
//!
//! Mikage (an iOS multi-engine player) drives the engine through the
//! `siglus_ios_*` functions and these. They take the same handle.

use std::ffi::{CString, c_char, c_void};
use std::path::PathBuf;
use std::sync::Mutex;

use crate::host::{SiglusHost, cstr_opt, default_frame_interval_ms};
use crate::text_render::{HostFontFamily, register_host_font};

static LAST_ERROR: Mutex<Option<CString>> = Mutex::new(None);

pub(crate) fn set_last_error(message: &str) {
    let message = CString::new(message.replace('\0', " ")).unwrap_or_default();
    match LAST_ERROR.lock() {
        Ok(mut last) => *last = Some(message),
        Err(poisoned) => *poisoned.into_inner() = Some(message),
    }
}

/// The last error from `siglus_ios_create` or `siglus_mikage_step`, or an
/// empty string. Valid until the next failing call.
#[unsafe(no_mangle)]
pub extern "C" fn siglus_mikage_last_error() -> *const c_char {
    static EMPTY: &[u8] = b"\0";
    let last = match LAST_ERROR.lock() {
        Ok(last) => last,
        Err(poisoned) => poisoned.into_inner(),
    };
    match last.as_ref() {
        // The CString lives in the static until it is replaced.
        Some(message) => message.as_ptr(),
        None => EMPTY.as_ptr() as *const c_char,
    }
}

/// Registers a font file as a stand-in for the Windows faces games ask for.
/// `family` 0 = gothic (MS Gothic and the generic fallback), 1 = mincho.
/// Call before creating the engine.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn siglus_mikage_register_font(path_utf8: *const c_char, family: i32) {
    let Some(path) = (unsafe { cstr_opt(path_utf8) }) else {
        return;
    };
    let family = if family == 1 {
        HostFontFamily::Mincho
    } else {
        HostFontFamily::Gothic
    };
    register_host_font(PathBuf::from(path), family);
}

/// Like `siglus_ios_step`: 0 running, 1 the game ended, 2 error (see
/// `siglus_mikage_last_error`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn siglus_mikage_step(handle: *mut c_void, dt_ms: u32) -> i32 {
    let Some(host) = (unsafe { (handle as *mut SiglusHost).as_mut() }) else {
        set_last_error("null handle");
        return 2;
    };
    match host.step(default_frame_interval_ms(dt_ms)) {
        Ok(false) => 0,
        Ok(true) => 1,
        Err(err) => {
            set_last_error(&format!("{err:#}; {}", host.debug_status_summary()));
            2
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn siglus_mikage_set_foreground(handle: *mut c_void, foreground: i32) {
    if let Some(host) = unsafe { (handle as *mut SiglusHost).as_mut() } {
        host.set_foreground(foreground != 0);
    }
}

/// A right click at a point in the same coordinates as `siglus_ios_touch`.
/// Games open their system menu or close windows with it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn siglus_mikage_secondary_click(handle: *mut c_void, x: f64, y: f64) {
    if let Some(host) = unsafe { (handle as *mut SiglusHost).as_mut() } {
        host.secondary_click(x, y);
    }
}

/// A key press and release by Windows virtual-key code (0x1B Escape,
/// 0x0D Enter, 0x20 Space, 0x11 Control for skip).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn siglus_mikage_key(handle: *mut c_void, key_code: i32, down: i32) {
    if let Some(host) = unsafe { (handle as *mut SiglusHost).as_mut() } {
        if down != 0 {
            host.key_down_code(key_code);
        } else {
            host.key_up_code(key_code);
        }
    }
}

/// Makes the game in `root_utf8` load `scene_utf8` instead of Scene.pck and
/// `gameexe_utf8` instead of Gameexe.dat, as a patched executable of a
/// translated release does (Scene.chs, Gameexe.chs...). Null or empty
/// names restore the defaults. Call before `siglus_ios_create`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn siglus_mikage_set_resource_names(
    root_utf8: *const c_char,
    scene_utf8: *const c_char,
    gameexe_utf8: *const c_char,
) {
    let Some(root) = (unsafe { cstr_opt(root_utf8) }) else {
        return;
    };
    let name = |pointer: *const c_char| unsafe { cstr_opt(pointer) };
    crate::resource::set_resource_names(
        std::path::Path::new(&root),
        crate::resource::ResourceNames {
            scene_pck: name(scene_utf8),
            gameexe: name(gameexe_utf8),
        },
    );
}
