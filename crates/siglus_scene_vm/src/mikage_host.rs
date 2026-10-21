//! Mikage host additions to the C API.
//!
//! Mikage (an iOS multi-engine player) drives the engine through the
//! `siglus_ios_*` functions and these. They take the same handle.

use std::ffi::{CString, c_char, c_void};
use std::path::PathBuf;
use std::sync::Mutex;

use crate::host::{SiglusHost, cstr_opt, default_frame_interval_ms};
use crate::text_render::{
    HostFontFamily, clear_host_fonts, register_fallback_font, register_host_font,
    register_host_font_face,
};

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

/// Like `siglus_mikage_register_font`, using the face named `face_utf8`
/// (PostScript or family name) inside the file, which matters for font
/// collections.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn siglus_mikage_register_font_face(
    path_utf8: *const c_char,
    family: i32,
    face_utf8: *const c_char,
) {
    let Some(path) = (unsafe { cstr_opt(path_utf8) }) else {
        return;
    };
    // An empty or null face is the file's first face.
    let face = unsafe { cstr_opt(face_utf8) }.unwrap_or_default();
    let family = if family == 1 {
        HostFontFamily::Mincho
    } else {
        HostFontFamily::Gothic
    };
    register_host_font_face(PathBuf::from(path), family, face);
}

/// The H.264 decoder for UCI images in `.g00` files; null removes it.
#[unsafe(no_mangle)]
pub extern "C" fn siglus_mikage_set_h264_decoder(
    decoder: Option<crate::assets::uci::H264DecodeFn>,
) {
    crate::assets::uci::set_h264_decoder(decoder);
}

/// Forgets every registered and fallback font; register the next game's
/// fonts after this, before creating it.
#[unsafe(no_mangle)]
pub extern "C" fn siglus_mikage_clear_fonts() {
    clear_host_fonts();
}

/// Adds the face named `face_utf8` (PostScript or family name) in the font
/// file at `path_utf8` to the chain used for characters the game's font
/// lacks. Faces are tried in the order they were added.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn siglus_mikage_register_fallback_font(
    path_utf8: *const c_char,
    face_utf8: *const c_char,
) {
    let Some(path) = (unsafe { cstr_opt(path_utf8) }) else {
        return;
    };
    // An empty or null face is the file's first face.
    let face = unsafe { cstr_opt(face_utf8) }.unwrap_or_default();
    register_fallback_font(PathBuf::from(path), face);
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

/// Receives engine log records: level (1 error, 2 warn, 3 info, 4 debug,
/// 5 trace), the module target and the message, both UTF-8 and valid only
/// during the call. It may be called from any thread.
pub type SiglusMikageLogCallback =
    extern "C" fn(level: i32, target: *const c_char, message: *const c_char, context: *mut c_void);

struct HostLogger {
    sink: Mutex<Option<(SiglusMikageLogCallback, usize)>>,
}

static HOST_LOGGER: HostLogger = HostLogger {
    sink: Mutex::new(None),
};

impl log::Log for HostLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let sink = *self
            .sink
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some((callback, context)) = sink else {
            return;
        };
        let target = CString::new(record.target().replace('\0', " ")).unwrap_or_default();
        let message =
            CString::new(record.args().to_string().replace('\0', " ")).unwrap_or_default();
        callback(
            record.level() as i32,
            target.as_ptr(),
            message.as_ptr(),
            context as *mut c_void,
        );
    }

    fn flush(&self) {}
}

/// Sends engine log records at `max_level` (as in the callback) and more
/// severe to `callback`; null stops them. Panics are logged as errors.
#[unsafe(no_mangle)]
pub extern "C" fn siglus_mikage_set_log_callback(
    callback: Option<SiglusMikageLogCallback>,
    context: *mut c_void,
    max_level: i32,
) {
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| {
        if log::set_logger(&HOST_LOGGER).is_ok() {
            let previous = std::panic::take_hook();
            std::panic::set_hook(Box::new(move |info| {
                log::error!("panic: {info}");
                previous(info);
            }));
        }
    });
    *HOST_LOGGER
        .sink
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) =
        callback.map(|callback| (callback, context as usize));
    log::set_max_level(match (callback.is_some(), max_level) {
        (false, _) | (_, ..=0) => log::LevelFilter::Off,
        (_, 1) => log::LevelFilter::Error,
        (_, 2) => log::LevelFilter::Warn,
        (_, 3) => log::LevelFilter::Info,
        (_, 4) => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    });
}
