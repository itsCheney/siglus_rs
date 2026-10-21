//! Movies the host platform decodes.
//!
//! Some translation repacks replace a game's MPEG movie with an MP4 (H.264
//! and AAC) and keep the old file name, which Windows plays anyway. siglus_rs
//! has no decoder for those, so a host that has one (Mikage uses
//! AVFoundation) registers it here, and such files then play through the WMV
//! stream path, which presents frames by timestamp.

use std::collections::HashMap;
use std::ffi::{CString, c_char, c_void};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, bail};

use crate::assets::RgbaImage;

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct HostMovieInfo {
    pub width: u32,
    pub height: u32,
    pub duration_ms: u64,
    pub channels: u32,
    pub sample_rate: u32,
}

pub type HostMovieOpenFn = unsafe extern "C" fn(
    path_utf8: *const c_char,
    want_audio: i32,
    info: *mut HostMovieInfo,
) -> *mut c_void;
pub type HostMovieReadVideoFn =
    unsafe extern "C" fn(movie: *mut c_void, rgba: *mut u8, pts_ms: *mut u64) -> i32;
pub type HostMovieReadAudioFn =
    unsafe extern "C" fn(movie: *mut c_void, samples: *mut i16, max_frames: u32) -> i64;
pub type HostMovieCloseFn = unsafe extern "C" fn(movie: *mut c_void);

#[derive(Clone, Copy)]
pub struct HostMovieDecoder {
    pub open: HostMovieOpenFn,
    pub read_video: HostMovieReadVideoFn,
    pub read_audio: HostMovieReadAudioFn,
    pub close: HostMovieCloseFn,
}

static DECODER: Mutex<Option<HostMovieDecoder>> = Mutex::new(None);
static SNIFFED: Mutex<Option<HashMap<PathBuf, bool>>> = Mutex::new(None);

pub fn set_decoder(decoder: Option<HostMovieDecoder>) {
    *DECODER.lock().unwrap_or_else(|p| p.into_inner()) = decoder;
}

fn decoder() -> Option<HostMovieDecoder> {
    *DECODER.lock().unwrap_or_else(|p| p.into_inner())
}

/// Whether `path` is a movie for the host decoder: an ISO media file (MP4,
/// MOV), whatever its extension, while a host decoder is registered.
pub fn is_host_movie(path: &Path) -> bool {
    if decoder().is_none() {
        return false;
    }
    let mut sniffed = SNIFFED.lock().unwrap_or_else(|p| p.into_inner());
    let sniffed = sniffed.get_or_insert_with(HashMap::new);
    if let Some(&known) = sniffed.get(path) {
        return known;
    }
    let is_iso_media = read_head(path).is_some_and(|head| &head[4..8] == b"ftyp");
    sniffed.insert(path.to_path_buf(), is_iso_media);
    is_iso_media
}

fn read_head(path: &Path) -> Option<[u8; 8]> {
    use std::io::Read;
    let mut head = [0u8; 8];
    std::fs::File::open(path).ok()?.read_exact(&mut head).ok()?;
    Some(head)
}

/// One open track of a host movie.
pub struct HostMovie {
    decoder: HostMovieDecoder,
    handle: *mut c_void,
    pub info: HostMovieInfo,
}

// The host decoder takes a handle on any thread, one thread at a time.
unsafe impl Send for HostMovie {}

impl HostMovie {
    pub fn open(path: &Path, audio: bool) -> Result<Self> {
        let decoder = decoder().context("no host movie decoder")?;
        let c_path =
            CString::new(path.to_string_lossy().as_bytes()).context("movie path has a NUL")?;
        let mut info = HostMovieInfo::default();
        let handle = unsafe { (decoder.open)(c_path.as_ptr(), audio as i32, &mut info) };
        if handle.is_null() {
            bail!(
                "host decoder can't open the {} of {}",
                if audio { "audio" } else { "video" },
                path.display()
            );
        }
        Ok(Self {
            decoder,
            handle,
            info,
        })
    }

    /// The next frame and its time in ms, or None at the end.
    pub fn next_frame(&mut self) -> Result<Option<(RgbaImage, u64)>> {
        let (width, height) = (self.info.width, self.info.height);
        if width == 0 || height == 0 {
            bail!("host movie has no picture size");
        }
        let mut rgba = vec![0u8; width as usize * height as usize * 4];
        let mut pts_ms = 0u64;
        match unsafe { (self.decoder.read_video)(self.handle, rgba.as_mut_ptr(), &mut pts_ms) } {
            0 => Ok(None),
            status if status < 0 => bail!("host video decode failed ({status})"),
            _ => Ok(Some((
                RgbaImage {
                    width,
                    height,
                    center_x: 0,
                    center_y: 0,
                    rgba,
                },
                pts_ms,
            ))),
        }
    }

    /// Reads the whole soundtrack as interleaved 16-bit samples.
    pub fn read_all_audio(&mut self, cancel: &std::sync::atomic::AtomicBool) -> Result<Vec<i16>> {
        const CHUNK_FRAMES: u32 = 8192;
        let channels = self.info.channels as usize;
        if channels == 0 {
            bail!("host movie has no audio");
        }
        let mut samples = Vec::new();
        let mut chunk = vec![0i16; CHUNK_FRAMES as usize * channels];
        loop {
            if cancel.load(std::sync::atomic::Ordering::Acquire) {
                bail!("cancelled");
            }
            let frames =
                unsafe { (self.decoder.read_audio)(self.handle, chunk.as_mut_ptr(), CHUNK_FRAMES) };
            if frames < 0 {
                bail!("host audio decode failed ({frames})");
            }
            if frames == 0 {
                return Ok(samples);
            }
            let len = (frames as usize).min(CHUNK_FRAMES as usize) * channels;
            samples.extend_from_slice(&chunk[..len]);
        }
    }
}

impl Drop for HostMovie {
    fn drop(&mut self) {
        unsafe { (self.decoder.close)(self.handle) };
    }
}

pub fn preview_frame(path: &Path) -> Result<Arc<RgbaImage>> {
    let mut movie = HostMovie::open(path, false)?;
    let (frame, _) = movie
        .next_frame()?
        .with_context(|| format!("host movie has no frames: {}", path.display()))?;
    Ok(Arc::new(frame))
}
