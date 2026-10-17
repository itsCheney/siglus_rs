//! UCI images inside `.g00` files.
//!
//! Some repacks of Siglus games shrink their images by replacing the LZSS
//! pixel data with UCI blobs, which a DLL hooked into the patched engine
//! decodes. A blob is `"UCI" mode u32 width u32 height`, then one or two
//! length-prefixed H.264 streams (Annex B, one intra frame each, full-range
//! YUV 4:2:0): the colour image, then the alpha in the luma plane.
//!
//! The engine has no H.264 decoder of its own; the host registers one.

use anyhow::{Context, Result, bail};
use std::sync::Mutex;

/// Decodes one H.264 intra frame of `width` x `height` into planar YUV 4:2:0
/// samples: `y` holds `width * height`, `u` and `v` hold
/// `ceil(width / 2) * ceil(height / 2)` each. Returns the bit depth of the
/// samples, or a negative value on failure.
pub type H264DecodeFn = unsafe extern "C" fn(
    data: *const u8,
    len: usize,
    width: u32,
    height: u32,
    y: *mut u16,
    u: *mut u16,
    v: *mut u16,
) -> i32;

static DECODER: Mutex<Option<H264DecodeFn>> = Mutex::new(None);

pub fn set_h264_decoder(decoder: Option<H264DecodeFn>) {
    *DECODER
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = decoder;
}

pub fn is_uci(data: &[u8]) -> bool {
    data.starts_with(b"UCI")
}

struct Planes {
    depth: u32,
    y: Vec<u16>,
    u: Vec<u16>,
    v: Vec<u16>,
}

fn decode_stream(stream: &[u8], width: u32, height: u32) -> Result<Planes> {
    let Some(decoder) = *DECODER
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
    else {
        bail!("UCI image needs an H.264 decoder and the host registered none");
    };
    let luma = width as usize * height as usize;
    let chroma = width.div_ceil(2) as usize * height.div_ceil(2) as usize;
    let mut planes = Planes {
        depth: 0,
        y: vec![0; luma],
        u: vec![0; chroma],
        v: vec![0; chroma],
    };
    // SAFETY: the planes are sized as the callback's contract states.
    let depth = unsafe {
        decoder(
            stream.as_ptr(),
            stream.len(),
            width,
            height,
            planes.y.as_mut_ptr(),
            planes.u.as_mut_ptr(),
            planes.v.as_mut_ptr(),
        )
    };
    if !(8..=16).contains(&depth) {
        bail!("H.264 decode failed ({depth})");
    }
    planes.depth = depth as u32;
    Ok(planes)
}

/// A decoded UCI blob: its size and BGRA pixels, plus how many bytes of
/// `data` it took.
pub struct UciImage {
    pub width: u32,
    pub height: u32,
    pub bgra: Vec<u8>,
    pub consumed: usize,
}

pub fn decode(data: &[u8]) -> Result<UciImage> {
    if !is_uci(data) || data.len() < 16 {
        bail!("not a UCI image");
    }
    let read = |off: usize| -> Result<usize> {
        let bytes = data.get(off..off + 4).context("UCI header truncated")?;
        Ok(u32::from_le_bytes(bytes.try_into().unwrap()) as usize)
    };
    let width = read(4)? as u32;
    let height = read(8)? as u32;
    if width == 0 || height == 0 || width > 16384 || height > 16384 {
        bail!("UCI image has a bad size {width}x{height}");
    }
    let mut off = 12;
    let mut streams = Vec::with_capacity(2);
    while streams.len() < 2 && off + 4 <= data.len() {
        let len = read(off)?;
        let stream = data.get(off + 4..off + 4 + len);
        // Anything that isn't an Annex B stream belongs to what follows.
        match stream {
            Some(s) if len > 0 && (s.starts_with(&[0, 0, 1]) || s.starts_with(&[0, 0, 0, 1])) => {
                streams.push(s);
                off += 4 + len;
            }
            _ => break,
        }
    }
    let Some(color) = streams.first() else {
        bail!("UCI image has no colour stream");
    };
    let color = decode_stream(color, width, height).context("UCI colour")?;
    let alpha = match streams.get(1) {
        Some(stream) => Some(decode_stream(stream, width, height).context("UCI alpha")?),
        None => None,
    };

    let w = width as usize;
    let cw = width.div_ceil(2) as usize;
    let mut bgra = Vec::with_capacity(w * height as usize * 4);
    let scale = |planes: &Planes, value: u16| -> f32 {
        value as f32 * 255.0 / ((1u32 << planes.depth) - 1) as f32
    };
    for row in 0..height as usize {
        for col in 0..w {
            let c = (row / 2) * cw + col / 2;
            let y = scale(&color, color.y[row * w + col]);
            let cb = scale(&color, color.u[c]) - 128.0;
            let cr = scale(&color, color.v[c]) - 128.0;
            // Full-range BT.601, as JPEG.
            let r = y + 1.402 * cr;
            let g = y - 0.344_136 * cb - 0.714_136 * cr;
            let b = y + 1.772 * cb;
            let a = alpha
                .as_ref()
                .map_or(255.0, |alpha| scale(alpha, alpha.y[row * w + col]));
            for value in [b, g, r, a] {
                bgra.push(value.round().clamp(0.0, 255.0) as u8);
            }
        }
    }
    Ok(UciImage {
        width,
        height,
        bgra,
        consumed: off,
    })
}
