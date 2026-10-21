//! UCA voices of translation repacks.
//!
//! Rewrite's Chinese repack ships its voices in `koe/uca.dat` and
//! `uca2.dat`: an index of 0x20-byte entries (name such as
//! `z206209682.nwa`, then u32 offset at +0x14 and u32 size at +0x18), each
//! entry a "UCA" stream. SiglusDebugger2.dll serves them to the engine in
//! place of the missing `koe\*.nwa` files, decoding them with the repack's
//! `ucadec.dll`. The codec is undocumented, so the DLL from the game folder
//! runs here in an x86 interpreter.

use anyhow::{Context, Result, bail};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::x86_dll::DllImage;

#[derive(Debug, Clone)]
pub struct UcaEntry {
    pub name: String,
    pub archive: PathBuf,
    pub offset: u32,
    pub size: u32,
}

/// Voices decoded ahead of time are kept, up to this many.
const CACHED_VOICES: usize = 24;
/// After a voice plays, the voices that follow it are decoded ahead: the
/// interpreter takes about a third of a voice's length to decode it.
const PREFETCH: usize = 4;

struct UcaGame {
    entries: HashMap<String, UcaEntry>,
    /// Entry names in order, which is mostly the order the script plays them.
    order: Vec<String>,
    decoder: Option<Arc<DllImage>>,
    decoded: Mutex<Decoded>,
}

#[derive(Default)]
struct Decoded {
    wavs: HashMap<String, Arc<Vec<u8>>>,
    age: VecDeque<String>,
    pending: HashSet<String>,
}

impl Decoded {
    fn insert(&mut self, name: String, wav: Arc<Vec<u8>>) {
        self.pending.remove(&name);
        if self.wavs.insert(name.clone(), wav).is_none() {
            self.age.push_back(name);
        }
        while self.age.len() > CACHED_VOICES {
            if let Some(old) = self.age.pop_front() {
                self.wavs.remove(&old);
            }
        }
    }
}

static GAMES: Mutex<Option<HashMap<PathBuf, Arc<UcaGame>>>> = Mutex::new(None);

fn archives(project_dir: &Path) -> Vec<PathBuf> {
    [
        project_dir.join("koe").join("uca.dat"),
        project_dir.join("uca2.dat"),
    ]
    .into_iter()
    .filter_map(|p| crate::resource::resolve_game_file(&p).ok().flatten())
    .collect()
}

/// Reads the index at the start of a UCA archive.
pub fn read_index(archive: &Path, data: &[u8]) -> HashMap<String, UcaEntry> {
    let mut entries = HashMap::new();
    for chunk in data.chunks_exact(0x20) {
        let name_end = chunk[..0x14].iter().position(|&b| b == 0).unwrap_or(0x14);
        if name_end == 0 {
            break;
        }
        let name = String::from_utf8_lossy(&chunk[..name_end]).to_ascii_lowercase();
        let offset = u32::from_le_bytes(chunk[0x14..0x18].try_into().unwrap());
        let size = u32::from_le_bytes(chunk[0x18..0x1c].try_into().unwrap());
        if (offset as usize) < data.len() || size == 0 {
            break;
        }
        entries.entry(name.clone()).or_insert(UcaEntry {
            name,
            archive: archive.to_path_buf(),
            offset,
            size,
        });
    }
    entries
}

fn game(project_dir: &Path) -> Arc<UcaGame> {
    let mut games = GAMES.lock().unwrap_or_else(|p| p.into_inner());
    let games = games.get_or_insert_with(HashMap::new);
    if let Some(game) = games.get(project_dir) {
        return game.clone();
    }
    let mut entries = HashMap::new();
    for archive in archives(project_dir) {
        match read_index_bytes(&archive) {
            Ok(data) => {
                for (name, entry) in read_index(&archive, &data) {
                    entries.entry(name).or_insert(entry);
                }
            }
            Err(err) => log::warn!("UCA archive {} unreadable: {err:#}", archive.display()),
        }
    }
    let decoder = if entries.is_empty() {
        None
    } else {
        let dll = project_dir.join("ucadec.dll");
        match crate::resource::read_file_bytes(&dll).and_then(|data| DllImage::load(&data)) {
            Ok(image) => Some(Arc::new(image)),
            Err(err) => {
                log::warn!("UCA voices need {}: {err:#}", dll.display());
                None
            }
        }
    };
    let mut order: Vec<String> = entries.keys().cloned().collect();
    order.sort();
    let game = Arc::new(UcaGame {
        entries,
        order,
        decoder,
        decoded: Mutex::default(),
    });
    games.insert(project_dir.to_path_buf(), game.clone());
    game
}

/// The UCA entry for a voice, if the game has UCA archives.
pub fn find_koe(project_dir: &Path, koe_no: u32) -> Option<UcaEntry> {
    let game = game(project_dir);
    game.entries.get(&format!("z{koe_no:09}.nwa")).cloned()
}

/// Decodes one entry to a WAV file, then starts decoding the voices after it.
pub fn decode_entry_to_wav(project_dir: &Path, entry: &UcaEntry) -> Result<Vec<u8>> {
    let game = game(project_dir);
    let decoder = game
        .decoder
        .clone()
        .context("UCA voice found, but ucadec.dll is missing or unusable")?;
    let cached = lock(&game).wavs.get(&entry.name).cloned();
    let wav = match cached {
        Some(wav) => wav,
        None => {
            let wav = Arc::new(decode_entry(&decoder, entry)?);
            lock(&game).insert(entry.name.clone(), wav.clone());
            wav
        }
    };
    prefetch_after(&game, &decoder, &entry.name);
    Ok(wav.as_ref().clone())
}

fn lock(game: &UcaGame) -> std::sync::MutexGuard<'_, Decoded> {
    game.decoded.lock().unwrap_or_else(|p| p.into_inner())
}

fn decode_entry(decoder: &DllImage, entry: &UcaEntry) -> Result<Vec<u8>> {
    let stream = read_range(&entry.archive, entry.offset as u64, entry.size as usize)?;
    decode_with(decoder, &stream)
}

/// The index part of an archive: everything before the first entry's data.
fn read_index_bytes(archive: &Path) -> Result<Vec<u8>> {
    let head = read_range(archive, 0, 0x20)?;
    let first = u32::from_le_bytes(head[0x14..0x18].try_into().unwrap()) as usize;
    if first < 0x20 || first > 16 << 20 {
        bail!("not a UCA archive index");
    }
    read_range(archive, 0, first)
}

fn read_range(path: &Path, offset: u64, len: usize) -> Result<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    file.seek(SeekFrom::Start(offset))?;
    let mut data = vec![0u8; len];
    file.read_exact(&mut data)
        .with_context(|| format!("read {} bytes at {offset} in {}", len, path.display()))?;
    Ok(data)
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
fn prefetch_after(_game: &Arc<UcaGame>, _decoder: &Arc<DllImage>, _name: &str) {}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
fn prefetch_after(game: &Arc<UcaGame>, decoder: &Arc<DllImage>, name: &str) {
    let Ok(at) = game.order.binary_search_by(|n| n.as_str().cmp(name)) else {
        return;
    };
    let next: Vec<UcaEntry> = {
        let mut decoded = lock(game);
        game.order[at + 1..]
            .iter()
            .take(PREFETCH)
            .filter(|n| !decoded.wavs.contains_key(*n) && decoded.pending.insert((*n).clone()))
            .filter_map(|n| game.entries.get(n).cloned())
            .collect()
    };
    if next.is_empty() {
        return;
    }
    let game = game.clone();
    let decoder = decoder.clone();
    std::thread::spawn(move || {
        for entry in next {
            match decode_entry(&decoder, &entry) {
                Ok(wav) => lock(&game).insert(entry.name, Arc::new(wav)),
                Err(err) => {
                    lock(&game).pending.remove(&entry.name);
                    log::warn!("UCA voice {} failed: {err:#}", entry.name);
                }
            }
        }
    });
}

/// Runs `UCADecode(src, len, &out, &out_len, 0)` and returns its WAV output.
pub fn decode_with(decoder: &DllImage, stream: &[u8]) -> Result<Vec<u8>> {
    let mut machine = decoder.instantiate();
    let src = machine.alloc_bytes(stream)?;
    let out_ptr = machine.alloc_zeroed(8)?;
    let out_len = out_ptr + 4;
    let status = machine.call(
        "UCADecode",
        &[src, stream.len() as u32, out_ptr, out_len, 0],
    )? as i32;
    if status < 0 {
        bail!("UCADecode failed ({status})");
    }
    let wav = machine.read_u32(out_ptr)?;
    let len = machine.read_u32(out_len)? as usize;
    Ok(machine.memory(wav, len)?.to_vec())
}
