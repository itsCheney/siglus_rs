//! Files packed into a Windows executable with Enigma Virtual Box.
//!
//! Translated releases are often a SiglusEngine.exe carrying the translated
//! Scene.pck, Gameexe.dat and images in its virtual file system. On Windows
//! the packed files appear in the executable's folder and hide the loose
//! files of the same name. A host names the executable it starts from with
//! `set_launcher`; from then on, every game path that a packed file covers
//! resolves to a copy of that file, unpacked once into a cache folder.
//!
//! Layout (the ".enigma1" section): "EVB\0" and 60 bytes, a main node, then
//! one node per folder or file in pre-order. A file's data follows the
//! table, in table order; compressed files are aPLib chunks.
use anyhow::{Context, Result, anyhow, bail};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};

const MAGIC: &[u8; 4] = b"EVB\0";
const NODE_FILE: u8 = 2;
const NODE_FOLDER: u8 = 3;
/// The executable's own folder.
const DEFAULT_FOLDER: &str = "%DEFAULT FOLDER%";
const MAX_FILES: usize = 100_000;

#[derive(Debug, Clone)]
pub struct EvbFile {
    /// Path below the executable's folder, '/' separated.
    pub name: String,
    pub size: u64,
    offset: u64,
    stored: u64,
}

/// The packed file list of one executable.
#[derive(Debug)]
pub struct EvbArchive {
    path: PathBuf,
    files: Vec<EvbFile>,
    by_name: HashMap<String, usize>,
    folders: HashSet<String>,
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn read_at<R: Read + Seek>(source: &mut R, offset: u64, length: usize) -> Result<Vec<u8>> {
    source.seek(SeekFrom::Start(offset))?;
    let mut bytes = vec![0; length];
    source.read_exact(&mut bytes)?;
    Ok(bytes)
}

/// Windows names compare without case and with either separator.
fn name_key(name: &str) -> String {
    name.replace('\\', "/").trim_matches('/').to_lowercase()
}

/// The file range of the ".enigma1" section, if the executable has one.
fn enigma_section<R: Read + Seek>(source: &mut R) -> Result<Option<(u64, u64)>> {
    let length = source.seek(SeekFrom::End(0))?;
    if length < 0x40 {
        return Ok(None);
    }
    let dos = read_at(source, 0, 0x40)?;
    if !dos.starts_with(b"MZ") {
        return Ok(None);
    }
    let pe = u32_at(&dos, 0x3C).unwrap_or(0) as u64;
    if pe.checked_add(24).is_none_or(|end| end > length) {
        return Ok(None);
    }
    let header = read_at(source, pe, 24)?;
    if !header.starts_with(b"PE\0\0") {
        return Ok(None);
    }
    let sections = u16_at(&header, 6).unwrap_or(0) as u64;
    let optional = u16_at(&header, 20).unwrap_or(0) as u64;
    let table = pe + 24 + optional;
    if table
        .checked_add(sections * 40)
        .is_none_or(|end| end > length)
    {
        return Ok(None);
    }
    let table = read_at(source, table, (sections * 40) as usize)?;
    for section in table.chunks_exact(40) {
        if section.starts_with(b".enigma1") {
            let size = u32_at(section, 16).unwrap_or(0) as u64;
            let start = u32_at(section, 20).unwrap_or(0) as u64;
            if start < length {
                return Ok(Some((start, size.min(length - start))));
            }
        }
    }
    Ok(None)
}

impl EvbArchive {
    /// The packed files of the executable at `path`, or None when it is not
    /// packed with Enigma Virtual Box.
    pub fn open(path: &Path) -> Result<Option<Self>> {
        let mut file = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
        let Some(files) = Self::list(&mut file)? else {
            return Ok(None);
        };
        let by_name = files
            .iter()
            .enumerate()
            .rev()
            .map(|(index, file)| (name_key(&file.name), index))
            .collect();
        let mut folders = HashSet::new();
        for file in &files {
            let mut name = name_key(&file.name);
            while let Some(cut) = name.rfind('/') {
                name.truncate(cut);
                folders.insert(name.clone());
            }
        }
        Ok(Some(Self {
            path: path.to_path_buf(),
            files,
            by_name,
            folders,
        }))
    }

    fn list<R: Read + Seek>(source: &mut R) -> Result<Option<Vec<EvbFile>>> {
        let Some((start, length)) = enigma_section(source)? else {
            return Ok(None);
        };
        // The file table sits at the start of the section; the data after it
        // is most of the section, so only look for the magic near the start.
        let probe = read_at(source, start, length.min(1 << 20) as usize)?;
        let Some(magic) = probe.windows(4).position(|w| w == MAGIC) else {
            return Ok(None);
        };
        let table_start = start + magic as u64;
        let table_len = (start + length - table_start).min(64 << 20) as usize;
        let table = read_at(source, table_start, table_len)?;
        let files = parse_table(&table, table_start)?;
        let total = source.seek(SeekFrom::End(0))?;
        if files.iter().any(|file| {
            file.offset
                .checked_add(file.stored)
                .is_none_or(|end| end > total)
        }) {
            bail!("EVB: file data beyond the executable");
        }
        Ok(Some(files))
    }

    pub fn files(&self) -> &[EvbFile] {
        &self.files
    }

    pub fn find(&self, name: &str) -> Option<&EvbFile> {
        self.by_name
            .get(&name_key(name))
            .map(|&index| &self.files[index])
    }

    pub fn has_folder(&self, name: &str) -> bool {
        self.folders.contains(&name_key(name))
    }

    pub fn read(&self, file: &EvbFile) -> Result<Vec<u8>> {
        let mut source =
            fs::File::open(&self.path).with_context(|| format!("open {}", self.path.display()))?;
        let stored = read_at(&mut source, file.offset, file.stored as usize)?;
        if file.stored == file.size {
            return Ok(stored);
        }
        unpack_chunks(&stored, file.size as usize).map_err(|e| anyhow!("EVB: {}: {e}", file.name))
    }
}

fn parse_table(table: &[u8], table_start: u64) -> Result<Vec<EvbFile>> {
    let short = || anyhow!("EVB: file table truncated");
    // Pack header (64) and main node (size, 8 unknown bytes, object count).
    let main_size = u32_at(table, 64).ok_or_else(short)? as u64;
    let top_level = u32_at(table, 76).ok_or_else(short)? as usize;
    // The data of the first file starts where the main node says the table
    // ends; the nodes themselves start one byte before the main node's end.
    let mut data = (table_start + 80 + main_size)
        .checked_sub(12)
        .ok_or_else(short)?;
    let mut at = 79usize;
    let mut files = Vec::new();
    // (folder path, children left) for each open folder.
    let mut folders: Vec<(String, usize)> = vec![(String::new(), top_level)];
    while let Some((_, left)) = folders.last() {
        if *left == 0 {
            folders.pop();
            continue;
        }
        if let Some(last) = folders.last_mut() {
            last.1 -= 1;
        }
        let objects = u32_at(table, at + 12).ok_or_else(short)? as usize;
        at += 16;
        let mut units = Vec::new();
        loop {
            let unit = u16_at(table, at).ok_or_else(short)?;
            at += 2;
            if unit == 0 {
                break;
            }
            units.push(unit);
        }
        let kind = *table.get(at).ok_or_else(short)?;
        at += 1;
        let name =
            String::from_utf16(&units).map_err(|_| anyhow!("EVB: node name is not UTF-16"))?;
        if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\\', ':']) {
            bail!("EVB: invalid node name");
        }
        let parent = folders.last().map(|(path, _)| path.as_str()).unwrap_or("");
        match kind {
            NODE_FILE => {
                let size = u32_at(table, at + 2).ok_or_else(short)? as u64;
                let stored = u32_at(table, at + 49).ok_or_else(short)? as u64;
                at += 53;
                files.push(EvbFile {
                    name: join(parent, &name),
                    size,
                    offset: data,
                    stored,
                });
                data += stored;
                if files.len() > MAX_FILES {
                    bail!("EVB: too many files");
                }
            }
            NODE_FOLDER => {
                at += 25;
                let path = if folders.len() == 1 && name == DEFAULT_FOLDER {
                    String::new()
                } else {
                    join(parent, &name)
                };
                if folders.len() > 64 {
                    bail!("EVB: folders nested too deep");
                }
                folders.push((path, objects));
            }
            _ => bail!("EVB: unknown node type {kind}"),
        }
    }
    Ok(files)
}

fn join(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_owned()
    } else {
        format!("{parent}/{name}")
    }
}

/// A compressed file: a chunk table (its byte size and 4 unknown bytes,
/// then 12 bytes per chunk whose first word is the chunk's packed size),
/// then the aPLib-packed chunks.
fn unpack_chunks(stored: &[u8], size: usize) -> std::result::Result<Vec<u8>, &'static str> {
    let table_size = u32_at(stored, 0).ok_or("chunk table truncated")? as usize;
    let table = stored.get(8..table_size).ok_or("chunk table truncated")?;
    let mut data = stored.get(table_size..).ok_or("chunk table truncated")?;
    let mut out = Vec::with_capacity(size);
    for entry in table.chunks(12) {
        let packed = u32_at(entry, 0).ok_or("chunk table truncated")? as usize;
        let chunk = data.get(..packed).ok_or("chunk beyond the file")?;
        data = &data[packed..];
        aplib_depack(chunk, &mut out, size)?;
    }
    if out.len() != size {
        return Err("unpacked size mismatch");
    }
    Ok(out)
}

struct Bits<'a> {
    input: &'a [u8],
    at: usize,
    tag: u8,
    left: u8,
}

impl Bits<'_> {
    fn byte(&mut self) -> Option<u8> {
        let byte = *self.input.get(self.at)?;
        self.at += 1;
        Some(byte)
    }
    fn bit(&mut self) -> Option<u32> {
        if self.left == 0 {
            self.tag = self.byte()?;
            self.left = 8;
        }
        self.left -= 1;
        let bit = (self.tag >> 7) as u32;
        self.tag <<= 1;
        Some(bit)
    }
    fn gamma(&mut self) -> Option<usize> {
        let mut value = 1usize;
        loop {
            value = value.checked_mul(2)? + self.bit()? as usize;
            if self.bit()? == 0 {
                return Some(value);
            }
        }
    }
}

/// Appends one aPLib-packed block (optionally with its "AP32" header) to
/// `out`, which may not grow past `limit`.
fn aplib_depack(
    packed: &[u8],
    out: &mut Vec<u8>,
    limit: usize,
) -> std::result::Result<(), &'static str> {
    let mut input = packed;
    if packed.starts_with(b"AP32") && packed.len() >= 24 {
        let header = u32_at(packed, 4).unwrap_or(0) as usize;
        let length = u32_at(packed, 8).unwrap_or(0) as usize;
        input = packed
            .get(header..header.saturating_add(length))
            .ok_or("aPLib header out of range")?;
    }
    let block_start = out.len();
    let mut bits = Bits {
        input,
        at: 0,
        tag: 0,
        left: 0,
    };
    let copy = |out: &mut Vec<u8>, offset: usize, length: usize| {
        // Each chunk is packed on its own.
        if offset == 0 || offset > out.len() - block_start {
            return Err("aPLib offset out of range");
        }
        if out.len() + length > limit {
            return Err("aPLib output larger than the file");
        }
        for _ in 0..length {
            out.push(out[out.len() - offset]);
        }
        Ok(())
    };
    let push = |out: &mut Vec<u8>, byte: u8| {
        if out.len() >= limit {
            return Err("aPLib output larger than the file");
        }
        out.push(byte);
        Ok(())
    };
    let Some(first) = bits.byte() else {
        return Ok(());
    };
    push(out, first)?;
    let mut last_offset = 0usize;
    let mut after_match = false;
    let truncated = "aPLib data truncated";
    loop {
        if bits.bit().ok_or(truncated)? == 0 {
            push(out, bits.byte().ok_or(truncated)?)?;
            after_match = false;
            continue;
        }
        if bits.bit().ok_or(truncated)? == 0 {
            let high = bits.gamma().ok_or(truncated)?;
            if !after_match && high == 2 {
                let length = bits.gamma().ok_or(truncated)?;
                copy(out, last_offset, length)?;
            } else {
                let high = high - if after_match { 2 } else { 3 };
                let offset = (high << 8) + bits.byte().ok_or(truncated)? as usize;
                let mut length = bits.gamma().ok_or(truncated)?;
                if offset >= 32000 {
                    length += 1;
                }
                if offset >= 1280 {
                    length += 1;
                }
                if offset < 128 {
                    length += 2;
                }
                copy(out, offset, length)?;
                last_offset = offset;
            }
            after_match = true;
        } else if bits.bit().ok_or(truncated)? == 0 {
            let byte = bits.byte().ok_or(truncated)? as usize;
            let (offset, length) = (byte >> 1, 2 + (byte & 1));
            if offset == 0 {
                return Ok(());
            }
            copy(out, offset, length)?;
            last_offset = offset;
            after_match = true;
        } else {
            let mut offset = 0usize;
            for _ in 0..4 {
                offset = (offset << 1) + bits.bit().ok_or(truncated)? as usize;
            }
            if offset == 0 {
                push(out, 0)?;
            } else {
                copy(out, offset, 1)?;
            }
            after_match = false;
        }
    }
}

/// The launcher of one game folder and where its packed files are unpacked.
struct Launcher {
    roots: Vec<PathBuf>,
    archive: Arc<EvbArchive>,
    cache: PathBuf,
    stamp: Option<std::time::SystemTime>,
}

static LAUNCHERS: Mutex<Vec<Launcher>> = Mutex::new(Vec::new());

fn launchers() -> std::sync::MutexGuard<'static, Vec<Launcher>> {
    LAUNCHERS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Makes the files packed in `executable` win over the loose files of
/// `root`, as they do when Windows runs it. They are unpacked on first use
/// into `cache` (default: a hidden folder in `root` named for the
/// executable). Returns false, and drops any earlier launcher of `root`,
/// when `executable` is None or packs nothing.
pub fn set_launcher(root: &Path, executable: Option<&Path>, cache: Option<&Path>) -> Result<bool> {
    let canonical = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let mut roots = vec![root.to_path_buf()];
    if canonical != root {
        roots.push(canonical);
    }
    launchers().retain(|launcher| !launcher.roots.iter().any(|known| roots.contains(known)));
    crate::resource::invalidate_game_path_cache(root);
    let Some(executable) = executable else {
        return Ok(false);
    };
    let executable = if executable.is_relative() {
        root.join(executable)
    } else {
        executable.to_path_buf()
    };
    let Some(archive) = EvbArchive::open(&executable)? else {
        return Ok(false);
    };
    if archive.files().is_empty() {
        return Ok(false);
    }
    let cache = match cache {
        Some(cache) => cache.to_path_buf(),
        None => {
            let stem = executable
                .file_stem()
                .map(|stem| stem.to_string_lossy().into_owned())
                .unwrap_or_default();
            root.join(format!(".evb-{stem}"))
        }
    };
    log::info!(
        "{} packs {} files; they win over the game folder's",
        executable.display(),
        archive.files().len()
    );
    let stamp = fs::metadata(&executable).and_then(|m| m.modified()).ok();
    launchers().push(Launcher {
        roots,
        archive: Arc::new(archive),
        cache,
        stamp,
    });
    Ok(true)
}

/// `path` below a registered root: the launcher's archive, its cache and
/// the '/' separated relative name.
fn lookup(
    path: &Path,
) -> Option<(
    Arc<EvbArchive>,
    PathBuf,
    Option<std::time::SystemTime>,
    String,
)> {
    let launchers = launchers();
    if launchers.is_empty() {
        return None;
    }
    for launcher in launchers.iter() {
        for root in &launcher.roots {
            let Ok(relative) = path.strip_prefix(root) else {
                continue;
            };
            let mut parts = Vec::new();
            for component in relative.components() {
                match component {
                    Component::Normal(part) => parts.push(part.to_string_lossy().into_owned()),
                    Component::CurDir => {}
                    _ => return None,
                }
            }
            if parts.is_empty() {
                return None;
            }
            return Some((
                launcher.archive.clone(),
                launcher.cache.clone(),
                launcher.stamp,
                parts.join("/"),
            ));
        }
    }
    None
}

/// The unpacked copy of the packed file at `path`, if the game's launcher
/// packs one.
pub fn resolve_file(path: &Path) -> Option<PathBuf> {
    let (archive, cache, stamp, name) = lookup(path)?;
    let file = archive.find(&name)?.clone();
    let target = cache.join(&file.name);
    match unpack(&archive, &file, &target, stamp) {
        Ok(()) => Some(target),
        Err(err) => {
            log::error!(
                "unpacking {} from {}: {err:#}",
                file.name,
                archive.path.display()
            );
            None
        }
    }
}

/// The cache folder standing in for a folder that exists only in the
/// launcher.
pub fn resolve_folder(path: &Path) -> Option<PathBuf> {
    let (archive, cache, _, name) = lookup(path)?;
    if !archive.has_folder(&name) {
        return None;
    }
    let folder = archive
        .files()
        .iter()
        .find_map(|file| {
            let key = name_key(&file.name);
            key.starts_with(&format!("{}/", name_key(&name)))
                .then(|| file.name.get(..name.len()).map(str::to_owned))
                .flatten()
        })
        .unwrap_or(name);
    let target = cache.join(folder);
    fs::create_dir_all(&target).ok()?;
    Some(target)
}

fn unpack(
    archive: &EvbArchive,
    file: &EvbFile,
    target: &Path,
    stamp: Option<std::time::SystemTime>,
) -> Result<()> {
    if let Ok(meta) = fs::metadata(target) {
        let fresh = match (stamp, meta.modified()) {
            (Some(stamp), Ok(modified)) => modified >= stamp,
            _ => true,
        };
        if meta.is_file() && meta.len() == file.size && fresh {
            return Ok(());
        }
    }
    let bytes = archive.read(file)?;
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    let partial = target.with_extension("evb-partial");
    fs::write(&partial, &bytes)?;
    fs::rename(&partial, target)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Writes aPLib bits most significant first, with the tag byte placed
    /// ahead of the literal bytes it covers, as the packer does.
    #[derive(Default)]
    struct Writer {
        out: Vec<u8>,
        tag_at: Option<usize>,
        used: u8,
    }
    impl Writer {
        fn bit(&mut self, bit: u8) {
            if self.tag_at.is_none() || self.used == 8 {
                self.tag_at = Some(self.out.len());
                self.out.push(0);
                self.used = 0;
            }
            let at = self.tag_at.unwrap();
            self.out[at] |= bit << (7 - self.used);
            self.used += 1;
        }
        fn gamma(&mut self, value: usize) {
            let bits = usize::BITS - value.leading_zeros();
            for index in (0..bits - 1).rev() {
                self.bit(((value >> index) & 1) as u8);
                self.bit(u8::from(index != 0));
            }
        }
    }

    #[test]
    fn aplib_literals_matches_and_end() {
        let mut w = Writer::default();
        w.out.push(b'a');
        w.bit(0);
        w.out.push(b'b');
        // short match: offset 2, length 2 -> "ab"
        w.bit(1);
        w.bit(1);
        w.bit(0);
        w.out.push(2 << 1);
        // literal 'c', then repeat the last offset for 2 bytes -> "bc"
        w.bit(0);
        w.out.push(b'c');
        w.bit(1);
        w.bit(0);
        w.gamma(2);
        w.gamma(2);
        // 4-bit offset match of 1 byte: offset 1 -> 'c'
        w.bit(1);
        w.bit(1);
        w.bit(1);
        for bit in [0, 0, 0, 1] {
            w.bit(bit);
        }
        // a zero byte
        w.bit(1);
        w.bit(1);
        w.bit(1);
        for _ in 0..4 {
            w.bit(0);
        }
        // end marker
        w.bit(1);
        w.bit(1);
        w.bit(0);
        w.out.push(0);
        let mut out = Vec::new();
        aplib_depack(&w.out, &mut out, 64).unwrap();
        assert_eq!(out, b"ababcbcc\0");
    }

    #[test]
    fn rejects_offsets_before_the_output() {
        let mut out = Vec::new();
        assert!(aplib_depack(&[b'a', 0b1100_0000, 5 << 1], &mut out, 64).is_err());
    }

    fn node(name: &str, kind: u8, objects: u32) -> Vec<u8> {
        let mut bytes = vec![0; 12];
        bytes.extend(objects.to_le_bytes());
        for unit in name.encode_utf16() {
            bytes.extend(unit.to_le_bytes());
        }
        bytes.extend([0, 0, kind]);
        bytes
    }

    fn file_node(name: &str, size: u32, stored: u32) -> Vec<u8> {
        let mut bytes = node(name, NODE_FILE, 0);
        let mut extra = vec![0u8; 53];
        extra[2..6].copy_from_slice(&size.to_le_bytes());
        extra[49..53].copy_from_slice(&stored.to_le_bytes());
        bytes.extend(extra);
        bytes
    }

    /// An image with a .enigma1 section holding `Scene.pck` and `g00/x.g00`.
    fn packed_exe() -> Vec<u8> {
        let mut table = MAGIC.to_vec();
        table.resize(64, 0);
        let mut nodes = node(DEFAULT_FOLDER, NODE_FOLDER, 2);
        nodes.extend([0; 25]);
        nodes.extend(file_node("Scene.pck", 5, 5));
        nodes.extend(node("g00", NODE_FOLDER, 1));
        nodes.extend([0; 25]);
        nodes.extend(file_node("x.g00", 2, 2));
        // Main node: its size is counted from its own 4th byte (see parse).
        let main_size = (nodes.len() - 1 + 12) as u32;
        table.extend(main_size.to_le_bytes());
        table.extend([0; 8]);
        table.extend(1u32.to_le_bytes());
        table.extend(&nodes[1..]);
        table.extend(b"hellohi");
        let section_at = 0x200usize;
        let mut exe = vec![0u8; section_at];
        exe[..2].copy_from_slice(b"MZ");
        exe[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        exe[0x80..0x84].copy_from_slice(b"PE\0\0");
        exe[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        let section = 0x80 + 24;
        exe[section..section + 8].copy_from_slice(b".enigma1");
        exe[section + 16..section + 20].copy_from_slice(&(table.len() as u32).to_le_bytes());
        exe[section + 20..section + 24].copy_from_slice(&(section_at as u32).to_le_bytes());
        exe.extend(table);
        exe
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("siglus-evb-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn lists_and_reads_packed_files() {
        let dir = temp_dir("list");
        let exe = dir.join("SiglusEngine_CHS.exe");
        fs::write(&exe, packed_exe()).unwrap();
        let archive = EvbArchive::open(&exe).unwrap().unwrap();
        let names: Vec<_> = archive.files().iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["Scene.pck", "g00/x.g00"]);
        let scene = archive.find("SCENE.PCK").unwrap();
        assert_eq!(archive.read(scene).unwrap(), b"hello");
        let image = archive.find("G00\\X.g00").unwrap();
        assert_eq!(archive.read(image).unwrap(), b"hi");
        assert!(archive.find("missing").is_none());
        assert!(archive.has_folder("G00"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn plain_files_are_not_packed() {
        let dir = temp_dir("plain");
        let exe = dir.join("SiglusEngine.exe");
        fs::write(
            &exe,
            b"MZ not a packed image at all, just bytes........................",
        )
        .unwrap();
        assert!(EvbArchive::open(&exe).unwrap().is_none());
        assert!(!set_launcher(&dir, Some(&exe), None).unwrap());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn packed_files_win_over_the_game_folder() {
        let dir = temp_dir("overlay");
        fs::write(dir.join("Scene.pck"), b"japanese").unwrap();
        fs::write(dir.join("Gameexe.dat"), b"loose").unwrap();
        fs::write(dir.join("SiglusEngine_CHS.exe"), packed_exe()).unwrap();
        let resolve = |name: &str| {
            crate::resource::resolve_game_file(&dir.join(name))
                .unwrap()
                .map(|path| fs::read(path).unwrap())
        };
        assert_eq!(resolve("Scene.pck").unwrap(), b"japanese");

        assert!(set_launcher(&dir, Some(Path::new("SiglusEngine_CHS.exe")), None).unwrap());
        assert_eq!(resolve("scene.PCK").unwrap(), b"hello");
        assert_eq!(resolve("G00/X.G00").unwrap(), b"hi");
        assert_eq!(resolve("Gameexe.dat").unwrap(), b"loose");
        assert!(crate::resource::game_path_exists(&dir.join("g00")));
        assert_eq!(
            crate::resource::read_file_bytes(&dir.join("Scene.pck")).unwrap(),
            b"hello"
        );

        // Starting from another executable brings the loose files back.
        assert!(!set_launcher(&dir, None, None).unwrap());
        assert_eq!(resolve("Scene.pck").unwrap(), b"japanese");
        assert!(resolve("g00/x.g00").is_none());
        fs::remove_dir_all(&dir).unwrap();
    }
}
