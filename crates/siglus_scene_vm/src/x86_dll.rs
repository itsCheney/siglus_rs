//! A small 32-bit x86 interpreter for running a codec DLL that ships with a
//! game, such as the `ucadec.dll` of translation repacks, whose formats have
//! no published decoder.
//!
//! It loads one PE image, resolves its imports to a few host functions
//! (`malloc`, `free`, `memcpy`, `memset`, `floor`, `_CIpow`), and runs one
//! exported function at a time. Only the integer and x87 instructions such
//! codecs use are implemented; anything else stops the call with an error.
//! The x87 stack holds `f64` values, not 80-bit ones.

use anyhow::{Context, Result, anyhow, bail};
use std::collections::HashMap;
use std::sync::OnceLock;

const IMAGE_BASE: u32 = 0x0001_0000;
const THUNK_BASE: u32 = 0x000E_0000;
const RETURN_MAGIC: u32 = 0x000E_FFF0;
const STACK_BOTTOM: u32 = 0x0010_0000;
const STACK_TOP: u32 = 0x0020_0000;
const HEAP_BASE: u32 = 0x0020_0000;
const MEMORY_LIMIT: usize = 512 << 20;
/// Instructions one call may run before it is taken for a hang.
const STEP_LIMIT: u64 = 20_000_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Import {
    Malloc,
    Free,
    Memcpy,
    Memset,
    Floor,
    CiPow,
}

/// A loaded DLL image, ready to be instantiated for calls.
pub struct DllImage {
    image: Vec<u8>,
    /// Recorded instructions, by offset in the image.
    tapes: Vec<OnceLock<Tape>>,
    exports: HashMap<String, u32>,
    imports: HashMap<u32, Import>,
}

impl DllImage {
    pub fn load(data: &[u8]) -> Result<Self> {
        let rd16 = |off: usize| -> Result<u32> {
            Ok(
                u16::from_le_bytes(data.get(off..off + 2).context("PE truncated")?.try_into()?)
                    as u32,
            )
        };
        let rd32 = |off: usize| -> Result<u32> {
            Ok(u32::from_le_bytes(
                data.get(off..off + 4).context("PE truncated")?.try_into()?,
            ))
        };
        if data.get(..2) != Some(b"MZ") {
            bail!("not a PE file");
        }
        let pe = rd32(0x3c)? as usize;
        if data.get(pe..pe + 4) != Some(b"PE\0\0") {
            bail!("not a PE file");
        }
        if rd16(pe + 4)? != 0x14c {
            bail!("not an x86 PE file");
        }
        let sections = rd16(pe + 6)? as usize;
        let opt = pe + 24;
        let opt_size = rd16(pe + 20)? as usize;
        if rd16(opt)? != 0x10b {
            bail!("not a PE32 file");
        }
        let preferred_base = rd32(opt + 28)?;
        let image_size = rd32(opt + 56)? as usize;
        let headers_size = rd32(opt + 60)? as usize;
        if image_size > 64 << 20 {
            bail!("PE image too large");
        }
        let dir = |i: usize| -> Result<(u32, u32)> {
            Ok((rd32(opt + 96 + i * 8)?, rd32(opt + 100 + i * 8)?))
        };

        let mut image = vec![0u8; image_size];
        let n = headers_size.min(data.len()).min(image_size);
        image[..n].copy_from_slice(&data[..n]);
        let table = opt + opt_size;
        for i in 0..sections {
            let s = table + i * 40;
            let va = rd32(s + 12)? as usize;
            let raw_size = rd32(s + 16)? as usize;
            let raw = rd32(s + 20)? as usize;
            let vsize = rd32(s + 8)? as usize;
            let len = raw_size.min(if vsize == 0 { raw_size } else { vsize });
            let src = data
                .get(raw..raw + len)
                .context("PE section out of bounds")?;
            image
                .get_mut(va..va + len)
                .context("PE section outside the image")?
                .copy_from_slice(src);
        }
        let img32 = |image: &[u8], off: usize| -> Result<u32> {
            Ok(u32::from_le_bytes(
                image
                    .get(off..off + 4)
                    .context("PE image read")?
                    .try_into()?,
            ))
        };
        let cstr = |image: &[u8], off: usize| -> Result<String> {
            let tail = image.get(off..).context("PE string")?;
            let end = tail.iter().position(|&b| b == 0).context("PE string")?;
            Ok(String::from_utf8_lossy(&tail[..end]).into_owned())
        };

        // Relocations to our base.
        let delta = IMAGE_BASE.wrapping_sub(preferred_base);
        let (reloc_rva, reloc_size) = dir(5)?;
        let mut at = reloc_rva as usize;
        let end = at + reloc_size as usize;
        while delta != 0 && at + 8 <= end {
            let page = img32(&image, at)? as usize;
            let block = img32(&image, at + 4)? as usize;
            if block < 8 {
                break;
            }
            for k in 0..(block - 8) / 2 {
                let entry = u16::from_le_bytes(image[at + 8 + k * 2..at + 10 + k * 2].try_into()?);
                match entry >> 12 {
                    0 => {}
                    3 => {
                        let off = page + (entry & 0xfff) as usize;
                        let v = img32(&image, off)?.wrapping_add(delta);
                        image[off..off + 4].copy_from_slice(&v.to_le_bytes());
                    }
                    kind => bail!("unsupported relocation type {kind}"),
                }
            }
            at += block;
        }

        // Imports, each pointed at a thunk address the interpreter catches.
        let mut imports = HashMap::new();
        let (import_rva, _) = dir(1)?;
        let mut desc = import_rva as usize;
        let mut thunk = THUNK_BASE;
        while import_rva != 0 {
            let lookup = img32(&image, desc)? as usize;
            let name = img32(&image, desc + 12)?;
            let iat = img32(&image, desc + 16)? as usize;
            if name == 0 && iat == 0 {
                break;
            }
            let lookup = if lookup != 0 { lookup } else { iat };
            for k in 0.. {
                let entry = img32(&image, lookup + k * 4)?;
                if entry == 0 {
                    break;
                }
                if entry & 0x8000_0000 != 0 {
                    bail!("import by ordinal is not supported");
                }
                let func = cstr(&image, entry as usize + 2)?;
                let import = match func.as_str() {
                    "malloc" => Import::Malloc,
                    "free" => Import::Free,
                    "memcpy" | "memmove" => Import::Memcpy,
                    "memset" => Import::Memset,
                    "floor" => Import::Floor,
                    "_CIpow" => Import::CiPow,
                    other => bail!("unsupported import {other}"),
                };
                imports.insert(thunk, import);
                let off = iat + k * 4;
                image[off..off + 4].copy_from_slice(&thunk.to_le_bytes());
                thunk += 4;
            }
            desc += 20;
        }

        let mut exports = HashMap::new();
        let (export_rva, _) = dir(0)?;
        if export_rva != 0 {
            let e = export_rva as usize;
            let names = img32(&image, e + 24)? as usize;
            let functions = img32(&image, e + 28)? as usize;
            let name_table = img32(&image, e + 32)? as usize;
            let ordinals = img32(&image, e + 36)? as usize;
            for k in 0..names {
                let name = cstr(&image, img32(&image, name_table + k * 4)? as usize)?;
                let ordinal =
                    u16::from_le_bytes(image[ordinals + k * 2..ordinals + k * 2 + 2].try_into()?)
                        as usize;
                let rva = img32(&image, functions + ordinal * 4)?;
                exports.insert(name, IMAGE_BASE + rva);
            }
        }
        Ok(Self {
            tapes: (0..image.len()).map(|_| OnceLock::new()).collect(),
            image,
            exports,
            imports,
        })
    }

    /// A fresh address space with this image in it.
    pub fn instantiate(&self) -> Machine<'_> {
        let mut mem = vec![0u8; HEAP_BASE as usize];
        let base = IMAGE_BASE as usize;
        mem[base..base + self.image.len()].copy_from_slice(&self.image);
        Machine {
            dll: self,
            mem,
            regs: [0; 8],
            eip: 0,
            flags: Flags::default(),
            fpu: [0.0; 8],
            top: 0,
            c: [false; 4],
            fcw: 0x037f,
            heap_next: HEAP_BASE,
            steps: 0,
            tape: Tape::default(),
            cur: &EMPTY_TAPE,
            tape_pos: 0,
            tape_end: 0,
            replaying: false,
        }
    }
}

#[derive(Default, Clone, Copy)]
struct Flags {
    cf: bool,
    zf: bool,
    sf: bool,
    of: bool,
    pf: bool,
}

const EAX: usize = 0;
const ECX: usize = 1;
const EDX: usize = 2;
const ESP: usize = 4;
const ESI: usize = 6;
const EDI: usize = 7;

#[derive(Clone, Copy)]
enum Operand {
    Reg(usize),
    Mem(u32),
}

#[derive(Clone, Copy, Default)]
struct ModRm {
    md: u8,
    reg: u8,
    rm: u8,
    /// Base and index registers, 8 for none.
    base: u8,
    index: u8,
    scale: u8,
    disp: u32,
}

static EMPTY_TAPE: Tape = Tape {
    vals: [0; 6],
    n: 0,
    modrm: ModRm {
        md: 0,
        reg: 0,
        rm: 0,
        base: 8,
        index: 8,
        scale: 0,
        disp: 0,
    },
    next: 0,
};

/// One instruction's bytes as `step` reads them: the values of its fetches,
/// its ModRM operand, and the address after it.
#[derive(Clone, Copy, Default)]
struct Tape {
    vals: [u32; 6],
    n: u8,
    modrm: ModRm,
    next: u32,
}

pub struct Machine<'a> {
    dll: &'a DllImage,
    mem: Vec<u8>,
    regs: [u32; 8],
    eip: u32,
    flags: Flags,
    fpu: [f64; 8],
    top: usize,
    /// C0..C3 of the x87 status word.
    c: [bool; 4],
    fcw: u16,
    heap_next: u32,
    steps: u64,
    tape: Tape,
    /// The recording being replayed.
    cur: &'a Tape,
    tape_pos: usize,
    tape_end: u32,
    replaying: bool,
}

fn mask(size: u32) -> u32 {
    if size == 4 {
        u32::MAX
    } else {
        (1u32 << (size * 8)) - 1
    }
}

fn sign(v: u32, size: u32) -> bool {
    v >> (size * 8 - 1) & 1 != 0
}

fn sext(v: u32, size: u32) -> u32 {
    match size {
        1 => v as u8 as i8 as i32 as u32,
        2 => v as u16 as i16 as i32 as u32,
        _ => v,
    }
}

impl Machine<'_> {
    pub fn memory(&self, addr: u32, len: usize) -> Result<&[u8]> {
        self.mem
            .get(addr as usize..addr as usize + len)
            .ok_or_else(|| anyhow!("x86 read out of bounds at {addr:#x}"))
    }

    pub fn read_u32(&self, addr: u32) -> Result<u32> {
        Ok(u32::from_le_bytes(self.memory(addr, 4)?.try_into()?))
    }

    /// Copies bytes into a new heap block and returns its address.
    pub fn alloc_bytes(&mut self, data: &[u8]) -> Result<u32> {
        let addr = self.malloc(data.len() as u32)?;
        self.mem[addr as usize..addr as usize + data.len()].copy_from_slice(data);
        Ok(addr)
    }

    pub fn alloc_zeroed(&mut self, len: u32) -> Result<u32> {
        self.malloc(len)
    }

    fn malloc(&mut self, len: u32) -> Result<u32> {
        let addr = (self.heap_next + 15) & !15;
        let end = addr as usize + len as usize + 16;
        if end > MEMORY_LIMIT {
            bail!("x86 heap exhausted");
        }
        if end > self.mem.len() {
            self.mem
                .resize(end.next_power_of_two().min(MEMORY_LIMIT), 0);
        }
        self.mem[addr as usize..addr as usize + len as usize].fill(0);
        self.heap_next = addr + len;
        Ok(addr)
    }

    /// Calls an exported `__stdcall` (or `__cdecl`) function with 32-bit
    /// arguments and returns EAX.
    pub fn call(&mut self, export: &str, args: &[u32]) -> Result<u32> {
        let entry = *self
            .dll
            .exports
            .get(export)
            .with_context(|| format!("DLL has no export {export}"))?;
        self.regs = [0; 8];
        self.regs[ESP] = STACK_TOP - 64;
        for &arg in args.iter().rev() {
            self.push(arg)?;
        }
        self.push(RETURN_MAGIC)?;
        self.eip = entry;
        self.top = 0;
        self.steps = 0;
        while self.eip != RETURN_MAGIC {
            if self.eip >= THUNK_BASE && self.eip < RETURN_MAGIC {
                self.host_call()?;
                continue;
            }
            let at = self.eip;
            let slot = self.dll.tapes.get(at.wrapping_sub(IMAGE_BASE) as usize);
            if let Some(tape) = slot.and_then(OnceLock::get) {
                self.cur = tape;
                self.tape_pos = 0;
                self.replaying = true;
                self.eip = tape.next;
            } else {
                self.tape = Tape::default();
                self.replaying = false;
            }
            let recording = !self.replaying;
            let result = self.step();
            if recording && result.is_ok() && (self.tape.n as usize) <= self.tape.vals.len() {
                self.tape.next = self.tape_end;
                if let Some(slot) = slot {
                    let _ = slot.set(self.tape);
                }
            }
            result.with_context(|| {
                format!(
                    "x86 instruction at {:#x}",
                    at.wrapping_sub(IMAGE_BASE).wrapping_add(0x1000_0000)
                )
            })?;
            self.steps += 1;
            if self.steps > STEP_LIMIT {
                bail!("x86 call ran too long");
            }
        }
        Ok(self.regs[EAX])
    }

    fn host_call(&mut self) -> Result<()> {
        let import = *self
            .dll
            .imports
            .get(&self.eip)
            .ok_or_else(|| anyhow!("jump into the import area at {:#x}", self.eip))?;
        let sp = self.regs[ESP];
        let arg = |m: &Self, i: u32| m.read_u32(sp + 4 + i * 4);
        match import {
            Import::Malloc => {
                let len = arg(self, 0)?;
                self.regs[EAX] = self.malloc(len)?;
            }
            Import::Free => {}
            Import::Memcpy => {
                let (dst, src, len) = (arg(self, 0)?, arg(self, 1)?, arg(self, 2)? as usize);
                self.check(dst, len)?;
                self.check(src, len)?;
                self.mem
                    .copy_within(src as usize..src as usize + len, dst as usize);
                self.regs[EAX] = dst;
            }
            Import::Memset => {
                let (dst, value, len) = (arg(self, 0)?, arg(self, 1)?, arg(self, 2)? as usize);
                self.check(dst, len)?;
                self.mem[dst as usize..dst as usize + len].fill(value as u8);
                self.regs[EAX] = dst;
            }
            Import::Floor => {
                let lo = arg(self, 0)? as u64;
                let hi = arg(self, 1)? as u64;
                let v = f64::from_bits(lo | hi << 32);
                self.fpush(v.floor());
            }
            Import::CiPow => {
                let y = self.fpop();
                let x = self.st(0);
                self.set_st(0, x.powf(y));
            }
        }
        // cdecl: the caller pops the arguments.
        self.eip = self.read_u32(sp)?;
        self.regs[ESP] = sp + 4;
        Ok(())
    }

    fn check(&self, addr: u32, len: usize) -> Result<()> {
        if addr as usize + len > self.mem.len() {
            bail!("x86 access out of bounds at {addr:#x}+{len}");
        }
        Ok(())
    }

    #[inline(always)]
    fn rd(&self, addr: u32, size: u32) -> Result<u32> {
        let a = addr as usize;
        let m = self
            .mem
            .get(a..a + size as usize)
            .ok_or_else(|| anyhow!("x86 read out of bounds at {addr:#x}"))?;
        Ok(match size {
            1 => m[0] as u32,
            2 => u16::from_le_bytes([m[0], m[1]]) as u32,
            _ => u32::from_le_bytes([m[0], m[1], m[2], m[3]]),
        })
    }

    #[inline(always)]
    fn wr(&mut self, addr: u32, size: u32, v: u32) -> Result<()> {
        let a = addr as usize;
        if a < STACK_BOTTOM as usize
            && !(IMAGE_BASE as usize..IMAGE_BASE as usize + self.dll.image.len()).contains(&a)
        {
            bail!("x86 write to unmapped memory at {addr:#x}");
        }
        let m = self
            .mem
            .get_mut(a..a + size as usize)
            .ok_or_else(|| anyhow!("x86 write out of bounds at {addr:#x}"))?;
        m.copy_from_slice(&v.to_le_bytes()[..size as usize]);
        Ok(())
    }

    fn rd64(&self, addr: u32) -> Result<u64> {
        Ok(self.rd(addr, 4)? as u64 | (self.rd(addr + 4, 4)? as u64) << 32)
    }

    fn wr64(&mut self, addr: u32, v: u64) -> Result<()> {
        self.wr(addr, 4, v as u32)?;
        self.wr(addr + 4, 4, (v >> 32) as u32)
    }

    /// Reads `size` instruction bytes. The first run of an instruction
    /// records them; later runs replay the recording.
    #[inline(always)]
    fn fetch(&mut self, size: u32) -> Result<u32> {
        if self.replaying {
            let v = self.cur.vals[self.tape_pos];
            self.tape_pos += 1;
            return Ok(v);
        }
        let v = self.rd(self.eip, size)?;
        self.eip += size;
        self.tape_end = self.eip;
        if (self.tape.n as usize) < self.tape.vals.len() {
            self.tape.vals[self.tape.n as usize] = v;
        }
        self.tape.n = self.tape.n.saturating_add(1);
        Ok(v)
    }

    #[inline(always)]
    fn fetch8(&mut self) -> Result<u32> {
        self.fetch(1)
    }

    #[inline(always)]
    fn fetch16(&mut self) -> Result<u32> {
        self.fetch(2)
    }

    #[inline(always)]
    fn fetch32(&mut self) -> Result<u32> {
        self.fetch(4)
    }

    #[inline(always)]
    fn fetch_imm(&mut self, size: u32) -> Result<u32> {
        match size {
            1 => self.fetch8(),
            2 => self.fetch16(),
            _ => self.fetch32(),
        }
    }

    #[inline(always)]
    fn push(&mut self, v: u32) -> Result<()> {
        self.regs[ESP] = self.regs[ESP].wrapping_sub(4);
        if self.regs[ESP] < STACK_BOTTOM {
            bail!("x86 stack overflow");
        }
        self.wr(self.regs[ESP], 4, v)
    }

    #[inline(always)]
    fn pop(&mut self) -> Result<u32> {
        let v = self.rd(self.regs[ESP], 4)?;
        self.regs[ESP] = self.regs[ESP].wrapping_add(4);
        Ok(v)
    }

    #[inline(always)]
    fn reg(&self, r: usize, size: u32) -> u32 {
        match size {
            1 if r >= 4 => (self.regs[r - 4] >> 8) & 0xff,
            1 => self.regs[r] & 0xff,
            2 => self.regs[r] & 0xffff,
            _ => self.regs[r],
        }
    }

    #[inline(always)]
    fn set_reg(&mut self, r: usize, size: u32, v: u32) {
        match size {
            1 if r >= 4 => self.regs[r - 4] = (self.regs[r - 4] & !0xff00) | (v & 0xff) << 8,
            1 => self.regs[r] = (self.regs[r] & !0xff) | (v & 0xff),
            2 => self.regs[r] = (self.regs[r] & !0xffff) | (v & 0xffff),
            _ => self.regs[r] = v,
        }
    }

    /// Decodes a ModRM byte (and SIB, displacement): (reg field, operand).
    #[inline(always)]
    fn modrm(&mut self) -> Result<(usize, Operand)> {
        let m = if self.replaying {
            self.cur.modrm
        } else {
            let m = self.decode_modrm()?;
            self.tape.modrm = m;
            m
        };
        if m.md == 3 {
            return Ok((m.reg as usize, Operand::Reg(m.rm as usize)));
        }
        let mut addr = m.disp;
        if m.base < 8 {
            addr = addr.wrapping_add(self.regs[m.base as usize]);
        }
        if m.index < 8 {
            addr = addr.wrapping_add(self.regs[m.index as usize] << m.scale);
        }
        Ok((m.reg as usize, Operand::Mem(addr)))
    }

    fn raw(&mut self, size: u32) -> Result<u32> {
        let v = self.rd(self.eip, size)?;
        self.eip += size;
        self.tape_end = self.eip;
        Ok(v)
    }

    fn decode_modrm(&mut self) -> Result<ModRm> {
        let b = self.raw(1)?;
        let mut m = ModRm {
            md: (b >> 6) as u8,
            reg: ((b >> 3) & 7) as u8,
            rm: (b & 7) as u8,
            base: 8,
            index: 8,
            scale: 0,
            disp: 0,
        };
        if m.md == 3 {
            return Ok(m);
        }
        if m.rm == 4 {
            let sib = self.raw(1)?;
            m.scale = (sib >> 6) as u8;
            let index = ((sib >> 3) & 7) as u8;
            let base = (sib & 7) as u8;
            if base == 5 && m.md == 0 {
                m.disp = self.raw(4)?;
            } else {
                m.base = base;
            }
            if index != 4 {
                m.index = index;
            }
        } else if m.rm == 5 && m.md == 0 {
            m.disp = self.raw(4)?;
        } else {
            m.base = m.rm;
        }
        match m.md {
            1 => m.disp = m.disp.wrapping_add(self.raw(1)? as u8 as i8 as i32 as u32),
            2 => m.disp = m.disp.wrapping_add(self.raw(4)?),
            _ => {}
        }
        Ok(m)
    }

    #[inline(always)]
    fn get(&self, op: Operand, size: u32) -> Result<u32> {
        match op {
            Operand::Reg(r) => Ok(self.reg(r, size)),
            Operand::Mem(a) => self.rd(a, size),
        }
    }

    #[inline(always)]
    fn set(&mut self, op: Operand, size: u32, v: u32) -> Result<()> {
        match op {
            Operand::Reg(r) => {
                self.set_reg(r, size, v);
                Ok(())
            }
            Operand::Mem(a) => self.wr(a, size, v),
        }
    }

    fn mem_addr(op: Operand) -> Result<u32> {
        match op {
            Operand::Mem(a) => Ok(a),
            Operand::Reg(_) => bail!("register operand where memory is required"),
        }
    }

    #[inline(always)]
    fn set_szp(&mut self, res: u32, size: u32) {
        let res = res & mask(size);
        self.flags.zf = res == 0;
        self.flags.sf = sign(res, size);
        self.flags.pf = (res as u8).count_ones() % 2 == 0;
    }

    /// The eight classic ALU operations (ADD OR ADC SBB AND SUB XOR CMP).
    #[inline(always)]
    fn alu(&mut self, op: u32, a: u32, b: u32, size: u32) -> u32 {
        let m = mask(size);
        let (a, b) = (a & m, b & m);
        let res = match op {
            0 | 2 => {
                let carry = if op == 2 && self.flags.cf { 1u64 } else { 0 };
                let wide = a as u64 + b as u64 + carry;
                let res = (wide as u32) & m;
                self.flags.cf = wide > m as u64;
                self.flags.of = sign((a ^ res) & (b ^ res), size);
                res
            }
            3 | 5 | 7 => {
                let borrow = if op == 3 && self.flags.cf { 1u64 } else { 0 };
                let res = (a as u64).wrapping_sub(b as u64).wrapping_sub(borrow) as u32 & m;
                self.flags.cf = (a as u64) < b as u64 + borrow;
                self.flags.of = sign((a ^ b) & (a ^ res), size);
                res
            }
            1 | 4 | 6 => {
                let res = match op {
                    1 => a | b,
                    4 => a & b,
                    _ => a ^ b,
                };
                self.flags.cf = false;
                self.flags.of = false;
                res
            }
            _ => unreachable!(),
        };
        self.set_szp(res, size);
        res
    }

    #[inline(always)]
    fn cond(&self, cc: u32) -> bool {
        let f = self.flags;
        let r = match cc >> 1 {
            0 => f.of,
            1 => f.cf,
            2 => f.zf,
            3 => f.cf || f.zf,
            4 => f.sf,
            5 => f.pf,
            6 => f.sf != f.of,
            _ => f.zf || f.sf != f.of,
        };
        r != (cc & 1 != 0)
    }

    fn shift(&mut self, kind: usize, op: Operand, size: u32, count: u32) -> Result<()> {
        let count = count & 31;
        if count == 0 {
            return Ok(());
        }
        let bits = size * 8;
        let m = mask(size);
        let v = self.get(op, size)? & m;
        let res = match kind {
            0 | 1 => {
                let n = count % bits;
                let res = if kind == 0 {
                    (v << n | v.checked_shr(bits - n).unwrap_or(0)) & m
                } else {
                    (v >> n | v.checked_shl(bits - n).unwrap_or(0)) & m
                };
                if kind == 0 {
                    self.flags.cf = res & 1 != 0;
                    self.flags.of = sign(res, size) != self.flags.cf;
                } else {
                    self.flags.cf = sign(res, size);
                    self.flags.of = sign(res, size) != sign(res << 1, size);
                }
                self.set(op, size, res)?;
                return Ok(());
            }
            2 | 3 => {
                // RCL / RCR through the carry, one bit at a time.
                let mut res = v;
                let mut cf = self.flags.cf;
                for _ in 0..count % (bits + 1) {
                    if kind == 2 {
                        let out = sign(res, size);
                        res = (res << 1 | cf as u32) & m;
                        cf = out;
                    } else {
                        let out = res & 1 != 0;
                        res = res >> 1 | (cf as u32) << (bits - 1);
                        cf = out;
                    }
                }
                self.flags.cf = cf;
                self.flags.of = if kind == 2 {
                    sign(res, size) != cf
                } else {
                    sign(res, size) != sign(res << 1, size)
                };
                self.set(op, size, res)?;
                return Ok(());
            }
            4 | 6 => {
                self.flags.cf = count <= bits && (v >> (bits - count)) & 1 != 0;
                let res = if count >= bits { 0 } else { (v << count) & m };
                self.flags.of = sign(res, size) != self.flags.cf;
                res
            }
            5 => {
                self.flags.cf = count <= bits && (v >> (count - 1)) & 1 != 0;
                self.flags.of = sign(v, size);
                if count >= bits { 0 } else { v >> count }
            }
            _ => {
                let s = sext(v, size) as i32;
                let n = count.min(bits - 1);
                self.flags.cf = (s >> (count.min(bits) - 1)) & 1 != 0;
                self.flags.of = false;
                (s >> n) as u32 & m
            }
        };
        self.set_szp(res, size);
        self.set(op, size, res)
    }

    #[inline(always)]
    fn st(&self, i: usize) -> f64 {
        self.fpu[(self.top + i) & 7]
    }

    #[inline(always)]
    fn set_st(&mut self, i: usize, v: f64) {
        self.fpu[(self.top + i) & 7] = v;
    }

    #[inline(always)]
    fn fpush(&mut self, v: f64) {
        self.top = (self.top + 7) & 7;
        self.fpu[self.top] = v;
    }

    #[inline(always)]
    fn fpop(&mut self) -> f64 {
        let v = self.fpu[self.top];
        self.top = (self.top + 1) & 7;
        v
    }

    fn fcompare(&mut self, a: f64, b: f64) {
        self.c[1] = false;
        if a.is_nan() || b.is_nan() {
            self.c[0] = true;
            self.c[2] = true;
            self.c[3] = true;
        } else {
            self.c[0] = a < b;
            self.c[2] = false;
            self.c[3] = a == b;
        }
    }

    fn status_word(&self) -> u32 {
        (self.c[0] as u32) << 8
            | (self.c[1] as u32) << 9
            | (self.c[2] as u32) << 10
            | (self.top as u32) << 11
            | (self.c[3] as u32) << 14
    }

    fn round_int(&self, v: f64) -> f64 {
        match (self.fcw >> 10) & 3 {
            0 => {
                let r = v.round();
                // Round half to even.
                if (v - v.trunc()).abs() == 0.5 && r % 2.0 != 0.0 {
                    r - v.signum()
                } else {
                    r
                }
            }
            1 => v.floor(),
            2 => v.ceil(),
            _ => v.trunc(),
        }
    }

    fn to_int(&self, v: f64, bits: u32) -> u64 {
        let r = self.round_int(v);
        let limit = 2f64.powi(bits as i32 - 1);
        if !r.is_finite() || r >= limit || r < -limit {
            // The integer indefinite value.
            1u64 << (bits - 1)
        } else {
            r as i64 as u64
        }
    }

    /// One arithmetic operation of the D8/DC group: dest = dest op src.
    fn farith(op: usize, dest: f64, src: f64) -> f64 {
        match op {
            0 => dest + src,
            1 => dest * src,
            4 => dest - src,
            5 => src - dest,
            6 => dest / src,
            _ => src / dest,
        }
    }

    fn step(&mut self) -> Result<()> {
        let mut size = 4u32;
        let mut rep = false;
        let mut op = self.fetch8()?;
        loop {
            match op {
                0x66 => size = 2,
                0xf3 | 0xf2 => rep = true,
                0x26 | 0x2e | 0x36 | 0x3e => {}
                _ => break,
            }
            op = self.fetch8()?;
        }
        match op {
            // ALU r/m, reg / reg, r/m / acc, imm
            0x00..=0x3f if op & 7 < 6 => {
                let kind = op >> 3;
                let sz = if op & 1 == 0 { 1 } else { size };
                match op & 7 {
                    0 | 1 => {
                        let (r, rm) = self.modrm()?;
                        let res = self.alu(kind, self.get(rm, sz)?, self.reg(r, sz), sz);
                        if kind != 7 {
                            self.set(rm, sz, res)?;
                        }
                    }
                    2 | 3 => {
                        let (r, rm) = self.modrm()?;
                        let res = self.alu(kind, self.reg(r, sz), self.get(rm, sz)?, sz);
                        if kind != 7 {
                            self.set_reg(r, sz, res);
                        }
                    }
                    _ => {
                        let imm = self.fetch_imm(sz)?;
                        let res = self.alu(kind, self.reg(EAX, sz), imm, sz);
                        if kind != 7 {
                            self.set_reg(EAX, sz, res);
                        }
                    }
                }
            }
            0x40..=0x4f => {
                let r = (op & 7) as usize;
                let cf = self.flags.cf;
                let v = self.reg(r, size);
                let res = if op < 0x48 {
                    self.alu(0, v, 1, size)
                } else {
                    self.alu(5, v, 1, size)
                };
                self.flags.cf = cf;
                self.set_reg(r, size, res);
            }
            0x50..=0x57 => self.push(self.regs[(op & 7) as usize])?,
            0x58..=0x5f => {
                let v = self.pop()?;
                self.regs[(op & 7) as usize] = v;
            }
            0x68 => {
                let v = self.fetch32()?;
                self.push(v)?;
            }
            0x6a => {
                let v = sext(self.fetch8()?, 1);
                self.push(v)?;
            }
            0x69 | 0x6b => {
                let (r, rm) = self.modrm()?;
                let a = sext(self.get(rm, size)?, size) as i32 as i64;
                let b = if op == 0x6b {
                    sext(self.fetch8()?, 1)
                } else {
                    sext(self.fetch_imm(size)?, size)
                };
                let b = b as i32 as i64;
                self.imul_into(r, a, b, size);
            }
            0x70..=0x7f => {
                let rel = sext(self.fetch8()?, 1);
                if self.cond(op & 15) {
                    self.eip = self.eip.wrapping_add(rel);
                }
            }
            0x80 | 0x81 | 0x83 => {
                let sz = if op == 0x80 { 1 } else { size };
                let (kind, rm) = self.modrm()?;
                let imm = if op == 0x83 {
                    sext(self.fetch8()?, 1)
                } else {
                    self.fetch_imm(sz)?
                };
                let res = self.alu(kind as u32, self.get(rm, sz)?, imm, sz);
                if kind != 7 {
                    self.set(rm, sz, res)?;
                }
            }
            0x84 | 0x85 => {
                let sz = if op == 0x84 { 1 } else { size };
                let (r, rm) = self.modrm()?;
                self.alu(4, self.get(rm, sz)?, self.reg(r, sz), sz);
            }
            0x86 | 0x87 => {
                let sz = if op == 0x86 { 1 } else { size };
                let (r, rm) = self.modrm()?;
                let a = self.get(rm, sz)?;
                let b = self.reg(r, sz);
                self.set(rm, sz, b)?;
                self.set_reg(r, sz, a);
            }
            0x88..=0x8b => {
                let sz = if op & 1 == 0 { 1 } else { size };
                let (r, rm) = self.modrm()?;
                if op < 0x8a {
                    self.set(rm, sz, self.reg(r, sz))?;
                } else {
                    let v = self.get(rm, sz)?;
                    self.set_reg(r, sz, v);
                }
            }
            0x8d => {
                let (r, rm) = self.modrm()?;
                let a = Self::mem_addr(rm)?;
                self.set_reg(r, size, a);
            }
            0x90 => {}
            0x91..=0x97 => {
                let r = (op & 7) as usize;
                let a = self.reg(EAX, size);
                let b = self.reg(r, size);
                self.set_reg(EAX, size, b);
                self.set_reg(r, size, a);
            }
            0x98 => {
                if size == 2 {
                    let v = sext(self.regs[EAX] & 0xff, 1);
                    self.set_reg(EAX, 2, v);
                } else {
                    self.regs[EAX] = sext(self.regs[EAX], 2);
                }
            }
            0x99 => {
                if size == 2 {
                    let v = if sign(self.regs[EAX], 2) { 0xffff } else { 0 };
                    self.set_reg(EDX, 2, v);
                } else {
                    self.regs[EDX] = if sign(self.regs[EAX], 4) { u32::MAX } else { 0 };
                }
            }
            0x9e => {
                let ah = (self.regs[EAX] >> 8) & 0xff;
                self.flags.cf = ah & 1 != 0;
                self.flags.pf = ah & 4 != 0;
                self.flags.zf = ah & 0x40 != 0;
                self.flags.sf = ah & 0x80 != 0;
            }
            0x9f => {
                let f = self.flags;
                let ah =
                    f.cf as u32 | 2 | (f.pf as u32) << 2 | (f.zf as u32) << 6 | (f.sf as u32) << 7;
                self.set_reg(4, 1, ah);
            }
            0xa0..=0xa3 => {
                let sz = if op & 1 == 0 { 1 } else { size };
                let addr = self.fetch32()?;
                if op < 0xa2 {
                    let v = self.rd(addr, sz)?;
                    self.set_reg(EAX, sz, v);
                } else {
                    self.wr(addr, sz, self.reg(EAX, sz))?;
                }
            }
            0xa4 | 0xa5 | 0xaa | 0xab => {
                let sz = if op & 1 == 0 { 1 } else { size };
                let mut count = if rep { self.regs[ECX] } else { 1 };
                while count > 0 {
                    if op < 0xaa {
                        let v = self.rd(self.regs[ESI], sz)?;
                        self.wr(self.regs[EDI], sz, v)?;
                        self.regs[ESI] = self.regs[ESI].wrapping_add(sz);
                    } else {
                        self.wr(self.regs[EDI], sz, self.reg(EAX, sz))?;
                    }
                    self.regs[EDI] = self.regs[EDI].wrapping_add(sz);
                    count -= 1;
                }
                if rep {
                    self.regs[ECX] = 0;
                }
            }
            0xa8 | 0xa9 => {
                let sz = if op == 0xa8 { 1 } else { size };
                let imm = self.fetch_imm(sz)?;
                self.alu(4, self.reg(EAX, sz), imm, sz);
            }
            0xb0..=0xb7 => {
                let v = self.fetch8()?;
                self.set_reg((op & 7) as usize, 1, v);
            }
            0xb8..=0xbf => {
                let v = self.fetch_imm(size)?;
                self.set_reg((op & 7) as usize, size, v);
            }
            0xc0 | 0xc1 | 0xd0..=0xd3 => {
                let sz = if op & 1 == 0 { 1 } else { size };
                let (kind, rm) = self.modrm()?;
                let count = match op {
                    0xc0 | 0xc1 => self.fetch8()?,
                    0xd0 | 0xd1 => 1,
                    _ => self.regs[ECX] & 0xff,
                };
                self.shift(kind, rm, sz, count)?;
            }
            0xc2 => {
                let n = self.fetch16()?;
                self.eip = self.pop()?;
                self.regs[ESP] = self.regs[ESP].wrapping_add(n);
            }
            0xc3 => self.eip = self.pop()?,
            0xc6 | 0xc7 => {
                let sz = if op == 0xc6 { 1 } else { size };
                let (_, rm) = self.modrm()?;
                let v = self.fetch_imm(sz)?;
                self.set(rm, sz, v)?;
            }
            0xc9 => {
                self.regs[ESP] = self.regs[5];
                self.regs[5] = self.pop()?;
            }
            0xd8..=0xdf => self.x87(op)?,
            0xe8 => {
                let rel = self.fetch32()?;
                self.push(self.eip)?;
                self.eip = self.eip.wrapping_add(rel);
            }
            0xe9 => {
                let rel = self.fetch32()?;
                self.eip = self.eip.wrapping_add(rel);
            }
            0xeb => {
                let rel = sext(self.fetch8()?, 1);
                self.eip = self.eip.wrapping_add(rel);
            }
            0xf6 | 0xf7 => {
                let sz = if op == 0xf6 { 1 } else { size };
                let (kind, rm) = self.modrm()?;
                self.group3(kind, rm, sz)?;
            }
            0xfc => {}
            0xfe | 0xff => {
                let sz = if op == 0xfe { 1 } else { size };
                let (kind, rm) = self.modrm()?;
                match kind {
                    0 | 1 => {
                        let cf = self.flags.cf;
                        let v = self.get(rm, sz)?;
                        let res = self.alu(if kind == 0 { 0 } else { 5 }, v, 1, sz);
                        self.flags.cf = cf;
                        self.set(rm, sz, res)?;
                    }
                    2 => {
                        let target = self.get(rm, 4)?;
                        self.push(self.eip)?;
                        self.eip = target;
                    }
                    4 => self.eip = self.get(rm, 4)?,
                    6 => {
                        let v = self.get(rm, 4)?;
                        self.push(v)?;
                    }
                    _ => bail!("unsupported FF /{kind}"),
                }
            }
            0x0f => self.two_byte()?,
            _ => bail!("unsupported opcode {op:#04x}"),
        }
        Ok(())
    }

    fn imul_into(&mut self, r: usize, a: i64, b: i64, size: u32) {
        let wide = a * b;
        let res = wide as u32 & mask(size);
        let fits = sext(res, size) as i32 as i64 == wide;
        self.flags.cf = !fits;
        self.flags.of = !fits;
        self.set_szp(res, size);
        self.set_reg(r, size, res);
    }

    fn group3(&mut self, kind: usize, rm: Operand, sz: u32) -> Result<()> {
        let m = mask(sz);
        match kind {
            0 | 1 => {
                let imm = self.fetch_imm(sz)?;
                self.alu(4, self.get(rm, sz)?, imm, sz);
            }
            2 => {
                let v = self.get(rm, sz)?;
                self.set(rm, sz, !v & m)?;
            }
            3 => {
                let v = self.get(rm, sz)?;
                let res = self.alu(5, 0, v, sz);
                self.flags.cf = v & m != 0;
                self.set(rm, sz, res)?;
            }
            4 | 5 => {
                let v = self.get(rm, sz)?;
                if sz == 1 {
                    let al = self.regs[EAX] & 0xff;
                    let res = if kind == 4 {
                        al * v
                    } else {
                        (sext(al, 1) as i32 * sext(v, 1) as i32) as u32 & 0xffff
                    };
                    self.set_reg(EAX, 2, res);
                    let high = if kind == 4 {
                        res >> 8 != 0
                    } else {
                        sext(res & 0xff, 1) & 0xffff != res
                    };
                    self.flags.cf = high;
                    self.flags.of = high;
                } else if kind == 4 {
                    let wide = self.reg(EAX, sz) as u64 * v as u64;
                    self.set_reg(EAX, sz, wide as u32);
                    self.set_reg(EDX, sz, (wide >> (sz * 8)) as u32);
                    let high = wide >> (sz * 8) != 0;
                    self.flags.cf = high;
                    self.flags.of = high;
                } else {
                    let wide =
                        sext(self.reg(EAX, sz), sz) as i32 as i64 * sext(v, sz) as i32 as i64;
                    self.set_reg(EAX, sz, wide as u32);
                    self.set_reg(EDX, sz, (wide >> (sz * 8)) as u32);
                    let fits = sext(wide as u32 & m, sz) as i32 as i64 == wide;
                    self.flags.cf = !fits;
                    self.flags.of = !fits;
                }
            }
            _ => {
                let v = self.get(rm, sz)?;
                if v & m == 0 {
                    bail!("x86 divide by zero");
                }
                if sz == 1 {
                    let ax = self.regs[EAX] & 0xffff;
                    let (q, r) = if kind == 6 {
                        (ax / v, ax % v)
                    } else {
                        let (a, b) = (ax as u16 as i16 as i32, v as u8 as i8 as i32);
                        ((a / b) as u32, (a % b) as u32)
                    };
                    self.set_reg(EAX, 1, q);
                    self.set_reg(4, 1, r);
                } else if kind == 6 {
                    let n = (self.reg(EDX, sz) as u64) << (sz * 8) | self.reg(EAX, sz) as u64;
                    let q = n / v as u64;
                    if q > m as u64 {
                        bail!("x86 divide overflow");
                    }
                    self.set_reg(EAX, sz, q as u32);
                    self.set_reg(EDX, sz, (n % v as u64) as u32);
                } else {
                    let n =
                        ((self.reg(EDX, sz) as u64) << (sz * 8) | self.reg(EAX, sz) as u64) as i64;
                    let n = if sz == 2 { n as i32 as i64 } else { n };
                    let d = sext(v, sz) as i32 as i64;
                    let q = n / d;
                    if q > i32::MAX as i64 || q < i32::MIN as i64 {
                        bail!("x86 divide overflow");
                    }
                    self.set_reg(EAX, sz, q as u32);
                    self.set_reg(EDX, sz, (n % d) as u32);
                }
            }
        }
        Ok(())
    }

    fn two_byte(&mut self) -> Result<()> {
        let op = self.fetch8()?;
        match op {
            0x1f => {
                self.modrm()?;
            }
            0x80..=0x8f => {
                let rel = self.fetch32()?;
                if self.cond(op & 15) {
                    self.eip = self.eip.wrapping_add(rel);
                }
            }
            0x90..=0x9f => {
                let (_, rm) = self.modrm()?;
                let v = self.cond(op & 15) as u32;
                self.set(rm, 1, v)?;
            }
            0xa2 => {
                // No SSE2: the DLL then keeps to its x87 code.
                self.regs[EAX] = 0;
                self.regs[1] = 0;
                self.regs[EDX] = 0;
                self.regs[3] = 0;
            }
            0xaf => {
                let (r, rm) = self.modrm()?;
                let a = sext(self.reg(r, 4), 4) as i32 as i64;
                let b = self.get(rm, 4)? as i32 as i64;
                self.imul_into(r, a, b, 4);
            }
            0xb6 | 0xb7 | 0xbe | 0xbf => {
                let (r, rm) = self.modrm()?;
                let sz = if op & 1 == 0 { 1 } else { 2 };
                let v = self.get(rm, sz)?;
                let v = if op >= 0xbe { sext(v, sz) } else { v };
                self.regs[r] = v;
            }
            _ => bail!("unsupported opcode 0x0f {op:#04x}"),
        }
        Ok(())
    }

    fn x87(&mut self, op: u32) -> Result<()> {
        let (reg, rm) = self.modrm()?;
        match rm {
            Operand::Mem(a) => self.x87_mem(op, reg, a),
            Operand::Reg(i) => self.x87_reg(op, reg, i),
        }
    }

    fn x87_mem(&mut self, op: u32, reg: usize, a: u32) -> Result<()> {
        let f32_at = |m: &Self| -> Result<f64> { Ok(f32::from_bits(m.rd(a, 4)?) as f64) };
        let f64_at = |m: &Self| -> Result<f64> { Ok(f64::from_bits(m.rd64(a)?)) };
        match (op, reg) {
            (0xd8 | 0xdc | 0xda | 0xde, _) => {
                let src = match op {
                    0xd8 => f32_at(self)?,
                    0xdc => f64_at(self)?,
                    0xda => self.rd(a, 4)? as i32 as f64,
                    _ => self.rd(a, 2)? as i16 as f64,
                };
                match reg {
                    2 | 3 => {
                        self.fcompare(self.st(0), src);
                        if reg == 3 {
                            self.fpop();
                        }
                    }
                    _ => {
                        let v = Self::farith(reg, self.st(0), src);
                        self.set_st(0, v);
                    }
                }
            }
            (0xd9, 0) => {
                let v = f32_at(self)?;
                self.fpush(v);
            }
            (0xd9, 2 | 3) => {
                self.wr(a, 4, (self.st(0) as f32).to_bits())?;
                if reg == 3 {
                    self.fpop();
                }
            }
            (0xd9, 5) => self.fcw = self.rd(a, 2)? as u16,
            (0xd9, 7) => self.wr(a, 2, self.fcw as u32)?,
            (0xdb, 0) => {
                let v = self.rd(a, 4)? as i32 as f64;
                self.fpush(v);
            }
            (0xdb, 2 | 3) => {
                let v = self.to_int(self.st(0), 32) as u32;
                self.wr(a, 4, v)?;
                if reg == 3 {
                    self.fpop();
                }
            }
            (0xdd, 0) => {
                let v = f64_at(self)?;
                self.fpush(v);
            }
            (0xdd, 2 | 3) => {
                self.wr64(a, self.st(0).to_bits())?;
                if reg == 3 {
                    self.fpop();
                }
            }
            (0xdd, 7) => self.wr(a, 2, self.status_word())?,
            (0xdf, 0) => {
                let v = self.rd(a, 2)? as i16 as f64;
                self.fpush(v);
            }
            (0xdf, 2 | 3) => {
                let v = self.to_int(self.st(0), 16) as u32;
                self.wr(a, 2, v)?;
                if reg == 3 {
                    self.fpop();
                }
            }
            (0xdf, 5) => {
                let v = self.rd64(a)? as i64 as f64;
                self.fpush(v);
            }
            (0xdf, 7) => {
                let v = self.to_int(self.st(0), 64);
                self.wr64(a, v)?;
                self.fpop();
            }
            _ => bail!("unsupported x87 {op:#04x} /{reg} (memory)"),
        }
        Ok(())
    }

    fn x87_reg(&mut self, op: u32, reg: usize, i: usize) -> Result<()> {
        match (op, reg) {
            (0xd8, 2 | 3) | (0xdc, 2 | 3) => {
                self.fcompare(self.st(0), self.st(i));
                if reg == 3 {
                    self.fpop();
                }
            }
            (0xd8, _) => {
                let v = Self::farith(reg, self.st(0), self.st(i));
                self.set_st(0, v);
            }
            // DC and DE: ST(i) = ST(i) op ST(0), with SUB/SUBR and DIV/DIVR
            // encoded the other way round from D8.
            (0xdc | 0xde, _) => {
                if op == 0xde && reg == 3 {
                    if i != 1 {
                        bail!("unsupported x87 de d8+{i}");
                    }
                    // FCOMPP
                    self.fcompare(self.st(0), self.st(1));
                    self.fpop();
                    self.fpop();
                    return Ok(());
                }
                if op == 0xde && reg == 2 {
                    bail!("unsupported x87 de /2");
                }
                let kind = match reg {
                    4 => 5,
                    5 => 4,
                    6 => 7,
                    7 => 6,
                    other => other,
                };
                let v = Self::farith(kind, self.st(i), self.st(0));
                self.set_st(i, v);
                if op == 0xde {
                    self.fpop();
                }
            }
            (0xd9, 0) => {
                let v = self.st(i);
                self.fpush(v);
            }
            (0xd9, 1) => {
                let a = self.st(0);
                let b = self.st(i);
                self.set_st(0, b);
                self.set_st(i, a);
            }
            (0xd9, 2) => {}
            (0xd9, _) => {
                let code = reg * 8 + i;
                let st0 = self.st(0);
                match code {
                    0x20 => self.set_st(0, -st0),
                    0x21 => self.set_st(0, st0.abs()),
                    0x24 => self.fcompare(st0, 0.0),
                    0x28 => self.fpush(1.0),
                    0x29 => self.fpush(std::f64::consts::LOG2_10),
                    0x2a => self.fpush(std::f64::consts::LOG2_E),
                    0x2b => self.fpush(std::f64::consts::PI),
                    0x2c => self.fpush(std::f64::consts::LOG10_2),
                    0x2d => self.fpush(std::f64::consts::LN_2),
                    0x2e => self.fpush(0.0),
                    0x30 => self.set_st(0, st0.exp2() - 1.0),
                    0x31 => {
                        let x = self.fpop();
                        let y = self.st(0);
                        self.set_st(0, y * x.log2());
                    }
                    0x33 => {
                        let x = self.fpop();
                        let y = self.st(0);
                        self.set_st(0, y.atan2(x));
                    }
                    0x3a => self.set_st(0, st0.sqrt()),
                    0x3c => {
                        let v = self.round_int(st0);
                        self.set_st(0, v);
                    }
                    0x3d => {
                        let v = st0 * 2f64.powf(self.st(1).trunc());
                        self.set_st(0, v);
                    }
                    0x3e => {
                        self.c[2] = false;
                        self.set_st(0, st0.sin());
                    }
                    0x3f => {
                        self.c[2] = false;
                        self.set_st(0, st0.cos());
                    }
                    _ => bail!("unsupported x87 d9 {:#04x}", 0xc0 + code),
                }
            }
            (0xda, 5) if i == 1 => {
                self.fcompare(self.st(0), self.st(1));
                self.fpop();
                self.fpop();
            }
            (0xdb, 4) => {
                // FNCLEX / FNINIT
                if i == 3 {
                    self.top = 0;
                    self.fcw = 0x037f;
                }
                self.c = [false; 4];
            }
            (0xdd, 0) => {}
            (0xdd, 2 | 3) => {
                let v = self.st(0);
                self.set_st(i, v);
                if reg == 3 {
                    self.fpop();
                }
            }
            (0xdd, 4 | 5) => {
                self.fcompare(self.st(0), self.st(i));
                if reg == 5 {
                    self.fpop();
                }
            }
            (0xdf, 4) if i == 0 => {
                let sw = self.status_word();
                self.set_reg(EAX, 2, sw);
            }
            _ => bail!("unsupported x87 {op:#04x} /{reg} st({i})"),
        }
        Ok(())
    }
}
