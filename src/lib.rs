use dashmap::DashMap;
use iced_x86::{BlockEncoder, BlockEncoderOptions, Decoder, DecoderOptions, Instruction, InstructionBlock, SpecializedFormatter, SpecializedFormatterTraitOptions, code_asm::*};
use parking_lot::RwLock;
use std::{ffi::CString, mem::zeroed, ptr::null, sync::{Arc, OnceLock}};
#[cfg(target_os = "windows")]
use winapi::{ctypes::c_void, um::{libloaderapi::GetModuleHandleA, memoryapi::{VirtualAlloc, VirtualProtect, VirtualQuery}, processthreadsapi::GetCurrentProcess, winnt::{HANDLE, MEM_COMMIT, MEM_FREE, MEM_RESERVE, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READWRITE}, wow64apiset::IsWow64Process}};

#[macro_export]
macro_rules! assemble_1 {
    // 1) Special case: “nop, $count ; …”
    //    — only matches when the instruction is exactly “nop” and there is a count expression.
    //    It emits `$count` calls to `$obj.nop()`, then recurses.
    ($obj:ident, nop, $count:expr ; $($rest:tt)*) => {{
        for _ in 0..$count {
            $obj.nop().expect("Failed assembling instruction!");
        }
        assemble_1!($obj, $($rest)*);
    }};

    // 2) General case #1: instruction with optional dst and zero or more src,
    //    e.g. “mov rax, rbx; …” or “add rax; …”.
    ($obj:ident, $instr:tt $($dst:expr)? $(, $src:expr)* ; $($rest:tt)* ) => {
        $obj.$instr($($dst)? $(, $src)*).expect("Failed assembling instruction!");
        assemble_1!($obj, $($rest)*)
    };

    // 3) General case #2: size‐annotated ptr form, e.g.
    //    “mov qword ptr [rax], rbx; …”
    ($obj:ident, $instr:tt $size:tt ptr [ $dst:expr ] $(, $src:tt)* ; $($rest:tt)* ) => {
        $obj.$instr(paste::paste!([<$size _ptr>] )($dst) $(, $src)*).expect("Failed assembling instruction!");
        assemble_1!($obj, $($rest)*)
    };

    // 4) General case #3: dst‐then‐size ptr src, e.g.
    //    “mov rax, qword ptr [rbx]; …”
    ($obj:ident, $instr:tt $dst:expr $(, $size:tt ptr [ $src:expr ])? ; $($rest:tt)* ) => {
        $obj.$instr($dst $(, paste::paste!([<$size _ptr>])($src))?).expect("Failed assembling instruction!");
        assemble_1!($obj, $($rest)*)
    };

    // 5) Label definition: “label: …”
    ($obj:ident, $labelname:tt : $($rest:tt)* ) => {
        $obj.set_label(&mut $labelname).expect("Failed assembling instruction!");
        assemble_1!($obj, $($rest)*)
    };

    // 6) Termination (no more instructions)
    ($obj:ident, ) => {};
}

#[macro_export]
macro_rules! assemble {
    ($($tt:tt)*) => {
        std::sync::Arc::new(move |assembler: &mut iced_x86::code_asm::CodeAssembler|  {
            use iced_x86::code_asm::*;
            use crate::assemble_1;
            crate::assemble_1!(assembler,
                $($tt)*
            );
        })
    };
}

const PAGE_SIZE: usize = 0x1000;
const SAFETY: usize = 0x10;

struct MyTraitOptions;
impl SpecializedFormatterTraitOptions for MyTraitOptions {}

#[derive(Clone)]
pub struct HookInfo {
  name: String,
  address: usize,
  typ: HookType,
  assembly: Arc<dyn Fn(&mut CodeAssembler) + Send + Sync + 'static>,
  org_bytes: Vec<u8>,
  org_nops: usize,
  jmp_size: usize,
  jumping_address: usize,
  enabled: bool,
}

impl std::fmt::Debug for HookInfo {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.debug_struct("HookInfo").field("name", &self.name).field("address", &format!("{:016X?}", &self.address)).field("typ", &self.typ).field("assembly", &opcode_display(arch(), self.assembly.as_ref())).finish() }
}

impl Default for HookInfo {
  fn default() -> Self {
    Self {
      name: String::new(),
      address: 0,
      typ: HookType::default(),
      assembly: Arc::new(|_: &mut CodeAssembler| {}),
      org_bytes: Vec::new(),
      org_nops: 0,
      jmp_size: 0,
      jumping_address: 0,
      enabled: true,
    }
  }
}

impl HookInfo {
  pub fn new(name: &str, address: usize, typ: HookType, assembly: Arc<dyn Fn(&mut CodeAssembler) + Send + Sync + 'static>) -> Self { Self { name: name.to_string(), address, typ, assembly, ..Default::default() } }

  pub fn enable(&mut self) {
    let address = self.address;
    let mem_address = self.jumping_address;
    let jmp_size = get_jmp_size(self.address, self.jumping_address);
    if self.org_nops > 0 {
      place_nops(address, self.org_nops, jmp_size);
    }
    let offset = get_jump_offset(address, mem_address) as usize;
    place_jump(address, jmp_size, offset);

    self.enabled = true;
  }

  pub fn disable(&mut self) {
    println!("Address = {:#X?}, {:#X?}", self.address, self.org_bytes);
    place_bytes(self.address, self.org_bytes.clone());

    self.enabled = false;
  }
}

#[derive(Clone, Default, Debug)]
pub struct OwnedMem {
  pub address: usize,
  pub size: usize,
  pub used: usize,
}

impl OwnedMem {
  /// increase the used memory propery
  pub fn inc_used(&mut self, size: usize) -> Result<(), Box<dyn std::error::Error>> {
    if self.used + size < self.size {
      self.used += size;

      Ok(())
    } else {
      Err("The used size has exceeded the available size".into())
    }
  }

  /// ckeck given address is near the owned memory location
  pub fn is_nearby(&self, address: usize) -> bool {
    const RANGE: usize = i32::MAX as usize; // 2 GB
    self.address.abs_diff(address) <= RANGE
  }

  /// check if the there is enough memory
  pub fn is_mem_enough(&self, required_size: usize) -> bool {
    let available = self.size.saturating_sub(self.used + SAFETY);
    required_size <= available
  }

  pub fn check_in_mem(address: usize, required_size: usize, owned_mems: &DashMap<usize, OwnedMem>) -> Option<usize> {
    // Iterate through all entries in the DashMap
    for entry in owned_mems.iter() {
      let (key, value) = entry.pair();
      if value.is_nearby(address) && value.is_mem_enough(required_size) {
        return Some(*key);
      }
    }

    None
  }
}

#[derive(Clone, Debug, Default)]
struct InstructionsInfo {
  pub address: usize,
  pub opcodes: Vec<String>,
  pub instrs: Vec<Instruction>,
  pub bytes: Vec<u8>,
  pub nops: usize,
}

/// Enum to hold the process identifier (either a handle or a PID).
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum ProcessId {
  Windows(*mut std::ffi::c_void), // Process handle for Windows
  Linux(u32),                     // PID for Linux
}

unsafe impl Send for ProcessId {}
unsafe impl Sync for ProcessId {}

impl Default for ProcessId {
  #[cfg(target_os = "windows")]
  fn default() -> Self { ProcessId::Windows(std::ptr::null_mut()) }

  #[cfg(target_os = "linux")]
  fn default() -> Self { ProcessId::Linux(0) }
}

/// # Usage
///
/// [`Patch`]: Does not allocate memory, places the instructions at the address and manges noping extra bytes if needed.
///
/// [`Detour`]: Allocates memeory near the address if possible, adds a jump to the allocated memory, places the instructions within the allocated memory and relocates the original instruction at the end of the added instructions.
///
/// [`DetourNoOrg`]: Allocates memeory near the address if possible, adds a jump to the allocated memory and places the instructions within the allocated memory without relocating the original instruction at the end of the added instructions.
///

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum HookLookup {
  Name(String),
  Address(usize),
  Index(usize),
}

impl Default for HookLookup {
  fn default() -> Self { HookLookup::Index(0) }
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum MemLookup {
  Address(usize),
  Index(usize),
}

impl Default for MemLookup {
  fn default() -> Self { MemLookup::Index(0) }
}

#[derive(PartialEq, Eq, Debug, Clone, Copy, Default)]
pub enum HookType {
  #[default]
  Patch,
  Detour,
  DetourNoOrg,
}

#[derive(Clone, Debug, Default)]
pub struct HookKing {
  // process id - can keep as Arc<RwLock> if you update it
  process: Arc<RwLock<ProcessId>>,

  // OwnedMem indexed by index (usize)
  owned_mems: DashMap<usize, OwnedMem>,
  // Map address -> index of OwnedMem
  owned_mems_address: DashMap<usize, usize>,

  // Hooks indexed by index (usize)
  hooks: DashMap<usize, HookInfo>,
  // Map name -> index
  hooks_name: DashMap<String, usize>,
  // Map address -> index
  hooks_address: DashMap<usize, usize>,
}

impl HookKing {
  pub fn new(process: Option<ProcessId>) -> Self {
    let process = if let Some(proc) = process { proc } else { Self::current_process() };

    Self { process: Arc::new(RwLock::new(process)), ..Default::default() }
  }

  fn current_process() -> ProcessId {
    #[cfg(target_os = "windows")]
    {
      ProcessId::Windows(unsafe { GetCurrentProcess() as _ })
    }

    #[cfg(target_os = "linux")]
    {
      let pid = process::id();
      ProcessId::Linux(pid)
    }
  }

  pub fn change_process(&mut self, process: Option<ProcessId>) { if process.is_some() { self.process = Arc::new(RwLock::new(process.unwrap())) } else { self.process = Arc::new(RwLock::new(Self::current_process())) } }

  pub fn get_hook(&self, lookup: HookLookup) -> Option<HookInfo> {
    match lookup {
      HookLookup::Name(name) => self.hooks_name.get_mut(&name).and_then(|idx| self.hooks.get_mut(idx.value()).map(|h| h.clone())),
      HookLookup::Address(address) => self.hooks_address.get_mut(&address).and_then(|idx| self.hooks.get_mut(idx.value()).map(|h| h.clone())),
      HookLookup::Index(index) => self.hooks.get_mut(&index).map(|h| h.clone()),
    }
  }

  pub fn get_mem(&self, lookup: MemLookup) -> Option<OwnedMem> {
    match lookup {
      MemLookup::Address(address) => self.owned_mems_address.get_mut(&address).and_then(|idx| self.owned_mems.get_mut(idx.value()).map(|h| h.clone())),
      MemLookup::Index(index) => self.owned_mems.get_mut(&index).map(|h| h.clone()),
    }
  }

  // pub fn get_hook_by_name(&self, name: &str) -> Option<HookInfo> { self.hooks_name.get_mut(name).and_then(|idx| self.hooks.get_mut(idx.value()).map(|h| h.clone())) }

  // pub fn get_hook_by_address(&self, address: usize) -> Option<HookInfo> { self.hooks_address.get_mut(&address).and_then(|idx| self.hooks.get_mut(idx.value()).map(|h| h.clone())) }

  // pub fn get_hook_by_index(&self, index: usize) -> Option<HookInfo> { self.hooks.get_mut(&index).map(|h| h.clone()) }

  // pub fn get_mem_by_index(&self, index: usize) -> Option<OwnedMem> { self.owned_mems.get_mut(&index).map(|h| h.clone()) }

  // pub fn get_mem_by_address(&self, address: usize) -> Option<OwnedMem> { self.owned_mems_address.get_mut(&address).and_then(|idx| self.owned_mems.get_mut(idx.value()).map(|h| h.clone())) }

  fn add_hook(&mut self, hook: HookInfo) {
    self.hooks.insert(self.hooks.len(), hook.clone());
    self.hooks_name.insert(hook.name.clone(), self.hooks_name.len());
    self.hooks_address.insert(hook.address, self.hooks_address.len());
  }

  fn add_owned_mem(&mut self, owned_mem: OwnedMem) {
    self.owned_mems.insert(self.owned_mems.len(), owned_mem.clone());
    self.owned_mems_address.insert(owned_mem.address, self.owned_mems.len());
  }

  fn update_hook(&mut self, hook: HookInfo, index: usize) -> Result<(), Box<dyn std::error::Error>> {
    if self.hooks.contains_key(&index) {
      self.hooks.entry(index).and_modify(|hk| {
        hk.name = hook.name;
        hk.address = hook.address;
        hk.typ = hook.typ;
        hk.assembly = hook.assembly;
      });

      Ok(())
    } else {
      Err("Failed to update hook, incorrect index".into())
    }
  }

  fn update_owned_mem(&mut self, owned_mem: OwnedMem, index: usize) -> Result<(), Box<dyn std::error::Error>> {
    if self.owned_mems.contains_key(&index) {
      self.owned_mems.entry(index).and_modify(|mem| {
        mem.address = owned_mem.address;
        mem.size = owned_mem.size;
        mem.used = owned_mem.used;
      });

      Ok(())
    } else {
      Err("Failed to update owned memory, incorrect index".into())
    }
  }

  /// # Warning
  ///
  /// Not giving a name or providing an invalid address will result in panicing
  ///
  /// Give the hook a proper name. Name must be no less than 5 characters!
  ///
  /// # Example
  /// ```
  ///let module_base: usize = 0x40000000;
  ///asm_hook(
  /// "infinite_money",
  ///  module_base + 0x428A43,
  ///  HookType::AllocWithOrg,
  ///  assemble!(
  ///    push rax;
  ///    mov rax,rcx;
  ///    mov byte ptr [rax+50],2;
  ///    mov word ptr [rax+50*4],2;
  ///    mov dword ptr [rax+rax*8+50],2;
  ///    mov qword ptr [rax],2;
  ///    label:
  ///    mov rsp,rsi;
  ///    mov r12d,4;
  ///    mov r12w,4;
  ///    mov r12b,4;
  ///    mov r12b,4;
  ///    jmp label;
  ///    movups xmm1,xmm0;
  ///    sub rsp,100;
  ///    call rax;
  ///    call module_base as u64;
  ///    xor al,bl;
  ///    xorps xmm0,xmm10;
  ///    add rsp,100;
  ///    pop rax;
  ///    call module_base as u64 + 0x428C16;
  ///    jmp module_base as u64 + 0x428AAC;
  ///    ret;
  ///    ret;
  ///    ret_1 1;
  ///    mpsadbw xmm0, xmm1, 2;
  ///    vsqrtps ymm10, dword ptr [rcx];
  ///    label_return:
  ///    ret;
  ///  ),
  ///);
  /// ```

  // #[cfg(feature = "parking-lot")]
  // #[cfg(feature = "std-lock")]
  // pub unsafe fn asm_hook(&self, hook_info: HookInfo, owned_mems: Option<Arc<RwLock<Vec<OwnedMem>>>>) -> Result<(), Box<dyn std::error::Error>> {
  pub unsafe fn hook(&mut self, hook_info: HookInfo) -> Result<(), Box<dyn std::error::Error>> {
    let mut hook_info = hook_info;
    let name = hook_info.name.clone();
    let address = hook_info.address;
    let hook_type = hook_info.typ;
    let assembly = hook_info.assembly.as_ref();
    let architecture = arch();
    let module_base = module_base(None);

    if name.len() < 5 {
      panic!("Give the hook a proper name. Name must be no less than 5 characters!")
    }

    let mut mbi = unsafe { std::mem::zeroed::<MEMORY_BASIC_INFORMATION>() };
    if unsafe { VirtualQuery(address as *const _, &mut mbi as *mut _, std::mem::size_of::<MEMORY_BASIC_INFORMATION>()) } == 0 || mbi.State == 0 {
      panic!("Not a valid address! {address:#X}");
    }

    if hook_type == HookType::Patch {
      unprotect(address);

      let bytes = assemble(address, architecture, assembly)?;
      let mut instr_info = instruction_info(address, bytes.len(), architecture);
      get_required_nops(&mut instr_info, 0);

      place_nops(address, instr_info.nops - bytes.len(), bytes.len());
      place_bytes(address, bytes);

      return Ok(());
    }

    let required_size = estimate_required_size(address, architecture, &assembly)?;
    let mem_index = OwnedMem::check_in_mem(address, required_size, &self.owned_mems);

    let mut mem = if let Some(index) = mem_index { self.get_mem(MemLookup::Index(index)).unwrap() } else { alloc(module_base)? };

    let bytes = assemble(address, architecture, assembly)?;
    insert_bytes(address, architecture, &mut mem, &mut hook_info, bytes.clone())?;

    println!("org_instr_info.bytes = {:#X?}", hook_info.org_bytes);
    println!("hook_info.jumping_address = {:#X}", hook_info.jumping_address);

    if let Some(index) = mem_index {
      self.update_owned_mem(mem.clone(), index)?;
    } else {
      self.add_owned_mem(mem.clone());
    }

    self.add_hook(hook_info.clone());

    // println!("hook_info {:X?}", hook_info);
    // println!("Allocated {:X?}", self.owned_mems);

    Ok(())
  }
}

fn process() -> HANDLE { unsafe { GetCurrentProcess() } }

fn module_base(module: Option<&str>) -> usize {
  let module_name = match module {
    Some(name) => {
      // Convert the Rust string to a null-terminated C string
      match CString::new(name) {
        Ok(c_str) => c_str.as_ptr(),
        Err(_) => null(), // In case of error, pass NULL
      }
    }
    None => null(), // NULL means get the handle of the calling process
  };

  // Call the Windows API function
  let handle = unsafe { GetModuleHandleA(module_name) };

  // Convert the handle to a usize
  handle as usize
}

fn alloc(address: usize) -> Result<OwnedMem, Box<dyn std::error::Error>> {
  let mut memory_info: MEMORY_BASIC_INFORMATION = unsafe { zeroed() };
  let mut current_address = address;
  let mut attempts = 0;
  let mut new_mem = OwnedMem::default();

  // Use only the attempt count in the loop condition
  while attempts < 100000 {
    // Query current memory region
    let mem_query = unsafe { VirtualQuery(current_address as *mut c_void, &mut memory_info as *mut MEMORY_BASIC_INFORMATION, size_of::<MEMORY_BASIC_INFORMATION>()) };

    // Only process if query succeeded
    if mem_query > 0 {
      // Check if region is FREE and large enough
      if memory_info.State == MEM_FREE && memory_info.RegionSize >= PAGE_SIZE {
        // Attempt allocation
        let alloc_mem = unsafe { VirtualAlloc(current_address as *mut c_void, PAGE_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE) };

        if !alloc_mem.is_null() {
          // Success: populate owned_mem and break
          let size = get_region_size(alloc_mem as usize).unwrap();
          new_mem = OwnedMem { address: alloc_mem as usize, size, ..Default::default() };

          break;
        }
      }

      // Move to NEXT region (backwards traversal)
      current_address = memory_info.BaseAddress as usize - memory_info.RegionSize;
    } else {
      // Query failed: move ahead by a safe increment
      current_address += PAGE_SIZE;
    }

    attempts += 1; // Count every iteration
    // println!("attempts = {}", attempts);
  }

  Ok(new_mem)
}

fn estimate_required_size(address: usize, architecture: u32, assembly: impl Fn(&mut CodeAssembler)) -> Result<usize, Box<dyn std::error::Error>> {
  let bytes = assemble(address, architecture, assembly)?.len();
  Ok(bytes * 2)
}

fn unprotect(address: usize) {
  let protection_size = 100;
  let mut old_protection = 0;
  let old_protection: *mut u32 = &mut old_protection;
  unsafe { VirtualProtect(address as _, protection_size, PAGE_EXECUTE_READWRITE, old_protection) };
}

fn assemble(address: usize, architecture: u32, assembly: impl Fn(&mut CodeAssembler)) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
  let mut assembler = CodeAssembler::new(architecture).expect("Failed at constructing CodeAssembler");
  assembly(&mut assembler);
  // let assembled_bytes = assembler.assemble(address as u64).expect("Failed at assembling CodeAssembler");
  // assembled_bytes

  let instructions = assembler.instructions();
  let block = InstructionBlock::new(instructions, address as u64);

  let result = BlockEncoder::encode(architecture, block, BlockEncoderOptions::DONT_FIX_BRANCHES).expect("Failed at encoding");
  Ok(result.code_buffer)
}

/// returns the size of the original instruction(s) and required nopes if needed
fn instruction_info(address: usize, length: usize, architecture: u32) -> InstructionsInfo {
  let bytes = unsafe { std::slice::from_raw_parts_mut(address as *mut u8, 100) };

  let mut instrs_size = 0;
  let mut opcodes = Vec::new();

  let mut decoder = Decoder::with_ip(architecture, &bytes, address as u64, DecoderOptions::NONE);
  let mut formatter = SpecializedFormatter::<MyTraitOptions>::new();
  let mut formated_instr = String::new();
  let mut instr = Instruction::default();
  let mut instrs = Vec::new();
  while decoder.can_decode() {
    decoder.decode_out(&mut instr);

    formated_instr.clear();
    formatter.format(&instr, &mut formated_instr);
    opcodes.push(formated_instr.clone());

    instrs_size += instr.len();
    instrs.push(instr);

    if instrs_size >= length {
      break;
    }
  }

  let block = InstructionBlock::new(&instrs, address as u64 + bytes.len() as u64);
  let instrs_bytes = BlockEncoder::encode(decoder.bitness(), block, BlockEncoderOptions::NONE).expect("Failed at encoding BlockEncoder").code_buffer;

  return InstructionsInfo { address, opcodes, instrs, bytes: instrs_bytes, nops: 0 };
}

fn opcode_display(architecture: u32, assembly: impl Fn(&mut CodeAssembler)) -> Vec<String> {
  let mut assembler = CodeAssembler::new(architecture).unwrap();

  // Apply the assembly function
  assembly(&mut assembler);

  // Constructing formmatter
  let mut formatter = SpecializedFormatter::<MyTraitOptions>::new();
  let mut formated_instr = String::new();

  // Convert to string
  let mut opcodes = Vec::new();
  for instr in assembler.instructions() {
    formated_instr.clear();
    formatter.format(&instr, &mut formated_instr);
    opcodes.push(formated_instr.clone());
  }
  opcodes
}

fn place_bytes(address: usize, bytes: Vec<u8>) {
  let address = address as *mut u8;
  let address = unsafe { std::slice::from_raw_parts_mut(address, bytes.len()) };

  for index in 0..bytes.len() {
    (*address)[index] = bytes[index];
  }
}

/// offset is the length of the bytes placed before it
fn place_nops(address: usize, length: usize, offset: usize) {
  let address = address as *mut u8;
  let address = unsafe { std::slice::from_raw_parts_mut(address, length + offset) };

  if length != 0 {
    for i in 0..length {
      (*address)[i + offset] = 0x90;
    }
  }
}

/// [offset]: is the offset or address to jump to. Address is needed in case the jump size is 14.
fn place_jump(address: usize, jmp_size: usize, offset: usize) {
  let address = address as *mut u8;
  let address = unsafe { std::slice::from_raw_parts_mut(address, 50) };

  if jmp_size == 5 {
    (*address)[0] = 0xE9;
    let mut v = offset;
    for p in &mut (*address)[1..5] {
      *p = v as u8;
      v >>= 8;
    }
  } else if jmp_size == 14 {
    let prefix = [0xFF, 0x25, 0x00, 0x00, 0x00, 0x00];
    address[..prefix.len()].copy_from_slice(&prefix);
    let mut v = offset;
    for p in &mut address[6..14] {
      *p = v as u8;
      v >>= 8;
    }
  }
}

fn get_required_nops(instr_info: &mut InstructionsInfo, jmp_size: usize) {
  let mut length = 0;
  for instr in instr_info.instrs.iter() {
    length += instr.len();
    if length >= jmp_size {
      break;
    }
  }

  instr_info.nops = length.abs_diff(jmp_size);
  // instr_info.nops
}

fn get_ret_jump(src_address: usize, dst_address: usize, jmp_size: usize, hook_type: HookType, instr_info: &mut InstructionsInfo, bytes_len: usize) -> usize {
  get_required_nops(instr_info, jmp_size);
  let rva_dst;
  let mut rva_ret_jmp = src_address;

  if jmp_size == 5 {
    if src_address < (dst_address as usize) {
      rva_dst = dst_address as usize - src_address - jmp_size;
      rva_ret_jmp = rva_dst + instr_info.bytes.len() + jmp_size + instr_info.nops + 1;
      if hook_type == HookType::DetourNoOrg {
        rva_ret_jmp = rva_dst + jmp_size + instr_info.nops + 1;
      }
    } else {
      rva_dst = src_address - dst_address as usize + jmp_size - 1;
      rva_ret_jmp = rva_dst - bytes_len - instr_info.bytes.len() - jmp_size + instr_info.nops + 1;
      if hook_type == HookType::DetourNoOrg {
        rva_ret_jmp = rva_dst - bytes_len - jmp_size + instr_info.nops + 1;
      }
    }
  } else if jmp_size == 14 {
    rva_ret_jmp = src_address + jmp_size + instr_info.nops;
  }
  rva_ret_jmp
}

fn get_jmp_size(src_address: usize, dst_address: usize) -> usize {
  let distance = dst_address.abs_diff(src_address);
  if distance > i32::MAX as usize { 14 } else { 5 }
}

fn get_jump_offset(src_address: usize, dst_address: usize) -> isize {
  let jmp_size = get_jmp_size(src_address, dst_address);
  let src_address = src_address as isize;
  let dst_address = dst_address as isize;

  if jmp_size == 14 {
    return dst_address;
  }

  dst_address - (src_address + jmp_size as isize)
}

static ARCHITECTURE: OnceLock<u32> = OnceLock::new();

fn arch() -> u32 { *ARCHITECTURE.get_or_init(|| get_architecture(process()).unwrap_or(64)) }

fn get_architecture(handle: winapi::um::winnt::HANDLE) -> Result<u32, Box<dyn std::error::Error>> {
  let mut is_wow64 = 0;
  let result = unsafe { IsWow64Process(handle, &mut is_wow64) };
  if result == 0 {
    return Err("Couldn't get the architecture".into());
  }
  Ok(if is_wow64 == 0 { 64 } else { 32 })
}

/// src_address: the address to insert the bytes at
///
/// hook_address: the hooked address
fn insert_bytes(src_address: usize, architecture: u32, owned_mem: &mut OwnedMem, hook_info: &mut HookInfo, bytes: Vec<u8>) -> Result<(InstructionsInfo, usize), Box<dyn std::error::Error>> {
  let dst_address = owned_mem.address + owned_mem.used;

  let jmp_size = get_jmp_size(dst_address, src_address);

  let rva_mem = get_jump_offset(src_address, dst_address);
  // println!("rva_mem = {:#X?}", rva_mem);

  unprotect(src_address);

  // getting the instructions length covered by the jump
  let mut org_instr_info = instruction_info(src_address, jmp_size, architecture);
  get_required_nops(&mut org_instr_info, jmp_size);

  // org_instr_info.nops = required_nops;

  // println!("ori_instr_info = {:X?}", ori_instr_info);

  let mut ret_address_jump = dst_address as usize + bytes.len() + org_instr_info.bytes.len();

  if hook_info.typ == HookType::DetourNoOrg {
    ret_address_jump = dst_address as usize + bytes.len();
  }

  if dst_address != 0 {
    let rva_ret_jmp = get_ret_jump(src_address, dst_address, jmp_size, hook_info.typ.clone(), &mut org_instr_info, bytes.len());

    // placing the hook jump
    place_jump(src_address, jmp_size, rva_mem as usize);

    // placing nops if needed at the hooked address
    place_nops(src_address, org_instr_info.nops, jmp_size);

    // placing the injected bytes
    place_bytes(dst_address, bytes.clone());

    if hook_info.typ == HookType::Detour {
      place_bytes(dst_address + bytes.len(), org_instr_info.bytes.clone());
      owned_mem.inc_used(org_instr_info.bytes.len()).unwrap();
    }

    // placing the return jump
    place_jump(ret_address_jump, jmp_size, rva_ret_jmp);

    owned_mem.inc_used(bytes.len()).unwrap();
    owned_mem.inc_used(jmp_size).unwrap();

    // println!("OwnedMem = {:#X?}", owned_mem);
  }

  hook_info.jumping_address = dst_address;
  hook_info.org_bytes = org_instr_info.bytes.clone();
  hook_info.org_nops = org_instr_info.nops;
  hook_info.jmp_size = jmp_size;

  Ok((org_instr_info, dst_address))
}

fn get_region_size(address: usize) -> Result<usize, Box<dyn std::error::Error>> {
  let mut mem_info = unsafe { zeroed() };
  let result = unsafe { VirtualQuery(address as *mut _, &mut mem_info, std::mem::size_of::<MEMORY_BASIC_INFORMATION>()) };

  if result > 0 { Ok(mem_info.RegionSize) } else { Err("Failed to retrieve region size".into()) }
}
