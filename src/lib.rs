use iced_x86::{BlockEncoder, BlockEncoderOptions, Decoder, DecoderOptions, Instruction, InstructionBlock, SpecializedFormatter, SpecializedFormatterTraitOptions, code_asm::*};
use parking_lot::RwLock;
use std::{collections::HashMap, ffi::CString, mem::zeroed, ptr::null, sync::{Arc, OnceLock}};
use winapi::{ctypes::c_void, shared::ntstatus::STATUS_RETRY, um::{libloaderapi::GetModuleHandleA, memoryapi::{VirtualAlloc, VirtualProtect, VirtualQuery}, processthreadsapi::GetCurrentProcess, winnt::{HANDLE, MEM_COMMIT, MEM_FREE, MEM_RESERVE, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READWRITE}, wow64apiset::IsWow64Process}};

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
  pub name: String,
  pub address: usize,
  pub typ: HookType,
  pub assembly: Arc<dyn Fn(&mut CodeAssembler) + Send + Sync + 'static>,
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
    }
  }
}

#[derive(Clone, Default, Debug)]
pub struct OwnedMem {
  // pub hooks: Vec<HookInfo>,
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

  pub fn check_in_vec(address: usize, required_size: usize, owned_mems: Arc<RwLock<Vec<Arc<RwLock<OwnedMem>>>>>) -> Option<usize> {
    for (index, item) in owned_mems.read().iter().enumerate() {
      if item.read().is_nearby(address) && item.read().is_mem_enough(required_size) {
        return Some(index);
      }
    }
    return None;
  }
}

/// # Usage
///
/// [`NoAlloc`]: Does not allocate memory, places the instructions at the address and manges noping extra bytes if needed.
///
/// [`AllocNoOrg`]: Allocates memeory near the address if possible, adds a jump to the allocated memory and places the instructions within the allocated memory without relocating the original instruction at the end of the added instructions.
///
/// [`AllocWithOrg`]: Allocates memeory near the address if possible, adds a jump to the allocated memory, places the instructions within the allocated memory and relocates the original instruction at the end of the added instructions.
///

#[derive(PartialEq, Eq, Debug, Clone, Copy, Default)]
pub enum HookType {
  #[default]
  NoAlloc,
  AllocNoOrg,
  AllocWithOrg,
}

#[derive(Clone, Debug)]
pub struct HookKing {
  process: Arc<RwLock<*mut std::ffi::c_void>>,

  owned_mems: Arc<RwLock<Vec<Arc<RwLock<OwnedMem>>>>>,
  owned_mems_address: Arc<RwLock<HashMap<usize, Arc<RwLock<OwnedMem>>>>>,

  hooks: Arc<RwLock<Vec<Arc<RwLock<HookInfo>>>>>,
  hooks_name: Arc<RwLock<HashMap<String, Arc<RwLock<HookInfo>>>>>,
  hooks_index: Arc<RwLock<HashMap<usize, Arc<RwLock<HookInfo>>>>>,
  hooks_address: Arc<RwLock<HashMap<usize, Arc<RwLock<HookInfo>>>>>,
}

impl Default for HookKing {
  fn default() -> Self {
    return Self {
      process: Arc::new(RwLock::new(std::ptr::null_mut())),
      owned_mems: Arc::new(RwLock::new(Vec::new())),
      owned_mems_address: Arc::new(RwLock::new(HashMap::new())),
      hooks: Arc::new(RwLock::new(Vec::new())),
      hooks_name: Arc::new(RwLock::new(HashMap::new())),
      hooks_index: Arc::new(RwLock::new(HashMap::new())),
      hooks_address: Arc::new(RwLock::new(HashMap::new())),
    };
  }
}

impl HookKing {
  pub fn new(process: *mut std::ffi::c_void) -> Self { Self { process: Arc::new(RwLock::new(process)), ..Default::default() } }

  pub fn change_process(&mut self, process: Option<*mut std::ffi::c_void>) { if process.is_some() { self.process = Arc::new(RwLock::new(process.unwrap())) } else { self.process = Arc::new(RwLock::new(unsafe { GetCurrentProcess() as _ })) } }

  pub fn get_hook_by_name(&self, name: &str) -> Option<Arc<RwLock<HookInfo>>> { self.hooks_name.read().get(name).cloned() }

  pub fn get_hook_by_index(&self, index: usize) -> Option<Arc<RwLock<HookInfo>>> { self.hooks_index.read().get(&index).cloned() }

  pub fn get_hook_by_address(&self, address: usize) -> Option<Arc<RwLock<HookInfo>>> { self.hooks_address.read().get(&address).cloned() }

  pub fn get_owned_mem_by_address(&self, address: usize) -> Option<Arc<RwLock<OwnedMem>>> { self.owned_mems_address.read().get(&address).cloned() }

  pub fn add_hook(&mut self, hook: HookInfo) {
    let arw = Arc::new(RwLock::new(hook));
    let index = self.hooks.read().len(); // current position will be the index

    self.hooks.write().push(arw.clone());
    self.hooks_name.write().insert(arw.read().name.clone(), arw.clone());
    self.hooks_index.write().insert(index, arw.clone());
    self.hooks_address.write().insert(arw.clone().read().address, arw);
  }

  pub fn add_owned_mem(&mut self, owned_mem: OwnedMem) {
    let arw = Arc::new(RwLock::new(owned_mem));

    self.owned_mems.write().push(arw.clone());
    self.owned_mems_address.write().insert(arw.clone().read().address, arw);
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
  pub unsafe fn asm_hook(&mut self, hook_info: HookInfo) -> Result<(), Box<dyn std::error::Error>> {
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

    if hook_type == HookType::NoAlloc {
      unprotect(address);

      let bytes = assemble(address, architecture, assembly).unwrap();
      let instr_info = instruction_info(address, bytes.len(), architecture);
      let required_nops = get_required_nops(instr_info.clone(), 0);

      place_nops(address, required_nops - bytes.len(), bytes.len());
      place_bytes(address, bytes);

      return Ok(());
    }

    let required_size = estimate_required_size(address, architecture, &assembly)?;
    let mem_index = OwnedMem::check_in_vec(address, required_size, self.owned_mems.clone());

    // println!("{:X?}", owned_mems.clone().unwrap().read());

    if let Some(mem_index) = mem_index {
      let mem = self.owned_mems.read()[mem_index].clone();
      let bytes = assemble(address, architecture, assembly)?;
      insert_bytes(address, architecture, mem.clone(), hook_type, bytes);

      // println!("hook_info {:X?}", hook_info);
      owned_mem.hooks.push(hook_info.clone());
      owned_mems.clone().write()[mem_index] = owned_mem.clone();
      // println!("{:X?}", owned_mems.clone().unwrap().read());
      // println!("Appended {:X?}", owned_mem);
    } else {
      let mem = alloc(module_base)?;
      let bytes = assemble(mem.address, architecture, assembly)?;
      let mut owned_mem = insert_bytes(address, architecture, mem.clone(), hook_type, bytes);

      // println!("hook_info {:X?}", hook_info);
      owned_mem.hooks.push(hook_info.clone());
      owned_mems.write().push(owned_mem.clone());
      // println!("{:X?}", owned_mems.clone().unwrap().read());
      // println!("Allocated {:X?}", owned_mem);
    }

    Ok(())
  }
}

fn process() -> HANDLE { unsafe { GetCurrentProcess() } }

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
          // if owned_mems.is_some() {
          new_mem = OwnedMem { address: alloc_mem as usize, size, ..Default::default() };
          //   owned_mems.unwrap().write().push(new_mem.clone());
          // }
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

#[derive(Clone, Debug, Default)]
struct InstructionsInfo {
  pub opcodes: Vec<String>,
  pub instrs: Vec<Instruction>,
  pub bytes: Vec<u8>,
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

  return InstructionsInfo { opcodes, instrs, bytes: instrs_bytes };
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

fn place_jump(address: usize, jump_size: usize, relative_offset: usize) {
  let address = address as *mut u8;
  let address = unsafe { std::slice::from_raw_parts_mut(address, 50) };

  if jump_size == 5 {
    (*address)[0] = 0xE9;
    let mut v = relative_offset;
    for p in &mut (*address)[1..5] {
      *p = v as u8;
      v >>= 8;
    }
  } else if jump_size == 14 {
    let prefix = [0xFF, 0x25, 0x00, 0x00, 0x00, 0x00];
    address[..prefix.len()].copy_from_slice(&prefix);
    let mut v = relative_offset;
    for p in &mut address[6..14] {
      *p = v as u8;
      v >>= 8;
    }
  }
}

fn get_required_nops(instr_info: InstructionsInfo, jump_size: usize) -> usize {
  let mut length = 0;
  for instr in instr_info.instrs {
    length += instr.len();
    if length >= jump_size {
      break;
    }
  }

  length.abs_diff(jump_size)
}

fn get_ret_jump(src_address: usize, dst_address: usize, jump_size: usize, hook_type: HookType, instr_info: InstructionsInfo, bytes_len: usize) -> usize {
  let required_nops = get_required_nops(instr_info.clone(), jump_size);
  let rva_dst;
  let mut rva_ret_jmp = src_address;

  if jump_size == 5 {
    if src_address < (dst_address as usize) {
      rva_dst = dst_address as usize - src_address - jump_size;
      rva_ret_jmp = rva_dst + instr_info.bytes.len() + jump_size + required_nops + 1;
      if hook_type == HookType::AllocNoOrg {
        rva_ret_jmp = rva_dst + jump_size + required_nops + 1;
      }
    } else {
      rva_dst = src_address - dst_address as usize + jump_size - 1;
      rva_ret_jmp = rva_dst - bytes_len - instr_info.bytes.len() - jump_size + required_nops + 1;
      if hook_type == HookType::AllocNoOrg {
        rva_ret_jmp = rva_dst - bytes_len - jump_size + required_nops + 1;
      }
    }
  } else if jump_size == 14 {
    rva_ret_jmp = src_address + jump_size + required_nops;
  }
  rva_ret_jmp
}

fn get_jump_size(src_address: usize, dst_address: usize) -> usize {
  let distance = dst_address.abs_diff(src_address);
  if distance > i32::MAX as usize { 14 } else { 5 }
}

fn get_jump_offset(src_address: usize, dst_address: usize) -> isize {
  let jump_size = get_jump_size(src_address, dst_address);
  let src_address = src_address as isize;
  let dst_address = dst_address as isize;

  if jump_size == 14 {
    return dst_address;
  }

  dst_address - (src_address + jump_size as isize)
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

/// ins_ddress: the address to insert the bytes at
///
/// hook_address: the hooked address
fn insert_bytes(src_address: usize, architecture: u32, owned_mem: Arc<RwLock<OwnedMem>>, hook_type: HookType, bytes: Vec<u8>) {
  let dst_address = owned_mem.read().address + owned_mem.read().used;

  let jump_size = get_jump_size(dst_address, src_address);

  let rva_mem = get_jump_offset(src_address, dst_address);
  // println!("rva_mem = {:#X?}", rva_mem);

  unprotect(src_address);

  // getting the instructions length covered by the jump
  let ori_instr_info = instruction_info(src_address, jump_size, architecture);
  let required_nops = get_required_nops(ori_instr_info.clone(), jump_size);

  // println!("ori_instr_info = {:X?}", ori_instr_info);

  let mut ret_address_jump = dst_address as usize + bytes.len() + ori_instr_info.bytes.len();

  if hook_type == HookType::AllocNoOrg {
    ret_address_jump = dst_address as usize + bytes.len();
  }

  if dst_address != 0 {
    let rva_ret_jmp = get_ret_jump(src_address, dst_address, jump_size, hook_type.clone(), ori_instr_info.clone(), bytes.len());

    // placing the hook jump
    place_jump(src_address, jump_size, rva_mem as usize);

    // placing nops if needed at the hooked address
    place_nops(src_address, required_nops, jump_size);

    // placing the injected bytes
    place_bytes(dst_address, bytes.clone());

    if hook_type == HookType::AllocWithOrg {
      place_bytes(dst_address + bytes.len(), ori_instr_info.bytes.clone());
      owned_mem.write().inc_used(ori_instr_info.bytes.len()).unwrap();
    }

    // placing the return jump
    place_jump(ret_address_jump, jump_size, rva_ret_jmp);

    owned_mem.write().inc_used(bytes.len()).unwrap();
    owned_mem.write().inc_used(jump_size).unwrap();

    // println!("OwnedMem = {:#X?}", owned_mem);
  }
}

fn get_region_size(address: usize) -> Result<usize, Box<dyn std::error::Error>> {
  let mut mem_info = unsafe { zeroed() };
  let result = unsafe { VirtualQuery(address as *mut _, &mut mem_info, std::mem::size_of::<MEMORY_BASIC_INFORMATION>()) };

  if result > 0 { Ok(mem_info.RegionSize) } else { Err("Failed to retrieve region size".into()) }
}
