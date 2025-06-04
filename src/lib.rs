use iced_x86::{BlockEncoder, BlockEncoderOptions, Decoder, DecoderOptions, Instruction, InstructionBlock, code_asm::*};
use parking_lot::RwLock;
use std::{ffi::CString, mem::zeroed, ptr::{null, null_mut}, sync::{Arc, OnceLock}};
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

#[derive(Clone, Default, Debug)]
pub struct OwnedMem {
  pub hooks: Vec<HookInfo>,
  pub address: usize,
  pub size: usize,
  pub used: usize,
}

impl OwnedMem {
  /// increase the used memory propery
  pub fn inc_used(&mut self, size: usize) -> Result<(), String> {
    if self.used + size < self.size {
      self.used += size;
      Ok(())
    } else {
      Err("The used size has exceeded the available size".to_string())
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

  pub fn check_in_vec(address: usize, required_size: usize, owned_mems: Vec<OwnedMem>) -> Option<usize> {
    for (index, item) in owned_mems.iter().enumerate() {
      if item.is_nearby(address) && item.is_mem_enough(required_size) {
        return Some(index);
      }
    }
    return None;
  }
}

#[derive(Clone)]
pub struct HookInfo {
  pub name: String,
  pub address: usize,
  pub typ: HookType,
  pub assembly: Arc<dyn Fn(&mut CodeAssembler) + Send + Sync + 'static>,
}

impl std::fmt::Debug for HookInfo {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.debug_struct("HookInfo").field("name", &self.name).field("address", &self.address).field("typ", &self.typ).field("assembly", &"").finish() }
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
///    push rbx;
///    push rcx;
///    push rdx;
///    push rsi;
///    push rdi;
///    push rbp;
///    push rsp;
///    push r8;
///    push r9;
///    push r11;
///    push r12;
///    push r13;
///    push r14;
///    push r15;
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
///    pop r15;
///    pop r14;
///    pop r13;
///    pop r12;
///    pop r11;
///    pop r10;
///    pop r9;
///    pop r8;
///    pop rsp;
///    pop rbp;
///    pop rdi;
///    pop rsi;
///    pop rdx;
///    pop rcx;
///    pop rbx;
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

// pub unsafe fn asm_hook(name: &str, address: usize, hook_type: HookType, owned_mems: Option<Arc<Mutex<Vec<OwnedMem>>>>, assembly: impl Fn(&mut CodeAssembler)) {
pub unsafe fn asm_hook(hook_info: HookInfo, owned_mems: Option<Arc<RwLock<Vec<OwnedMem>>>>) {
  let name = hook_info.name.clone();
  let address = hook_info.address;
  let hook_type = hook_info.typ;
  let assembly = hook_info.assembly.as_ref();

  let module_base = module_base(None);

  if name.len() < 5 {
    panic!("Give the hook a proper name. Name must be no less than 5 characters!")
  }

  let mut mbi = unsafe { std::mem::zeroed::<MEMORY_BASIC_INFORMATION>() };
  if unsafe { VirtualQuery(address as *const _, &mut mbi as *mut _, std::mem::size_of::<MEMORY_BASIC_INFORMATION>()) } == 0 || mbi.State == 0 {
    panic!("Not a valid address! {address:#X}");
  }

  let architecture = arch();

  let mut original_instructions_size = 0;
  let protection_size = 100;
  let mut required_nops = 0;
  let original_bytes = address as *mut u8;
  let original_bytes = unsafe { std::slice::from_raw_parts_mut(original_bytes, protection_size) };

  if hook_type == HookType::NoAlloc {
    let mut old_protection = 0;
    let old_protection: *mut u32 = &mut old_protection;
    unsafe { VirtualProtect(address as _, protection_size, PAGE_EXECUTE_READWRITE, old_protection) };

    let mut assembler = CodeAssembler::new(architecture).expect("Failed at constructing CodeAssembler");
    assembly(&mut assembler);
    let assembled_bytes = assembler.assemble(address as u64).expect("Failed at assembling CodeAssembler");
    let bytes = assembled_bytes;

    let mut decoder = Decoder::with_ip(architecture, &*original_bytes, address as u64, DecoderOptions::NONE);
    let mut instruction = Instruction::default();
    let mut original_instructions = Vec::new();
    while decoder.can_decode() {
      decoder.decode_out(&mut instruction);
      original_instructions_size += instruction.len();
      original_instructions.push(instruction);
      if original_instructions_size >= bytes.len() {
        required_nops = (original_instructions_size).abs_diff(bytes.len());
        break;
      }
    }
    if required_nops != 0 {
      for count in 0..required_nops {
        (*original_bytes)[count + bytes.len()] = 0x90;
      }
    }

    for index in 0..bytes.len() {
      (*original_bytes)[index] = bytes[index];
    }
    return;
  }

  if owned_mems.is_some() {
    let vec_mem = owned_mems.clone().unwrap().read().clone();
    let required_size = estimate_required_size(address, architecture, &assembly);
    let mem_index = if owned_mems.is_some() { OwnedMem::check_in_vec(address, required_size, vec_mem.clone()) } else { None };

    // println!("{:X?}", owned_mems.clone().unwrap().read());

    if mem_index.is_some() {
      let mem = vec_mem[mem_index.unwrap()].clone();
      let bytes = assemble(address, architecture, assembly);
      let mut owned_mem = insert_bytes(address, architecture, mem.clone(), hook_type, bytes);

      owned_mem.hooks.push(hook_info.clone());
      owned_mems.clone().unwrap().write()[mem_index.unwrap()] = owned_mem.clone();
      // println!("{:X?}", owned_mems.clone().unwrap().read());
      println!("Appended {:X?}", owned_mem);
    } else {
      let mem = alloc(module_base).unwrap();
      let bytes = assemble(mem.address, architecture, assembly);
      let mut owned_mem = insert_bytes(address, architecture, mem.clone(), hook_type, bytes);

      owned_mem.hooks.push(hook_info.clone());
      owned_mems.unwrap().write().push(owned_mem.clone());
      // println!("{:X?}", owned_mems.clone().unwrap().read());
      println!("Allocated {:X?}", owned_mem);
    }
  } else {
    let mem = alloc(module_base).unwrap();
    let bytes = assemble(mem.address, architecture, assembly);
    insert_bytes(address, architecture, mem.clone(), hook_type, bytes);
    // println!("No owned memory provided {:X?}", owned_mem);
  }
}

fn process() -> HANDLE { unsafe { GetCurrentProcess() } }

fn alloc(address: usize) -> Result<OwnedMem, String> {
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

fn estimate_required_size(address: usize, architecture: u32, assembly: impl Fn(&mut CodeAssembler)) -> usize {
  let bytes = assemble(address, architecture, assembly).len();
  bytes * 2
}

fn unprotect(address: usize) {
  let protection_size = 100;
  let mut old_protection = 0;
  let old_protection: *mut u32 = &mut old_protection;
  unsafe { VirtualProtect(address as _, protection_size, PAGE_EXECUTE_READWRITE, old_protection) };
}

fn assemble(address: usize, architecture: u32, assembly: impl Fn(&mut CodeAssembler)) -> Vec<u8> {
  let mut assembler = CodeAssembler::new(architecture).expect("Failed at constructing CodeAssembler");
  assembly(&mut assembler);
  // let assembled_bytes = assembler.assemble(address as u64).expect("Failed at assembling CodeAssembler");
  // assembled_bytes

  let instructions = assembler.instructions();
  let block = InstructionBlock::new(instructions, address as u64);

  let result = BlockEncoder::encode(architecture, block, BlockEncoderOptions::DONT_FIX_BRANCHES).expect("Failed at encoding");
  result.code_buffer
}

#[derive(Clone, Debug, Default)]
struct InstructionInfo {
  pub bytes: Vec<u8>,
  pub nops: usize,
}

/// returns the size of the original instruction(s) and required nopes if needed
fn instruction_info(address: usize, architecture: u32, bytes: Vec<u8>) -> InstructionInfo {
  let protection_size = 100;

  let mut original_instructions_size = 0;
  let original_bytes = address as *mut u8;
  let original_bytes = unsafe { std::slice::from_raw_parts_mut(original_bytes, protection_size) };

  let mut required_nops = 0;

  let mut decoder = Decoder::with_ip(architecture, &*original_bytes, address as u64, DecoderOptions::NONE);
  let mut instruction = Instruction::default();
  let mut original_instructions = Vec::new();
  while decoder.can_decode() {
    decoder.decode_out(&mut instruction);
    original_instructions_size += instruction.len();
    original_instructions.push(instruction);
    if original_instructions_size >= bytes.len() {
      required_nops = (original_instructions_size).abs_diff(bytes.len());
      break;
    }
  }

  let block = InstructionBlock::new(&original_instructions, address as u64 + bytes.len() as u64);
  let original_instructions_bytes = BlockEncoder::encode(decoder.bitness(), block, BlockEncoderOptions::NONE).expect("Failed at encoding BlockEncoder").code_buffer;

  return InstructionInfo { bytes: original_instructions_bytes, nops: required_nops };
}

fn place_bytes(address: usize, bytes: Vec<u8>) {
  let address = address as *mut u8;
  let address = unsafe { std::slice::from_raw_parts_mut(address, bytes.len()) };

  for index in 0..bytes.len() {
    (*address)[index] = bytes[index];
  }
}

/// offset is the length of the bytes placed before it
fn place_nops(address: usize, required_nops: usize, offset: usize) {
  let address = address as *mut u8;
  let address = unsafe { std::slice::from_raw_parts_mut(address, required_nops + offset) };

  if required_nops != 0 {
    for i in 0..required_nops {
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

fn get_ret_jump(src_address: usize, dst_address: usize, jump_size: usize, hook_type: HookType, instruction_info: InstructionInfo, bytes_len: usize) -> usize {
  let rva_dst;
  let mut rva_ret_jmp = src_address;
  if jump_size == 5 {
    if src_address < (dst_address as usize) {
      rva_dst = dst_address as usize - src_address - jump_size;
      rva_ret_jmp = rva_dst + instruction_info.bytes.len() + jump_size + instruction_info.nops + 1;
      if hook_type == HookType::AllocNoOrg {
        rva_ret_jmp = rva_dst + jump_size + instruction_info.nops + 1;
      }
    } else {
      rva_dst = src_address - dst_address as usize + jump_size - 1;
      rva_ret_jmp = rva_dst - bytes_len - instruction_info.bytes.len() - jump_size + instruction_info.nops + 1;
      if hook_type == HookType::AllocNoOrg {
        rva_ret_jmp = rva_dst - bytes_len - jump_size + instruction_info.nops + 1;
      }
    }
  } else if jump_size == 14 {
    rva_ret_jmp = src_address + jump_size + instruction_info.nops;
  }
  rva_ret_jmp
}

fn get_jump_size(src_address: usize, dst_address: usize) -> usize {
  let distance = dst_address.abs_diff(src_address);
  if distance > i32::MAX as usize {
    14 // long jump
  } else {
    5 // near jump
  }
}

fn get_jump_offset(src_address: usize, dst_address: usize) -> isize {
  let jump_size = get_jump_size(src_address, dst_address);

  if jump_size == 14 {
    return dst_address as isize;
  }

  let offset = if (src_address as isize) < (dst_address as isize) {
    println!("Jumping backward: {:#x}", src_address - dst_address);
    src_address as isize - dst_address as isize
  } else {
    println!("Jumping forward: {:#x}", dst_address - src_address);
    dst_address as isize - src_address as isize - jump_size as isize
  };

  offset as isize
}

static ARCHITECTURE: OnceLock<u32> = OnceLock::new();

fn arch() -> u32 { *ARCHITECTURE.get_or_init(|| get_architecture(process()).unwrap_or(64)) }

fn get_architecture(handle: winapi::um::winnt::HANDLE) -> Result<u32, String> {
  let mut is_wow64 = 0;
  let result = unsafe { IsWow64Process(handle, &mut is_wow64) };
  if result == 0 {
    return Err("Couldn't get the architecture".to_string());
  }
  Ok(if is_wow64 == 0 { 64 } else { 32 })
}

/// ins_ddress: the address to insert the bytes at
///
/// hook_address: the hooked address
fn insert_bytes(src_address: usize, architecture: u32, owned_mem: OwnedMem, hook_type: HookType, bytes: Vec<u8>) -> OwnedMem {
  let mut owned_mem = owned_mem;
  let dst_address = owned_mem.address + owned_mem.used;

  let jump_size = get_jump_size(dst_address, src_address);

  let rva_mem = get_jump_offset(src_address, dst_address);
  // println!("rva_mem = {:#X?}", rva_mem);

  unprotect(src_address);

  let instruction_info = instruction_info(src_address, architecture, bytes.clone());

  let mut ret_address_jump = dst_address as usize + bytes.len() + instruction_info.bytes.len();

  if hook_type == HookType::AllocNoOrg {
    ret_address_jump = dst_address as usize + bytes.len();
  }

  if dst_address != 0 {
    let rva_ret_jmp = get_ret_jump(src_address, dst_address, jump_size, hook_type.clone(), instruction_info.clone(), bytes.len());

    // placing the hook jump
    place_jump(src_address, jump_size, rva_mem as usize);

    // placing nops if needed at the hooked address
    place_nops(src_address, instruction_info.nops, jump_size);

    // placing the injected bytes
    place_bytes(dst_address, bytes.clone());

    if hook_type == HookType::AllocWithOrg {
      place_bytes(dst_address + bytes.len(), instruction_info.bytes.clone());
      owned_mem.inc_used(instruction_info.bytes.len()).unwrap();
    }

    // placing the return jump
    place_jump(ret_address_jump, jump_size, rva_ret_jmp);

    owned_mem.inc_used(bytes.len()).unwrap();
    owned_mem.inc_used(jump_size).unwrap();

    println!("OwnedMem = {:#X?}", owned_mem);
  }

  owned_mem
}

fn get_region_size(address: usize) -> Result<usize, String> {
  let mut mem_info = unsafe { zeroed() };
  let result = unsafe { VirtualQuery(address as *mut _, &mut mem_info, std::mem::size_of::<MEMORY_BASIC_INFORMATION>()) };

  if result > 0 { Ok(mem_info.RegionSize) } else { Err("Failed to retrieve region size".to_string()) }
}

// #[test]
// fn test() {
//   let module_base: usize = 0x40000000;

//   let asm = Box::new(move |a: &mut CodeAssembler| {
//     assemble_1!(a,
//       push rax;
//       push rbx;
//       pop rcx;
//     );
//   });

//   let hook_info = HookInfo {
//     name: "The name".to_string(),
//     address: module_base + 0x428A43,
//     typ: HookType::AllocWithOrg,
//     assembly: asm,
//   };
//   unsafe { asm_hook(hook_info, None) }
// }

#[test]
fn test() {
  let module_base: usize = 0x40000000;

  let asm = assemble!(
    push rax;
    push rbx;
    pop rcx;
    nop, 3;
  );

  let hook_info = HookInfo {
    name: "The name".to_string(),
    address: module_base + 0x428A43,
    typ: HookType::AllocWithOrg,
    assembly: asm,
  };
  unsafe { asm_hook(hook_info, None) }
}

// #[test]
// fn test() {
//   let module_base: usize = 0x40000000;
//   unsafe {
//     asm_hook(
//       "infinite_money",
//       module_base + 0x428A43,
//       HookType::AllocWithOrg,
//       assemble!(

//         push rax;
//         push rbx;
//         push rcx;
//         label2|label3|
//         push rdx;
//         push rsi;
//         push rdi;
//         push rbp;
//         push rsp;
//         push r8;
//         push r9;
//         push r11;
//         push r12;
//         push r13;
//         push r14;
//         push r15;
//         mov rax,rcx;
//         mov byte ptr [rax+50],2;
//         mov word ptr [rax+50*4],2;
//         mov dword ptr [rax+rax*8+50],2;
//         mov qword ptr [rax],2;
//         jmp label2;
//         label:
//         mov rsp,rsi;
//         mov r12d,4;
//         mov r12w,4;
//         mov r12b,4;
//         mov r12b,4;
//         jmp label;
//         movups xmm1,xmm0;
//         sub rsp,100;
//         call rax;
//         call module_base as u64;
//         xor al,bl;
//         xorps xmm0,xmm10;
//         add rsp,100;
//         pop r15;
//         pop r14;
//         pop r13;
//         pop r12;
//         pop r11;
//         pop r10;
//         pop r9;
//         pop r8;
//         pop rsp;
//         pop rbp;
//         pop rdi;
//         pop rsi;
//         pop rdx;
//         pop rcx;
//         pop rbx;
//         pop rax;
//         call module_base as u64 + 0x428C16;
//         jmp module_base as u64 + 0x428AAC;
//         ret;
//         ret;
//         ret_1 1;
//         mpsadbw xmm0, xmm1, 2;
//         vsqrtps ymm10, dword ptr [rcx];
//         label_return:
//         ret;
//       ),
//     );
//   }
// }
