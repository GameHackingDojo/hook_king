use dashmap::DashMap;
use iced_x86::{BlockEncoder, BlockEncoderOptions, Decoder, DecoderOptions, Instruction, InstructionBlock, SpecializedFormatter, SpecializedFormatterTraitOptions, code_asm::*};
#[cfg(target_os = "windows")]
use ntapi::ntmmapi::{MemoryBasicInformation, NtAllocateVirtualMemory, NtQueryVirtualMemory};
use std::{ffi::{CString, OsStr}, os::windows::ffi::OsStrExt, sync::{Arc, OnceLock}};
#[cfg(target_os = "windows")]
use winapi::{shared::ntdef::NT_SUCCESS, um::{handleapi::CloseHandle, memoryapi::{ReadProcessMemory, VirtualProtectEx, VirtualQueryEx, WriteProcessMemory}, processthreadsapi::OpenProcess, tlhelp32::{CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW, PROCESSENTRY32, Process32First, Process32Next, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS}, winnt::PROCESS_ALL_ACCESS}, um::{libloaderapi::GetModuleHandleA, memoryapi::{VirtualProtect, VirtualQuery}, processthreadsapi::GetCurrentProcess, winnt::{MEM_COMMIT, MEM_FREE, MEM_RESERVE, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READWRITE}, wow64apiset::IsWow64Process}};

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
            use hook_king::assemble_1;
            hook_king::assemble_1!(assembler,
                $($tt)*
            );
        })
    };
}

const PAGE_SIZE: usize = 0x1000;
const SAFETY: usize = 0x10;
const DEFAULT_BYTES_TO_READ: usize = 0x32;

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
  jmp_size: JmpSize,
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
      jmp_size: JmpSize::Near,
      jumping_address: 0,
      enabled: true,
    }
  }
}

impl HookInfo {
  ///
  /// Create new hook
  /// It must be provided with a name no shorter than 3 characters, or else it will panic
  /// The hook is enabled by default
  ///
  pub fn new(name: &str, address: usize, typ: HookType, assembly: Arc<dyn Fn(&mut CodeAssembler) + Send + Sync + 'static>) -> Self { Self { name: name.to_string(), address, typ, assembly, ..Default::default() } }

  ///
  /// Enable the hook in case was previously disabled.
  /// A new hook is enabled by default
  ///
  pub fn enable(&mut self, hook_king: &HookKing) {
    let address = self.address;
    let mem_address = self.jumping_address;
    let jmp_size = get_jmp_size(self.address, self.jumping_address);

    if self.org_nops > 0 {
      let nops = hook_king.get_nop_bytes(self.org_nops);
      hook_king.write_bytes(address, nops).unwrap();
    }

    let offset = get_jump_offset(address, mem_address) as usize;
    let jmp_bytes = hook_king.get_jump_bytes(jmp_size, offset);
    hook_king.write_bytes(address, jmp_bytes).unwrap();

    self.enabled = true;
  }

  ///
  /// Disable the hook and place the original bytes back to place
  ///
  pub fn disable(&mut self, hook_king: &HookKing) {
    // println!("Address = {:#X?}, {:#X?}", self.address, self.org_bytes);
    hook_king.write_bytes(self.address, self.org_bytes.clone()).unwrap();

    self.enabled = false;
  }

  /// Return the name of the hook
  pub fn name(&self) -> &str { &self.name }

  /// Return the address the hooked
  pub fn address(&self) -> usize { self.address }

  /// Return the address of the detour
  pub fn jumping_address(&self) -> usize { self.jumping_address }
}

#[derive(Clone, Default, Debug)]
pub struct OwnedMem {
  pub address: usize,
  pub size: usize,
  pub used: usize,
}

impl OwnedMem {
  /// increase the used memory propery
  fn inc_used(&mut self, size: usize) {
    if self.used + size < self.size {
      self.used += size;
    }
  }

  /// ckeck given address is near the owned memory location
  fn is_nearby(&self, address: usize, jmp_size: JmpSize) -> bool {
    let range = match jmp_size {
      JmpSize::None => 0,
      JmpSize::Short => i8::MAX as usize,
      JmpSize::Near => i32::MAX as usize,
      JmpSize::Far => i64::MAX as usize,
    };

    self.address.abs_diff(address) <= range
  }

  /// check if the there is enough memory
  fn is_mem_enough(&self, required_size: usize) -> bool {
    let available = self.size.saturating_sub(self.used + SAFETY);
    required_size <= available
  }

  fn check_in_mem(address: usize, required_size: usize, owned_mems: &DashMap<usize, OwnedMem>, jmp_size: JmpSize) -> Option<usize> {
    // Iterate through all entries in the DashMap
    for entry in owned_mems.iter() {
      let (key, value) = entry.pair();
      if value.is_nearby(address, jmp_size) && value.is_mem_enough(required_size) {
        return Some(*key);
      }
    }

    None
  }

  /// Returns the address of the managed memory
  pub fn address(&self) -> usize { self.address }

  /// Returns the size of the managed memory
  pub fn size(&self) -> usize { self.size }

  /// Returns the used size of the managed memory
  pub fn used(&self) -> usize { self.used }
}

#[derive(Clone, Debug, Default)]
struct InstructionsInfo {
  pub address: usize,
  pub opcodes: Vec<String>,
  pub instrs: Vec<Instruction>,
  pub bytes: Vec<u8>,
  pub nops: usize,
}

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum Process {
  Windows(*mut std::ffi::c_void),
  Linux(u32),
}

unsafe impl Send for Process {}
unsafe impl Sync for Process {}

impl Default for Process {
  #[cfg(target_os = "windows")]
  fn default() -> Self { Process::Windows(std::ptr::null_mut()) }

  #[cfg(target_os = "linux")]
  fn default() -> Self { Process::Linux(0) }
}

impl Process {
  #[cfg(target_os = "windows")]
  pub fn get(&self) -> Option<*mut std::ffi::c_void> { if let Process::Windows(ptr) = *self { Some(ptr) } else { None } }

  #[cfg(target_os = "linux")]
  pub fn get(self) -> Option<u32> { if let Process::Linux(id) = self { Some(id) } else { None } }

  #[cfg(target_os = "windows")]
  pub fn is_null(&self) -> bool {
    match self {
      Process::Windows(ptr) => ptr.is_null(),
      Process::Linux(num) => *num == 0,
    }
  }
}

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

///
/// `Patch`: Does not allocate memory, places the instructions at the address and manges noping extra bytes if needed.
///
/// `Detour`: Allocates memeory near the address if possible, adds a jump to the allocated memory, places the instructions within the allocated memory and relocates the original instruction at the end of the added instructions.
///
/// `DetourNoOrg`: Allocates memeory near the address if possible, adds a jump to the allocated memory and places the instructions within the allocated memory without relocating the original instruction at the end of the added instructions.
///
#[derive(PartialEq, Eq, Debug, Clone, Copy, Default)]
pub enum HookType {
  #[default]
  Patch,
  Detour,
  DetourNoOrg,
}

#[derive(PartialEq, Eq, Debug, Clone, Copy, Default)]
enum AttachType {
  #[default]
  Internal,
  External,
  // Kernel,
}

#[derive(PartialEq, Eq, Debug, Clone, Copy, Default)]
enum JmpSize {
  #[default]
  None = 0,
  Short = 2,
  Near = 5,
  Far = 14,
}

///
/// Create once and use it for all the hooks.
///
#[derive(Clone, Debug, Default)]
pub struct HookKing {
  process: Process,
  attach_typ: AttachType,
  owned_mems: DashMap<usize, OwnedMem>,
  owned_mems_address: DashMap<usize, usize>,
  hooks: DashMap<usize, HookInfo>,
  hooks_name: DashMap<String, usize>,
  hooks_address: DashMap<usize, usize>,
}

impl HookKing {
  ///
  /// Initialise a HookKing instance to use all over your program.
  /// Passing None will hook the current process (internal) otherwise you should provide the process handle (Windows) or process id (Linux).
  ///
  pub fn new(process: Option<Process>) -> Self {
    let proc = if let Some(process) = process { process } else { Self::current_process() };
    let attach_typ = if process.is_some() { AttachType::External } else { AttachType::Internal };

    Self { process: proc, attach_typ, ..Default::default() }
  }

  fn current_process() -> Process {
    #[cfg(target_os = "windows")]
    {
      Process::Windows(unsafe { GetCurrentProcess() as _ })
    }

    #[cfg(target_os = "linux")]
    {
      let pid = process::id();
      Process::Linux(pid)
    }
  }

  /// update the process handle, None for internal
  pub fn set_process(&mut self, process: Option<Process>) {
    if process.is_some() {
      self.process = process.unwrap();
      self.attach_typ = AttachType::External;
    } else {
      self.process = Self::current_process();
      self.attach_typ = AttachType::Internal;
    }
  }

  /// search for a previously placed hook by name, address or index
  pub fn get_hook(&self, lookup: HookLookup) -> Option<HookInfo> {
    match lookup {
      HookLookup::Name(name) => self.hooks_name.get_mut(&name).and_then(|idx| self.hooks.get_mut(idx.value()).map(|h| h.clone())),
      HookLookup::Address(address) => self.hooks_address.get_mut(&address).and_then(|idx| self.hooks.get_mut(idx.value()).map(|h| h.clone())),
      HookLookup::Index(index) => self.hooks.get_mut(&index).map(|h| h.clone()),
    }
  }

  /// search for a previously allocated memory by address or index
  pub fn get_mem(&self, lookup: MemLookup) -> Option<OwnedMem> {
    match lookup {
      MemLookup::Address(address) => self.owned_mems_address.get_mut(&address).and_then(|idx| self.owned_mems.get_mut(idx.value()).map(|h| h.clone())),
      MemLookup::Index(index) => self.owned_mems.get_mut(&index).map(|h| h.clone()),
    }
  }

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
  /// Give the hook a proper name. Name must be no less than 3 characters!
  ///
  /// # Example - Internal
  ///
  /// ```
  ///  use hook_king::*;
  ///  use winapi::um::libloaderapi::GetModuleHandleA;
  ///
  /// fn internal_detour() {
  ///  let module_base = unsafe { GetModuleHandleA(std::ptr::null()) } as usize;
  ///  let mut hook_king = HookKing::default();
  ///  let hook_info = HookInfo::new(
  ///    "health",
  ///    module_base + 0x12321,
  ///    HookType::Detour,
  ///    assemble!(
  ///      push rax;
  ///      mov rax,rcx;
  ///      mov byte ptr [rax+50],2;
  ///      mov word ptr [rax+50*4],2;
  ///      mov dword ptr [rax+rax*8+50],2;
  ///      mov qword ptr [rax],2;
  ///      // label:
  ///      mov rsp,rsi;
  ///      mov r12d,4;
  ///      mov r12w,4;
  ///      mov r12b,4;
  ///      mov r12b,4;
  ///      // jmp label;
  ///      movups xmm1,xmm0;
  ///      sub rsp,100;
  ///      call rax;
  ///      call module_base as u64;
  ///      xor al,bl;
  ///      xorps xmm0,xmm10;
  ///      add rsp,100;
  ///      pop rax;
  ///      call module_base as u64 + 0x428C16;
  ///      jmp module_base as u64 + 0x428AAC;
  ///      ret;
  ///      ret;
  ///      ret_1 1;
  ///      mpsadbw xmm0, xmm1, 2;
  ///      vsqrtps ymm10, dword ptr [rcx];
  ///      // label_return:
  ///      ret;
  ///    )
  ///  );
  ///
  ///  unsafe { hook_king.hook(hook_info).unwrap() };
  /// }
  /// ```
  ///
  /// # Example - External
  ///
  /// ```
  ///  use hook_king::*;
  ///  use winapi::um::libloaderapi::GetModuleHandleA;
  ///  use std::{sync::{Arc, RwLock}, time::Duration, thread::sleep, ptr::null_mut};
  ///
  /// fn external_detour() {
  ///    let process_id = HookKing::process_id("NieRAutomata.exe").unwrap();
  ///    let process = HookKing::process(process_id).unwrap();
  ///    let module_base = HookKing::module_base(None, process_id).unwrap();
  ///
  ///    let hook_king = Arc::new(RwLock::new(HookKing::new(Some(process))));
  ///    let hook_king_c = Arc::clone(&hook_king);
  ///
  ///    let handle = std::thread::spawn(move || {
  ///      let module_base = unsafe { GetModuleHandleA(null_mut()) } as usize;
  ///      let hook_info = HookInfo::new(
  ///        "Something",
  ///        module_base,
  ///        HookType::Detour,
  ///        assemble!(
  ///          push rax;
  ///          pop rax;
  ///        ),
  ///      );
  ///
  ///      unsafe { hook_king_c.write().unwrap().hook(hook_info).unwrap() };
  ///
  ///      let hook_info = HookInfo::new(
  ///        "Something_2",
  ///        module_base + 0x589E50,
  ///        HookType::Detour,
  ///        assemble!(
  ///          mov rax,rcx;
  ///        ),
  ///      );
  ///
  ///      unsafe { hook_king_c.write().unwrap().hook(hook_info).unwrap() };
  ///
  ///      let hook_info = HookInfo::new(
  ///        "Something_3",
  ///        module_base + 0x589220,
  ///        HookType::Patch,
  ///        assemble!(
  ///          mov rax,rbx;
  ///        ),
  ///      );
  ///
  ///      unsafe { hook_king_c.write().unwrap().hook(hook_info).unwrap() };
  ///
  ///      let hook_info = HookInfo::new(
  ///        "Something_4",
  ///        module_base + 0x124F15,
  ///        HookType::DetourNoOrg,
  ///        assemble!(
  ///          mov r9,r12;
  ///          xor r11,r11;
  ///          add rax,20;
  ///        ),
  ///      );
  ///
  ///      unsafe { hook_king_c.write().unwrap().hook(hook_info).unwrap() };
  ///
  ///      hook_king_c
  ///    });
  ///
  ///    let hook_king_r = handle.join().unwrap();
  ///
  ///    sleep(Duration::from_secs(10));
  ///
  ///    let hook = hook_king_r.read().unwrap().get_hook(HookLookup::Name("Something_4".to_string()));
  ///
  ///    if hook.is_some() {
  ///      println!("Found the hook");
  ///      let mut hook = hook.unwrap();
  ///      sleep(Duration::from_secs(10));
  ///      hook.disable(&hook_king.read().unwrap());
  ///      sleep(Duration::from_secs(10));
  ///      hook.enable(&hook_king.read().unwrap());
  ///    }
  ///  }
  /// ```

  pub unsafe fn hook(&mut self, hook_info: HookInfo) -> Result<(), Box<dyn std::error::Error>> {
    let mut hook_info = hook_info;
    let name = hook_info.name.clone();
    let address = hook_info.address;
    let hook_type = hook_info.typ;
    let assembly = hook_info.assembly.as_ref();
    let architecture = arch();

    if name.len() < 3 {
      panic!("Give the hook a proper name. Name must be no less than 3 characters!")
    }

    let mut mbi = unsafe { std::mem::zeroed::<MEMORY_BASIC_INFORMATION>() };
    match self.attach_typ {
      AttachType::Internal => {
        if unsafe { VirtualQuery(address as *const _, &mut mbi as *mut _, std::mem::size_of::<MEMORY_BASIC_INFORMATION>()) } == 0 || mbi.State == 0 {
          panic!("Not a valid address! {address:#X}");
        }
      }
      AttachType::External => {
        if unsafe { VirtualQueryEx(self.process.get().unwrap() as _, address as *const _, &mut mbi as *mut _, std::mem::size_of::<MEMORY_BASIC_INFORMATION>()) } == 0 || mbi.State == 0 {
          panic!("Not a valid address! {address:#X}");
        }
      }
    }

    if hook_type == HookType::Patch {
      self.unprotect(address);

      let bytes = assemble(address, architecture, assembly)?;
      let mut org_instr_info = self.instruction_info(address, bytes.len(), architecture);
      get_required_nops(&mut org_instr_info, 0);

      self.write_bytes(address, bytes.clone())?;

      let nop_bytes = self.get_nop_bytes(org_instr_info.nops - bytes.len());
      self.write_bytes(address, nop_bytes)?;

      hook_info.org_bytes = org_instr_info.bytes.clone();
      hook_info.org_nops = org_instr_info.nops;

      self.add_hook(hook_info.clone());

      return Ok(());
    }

    let required_size = estimate_required_size(address, architecture, &assembly)?;
    let mem_index = OwnedMem::check_in_mem(address, required_size, &self.owned_mems, JmpSize::Near);

    let mut mem = if let Some(index) = mem_index { self.get_mem(MemLookup::Index(index)).unwrap() } else { self.alloc(address)? };

    let bytes = assemble(address, architecture, assembly)?;
    self.insert_bytes(address, architecture, &mut mem, &mut hook_info, bytes.clone())?;

    // println!("org_instr_info.bytes = {:#X?}", hook_info.org_bytes);
    // println!("hook_info.jumping_address = {:#X}", hook_info.jumping_address);

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

  fn unprotect(&self, address: usize) {
    let mut old_protection = 0;
    let old_protection: *mut u32 = &mut old_protection;

    unsafe {
      match self.attach_typ {
        AttachType::Internal => VirtualProtect(address as _, DEFAULT_BYTES_TO_READ, PAGE_EXECUTE_READWRITE, old_protection),
        AttachType::External => VirtualProtectEx(self.process.get().unwrap() as _, address as _, DEFAULT_BYTES_TO_READ, PAGE_EXECUTE_READWRITE, old_protection),
      };
    }
  }

  fn write_bytes(&self, address: usize, bytes: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
    self.unprotect(address);
    match self.attach_typ {
      AttachType::Internal => {
        let address = address as *mut u8;
        let address = unsafe { std::slice::from_raw_parts_mut(address, bytes.len()) };

        for index in 0..bytes.len() {
          (*address)[index] = bytes[index];
        }

        Ok(())
      }
      AttachType::External => {
        #[cfg(target_os = "windows")]
        {
          let process = match self.process.get() {
            Some(v) => v,
            None => return Err("Invalid process handle".into()),
          };

          // Ensure we have a valid handle
          if process.is_null() {
            return Err("Null process handle".into());
          }

          // Get the length of the data to write
          let size = bytes.len();
          if size == 0 {
            return Ok(()); // Nothing to write
          }

          let mut bytes_written = 0;
          let result = unsafe { WriteProcessMemory(process as _, address as *mut _, bytes.as_ptr() as *const _, size, &mut bytes_written) };

          if result == 0 {
            // Failed - get last error
            return Err(format!("WriteProcessMemory failed: {:#X?}", std::io::Error::last_os_error()).into());
          }

          if bytes_written != size {
            return Err(format!("Only wrote {} of {} bytes", bytes_written, size).into());
          }

          Ok(())
        }

        #[cfg(target_os = "linux")]
        {
          Err("Linux implementation not provided".into())
        }
      }
    }
  }

  /// src_address: the address to insert the bytes at
  fn insert_bytes(&self, src_address: usize, architecture: u32, owned_mem: &mut OwnedMem, hook_info: &mut HookInfo, bytes: Vec<u8>) -> Result<(InstructionsInfo, usize), Box<dyn std::error::Error>> {
    let dst_address = owned_mem.address + owned_mem.used;

    let jmp_size = get_jmp_size(dst_address, src_address);
    // dbg!(jmp_size);
    let rva_mem = get_jump_offset(src_address, dst_address);
    // dbg!(rva_mem);
    // println!("rva_mem = {:#X?}", rva_mem);

    self.unprotect(src_address);

    // getting the instructions length covered by the jump
    let mut org_instr_info = self.instruction_info(src_address, jmp_size as usize, architecture);
    get_required_nops(&mut org_instr_info, jmp_size as usize);

    // println!("ori_instr_info = {:X?}", org_instr_info.bytes);

    let mut ret_address_jump = dst_address as usize + bytes.len() + org_instr_info.bytes.len();

    if hook_info.typ == HookType::DetourNoOrg {
      ret_address_jump = dst_address as usize + bytes.len();
    }

    if dst_address != 0 {
      let rva_ret_jmp = get_ret_jump(src_address, dst_address, jmp_size, hook_info.typ.clone(), &mut org_instr_info, bytes.len());

      // placing the hook jump
      let hook_jmp = self.get_jump_bytes(jmp_size, rva_mem as usize);
      match self.write_bytes(src_address, hook_jmp) {
        Ok(_) => (),
        Err(e) => panic!("Failed to place hook jump bytes {:X?}", e),
      }

      // placing nops if needed at the hooked address
      let nops = self.get_nop_bytes(org_instr_info.nops);
      match self.write_bytes(src_address + jmp_size as usize, nops) {
        Ok(_) => (),
        Err(e) => panic!("Failed to place nops bytes, error: {:X?}", e),
      };

      // placing the injected bytes
      match self.write_bytes(dst_address, bytes.clone()) {
        Ok(_) => (),
        Err(e) => panic!("Failed to place injected bytes, error: {:X?}", e),
      };

      if hook_info.typ == HookType::Detour {
        match self.write_bytes(dst_address + bytes.len(), org_instr_info.bytes.clone()) {
          Ok(_) => (),
          Err(e) => panic!("Failed to place original bytes, error: {:X?}", e),
        };
        owned_mem.inc_used(org_instr_info.bytes.len());
      }

      // placing the return jump
      let ret_jmp_bytes = self.get_jump_bytes(jmp_size, rva_ret_jmp);
      match self.write_bytes(ret_address_jump, ret_jmp_bytes) {
        Ok(_) => (),
        Err(e) => panic!("Failed to place return jump bytes, error: {:X?}", e),
      };

      owned_mem.inc_used(jmp_size as usize + bytes.len());

      // println!("OwnedMem = {:#X?}", owned_mem);
    }

    hook_info.jumping_address = dst_address;
    hook_info.org_bytes = org_instr_info.bytes.clone();
    hook_info.org_nops = org_instr_info.nops;
    hook_info.jmp_size = jmp_size;

    Ok((org_instr_info, dst_address))
  }

  /// returns the size of the original instruction(s) and required nopes if needed
  fn instruction_info(&self, address: usize, length: usize, architecture: u32) -> InstructionsInfo {
    self.unprotect(address);
    let mut bytes = match self.read_bytes(address, length + SAFETY) {
      Ok(v) => v,
      Err(e) => panic!("Failed to read bytes bytes, at address {:#X?}, error: {:X?}", address, e),
    };
    // println!("{:02X?}", &bytes);

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
      // println!("instr.op_code() {:02X?}", instr.op_code());
      instrs_size += instr.len();
      instrs.push(instr);

      if instrs_size >= length {
        break;
      }
    }

    // let block = InstructionBlock::new(&instrs, address as u64 + bytes.len() as u64);
    // let instrs_bytes = BlockEncoder::encode(decoder.bitness(), block, BlockEncoderOptions::NONE).expect("Failed at encoding BlockEncoder").code_buffer;
    bytes.truncate(instrs_size);

    return InstructionsInfo { address, opcodes, instrs, bytes, nops: 0 };
  }

  fn read_bytes(&self, address: usize, length: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    self.unprotect(address);
    let process = match self.attach_typ {
      // AttachType::Internal => Ok(unsafe { std::slice::from_raw_parts_mut(address as *mut u8, length).to_vec() }),
      AttachType::Internal => unsafe { GetCurrentProcess() },
      AttachType::External => self.process.get().unwrap() as _,
    };

    let mut bytes = vec![0u8; length];
    let mut bytes_read = 0;

    if unsafe { ReadProcessMemory(process, address as _, bytes.as_mut_ptr() as *mut _, length, &mut bytes_read) == 1 } { Ok(bytes) } else { Err(format!("Failed to read bytes {:#X?}", std::io::Error::last_os_error()).into()) }
  }

  // fn alloc(&self, address: usize) -> Result<OwnedMem, Box<dyn std::error::Error>> {
  //   let mut memory_info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
  //   let mut current_address = address;
  //   let mut attempts = 0;
  //   let mut new_mem = OwnedMem::default();

  //   while attempts < 100000 {
  //     let mem_query = match self.attach_typ {
  //       AttachType::Internal => unsafe { VirtualQuery(current_address as *mut c_void, &mut memory_info as *mut MEMORY_BASIC_INFORMATION, size_of::<MEMORY_BASIC_INFORMATION>()) },
  //       AttachType::External => unsafe { VirtualQueryEx(self.process.get().unwrap() as _, current_address as *mut c_void, &mut memory_info as *mut MEMORY_BASIC_INFORMATION, size_of::<MEMORY_BASIC_INFORMATION>()) },
  //     };

  //     let status = unsafe { NtQueryVirtualMemory(self.process.get().unwrap() as _, current_address as _, MemoryBasicInformation, &mut mem_info, mem_info_size, &mut return_length) };

  //     if mem_query > 0 {
  //       if memory_info.State == MEM_FREE && memory_info.RegionSize >= PAGE_SIZE {
  //         let alloc_mem = match self.attach_typ {
  //           AttachType::Internal => unsafe { VirtualAlloc(current_address as *mut c_void, PAGE_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE) },
  //           AttachType::External => unsafe { VirtualAllocEx(self.process.get().unwrap() as _, current_address as *mut c_void, PAGE_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE) },
  //         };

  //         if !alloc_mem.is_null() {
  //           let size = get_region_size(alloc_mem as usize).unwrap();
  //           new_mem = OwnedMem { address: alloc_mem as usize, size, ..Default::default() };

  //           break;
  //         }
  //       }

  //       // match self.attach_typ {
  //       //   AttachType::Internal => current_address = memory_info.BaseAddress as usize - memory_info.RegionSize, // Move to NEXT region (backwards traversal)
  //       //   AttachType::External => current_address = memory_info.BaseAddress as usize + memory_info.RegionSize, // Move to NEXT region (forewards traversal)
  //       // }

  //       current_address = memory_info.BaseAddress as usize - memory_info.RegionSize; // Move to NEXT region (backwards traversal)
  //     } else {
  //       current_address += PAGE_SIZE;
  //     }

  //     attempts += 1;
  //     // println!("attempts = {}", attempts);
  //   }

  //   Ok(new_mem)
  // }

  fn alloc(&self, address: usize) -> Result<OwnedMem, Box<dyn std::error::Error>> {
    let mut mem_info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let mut return_length: usize = 0;
    let mut current_address = address;
    let mut attempts = 0;
    let mut new_mem = OwnedMem::default();

    while attempts < 100000 {
      let process_handle = match self.attach_typ {
        AttachType::Internal => unsafe { GetCurrentProcess() },
        AttachType::External => self.process.get().unwrap() as _,
      };

      let status = unsafe { NtQueryVirtualMemory(process_handle, current_address as _, MemoryBasicInformation, &mut mem_info as *mut _ as _, size_of::<MEMORY_BASIC_INFORMATION>(), &mut return_length as *mut _ as *mut _) };

      if NT_SUCCESS(status) {
        if mem_info.State == MEM_FREE && mem_info.RegionSize >= PAGE_SIZE {
          let mut base_address = current_address as _;
          let mut region_size = PAGE_SIZE;

          let alloc_status = unsafe { NtAllocateVirtualMemory(process_handle, &mut base_address, 0, &mut region_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE) };

          if NT_SUCCESS(alloc_status) && !base_address.is_null() {
            let size = get_region_size(base_address as usize).unwrap();
            new_mem = OwnedMem { address: base_address as usize, size, ..Default::default() };

            break;
          }
        }

        current_address = mem_info.BaseAddress as usize - mem_info.RegionSize;
      } else {
        current_address += PAGE_SIZE;
      }

      attempts += 1;
    }

    Ok(new_mem)
  }

  fn get_nop_bytes(&self, length: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    if length != 0 {
      for _ in 0..length {
        bytes.push(0x90);
      }
    }

    bytes
  }

  fn get_jump_bytes(&self, jmp_size: JmpSize, offset: usize) -> Vec<u8> {
    let mut bytes = Vec::new();

    match jmp_size {
      JmpSize::None => return bytes,
      JmpSize::Short => bytes.extend_from_slice(&[0xEB, offset as u8]),
      JmpSize::Near => {
        bytes.push(0xE9);

        let mut v = offset;
        for _ in 0..4 {
          bytes.push(v as u8);
          v >>= 8
        }
      }
      JmpSize::Far => {
        let prefix = [0xFF, 0x25, 0x00, 0x00, 0x00, 0x00];
        bytes.extend_from_slice(&prefix);

        let mut v = offset;
        for _ in 0..8 {
          bytes.push(v as u8);
          v >>= 8;
        }
      }
    }

    bytes
  }

  /// get the process handle using the process id
  #[cfg(target_os = "windows")]
  pub fn process(process_id: u32) -> Result<Process, Box<dyn std::error::Error>> {
    let process = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, process_id) };
    if process.is_null() { Err(format!("Failed to open process, error {:#X?}", std::io::Error::last_os_error()).into()) } else { Ok(Process::Windows(process as _)) }
  }

  /// get the process_id from the name of the process
  #[cfg(target_os = "windows")]
  pub fn process_id(name: &str) -> Result<u32, String> {
    unsafe {
      let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
      if snapshot == std::ptr::null_mut() {
        return Err(format!("CreateToolhelp32Snapshot failed {:#X?}", std::io::Error::last_os_error()));
      }

      let mut entry: PROCESSENTRY32 = std::mem::zeroed();
      entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

      if Process32First(snapshot, &mut entry) == 0 {
        CloseHandle(snapshot);
        return Err(format!("Process32First failed {:#X?}", std::io::Error::last_os_error()));
      }

      loop {
        let exe_name_cstr = std::ffi::CStr::from_ptr(entry.szExeFile.as_ptr());
        if let Ok(exe_name) = exe_name_cstr.to_str() {
          if exe_name.eq_ignore_ascii_case(name) {
            CloseHandle(snapshot);
            return Ok(entry.th32ProcessID);
          }
        }

        if Process32Next(snapshot, &mut entry) == 0 {
          break;
        }
      }

      CloseHandle(snapshot);
      Err("Process not found".to_string())
    }
  }

  /// get the passed module base address if none it will return the main module base address
  #[cfg(target_os = "windows")]
  pub fn module_base(module_name: Option<&str>, process_id: u32) -> Result<usize, Box<dyn std::error::Error>> {
    unsafe {
      let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id);
      if snapshot == winapi::um::handleapi::INVALID_HANDLE_VALUE {
        return Err("Failed to create snapshot".into());
      }

      let mut module_entry: MODULEENTRY32W = std::mem::zeroed();
      module_entry.dwSize = size_of::<MODULEENTRY32W>() as u32;

      let mut success = Module32FirstW(snapshot, &mut module_entry);
      while success != 0 {
        if let Some(name) = module_name {
          let wide_name: Vec<u16> = OsStr::new(name).encode_wide().chain(Some(0)).collect();
          if module_entry.szModule[..wide_name.len() - 1] == wide_name[..wide_name.len() - 1] {
            CloseHandle(snapshot);
            return Ok(module_entry.modBaseAddr as usize);
          }
        } else {
          CloseHandle(snapshot);
          return Ok(module_entry.modBaseAddr as usize);
        }
        success = Module32NextW(snapshot, &mut module_entry);
      }

      CloseHandle(snapshot);
      Err("Module not found".into())
    }
  }
}

fn module_base(module: Option<&str>) -> usize {
  let module_name = match module {
    Some(name) => match CString::new(name) {
      Ok(c_str) => c_str.as_ptr(),
      Err(_) => std::ptr::null(),
    },
    None => std::ptr::null(),
  };

  let handle = unsafe { GetModuleHandleA(module_name) };

  handle as usize
}

fn estimate_required_size(address: usize, architecture: u32, assembly: impl Fn(&mut CodeAssembler)) -> Result<usize, Box<dyn std::error::Error>> {
  let bytes = assemble(address, architecture, assembly)?.len();
  Ok(bytes * 2)
}

fn assemble(address: usize, architecture: u32, assembly: impl Fn(&mut CodeAssembler)) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
  let mut assembler = CodeAssembler::new(architecture).expect("Failed at constructing CodeAssembler");
  assembly(&mut assembler);

  let instructions = assembler.instructions();
  let block = InstructionBlock::new(instructions, address as u64);

  let result = BlockEncoder::encode(architecture, block, BlockEncoderOptions::DONT_FIX_BRANCHES).expect("Failed at encoding");
  Ok(result.code_buffer)
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

fn get_required_nops(instr_info: &mut InstructionsInfo, jmp_size: usize) {
  let mut length = 0;
  for instr in instr_info.instrs.iter() {
    length += instr.len();
    if length >= jmp_size {
      break;
    }
  }

  instr_info.nops = length.abs_diff(jmp_size);
}

fn get_ret_jump(src_address: usize, dst_address: usize, jmp_size: JmpSize, hook_type: HookType, instr_info: &mut InstructionsInfo, bytes_len: usize) -> usize {
  get_required_nops(instr_info, jmp_size as usize);
  let rva_dst;
  let mut rva_ret_jmp;

  match jmp_size {
    JmpSize::None => todo!(),
    JmpSize::Short => todo!(),
    JmpSize::Near => {
      if src_address < (dst_address as usize) {
        rva_dst = dst_address as usize - src_address - jmp_size as usize;
        rva_ret_jmp = rva_dst + instr_info.bytes.len() + jmp_size as usize + instr_info.nops + 1;
        if hook_type == HookType::DetourNoOrg {
          rva_ret_jmp = rva_dst + jmp_size as usize + instr_info.nops + 1;
        }
      } else {
        rva_dst = src_address - dst_address as usize + jmp_size as usize - 1;
        rva_ret_jmp = rva_dst - bytes_len - instr_info.bytes.len() - jmp_size as usize + instr_info.nops + 1;
        if hook_type == HookType::DetourNoOrg {
          rva_ret_jmp = rva_dst - bytes_len - jmp_size as usize + instr_info.nops + 1;
        }
      }
    }
    JmpSize::Far => rva_ret_jmp = src_address + jmp_size as usize + instr_info.nops,
  }

  rva_ret_jmp
}

fn get_jmp_size(src_address: usize, dst_address: usize) -> JmpSize {
  let distance = dst_address.abs_diff(src_address);
  if distance > i32::MAX as usize { JmpSize::Far } else { JmpSize::Near }
}

fn get_jump_offset(src_address: usize, dst_address: usize) -> isize {
  let jmp_size = get_jmp_size(src_address, dst_address);
  let src_address = src_address as isize;
  let dst_address = dst_address as isize;

  if jmp_size == JmpSize::Far {
    return dst_address;
  }

  dst_address - (src_address + jmp_size as isize)
}

static ARCHITECTURE: OnceLock<u32> = OnceLock::new();

fn arch() -> u32 { *ARCHITECTURE.get_or_init(|| get_architecture(unsafe { GetCurrentProcess() }).unwrap_or(64)) }

fn get_architecture(handle: winapi::um::winnt::HANDLE) -> Result<u32, Box<dyn std::error::Error>> {
  let mut is_wow64 = 0;
  let result = unsafe { IsWow64Process(handle, &mut is_wow64) };
  if result == 0 {
    return Err("Couldn't get the architecture".into());
  }
  Ok(if is_wow64 == 0 { 64 } else { 32 })
}

fn get_region_size(address: usize) -> Result<usize, Box<dyn std::error::Error>> {
  let mut mem_info = unsafe { std::mem::zeroed() };
  let result = unsafe { VirtualQuery(address as *mut _, &mut mem_info, std::mem::size_of::<MEMORY_BASIC_INFORMATION>()) };

  if result > 0 { Ok(mem_info.RegionSize) } else { Err("Failed to retrieve region size".into()) }
}
