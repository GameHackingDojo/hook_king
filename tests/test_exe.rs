use hook_king::*;
use winapi::um::{errhandlingapi::GetLastError, handleapi::CloseHandle, libloaderapi::GetModuleHandleA, processthreadsapi::OpenProcess, tlhelp32::{CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, PROCESSENTRY32, Process32First, Process32Next, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS}, winnt::{PROCESS_ALL_ACCESS, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ}};

fn get_pid(name: &str) -> Result<u32, String> {
  unsafe {
    let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if snapshot == std::ptr::null_mut() {
      return Err(format!("CreateToolhelp32Snapshot failed {}", GetLastError()));
    }

    let mut entry: PROCESSENTRY32 = std::mem::zeroed();
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

    if Process32First(snapshot, &mut entry) == 0 {
      CloseHandle(snapshot);
      return Err(format!("Process32First failed {}", GetLastError()));
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

fn get_main_module_base_address(pid: u32) -> Result<usize, Box<dyn std::error::Error>> {
  unsafe {
    let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if snapshot == winapi::um::handleapi::INVALID_HANDLE_VALUE {
      return Err("".into());
    }

    let mut module_entry: MODULEENTRY32W = std::mem::zeroed();
    module_entry.dwSize = size_of::<MODULEENTRY32W>() as u32;

    let success = Module32FirstW(snapshot, &mut module_entry);
    CloseHandle(snapshot);

    if success != 0 { Ok(module_entry.modBaseAddr as usize) } else { Err("".into()) }
  }
}

fn main() {
  let process_id = get_pid("010Editor.exe").unwrap();
  let process = ProcessId::Windows(unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, process_id) } as _);

  let module_handle = get_main_module_base_address(process_id).unwrap();

  let mut hook_king = HookKing::new(Some(process));
  // let module_handle = unsafe { GetModuleHandleA(std::ptr::null()) } as usize;
  let hook_info = HookInfo::new("health", module_handle, HookType::Detour, assemble!(push rax;));

  unsafe { hook_king.hook(hook_info).unwrap() };
}
