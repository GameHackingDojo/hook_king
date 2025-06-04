use hook_king::*;
use winapi::um::libloaderapi::GetModuleHandleA;

fn main() {
  let module_handle = unsafe { GetModuleHandleA(std::ptr::null()) } as usize;
  let hook_info = HookInfo {
    name: "my name".to_string(),
    address: module_handle + 0x12321,
    typ: HookType::AllocWithOrg,
    assembly: assemble!(push rax;),
  };
  unsafe { asm_hook(hook_info, None) };
}
