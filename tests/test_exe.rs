use hook_king::*;
use winapi::um::libloaderapi::GetModuleHandleA;

fn main() {
  let mut hook_king = HookKing::default();
  let module_handle = unsafe { GetModuleHandleA(std::ptr::null()) } as usize;
  let hook_info = HookInfo::new("health", module_handle + 0x12321, HookType::Detour, assemble!(push rax;));

  unsafe { hook_king.hook(hook_info).unwrap() };
}
