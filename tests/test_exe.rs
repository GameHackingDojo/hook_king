use hook_king::*;
use winapi::um::libloaderapi::GetModuleHandleA;

fn main() {
  let mut hook_king = HookKing::default();
  let module_handle = unsafe { GetModuleHandleA(std::ptr::null()) } as usize;
  let hook_info = HookInfo {
    name: "my name".to_string(),
    address: module_handle + 0x12321,
    typ: HookType::Detour,
    assembly: assemble!(push rax;),
  };

  unsafe { hook_king.asm_hook(hook_info).unwrap() };
}
