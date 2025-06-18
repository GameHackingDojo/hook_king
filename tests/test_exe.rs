use hook_king::*;

fn main() {
  // let process_id = HookKing::process_id("010Editor.exe").unwrap();
  let process_id = HookKing::process_id("NieRAutomata.exe").unwrap();
  let process = HookKing::process(process_id).unwrap();
  let module_base = HookKing::module_base(None, process_id).unwrap();

  let mut hook_king = HookKing::new(Some(process));
  let hook_info = HookInfo::new("health", module_base, HookType::Detour, assemble!(push rax;));

  unsafe { hook_king.hook(hook_info).unwrap() };
}
