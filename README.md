# hook_king

A low-level automated hooking library providing detours, trampolines, and memory management capabilities. Supports both internal and external process hooking with optional original code preservation.

## **THIS CRATE DEPENDS ON iced-x86**
  **Add iced-x86 to your cargo.toml with (features = ["code_asm"])**

## Features

- **Function Hooking**: Intercept function calls with detours
- **Trampolines**: Preserve original function functionality
- **Memory Management**: Safe memory operations for hooking
- **Cross-Process Support**: Hook both internal and external processes
- **Original Code Preservation**: Optional preservation of overwritten instructions
- **x86/x64 Support**: Works with both 32-bit and 64-bit architectures
- **Still in early development**


 # Warning

 Not giving a name or providing an invalid address will result in panicing

 Give the hook a proper name. Name must be no less than 3 characters!

## To be fixed
- **Can't use labels in assembly**
- **Can't use variables in assembly when attached externally**

 # Example - Internal

 ```rust
  use hook_king::*;

 fn internal_detour() {
  let module_base = HookKing::module_base(None, None).unwrap();
  let mut hook_king = HookKing::default();

  let hook_info = HookInfo::new(
    "health",
    module_base + 0x12321,
    HookType::Detour,
    assemble!(
      push rax;
      mov rax,rcx;
      mov byte ptr [rax+50],2;
      mov word ptr [rax+50*4],2;
      mov dword ptr [rax+rax*8+50],2;
      mov qword ptr [rax],2;
      // label:
      mov rsp,rsi;
      mov r12d,4;
      mov r12w,4;
      mov r12b,4;
      mov r12b,4;
      // jmp label;
      movups xmm1,xmm0;
      sub rsp,100;
      call rax;
      call module_base as u64;
      xor al,bl;
      xorps xmm0,xmm10;
      add rsp,100;
      pop rax;
      call module_base as u64 + 0x428C16;
      jmp module_base as u64 + 0x428AAC;
      ret;
      ret;
      ret_1 1;
      mpsadbw xmm0, xmm1, 2;
      vsqrtps ymm10, dword ptr [rcx];
      // label_return:
      ret;
    )
  );

  unsafe { hook_king.hook(hook_info).unwrap() };
 }
 ```

 # Example - External

 ```rust
  use hook_king::*;
  use std::{sync::{Arc, RwLock}, time::Duration, thread::sleep, ptr::null_mut};

 fn external_detour() {
    let process_id = HookKing::process_id("NieRAutomata.exe").unwrap();
    let process = HookKing::process(process_id).unwrap();
    let module_base = HookKing::module_base(None, Some(process_id)).unwrap();

    let hook_king = Arc::new(RwLock::new(HookKing::new(Some(process))));
    let hook_king_c = Arc::clone(&hook_king);

    let handle = std::thread::spawn(move || {
      let hook_info = HookInfo::new(
        "Something",
        module_base,
        HookType::Detour,
        assemble!(
          push rax;
          pop rax;
        ),
      );

      unsafe { hook_king_c.write().unwrap().hook(hook_info).unwrap() };

      let hook_info = HookInfo::new(
        "Something_2",
        module_base + 0x589E50,
        HookType::Detour,
        assemble!(
          mov rax,rcx;
        ),
      );

      unsafe { hook_king_c.write().unwrap().hook(hook_info).unwrap() };

      let hook_info = HookInfo::new(
        "Something_3",
        module_base + 0x589220,
        HookType::Patch,
        assemble!(
          mov rax,rbx;
        ),
      );

      unsafe { hook_king_c.write().unwrap().hook(hook_info).unwrap() };

      let hook_info = HookInfo::new(
        "Something_4",
        module_base + 0x124F15,
        HookType::DetourNoOrg,
        assemble!(
          mov r9,r12;
          xor r11,r11;
          add rax,20;
        ),
      );

      unsafe { hook_king_c.write().unwrap().hook(hook_info).unwrap() };

      hook_king_c
    });

    let hook_king_r = handle.join().unwrap();

    let hook_king_r_g = hook_king_r.read().unwrap();

    match hook_king_r_g.get_hook(HookLookup::Name("Something_4".to_string())) {
    Some(mut v) => {
      std::thread::sleep(Duration::from_secs(2));
      println!("Found hook");

      std::thread::sleep(Duration::from_secs(5));
      v.disable(&hook_king_r_g);
      println!("Hook disabled");

      std::thread::sleep(Duration::from_secs(5));
      v.enable(&hook_king_r_g);
      println!("Hook enabled");
    }
    None => panic!(),
  };



  }
 ```
