use jni::objects::{JClass, JObject, JString};
use jni::sys::{jboolean, jbyteArray, jint, jlong, jstring, JNI_TRUE, JNI_VERSION_1_6};
use jni::{JNIEnv, JavaVM};

use crate::decompiler::{decompile_to_c, generate_disassembly_text, generate_flowchart_text};
use crate::elf_parser::ElfContext;

#[no_mangle]
pub unsafe extern "C" fn JNI_OnLoad(_vm: JavaVM, _reserved: *mut std::ffi::c_void) -> jint {
    JNI_VERSION_1_6
}

// ==========================================
// Native Handlers
// ==========================================

unsafe fn handle_init(env: &JNIEnv, path_str: JString) -> jlong {
    let path: String = match env.get_string(path_str) {
        Ok(s) => s.into(),
        Err(_) => return 0,
    };
    match ElfContext::open(&path) {
        Ok(ctx) => Box::into_raw(Box::new(ctx)) as jlong,
        Err(_) => 0,
    }
}

unsafe fn handle_info(env: &JNIEnv, handle: jlong) -> jstring {
    if handle == 0 {
        return env.new_string("{}").unwrap().into_inner();
    }
    let ctx = &*(handle as *const ElfContext);
    match ctx.get_info() {
        Ok(info) => {
            let json = serde_json::to_string(&info).unwrap_or_else(|_| "{}".to_string());
            env.new_string(json).unwrap().into_inner()
        }
        Err(err) => {
            let err_json = format!("{{\"error\": \"{}\"}}", err);
            env.new_string(err_json).unwrap().into_inner()
        }
    }
}

unsafe fn handle_disasm(
    env: &JNIEnv,
    handle: jlong,
    address: jlong,
    size: jlong,
    thumb: jboolean,
) -> jstring {
    if handle == 0 {
        return env.new_string("{\"data\":[]}").unwrap().into_inner();
    }
    let ctx = &*(handle as *const ElfContext);
    let vaddr = address as u64;

    let offset = match ctx.vaddr_to_offset(vaddr) {
        Some(off) => off as usize,
        None => return env.new_string("{\"data\":[]}").unwrap().into_inner(),
    };

    if offset >= ctx.raw.len() {
        return env.new_string("{\"data\":[]}").unwrap().into_inner();
    }

    let code_slice = &ctx.raw[offset..];
    let e_machine = ctx.get_info().map(|i| i.e_machine).unwrap_or(183);
    let is_thumb = thumb == JNI_TRUE;

    let is_jni = ctx
        .syms_map
        .get(&vaddr)
        .map(|s| s.sym.starts_with("Java_") || s.sym == "JNI_OnLoad" || s.jni_method.is_some())
        .unwrap_or(false);

    let symbol_resolver = |v: u64| {
        if let Some(sym) = ctx.syms_map.get(&v) {
            let name = sym.demangled.as_deref().unwrap_or(sym.sym.as_str());
            return Some(name.to_string());
        }
        ctx.get_string_at_vaddr(v).map(|s| format!("\"{}\"", s))
    };
    match crate::disasm::disassemble_with_resolver(
        code_slice,
        vaddr,
        size as u64,
        e_machine,
        is_thumb,
        Some(&symbol_resolver),
        is_jni,
    ) {
        Ok(code_ins) => {
            let json =
                serde_json::to_string(&code_ins).unwrap_or_else(|_| "{\"data\":[]}".to_string());
            env.new_string(json).unwrap().into_inner()
        }
        Err(err) => {
            let err_json = format!("{{\"error\":\"{}\", \"data\":[]}}", err);
            env.new_string(err_json).unwrap().into_inner()
        }
    }
}

unsafe fn handle_dec(env: &JNIEnv, mode: jint, handle: jlong, address: jlong) -> jstring {
    if handle == 0 {
        return env
            .new_string("// [Error] Invalid ELF handle\n")
            .unwrap()
            .into_inner();
    }
    let ctx = &*(handle as *const ElfContext);
    let vaddr = address as u64;

    let output = match mode {
        1 => decompile_to_c(ctx, vaddr),
        2 => generate_disassembly_text(ctx, vaddr),
        3 => generate_flowchart_text(ctx, vaddr),
        _ => format!("// Unknown mode: {}\n", mode),
    };
    env.new_string(output).unwrap().into_inner()
}

unsafe fn handle_strings(env: &JNIEnv, handle: jlong) -> jstring {
    if handle == 0 {
        return env.new_string("{\"data\":[]}").unwrap().into_inner();
    }
    let ctx = &*(handle as *const ElfContext);
    match ctx.extract_strings() {
        Ok(sdata) => {
            let json =
                serde_json::to_string(&sdata).unwrap_or_else(|_| "{\"data\":[]}".to_string());
            env.new_string(json).unwrap().into_inner()
        }
        Err(_) => env.new_string("{\"data\":[]}").unwrap().into_inner(),
    }
}

unsafe fn handle_write(env: &JNIEnv, handle: jlong, address: jlong, bytes: jbyteArray) {
    if handle == 0 || bytes.is_null() {
        return;
    }
    let ctx = &mut *(handle as *mut ElfContext);
    if let Ok(byte_vec) = env.convert_byte_array(bytes) {
        let _ = ctx.patch_bytes(address as u64, &byte_vec);
    }
}

unsafe fn handle_save(env: &JNIEnv, handle: jlong) -> jbyteArray {
    if handle == 0 {
        return env.new_byte_array(0).unwrap();
    }
    let ctx = &*(handle as *const ElfContext);
    let bytes_signed: Vec<i8> = ctx.raw.iter().map(|&b| b as i8).collect();
    let j_arr = env.new_byte_array(bytes_signed.len() as i32).unwrap();
    env.set_byte_array_region(j_arr, 0, &bytes_signed).unwrap();
    j_arr
}

unsafe fn handle_finalize(handle: jlong) {
    if handle != 0 {
        let _ = Box::from_raw(handle as *mut ElfContext);
    }
}

unsafe fn handle_trace_init(handle: jlong, address: jlong) {
    if handle != 0 {
        let ctx = &mut *(handle as *mut ElfContext);
        // Build the tracer without holding a mutable borrow of `ctx` across the
        // call, then store it. Default build selects `Tracer::Native`.
        let tracer = {
            let c: &ElfContext = ctx;
            crate::tracer::Tracer::new(address as u64, c)
        };
        match tracer {
            Ok(t) => {
                ctx.vcpu = Some(t);
                ctx.trace_init_error = None;
            }
            Err(e) => {
                ctx.vcpu = None;
                ctx.trace_init_error = Some(e);
            }
        }
    }
}

unsafe fn handle_trace_step(env: &JNIEnv, handle: jlong) -> jstring {
    if handle == 0 {
        return env.new_string("{}").unwrap().into_inner();
    }
    let ctx = &mut *(handle as *mut ElfContext);
    if let Some(mut vcpu) = ctx.vcpu.take() {
        let res = vcpu.step(ctx);
        ctx.vcpu = Some(vcpu);
        match res {
            Ok(state) => {
                let json = serde_json::to_string(&state).unwrap_or_else(|_| "{}".to_string());
                env.new_string(json).unwrap().into_inner()
            }
            Err(e) => {
                // Use serde_json so quotes/backslashes in the message are escaped.
                let err_json = serde_json::json!({ "error": e }).to_string();
                env.new_string(err_json).unwrap().into_inner()
            }
        }
    } else {
        // Surface the real initialization failure instead of a generic message.
        let msg = ctx
            .trace_init_error
            .clone()
            .unwrap_or_else(|| "Tracer not initialized".to_string());
        let err_json = serde_json::json!({ "error": msg }).to_string();
        env.new_string(err_json).unwrap().into_inner()
    }
}

unsafe fn handle_trace_back(env: &JNIEnv, handle: jlong) -> jstring {
    if handle == 0 {
        return env.new_string("{}").unwrap().into_inner();
    }
    let ctx = &mut *(handle as *mut ElfContext);
    if let Some(vcpu) = &mut ctx.vcpu {
        if let Some(state) = vcpu.step_back() {
            let json = serde_json::to_string(&state).unwrap_or_else(|_| "{}".to_string());
            env.new_string(json).unwrap().into_inner()
        } else {
            env.new_string("{\"error\":\"Start of trace reached\"}")
                .unwrap()
                .into_inner()
        }
    } else {
        // Surface the real init failure on the Back path too.
        let msg = ctx
            .trace_init_error
            .clone()
            .unwrap_or_else(|| "Tracer not initialized".to_string());
        let err_json = serde_json::json!({ "error": msg }).to_string();
        env.new_string(err_json).unwrap().into_inner()
    }
}

// ==========================================
// JNI Exports for Modern Package: com.diself.app
// ==========================================

#[no_mangle]
pub unsafe extern "C" fn Java_io_elftrace_app_core_JNIBridge_init0(
    env: JNIEnv,
    _class: JClass,
    path: JString,
) -> jlong {
    handle_init(&env, path)
}

#[no_mangle]
pub unsafe extern "C" fn Java_io_elftrace_app_core_JNIBridge_info0(
    env: JNIEnv,
    _obj: JObject,
    handle: jlong,
    _flag: jboolean,
) -> jstring {
    handle_info(&env, handle)
}

#[no_mangle]
pub unsafe extern "C" fn Java_io_elftrace_app_core_JNIBridge_disasm0(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
    address: jlong,
    size: jlong,
    thumb: jboolean,
) -> jstring {
    handle_disasm(&env, handle, address, size, thumb)
}

#[no_mangle]
pub unsafe extern "C" fn Java_io_elftrace_app_core_JNIBridge_dec0(
    env: JNIEnv,
    _class: JClass,
    mode: jint,
    handle: jlong,
    address: jlong,
) -> jstring {
    handle_dec(&env, mode, handle, address)
}

#[no_mangle]
pub unsafe extern "C" fn Java_io_elftrace_app_core_JNIBridge_strings0(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jstring {
    handle_strings(&env, handle)
}

#[no_mangle]
pub unsafe extern "C" fn Java_io_elftrace_app_core_JNIBridge_write0(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
    address: jlong,
    bytes: jbyteArray,
) {
    handle_write(&env, handle, address, bytes)
}

#[no_mangle]
pub unsafe extern "C" fn Java_io_elftrace_app_core_JNIBridge_save0(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jbyteArray {
    handle_save(&env, handle)
}

#[no_mangle]
pub unsafe extern "C" fn Java_io_elftrace_app_core_JNIBridge_readBytes0(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
    address: jlong,
    length: jint,
) -> jbyteArray {
    if handle == 0 || length <= 0 {
        return env.new_byte_array(0).unwrap();
    }
    let ctx = &*(handle as *const ElfContext);
    let offset = ctx
        .vaddr_to_offset(address as u64)
        .map(|o| o as usize)
        .or_else(|| {
            let direct = address as usize;
            if direct < ctx.raw.len() {
                Some(direct)
            } else {
                None
            }
        });

    let offset = match offset {
        Some(off) => off,
        None => return env.new_byte_array(0).unwrap(),
    };

    let len = (length as usize).min(ctx.raw.len().saturating_sub(offset));
    let slice = &ctx.raw[offset..offset + len];
    let byte_arr = env.new_byte_array(slice.len() as i32).unwrap();
    let signed_slice: &[i8] = std::slice::from_raw_parts(slice.as_ptr() as *const i8, slice.len());
    env.set_byte_array_region(byte_arr, 0, signed_slice)
        .unwrap();
    byte_arr
}

#[no_mangle]
pub unsafe extern "C" fn Java_io_elftrace_app_core_JNIBridge_finalize0(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    handle_finalize(handle)
}

#[no_mangle]
pub unsafe extern "C" fn Java_io_elftrace_app_core_JNIBridge_traceInit(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
    address: jlong,
) -> jstring {
    handle_trace_init(handle, address);
    // Report initialization success/failure immediately so the UI can show it
    // instead of only after the first Step.
    if handle == 0 {
        return env
            .new_string("{\"error\":\"Invalid handle\"}")
            .unwrap()
            .into_inner();
    }
    let ctx = &*(handle as *const ElfContext);
    let json = match &ctx.trace_init_error {
        Some(e) => serde_json::json!({ "error": e }).to_string(),
        None => "{}".to_string(),
    };
    env.new_string(json).unwrap().into_inner()
}

#[no_mangle]
pub unsafe extern "C" fn Java_io_elftrace_app_core_JNIBridge_traceStep(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jstring {
    handle_trace_step(&env, handle)
}

#[no_mangle]
pub unsafe extern "C" fn Java_io_elftrace_app_core_JNIBridge_traceBack(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jstring {
    handle_trace_back(&env, handle)
}

#[no_mangle]
pub unsafe extern "C" fn Java_io_elftrace_app_core_JNIBridge_getXrefs(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
    address: jlong,
) -> jstring {
    if handle == 0 {
        return env
            .new_string("{\"target_address\":0,\"refs\":[]}")
            .unwrap()
            .into_inner();
    }
    let ctx = &*(handle as *const ElfContext);
    let target_vaddr = address as u64;

    let refs = crate::xref::find_callers_to(ctx, target_vaddr);
    let resp = crate::xref::XRefResponse {
        target_address: target_vaddr,
        refs,
    };

    let json = serde_json::to_string(&resp)
        .unwrap_or_else(|_| "{\"target_address\":0,\"refs\":[]}".to_string());
    env.new_string(json).unwrap().into_inner()
}

#[no_mangle]
pub unsafe extern "C" fn Java_io_elftrace_app_core_JNIBridge_getHierarchy(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
    address: jlong,
) -> jstring {
    if handle == 0 {
        return env
            .new_string(
                "{\"function_address\":0,\"function_name\":\"\",\"callers\":[],\"callees\":[]}",
            )
            .unwrap()
            .into_inner();
    }
    let ctx = &*(handle as *const ElfContext);
    let target_vaddr = address as u64;

    let hierarchy = crate::xref::get_hierarchy(ctx, target_vaddr);
    let json = serde_json::to_string(&hierarchy).unwrap_or_else(|_| "{}".to_string());
    env.new_string(json).unwrap().into_inner()
}

#[no_mangle]
pub unsafe extern "C" fn Java_io_elftrace_app_core_JNIBridge_quickPatch(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
    address: jlong,
    patch_type: jint,
    thumb: jboolean,
) -> jstring {
    if handle == 0 {
        return env
            .new_string("{\"success\":false,\"error\":\"Invalid handle\"}")
            .unwrap()
            .into_inner();
    }
    let ctx = &mut *(handle as *mut ElfContext);
    let ptype = match patch_type {
        1 => crate::patcher::QuickPatchType::Nop,
        2 => crate::patcher::QuickPatchType::ReturnTrue,
        3 => crate::patcher::QuickPatchType::ReturnFalse,
        4 => crate::patcher::QuickPatchType::ReturnVoid,
        _ => {
            return env
                .new_string("{\"success\":false,\"error\":\"Invalid patch type\"}")
                .unwrap()
                .into_inner()
        }
    };
    let is_thumb = thumb == JNI_TRUE;
    let res = crate::patcher::apply_quick_patch(ctx, address as u64, ptype, is_thumb);
    let json = serde_json::to_string(&res).unwrap_or_else(|_| "{}".to_string());
    env.new_string(json).unwrap().into_inner()
}

#[no_mangle]
pub unsafe extern "C" fn Java_io_elftrace_app_core_JNIBridge_assemblePatch(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
    address: jlong,
    text_str: JString,
) -> jstring {
    if handle == 0 {
        return env
            .new_string("{\"success\":false,\"error\":\"Invalid handle\"}")
            .unwrap()
            .into_inner();
    }
    let ctx = &mut *(handle as *mut ElfContext);
    let text: String = match env.get_string(text_str) {
        Ok(s) => s.into(),
        Err(_) => {
            return env
                .new_string("{\"success\":false,\"error\":\"Invalid text\"}")
                .unwrap()
                .into_inner()
        }
    };
    let res = crate::patcher::assemble_and_patch(ctx, address as u64, &text);
    let json = serde_json::to_string(&res).unwrap_or_else(|_| "{}".to_string());
    env.new_string(json).unwrap().into_inner()
}

#[no_mangle]
pub unsafe extern "C" fn Java_io_elftrace_app_core_JNIBridge_scanSecurity(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jstring {
    if handle == 0 {
        return env
            .new_string("{\"total_findings\":0,\"findings\":[]}")
            .unwrap()
            .into_inner();
    }
    let ctx = &*(handle as *const ElfContext);
    let report = crate::scanner::scan_security(ctx);
    let json = serde_json::to_string(&report)
        .unwrap_or_else(|_| "{\"total_findings\":0,\"findings\":[]}".to_string());
    env.new_string(json).unwrap().into_inner()
}

#[no_mangle]
pub unsafe extern "C" fn Java_io_elftrace_app_core_JNIBridge_getEntropyReport(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jstring {
    if handle == 0 {
        return env.new_string("{\"overall_entropy\":0.0,\"overall_verdict\":\"Error\",\"is_likely_packed\":false,\"sections\":[]}").unwrap().into_inner();
    }
    let ctx = &*(handle as *const ElfContext);
    let report = crate::scanner::calculate_entropy_report(ctx);
    let json = serde_json::to_string(&report).unwrap_or_else(|_| "{}".to_string());
    env.new_string(json).unwrap().into_inner()
}

#[no_mangle]
pub unsafe extern "C" fn Java_io_elftrace_app_core_JNIBridge_loadScriptJson(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
    path_str: JString,
) -> jint {
    if handle == 0 {
        return 0;
    }
    let ctx = &mut *(handle as *mut ElfContext);
    let path: String = match env.get_string(path_str) {
        Ok(s) => s.into(),
        Err(_) => return 0,
    };
    match crate::il2cpp::load_script_json(ctx, &path) {
        Ok(count) => count as jint,
        Err(_) => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn Java_io_elftrace_app_core_JNIBridge_loadGlobalMetadata(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
    path_str: JString,
) -> jint {
    if handle == 0 {
        return -1;
    }
    let ctx = &mut *(handle as *mut ElfContext);
    let path: String = match env.get_string(path_str) {
        Ok(s) => s.into(),
        Err(_) => return -1,
    };
    match crate::il2cpp::load_global_metadata(ctx, &path) {
        Ok(_) => 0,   // validated, no symbols injected (expected)
        Err(_) => -1, // file invalid
    }
}

#[no_mangle]
pub unsafe extern "C" fn Java_io_elftrace_app_core_JNIBridge_renameFunction(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
    address: jlong,
    new_name: JString,
) -> jboolean {
    if handle == 0 {
        return 0;
    }
    let ctx = &mut *(handle as *mut ElfContext);
    let name: String = match env.get_string(new_name) {
        Ok(s) => s.into(),
        Err(_) => return 0,
    };
    if ctx.rename_function(address as u64, &name) {
        1
    } else {
        0
    }
}
