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
// Panic Guard
// ==========================================
//
// The ELF parser and disassembler contain `unwrap()`s on bounds that are
// normally checked, but a malformed or adversarial ELF can still reach a panic.
// With `panic = "unwind"` (see Cargo.toml) we catch it here and return a valid
// JSON error string instead of aborting the entire process.
//
// Usage: wrap the body of a `Java_*` export that returns a `jstring`.
unsafe fn guard_jstring<F>(env: &JNIEnv, fallback_json: &str, f: F) -> jstring
where
    F: FnOnce() -> jstring,
{
    // AssertUnwindSafe: the closures only touch the read-only ElfContext and the
    // JNIEnv. The single-threaded native dispatcher guarantees no concurrent
    // mutation, so a panic leaving partially-observed state is not a soundness
    // concern here.
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(js) => js,
        Err(_) => match env.new_string(fallback_json) {
            Ok(s) => s.into_inner(),
            Err(_) => std::ptr::null_mut(),
        },
    }
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
    let raw_vaddr = address as u64;
    let e_machine = ctx.get_info().map(|i| i.e_machine).unwrap_or(183);
    let vaddr = if e_machine == 40 { raw_vaddr & !1 } else { raw_vaddr };

    let offset = match ctx.vaddr_to_offset(vaddr) {
        Some(off) => off as usize,
        None => return env.new_string("{\"data\":[]}").unwrap().into_inner(),
    };

    if offset >= ctx.raw.len() {
        return env.new_string("{\"data\":[]}").unwrap().into_inner();
    }

    let code_slice = &ctx.raw[offset..];
    let is_thumb = if e_machine == 40 {
        thumb == JNI_TRUE
            || (raw_vaddr & 1) != 0
            || crate::decompiler::find_function_range(ctx, vaddr).thumb
    } else {
        false
    };

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
    let len = ctx.raw.len();
    let j_arr = env.new_byte_array(len as i32).unwrap();
    if len > 0 {
        // Zero-copy reinterpretation: the JNI API wants &[i8], but the bytes are
        // already in memory. Avoids duplicating the whole file (which can be
        // hundreds of MB for a large .so).
        let signed_slice: &[i8] =
            std::slice::from_raw_parts(ctx.raw.as_ptr() as *const i8, len);
        env.set_byte_array_region(j_arr, 0, signed_slice).unwrap();
    }
    j_arr
}

unsafe fn handle_finalize(handle: jlong) {
    if handle != 0 {
        let _ = Box::from_raw(handle as *mut ElfContext);
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
    guard_jstring(&env, "{\"error\":\"panic while parsing ELF info\"}", || {
        handle_info(&env, handle)
    })
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
    guard_jstring(&env, "{\"error\":\"panic while disassembling\",\"data\":[]}", || {
        handle_disasm(&env, handle, address, size, thumb)
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_io_elftrace_app_core_JNIBridge_dec0(
    env: JNIEnv,
    _class: JClass,
    mode: jint,
    handle: jlong,
    address: jlong,
) -> jstring {
    guard_jstring(&env, "// [Error] panic during decompilation\n", || {
        handle_dec(&env, mode, handle, address)
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_io_elftrace_app_core_JNIBridge_strings0(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jstring {
    guard_jstring(&env, "{\"error\":\"panic while extracting strings\",\"data\":[]}", || {
        handle_strings(&env, handle)
    })
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

    guard_jstring(&env, "{\"target_address\":0,\"refs\":[]}", || {
        let refs = crate::xref::find_callers_to(ctx, target_vaddr);
        let resp = crate::xref::XRefResponse {
            target_address: target_vaddr,
            refs,
        };
        let json = serde_json::to_string(&resp)
            .unwrap_or_else(|_| "{\"target_address\":0,\"refs\":[]}".to_string());
        env.new_string(json).unwrap().into_inner()
    })
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

    guard_jstring(&env, "{\"function_address\":0,\"function_name\":\"\",\"callers\":[],\"callees\":[]}", || {
        let hierarchy = crate::xref::get_hierarchy(ctx, target_vaddr);
        let json = serde_json::to_string(&hierarchy).unwrap_or_else(|_| "{}".to_string());
        env.new_string(json).unwrap().into_inner()
    })
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
    guard_jstring(&env, "{\"total_findings\":0,\"findings\":[]}", || {
        let report = crate::scanner::scan_security(ctx);
        let json = serde_json::to_string(&report)
            .unwrap_or_else(|_| "{\"total_findings\":0,\"findings\":[]}".to_string());
        env.new_string(json).unwrap().into_inner()
    })
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
    guard_jstring(&env, "{\"overall_entropy\":0.0,\"overall_verdict\":\"Error\",\"is_likely_packed\":false,\"sections\":[]}", || {
        let report = crate::scanner::calculate_entropy_report(ctx);
        let json = serde_json::to_string(&report).unwrap_or_else(|_| "{}".to_string());
        env.new_string(json).unwrap().into_inner()
    })
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

#[no_mangle]
pub unsafe extern "C" fn Java_io_elftrace_app_core_JNIBridge_runPlugin(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
    plugin_json: JString,
) -> jstring {
    if handle == 0 {
        return env
            .new_string("{\"plugin_id\":\"\",\"plugin_name\":\"\",\"total_findings\":0,\"findings\":[],\"error\":\"Invalid handle\"}")
            .unwrap()
            .into_inner();
    }
    let ctx = &*(handle as *const ElfContext);
    let json_str: String = match env.get_string(plugin_json) {
        Ok(s) => s.into(),
        Err(_) => {
            return env
                .new_string("{\"plugin_id\":\"\",\"plugin_name\":\"\",\"total_findings\":0,\"findings\":[],\"error\":\"Invalid plugin JSON\"}")
                .unwrap()
                .into_inner();
        }
    };
    guard_jstring(&env, "{\"plugin_id\":\"\",\"plugin_name\":\"\",\"total_findings\":0,\"findings\":[],\"error\":\"panic while running plugin\"}", || {
        let out = crate::plugins::run_plugin_json(ctx, &json_str);
        env.new_string(out).unwrap().into_inner()
    })
}

#[no_mangle]
pub unsafe extern "C" fn Java_io_elftrace_app_core_JNIBridge_applyPluginPatch(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
    address: jlong,
    mode_str: JString,
    value_str: JString,
) -> jstring {
    if handle == 0 {
        return env
            .new_string("{\"success\":false,\"error\":\"Invalid handle\"}")
            .unwrap()
            .into_inner();
    }
    let ctx = &mut *(handle as *mut ElfContext);
    let mode: String = match env.get_string(mode_str) {
        Ok(s) => s.into(),
        Err(_) => {
            return env
                .new_string("{\"success\":false,\"error\":\"Invalid patch mode\"}")
                .unwrap()
                .into_inner();
        }
    };
    let value: String = match env.get_string(value_str) {
        Ok(s) => s.into(),
        Err(_) => {
            return env
                .new_string("{\"success\":false,\"error\":\"Invalid patch value\"}")
                .unwrap()
                .into_inner();
        }
    };
    let res = crate::plugins::apply_plugin_patch(ctx, address as u64, &mode, &value);
    let out = serde_json::to_string(&res).unwrap_or_else(|_| "{}".to_string());
    env.new_string(out).unwrap().into_inner()
}
