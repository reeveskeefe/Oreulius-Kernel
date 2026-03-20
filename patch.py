with open("kernel/src/execution/wasm.rs", "r") as f:
    content = f.read()

import re

old_text = """fn parsed_signature_equal(a: ParsedFunctionType, b: ParsedFunctionType) -> bool {
    if a.param_count != b.param_count || a.result_count != b.result_count {
        return false;
    }
    let mut i = 0usize;
    while i < a.param_count {
        if a.param_types[i] != b.param_types[i] {
            return false;
        }
        i += 1;
    }
    let mut r = 0usize;
    while r < a.result_count {
        if a.result_types[r] != b.result_types[r] {
            return false;
        }
        r += 1;
    }
    true
}"""

new_text = """fn parsed_signature_equal(a: ParsedFunctionType, b: ParsedFunctionType) -> bool {
    if a.param_count != b.param_count || a.result_count != b.result_count {
        return false;
    }
    if a.param_count > MAX_WASM_TYPE_ARITY || a.result_count > MAX_WASM_TYPE_ARITY {
        return false;
    }
    let mut i = 0usize;
    while i < a.param_count {
        if a.param_types[i] != b.param_types[i] {
            return false;
        }
        i += 1;
    }
    let mut r = 0usize;
    while r < a.result_count {
        if a.result_types[r] != b.result_types[r] {
            return false;
        }
        r += 1;
    }
    true
}"""

if old_text in content:
    content = content.replace(old_text, new_text)
    with open("kernel/src/execution/wasm.rs", "w") as f:
        f.write(content)
    print("Patched parsed_signature_equal successfully")
else:
    print("Could not find parsed_signature_equal block")
