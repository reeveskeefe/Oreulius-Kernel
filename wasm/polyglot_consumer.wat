(module
  (import "oreulius" "polyglot_link" (func $polyglot_link (param i32 i32 i32 i32) (result i32)))
  (import "oreulius" "service_invoke" (func $service_invoke (param i32 i32 i32) (result i32)))
  (memory 1)
  (data (i32.const 0) "svc")
  (data (i32.const 16) "add")
  (data (i32.const 32) "missing")

  (func (export "_start")
    (local $cap i32)
    i32.const 0
    i32.const 3
    i32.const 16
    i32.const 3
    call $polyglot_link
    local.set $cap
    local.get $cap
    i32.const 0
    i32.const 0
    call $service_invoke
    drop

    i32.const 0
    i32.const 3
    i32.const 32
    i32.const 7
    call $polyglot_link
    drop))
