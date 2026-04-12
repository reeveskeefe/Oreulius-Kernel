(module
  (import "oreulius" "service_register" (func $service_register (param i32 i32) (result i32)))

  (func $add (result i32)
    i32.const 1)

  (func $sub (result i32)
    i32.const 2)

  (func (export "_start")
    i32.const 1
    i32.const 1
    call $service_register
    drop
    i32.const 2
    i32.const 1
    call $service_register
    drop)

  (export "add" (func $add))
  (export "sub" (func $sub)))
