(module
  (import "oreulius" "polyglot_link" (func $polyglot_link (param i32 i32 i32 i32) (result i32)))
  (import "oreulius" "polyglot_lineage_rebind" (func $polyglot_lineage_rebind (param i32 i32) (result i32)))
  (import "oreulius" "polyglot_lineage_event_query" (func $polyglot_lineage_event_query (param i32 i32 i32 i32) (result i32)))
  (import "oreulius" "proc_exit" (func $proc_exit (param i32)))

  (memory 1)
  (data (i32.const 0) "svc")
  (data (i32.const 16) "add")

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
    call $polyglot_lineage_rebind
    drop

    i32.const 0
    i32.const 8
    i32.const 256
    i32.const 40
    call $polyglot_lineage_event_query
    drop

    i32.const 0
    call $proc_exit))
