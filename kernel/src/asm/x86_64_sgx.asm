; Oreulius Kernel Project
; SPDX-License-Identifier: BUSL-1.1
;
; x86_64_sgx.asm — Intel SGX ENCLS/ENCLU wrappers and EPC discovery (64-bit)
;
; Provides:
;   sgx_encls           — ring-0 SGX hypervisor leaf dispatcher (ENCLS, 0F 01 CF)
;   sgx_enclu           — ring-3 SGX user-mode leaf dispatcher (ENCLU, 0F 01 D7)
;   sgx_cpuid_leaf12    — CPUID leaf 0x12 sub-leaf query for EPC enumeration
;   sgx_read_feature_ctrl — read IA32_FEATURE_CONTROL MSR (0x3A)
;   sgx_write_sgxlepubkeyhash — write IA32_SGXLEPUBKEYHASHn MSRs for FLC
;
; ABI: System V AMD64 (rdi=arg0, rsi=arg1, rdx=arg2, rcx=arg3, r8=arg4)
; All functions are `extern "C"` compatible.
;
; SGX ENCLS ABI (Intel SDM Vol 3D §38.3):
;   EAX = leaf
;   RBX = operand 1 (pointer-sized)
;   RCX = operand 2 (pointer-sized)
;   RDX = operand 3 (pointer-sized)
;   Returns: EAX = 0 on success, error code on failure
;
; Build: nasm -f elf64 x86_64_sgx.asm -o x86_64_sgx.o

[bits 64]
default rel

section .text

; ---- sgx_encls ---------------------------------------------------------------
; Prototype: u32 sgx_encls(u32 leaf, u64 rbx_operand, u64 rcx_operand, u64 rdx_operand)
; rdi = leaf (u32)
;   rsi = RBX operand (u64 — typically a pointer)
;   rdx = RCX operand (u64 — note: rdx passes arg2 in SysV, maps to RCX for SGX)
;   rcx = RDX operand (u64 — rcx passes arg3 in SysV, maps to RDX for SGX)
; Returns u32 in eax (zero-extended to rax).
;
; ENCLS is a ring-0 only instruction.  The CPU faults with #UD if executed
; from CPL>0 or when CR0.PE=0.  The hardware also requires:
;   - CPUID.12H:EAX[0] = 1  (SGX1 supported)
;   - IA32_FEATURE_CONTROL[18] = 1 (SGX global enable)
;   - IA32_FEATURE_CONTROL[0]  = 1 (lock bit set)
; If any condition is not met the instruction generates #UD or #GP.
;
; Caller must ensure these preconditions.  sgx_cpu_ready() in enclave.rs
; validates IA32_FEATURE_CONTROL before dispatching here.

global sgx_encls
sgx_encls:
    ; SysV args:  rdi=leaf  rsi=rbx_op  rdx=rcx_op  rcx=rdx_op
    ; SGX ENCLS:  eax=leaf  rbx=ptr     rcx=ptr      rdx=ptr
    ;
    ; Shuffle: SysV rdx→SGX rcx, SysV rcx→SGX rdx.
    ; Use r10 (caller-saved) to avoid the read-after-write hazard on rcx.
    ; Save rbx (callee-saved per SysV ABI).
    push    rbx

    mov     r10, rcx        ; save SysV rcx (rdx_operand) before we clobber rcx
    mov     eax, edi        ; leaf → eax
    mov     rbx, rsi        ; rbx_operand → rbx
    mov     rcx, rdx        ; SysV rdx → SGX RCX operand
    mov     rdx, r10        ; SysV rcx (saved) → SGX RDX operand

    ; Execute ENCLS: opcode 0F 01 CF
    db      0x0F, 0x01, 0xCF

    ; EAX = status on return.  movzx ensures upper 32 bits are zeroed.
    ; eax already zero-extends to rax on x86_64

    pop     rbx
    ret

; ---- sgx_enclu ---------------------------------------------------------------
; Prototype: u32 sgx_enclu(u32 leaf, u64 rbx_operand, u64 rcx_operand, u64 rdx_operand)
; Same argument mapping as sgx_encls above.
;
; ENCLU is a ring-3 callable instruction (CPL 3 allowed when the SECS flags
; permit it).  The kernel calls ENCLU only for EENTER (leaf=2) to transfer
; control into an enclave TCS.  EEXIT (leaf=4) is executed from enclave code.
;
; On EENTER, the CPU saves the host state into a State Save Area (SSA) and
; jumps to the TCS.OENTRY offset within the enclave.  Execution returns here
; (via EEXIT or an AEX) with EAX=0 on success.

global sgx_enclu
sgx_enclu:
    push    rbx

    mov     r10, rcx        ; save SysV rcx (rdx_operand)
    mov     eax, edi
    mov     rbx, rsi
    mov     rcx, rdx        ; SysV rdx → SGX RCX operand
    mov     rdx, r10        ; saved SysV rcx → SGX RDX operand

    ; Execute ENCLU: opcode 0F 01 D7
    db      0x0F, 0x01, 0xD7

    ; eax already zero-extends to rax on x86_64

    pop     rbx
    ret

; ---- sgx_cpuid_leaf12 --------------------------------------------------------
; Prototype:
;   void sgx_cpuid_leaf12(u32 sub_leaf,
;                         u32 *out_eax, u32 *out_ebx,
;                         u32 *out_ecx, u32 *out_edx)
; rdi = sub_leaf
; rsi = *out_eax
; rdx = *out_ebx
; rcx = *out_ecx
; r8  = *out_edx
;
; CPUID leaf 0x12 (SGX Enumeration):
;   sub_leaf 0 → SGX1/SGX2 capability flags
;   sub_leaf 1 → MISCSELECT/ATTRIBUTES/XFRM
;   sub_leaf 2+ → EPC sections  (ECX[3:0] = type; 1 = confidential EPC section)
;       ECX[3:0]=1:  EAX[31:12]:EBX[19:0] = EPC physical base PA (52-bit)
;                    ECX[31:12]:EDX[19:0]  = EPC section size     (52-bit)
;       ECX[3:0]=0:  no more EPC sections
;
; Callers iterate sub_leaf from 2 upward until ECX[3:0] returns 0.

global sgx_cpuid_leaf12
sgx_cpuid_leaf12:
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15

    ; Save output pointer args before CPUID clobbers rcx/rdx etc.
    mov     r12, rsi    ; *out_eax
    mov     r13, rdx    ; *out_ebx
    mov     r14, rcx    ; *out_ecx
    mov     r15, r8     ; *out_edx

    mov     eax, 0x12   ; CPUID leaf 12h
    mov     ecx, edi    ; sub_leaf

    cpuid               ; out: eax, ebx, ecx, edx

    ; Store results through output pointers (if non-null).
    test    r12, r12
    jz      .no_eax
    mov     dword [r12], eax
.no_eax:
    test    r13, r13
    jz      .no_ebx
    mov     dword [r13], ebx
.no_ebx:
    test    r14, r14
    jz      .no_ecx
    mov     dword [r14], ecx
.no_ecx:
    test    r15, r15
    jz      .no_edx
    mov     dword [r15], edx
.no_edx:

    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret

; ---- sgx_read_feature_ctrl ---------------------------------------------------
; Prototype: u64 sgx_read_feature_ctrl(void)
; Returns the value of IA32_FEATURE_CONTROL MSR (0x3A).
; Reads are safe from ring-0; will #GP if called from ring-3.

global sgx_read_feature_ctrl
sgx_read_feature_ctrl:
    xor     ecx, ecx
    mov     ecx, 0x3A       ; IA32_FEATURE_CONTROL
    rdmsr                   ; EDX:EAX = MSR value
    shl     rdx, 32
    or      rax, rdx        ; combine into 64-bit rax
    ret

; ---- sgx_write_sgxlepubkeyhash -----------------------------------------------
; Prototype: void sgx_write_sgxlepubkeyhash(u64 hash0, u64 hash1, u64 hash2, u64 hash3)
; rdi = SGXLEPUBKEYHASH0 (MSR 0x8C)
; rsi = SGXLEPUBKEYHASH1 (MSR 0x8D)
; rdx = SGXLEPUBKEYHASH2 (MSR 0x8E)
; rcx = SGXLEPUBKEYHASH3 (MSR 0x8F)
;
; Flexible Launch Control (FLC, CPUID.7.ECX[30]) allows the platform owner
; (OS/VMM running at ring-0) to set the SHA-256 hash of the launch enclave
; public key.  When SGXLEPUBKEYHASHn matches the signing key in a SIGSTRUCT,
; EINIT succeeds without requiring Intel's proprietary Launch Enclave.
;
; The hash must be written as four 64-bit little-endian chunks covering the
; 256-bit SHA-256 hash of the launch enclave public modulus (big-endian).
;
; NOTE: IA32_FEATURE_CONTROL[17] (SGX_LC_ENABLE) must be 1 and the lock bit
;       (bit 0) must NOT yet be set, or this write will #GP.  On systems where
;       the firmware has already locked IA32_FEATURE_CONTROL, you can only
;       write SGXLEPUBKEYHASHn if the VMX FLC controls are used instead.

global sgx_write_sgxlepubkeyhash
sgx_write_sgxlepubkeyhash:
    ; rdx is both hash2 (SysV arg2) and the high-word register for WRMSR.
    ; Save hash2 and hash3 into callee-saved registers before any WRMSR clobbers rdx.
    push    rbx
    push    r12

    mov     rbx, rdx        ; hash2 → rbx (callee-saved)
    mov     r12, rcx        ; hash3 → r12 (callee-saved)

    ; Write SGXLEPUBKEYHASH0 (MSR 0x8C) = rdi (hash0)
    mov     ecx, 0x8C
    mov     eax, edi
    mov     rdx, rdi
    shr     rdx, 32
    wrmsr

    ; Write SGXLEPUBKEYHASH1 (MSR 0x8D) = rsi (hash1)
    mov     ecx, 0x8D
    mov     eax, esi
    mov     rdx, rsi
    shr     rdx, 32
    wrmsr

    ; Write SGXLEPUBKEYHASH2 (MSR 0x8E) = rbx (original rdx = hash2)
    mov     ecx, 0x8E
    mov     eax, ebx
    mov     rdx, rbx
    shr     rdx, 32
    wrmsr

    ; Write SGXLEPUBKEYHASH3 (MSR 0x8F) = r12 (original rcx = hash3)
    mov     ecx, 0x8F
    mov     eax, r12d
    mov     rdx, r12
    shr     rdx, 32
    wrmsr

    pop     r12
    pop     rbx
    ret

; ---- sgx_eremove -------------------------------------------------------------
; Prototype: u32 sgx_eremove(u64 epc_page_ptr)
; Removes a single EPC page from the enclave (ENCLS leaf EREMOVE = 0x8).
; rdi = linear address of the EPC page to remove.
; Returns 0 on success, SGX error code on failure.
;
; Must be called after EINIT has completed and the enclave is being torn down.
; The page must not be in use (TCS must be inactive, SSA must be empty).

global sgx_eremove
sgx_eremove:
    push    rbx

    xor     eax, eax
    mov     eax, 0x8        ; ENCLS leaf EREMOVE = 8
    xor     rbx, rbx        ; RBX = 0 (not used for EREMOVE)
    mov     rcx, rdi        ; RCX = linear address of the EPC page

    db      0x0F, 0x01, 0xCF    ; ENCLS

    ; eax already zero-extends to rax on x86_64

    pop     rbx
    ret

; ---- Stack guard (no executable stack) ---------------------------------------
section .note.GNU-stack noalloc noexec nowrite progbits
