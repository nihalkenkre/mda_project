[bits 64]

push r15
sub rsp, 8
call reloc_base

reloc_base:
    pop r15
    sub r15, 11

jmp main

main:
        push rbp
        mov rbp, rsp

        sub rsp, 32                         ; shadow space
        
        ; Get a handle to the target proc
        mov rcx, 0x1fFFFF
        xor rdx, rdx
        mov r8, [r15 + params + 1240]
        call [r15 + params + 1264]          ; openProcess

        ; save the handle value for retrival
        mov [r15 + params + 1232], rax;     ; target proc hnd
        
        ; wait for 3 secs for the retrival to happen
        mov rcx, 3000
        call [r15 + params + 1256]          ; sleep

        ; close the handle
        mov rcx, [r15 + params + 1232]      ; target proc hnd
        call [r15 + params + 1272]          ; closeHandle

        ; continue to ctx
        mov rcx, r15
        add rcx, params                     ; ntContinueCtx
        xor rdx, rdx
        call [r15 + params + 1248]        ; ntcontinue

align 16
params:
; ntContinueCtx         0
; retVal                1232    retVal
; params                1240    (1 - open process)
; func3                 1248    ntContinue
; func2                 1256    Sleep
; func1                 1264    openProcess
; func0                 1272    closeHandle