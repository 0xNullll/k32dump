; ============================================================
; k32dump.asm
;   desc:    maps a file and dumps hex/dec/oct/bin + offset
;            to stdout using only kernel32 functions
;   target:  x86 32-bit Windows (NASM, stdcall)
;   author:  0xNullll (https://github.com/0xNullll)
;   nasm:    2.16 (compiled Dec 20 2022)
;   build:   nasm -w+all -f win32 k32dump.asm -o k32dump.obj
;            link /subsystem:console /entry:_main /nodefaultlib k32dump.obj
;                 <path to Windows Kits x86 um lib>\kernel32.lib
;   note:    kernel32.lib is found in the Windows SDK under
;            Lib\<version>\um\x86\kernel32.lib
; ============================================================

; --- 32-bit mode ---
BITS 32

; --- export entry point to linker ---
global _main

; --- utility functions ---
extern _GetStdHandle@4
extern _GetFileSize@8

; --- Main stdout/stdin and IO functions ---
extern _WriteConsoleA@20
extern _GetCommandLineA@0
extern _CreateFileA@28
extern _CreateFileMappingA@24
extern _MapViewOfFile@20

; --- Error handling and memory cleaning functions ---
extern _GetLastError@0
extern _FormatMessageA@28
extern _UnmapViewOfFile@4
extern _CloseHandle@4
extern _ExitProcess@4

%define CRLF         13, 10
%define STDIN        -10
%define STDOUT       -11
%define STDERR       -12
%define MAX_PATH     260

struc arg_t
    .arg_start:     resd 1      ; offset 0, 4 bytes
    .arg_end:       resd 1      ; offset 4, 4 bytes
endstruc                        ; arg_t_size = 8

section .data
    ; --- error messages ---
    err_handles_msg         db "(!) Failed to acquire STD handles...", CRLF, 0
    err_handles_msg_len     equ $ - err_handles_msg

    err_open_msg            db "(!) Failed to open file...", CRLF, 0
    err_open_msg_len        equ $ - err_open_msg

    err_mapping_msg         db "(!) Failed to create file mapping...", CRLF, 0
    err_mapping_msg_len     equ $ - err_mapping_msg

    err_mapview_msg         db "(!) Failed to map view of file...", CRLF, 0
    err_mapview_msg_len     equ $ - err_mapview_msg

    err_usage_msg           db "(!) Usage: k32dump.exe <filename> [-h | -d | -o | -b]", CRLF, 0
    err_usage_msg_len       equ $ - err_usage_msg

    err_parse_arg_msg       db "(!) Failed to parse arguments...", CRLF, 0
    err_parse_arg_msg_len   equ $ - err_parse_arg_msg

    err_general_msg         db "(!) Error: ", 0
    err_general_msg_len     equ $ - err_general_msg

    ; --- header ---
    ; Hex (2 chars per byte) - offsets in hex
    header_hex              db "(*) Offset    00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F", CRLF
                            db "    --------  ------------------------------------------------", CRLF, 0
    header_hex_len          equ $ - header_hex

    ; Decimal (3 chars per byte) - offsets in hex but padded to 3
    header_dec              db "(*) Offset     00  01  02  03  04  05  06  07  08  09  0A  0B  0C  0D  0E  0F", CRLF
                            db "    --------  ---------------------------------------------------------------", CRLF, 0
    header_dec_len          equ $ - header_dec

    ; Octal (3 chars per byte) - same width as decimal
    header_oct              db "(*) Offset     00  01  02  03  04  05  06  07  08  09  0A  0B  0C  0D  0E  0F", CRLF
                            db "    --------  ---------------------------------------------------------------", CRLF, 0
    header_oct_len          equ $ - header_oct

    ; Binary (8 chars per byte, 8 bytes per row)
    header_bin              db "(*) Offset    00       01       02       03       04       05       06       07", CRLF
                            db "    --------  -----------------------------------------------------------------------", CRLF, 0
    header_bin_len          equ $ - header_bin

    ; --- footers ---
    footer_hex  db "    --------  ------------------------------------------------", CRLF, 0
    footer_hex_len  equ $ - footer_hex

    footer_dec  db "    --------  ---------------------------------------------------------------", CRLF, 0
    footer_dec_len  equ $ - footer_dec

    footer_oct  db "    --------  ---------------------------------------------------------------", CRLF, 0
    footer_oct_len  equ $ - footer_oct

    footer_bin  db "    --------  -----------------------------------------------------------------------", CRLF, 0
    footer_bin_len  equ $ - footer_bin

    ; table: index = base, value = pad width
    pad_table:
        dd 0    ; base 0  - unused
        dd 0    ; base 1  - unused
        dd 8    ; base 2  - binary  (8 digits for a byte)
        dd 0    ; base 3  - unused
        dd 0    ; base 4  - unused
        dd 0    ; base 5  - unused
        dd 0    ; base 6  - unused
        dd 0    ; base 7  - unused
        dd 3    ; base 8  - octal   (3 digits for a byte)
        dd 0    ; base 9  - unused
        dd 3    ; base 10 - decimal (3 digits for a byte)
        dd 0    ; base 11 - unused
        dd 0    ; base 12 - unused
        dd 0    ; base 13 - unused
        dd 0    ; base 14 - unused
        dd 0    ; base 15 - unused
        dd 2    ; base 16 - hex     (2 digits for a byte)

section .bss
    ; --- Reserved STD handles ---
    stdin_handle        resd 1
    stdout_handle       resd 1
    stderr_handle       resd 1

    ; --- Reserved buffer to store the filename and one flag ---
    argv                resb arg_t_size * 3
    argv_size           equ $ - argv
    
    base_encoder        resb 1

    ; --- Reserved file handles and metadata ---
    file_handle         resd 1      ; CreateFileA
    mapping_object      resd 1      ; CreateFileMappingA
    file_view           resd 1      ; MapViewOfFile (ptr to file bytes)
    file_size           resd 1      ; GetFileSize

    ; --- Reserved dword for the last error
    last_error          resd 1

section .text

; --------------------------------------------------------
; init_handles
;   purpose: Gets current process stdin, stdout and stderr handles
;   input:   [ebp+8]  (4 bytes) - ptr to stdin storage
;            [ebp+12] (4 bytes) - ptr to stdout storage
;            [ebp+16] (4 bytes) - ptr to stderr storage
;   output:  eax = 0 on success, -1 on failure (failed to initialize given handles)
;   trashes: ecx, edx
;   saves:   none
; --------------------------------------------------------
init_handles:
    push ebp
    mov  ebp, esp

    ; Get STDIN handle, Else jump to '.fail'
    push STDIN
    call _GetStdHandle@4
    test eax, eax
    jz   .fail
    cmp  eax, -1
    je   .fail
    mov  ecx, [ebp+8]
    mov  [ecx], eax

    ; Get STDOUT handle, Else jump to '.fail'
    push STDOUT
    call _GetStdHandle@4
    test eax, eax
    jz   .fail
    cmp  eax, -1
    je   .fail
    mov  ecx, [ebp+12]
    mov  [ecx], eax

    ; Get STDERR handle, Else jump to '.fail'
    push STDERR
    call _GetStdHandle@4
    test eax, eax
    jz   .fail
    cmp  eax, -1
    je   .fail
    mov  ecx, [ebp+16]
    mov  [ecx], eax

    ; Return 0 for sucess
    xor  eax, eax
    pop  ebp
    ret  12

.fail:
    ; Return 1 for failure
    mov  eax, -1
    pop  ebp
    ret  12

; --------------------------------------------------------
; write_console
;   purpose: writes a buffer to any valid output handle
;   input:   [ebp+8]  handle  (4 bytes) - stdout or stderr
;            [ebp+12] buf ptr (4 bytes)
;            [ebp+16] buf len (4 bytes)
;   output:  eax = 0 on success, eax = -1 on failure
;   trashes: ecx, edx
;   saves:   none
;   stack:   4 bytes (1 local slot)
;              ebp-4  = bytes written (passed to WriteConsoleA)
; --------------------------------------------------------
write_console:
    push ebp
    mov  ebp, esp
    sub  esp, 4                  ; local: bytes written

    mov  dword [ebp-4], 0

    mov  eax, [ebp+8]            ; handle (whatever was passed)
    cmp  eax, 0
    je   .fail
    cmp  eax, -1
    je   .fail

    mov  ecx, [ebp+12]           ; buf ptr
    mov  edx, [ebp+16]           ; buf len
    lea  edi, [ebp-4]            ; ptr to bytes written

    push dword 0
    push edi
    push edx
    push ecx
    push eax
    call _WriteConsoleA@20
    test eax, eax
    jz   .fail

    mov  esp, ebp
    pop  ebp
    xor  eax, eax
    ret  12

.fail:
    mov  esp, ebp
    pop  ebp
    mov  eax, -1
    ret  12

; --------------------------------------------------------
; print_error
;   purpose: prints a custom message followed by the windows
;            error string retrieved via FormatMessageA
;   input:   [ebp+8]  handle  (4 bytes)
;            [ebp+12] msg ptr (4 bytes)
;            [ebp+16] msg len (4 bytes)
;   output:  eax = 0 on success, eax = -1 on failure
;   trashes: ecx
;   saves:   none
;   stack:   516 bytes (1 local slot + format message buffer)
;              ebp-4   = error code / format message length
;              ebp-512 = FormatMessageA output buffer
; --------------------------------------------------------
print_error:
    push ebp
    mov  ebp, esp
    sub  esp, 516

    call _GetLastError@0
    mov  [ebp-516], eax         ; save error code at bottom of buffer space

    push 0                      ; Arguments = NULL
    push 512                    ; nSize
    lea  ecx, [ebp-512]         ; ptr to our stack buffer
    push ecx                    ; lpBuffer
    push 0                      ; dwLanguageId = NULL
    push dword [ebp-516]        ; dwMessageId (error code)
    push 0                      ; lpSource = NULL
    push 0x1000 | 0x200         ; dwFlags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS
    call _FormatMessageA@28
    cmp eax, -1
    je .fail

    mov  [ebp-516], eax         ; reuse same slot for format length now

    push dword [ebp+16]
    push dword [ebp+12]
    push dword [ebp+8]
    call write_console
    test eax, eax
    jnz .fail

    push dword [ebp-516]
    lea  ecx, [ebp-512]
    push ecx
    push dword [ebp+8]
    call write_console
    test eax, eax
    jnz .fail

    mov  esp, ebp
    pop  ebp
    xor  eax, eax
    ret  12

.fail:
    mov  esp, ebp
    pop  ebp
    mov  eax, -1
    ret  12

; --------------------------------------------------------
; parse_arg
;   purpose: Parse an argument from a command line buffer
;            handles quoted ("" and '') and unquoted arguments
;   input:   [ebp+8]   buffer ptr              (4 bytes)
;            [ebp+12]  argument structure ptr  (4 bytes)
;   output:  eax = ptr to first char past parsed argument
;            eax = -1 on failure (null input / unterminated quote)
;   trashes: ecx, edx
;   saves:   none
; --------------------------------------------------------
parse_arg:
    push ebp
    mov  ebp, esp
    mov  ecx, [ebp+8]        ; ecx = pointer to command line buffer
    mov  edx, [ebp+12]       ; edx = pointer to argument structure

; skip leading spaces
.skip_spaces:
    cmp  byte [ecx], 0
    je   .fail
    cmp  byte [ecx], ' '
    jne  .found_start
    inc  ecx
    jmp  .skip_spaces

.found_start:
    cmp  byte [ecx], '"'
    je   .parse_quoted
    cmp  byte [ecx], "'"
    je   .parse_single_quoted

    mov  dword [edx + arg_t.arg_start], ecx

.find_end:
    cmp  byte [ecx], ' '
    je   .found_end
    cmp  byte [ecx], 0
    je   .found_end
    inc  ecx
    jmp  .find_end

.found_end:
    mov  dword [edx + arg_t.arg_end], ecx
    mov  eax, ecx

    mov  esp, ebp
    pop  ebp
    ret  8

.parse_quoted:
    inc  ecx
    mov  dword [edx + arg_t.arg_start], ecx

.find_quoted_end:
    cmp  byte [ecx], '"'
    je   .found_quoted_end
    cmp  byte [ecx], 0
    je   .fail
    inc  ecx
    jmp  .find_quoted_end

.found_quoted_end:
    mov  dword [edx + arg_t.arg_end], ecx
    inc  ecx
    mov  eax, ecx

    mov  esp, ebp
    pop  ebp
    ret  8

.parse_single_quoted:
    inc  ecx
    mov  dword [edx + arg_t.arg_start], ecx

.find_single_quoted_end:
    cmp  byte [ecx], "'"
    je   .found_single_quoted_end
    cmp  byte [ecx], 0
    je   .fail
    inc  ecx
    jmp  .find_single_quoted_end

.found_single_quoted_end:
    mov  dword [edx + arg_t.arg_end], ecx
    inc  ecx
    mov  eax, ecx

    mov  esp, ebp
    pop  ebp
    ret  8

.fail:
    mov  esp, ebp
    pop  ebp

    mov eax, -1

    ret  8

; --------------------------------------------------------
; build_arg_table
;   purpose: Parse a command line buffer into an arg table
;            populating argc and an array of arg_entry structs
;   input:   [ebp+8]  command line buffer ptr   (4 bytes)
;            [ebp+12] arg table buffer ptr      (4 bytes)
;            [ebp+16] arg table buffer size     (4 bytes)
;   output:  eax = argc (number of arguments parsed)
;            eax = -1 on failure (null input / buffer too small)
;   trashes: ecx, edx
;   saves:   none
;   stack:   4 bytes (1 local slot)
;              ebp-4  = argc counter
; --------------------------------------------------------
build_arg_table:
    push ebp
    mov ebp, esp
    sub esp, 4              ; local argc counter

    mov dword [ebp-4], 0    ; argc = 0

    mov  ecx, [ebp+8]       ; ecx = pointer to command line buffer
    mov  edx, [ebp+12]      ; ecx = pointer to buffer

    mov  eax, [ebp+16]      ; buffer size
    test eax, 7             ; divisible by 8?
    jnz  .fail              ; not aligned = invalid buffer size

.loop:
    push edx                ; save edx

    push edx
    push ecx
    call parse_arg          ; ret 8 cleans the two args
    
    pop  edx                ; restore saved edx

    cmp  eax, -1
    je   .done

    mov  ecx, eax           ; new cmdline position
    inc  dword [ebp-4]      ; increment argc
    add  edx, arg_t_size    ; next slot
    jmp  .loop

.done:
    mov eax, dword [ebp-4]

    mov  esp, ebp
    pop  ebp
    ret  12

.fail:
    mov  esp, ebp
    pop  ebp
    mov  eax, -1
    ret  12

; --------------------------------------------------------
; open_file
;   purpose: opens file, gets size, creates mapping and maps view
;   input:   [ebp+8] arg ptr    (4 bytes)
;   output:  eax = 0 on success, -1 on failure (failed to open the file)
;            sets file_handle, file_size, mapping_object, file_view
;   trashes: none
;   saves:   none
; --------------------------------------------------------
open_file:
    push ebp
    mov ebp, esp

    ; --- Get file handle ---
    push 0                               ; hTemplateFile = NULL
    push 0x80                            ; dwFlagsAndAttributes = FILE_ATTRIBUTE_NORMAL
    push 3                               ; dwCreationDisposition = OPEN_EXISTING
    push 0                               ; lpSecurityAttributes = NULL
    push 0x1                             ; dwShareMode = FILE_SHARE_READ 
    push 0x80000000                      ; dwDesiredAccess = GENERIC_READ
    push dword [ebp+8 + arg_t.arg_start] ; lpFileName
    call _CreateFileA@28
    test eax, eax
    je   .win_fail

    mov  dword [file_handle], eax

    ; --- Get file size ---
    push 0
    push dword [file_handle]    ; hFile
    call _GetFileSize@8
    test eax, eax
    je   .win_fail

    mov dword [file_size], eax

    ; --- Create a file mapping object ---
    push 0                      ; lpName (anonymous mapping)
    push 0                      ; dwMaximumSizeLow = 0 (use file size)
    push 0                      ; dwMaximumSizeHigh = 0 (use file size)
    push 2                      ; flProtect = PAGE_READONLY
    push 0                      ; lpFileMappingAttributes = NULL
    push dword [file_handle]    ; hFile
    call _CreateFileMappingA@24
    test eax, eax
    jz   .win_fail

    mov dword [mapping_object], eax

    ; --- Get a pointer to the file data ---
    push 0                      ; dwNumberOfBytesToMap = 0 (map whole file)
    push 0                      ; dwFileOffsetLow = 0 (start from beginning)
    push 0                      ; dwFileOffsetHigh = 0
    push 4                      ; dwDesiredAccess = FILE_MAP_READ
    push dword [mapping_object] ; hFileMappingObject
    call _MapViewOfFile@20

    test eax, eax
    jz   .win_fail              ; NULL on failure

    mov  dword [file_view], eax

    mov esp, ebp
    pop ebp

    xor eax, eax
    ret 

.win_fail:
    ; --- Print error message ---
    push err_general_msg_len
    push err_general_msg
    push dword [stderr_handle]
    call print_error

    call close_file

    mov esp, ebp
    pop ebp

    mov eax, -1
    ret

; --------------------------------------------------------
; close_file
;   purpose: unmaps file view and closes file handles
;   input:   none (uses file_view, mapping_object, file_handle)
;   output:  none
;   trashes: none
;   saves:   none
; --------------------------------------------------------
close_file:
    ; --- Cleanup mapped view ---
    mov  eax, [file_view]
    test eax, eax
    jz   .close_mapping

    push eax
    call _UnmapViewOfFile@4

.close_mapping:
    ; --- Cleanup mapping object ---
    mov  eax, [mapping_object]
    test eax, eax
    jz   .close_handle

    push eax
    call _CloseHandle@4

.close_handle:
    ; --- Cleanup file handle ---
    mov  eax, [file_handle]
    cmp  eax, -1
    je   .done
    test eax, eax
    jz   .done

    push eax
    call _CloseHandle@4

.done:
    ret

; --------------------------------------------------------
; num_to_str
;   purpose: converts a number to a string in a given base
;   input:   [ebp+8]  number to convert (4 bytes)
;            [ebp+12] buffer pointer    (4 bytes)
;            [ebp+16] encoder base      (4 bytes)
;            [ebp+20] pad_width         (4 bytes)
;   output:  eax = number of digits written (after padding)
;   trashes: ecx, edx
;   saves:   ebx, esi, edi
; --------------------------------------------------------
num_to_str:
    push ebp
    mov ebp, esp

    push ebx
    push edi
    push esi

    mov eax, [ebp+8]    ; number to convert
    mov esi, [ebp+12]   ; buffer pointer
    mov ebx, [ebp+16]   ; encoder base

    xor ecx, ecx        ; digit counter

.div_loop:
    xor edx, edx        ; clear EDX before every divide
    div ebx             ; eax = quotient, edx = remainder
    cmp edx, 10         ; let the user decide the quotient
    jl .is_decimal
    add edx, 0x37       ; 10-15 -> 'A' - 'F'
    jmp .done

.is_decimal:
    add edx, 0x30

.done:
    push edx
    inc ecx
    test eax, eax
    jnz .div_loop

    mov edi, ecx        ; save digit count in edi before pop loop destroys ecx

    mov ebx, [ebp+20]   ; padding width

.padding_loop:
    cmp ecx, ebx
    jge .save_count
    mov edx, 0x30
    push edx
    inc ecx
    jmp .padding_loop

.save_count:
    mov edi, ecx        ; save ONCE here, after padding, before loop

.pop_loop:
    pop edx
    mov byte [esi], dl
    inc esi
    dec ecx
    jnz .pop_loop

    mov eax, edi        ; pass the count back to user

    pop esi
    pop edi
    pop ebx

    mov esp, ebp
    pop ebp
    ret 16

; --------------------------------------------------------
; dump_header
;   purpose: Evaluate a parsed flag argument and prints
;             the corresponding correct header
;   input:   [ebp+8]  flag string ptr          (4 bytes)
;   output:  eax = 0 on success, eax = -1 on failure (unknown flag)
;   trashes: ecx
;   saves:   none
; --------------------------------------------------------
dump_header:
    push ebp
    mov  ebp, esp

    mov  eax, [ebp+8]

    cmp  byte [eax], '-'
    jne  .fail
    inc  eax                ; eax -> flag char

    movzx ecx, byte [eax]   ; save flag char
    inc  eax                ; eax -> terminator

    ; --- validate terminator ---
    cmp  byte [eax], ' '
    je   .dispatch
    cmp  byte [eax], 0
    je   .dispatch
    jmp  .fail

.dispatch:
    cmp  cl, 'h'
    je   .process_hex_header
    cmp  cl, 'd'
    je   .process_dec_header
    cmp  cl, 'o'
    je   .process_oct_header
    cmp  cl, 'b'
    je   .process_bin_header
    jmp  .fail

.process_hex_header:
    mov dword [base_encoder], 16

    push header_hex_len
    push header_hex
    push dword [stdout_handle]
    call write_console
    test eax, eax
    jnz  .fail
    jmp  .success

.process_dec_header:
    mov dword [base_encoder], 10

    push header_dec_len
    push header_dec
    push dword [stdout_handle]
    call write_console
    test eax, eax
    jnz  .fail
    jmp  .success

.process_oct_header:
    mov dword [base_encoder], 8

    push header_oct_len
    push header_oct
    push dword [stdout_handle]
    call write_console
    test eax, eax
    jnz  .fail
    jmp  .success

.process_bin_header:
    mov dword [base_encoder], 2

    push header_bin_len
    push header_bin
    push dword [stdout_handle]
    call write_console
    test eax, eax
    jnz  .fail

.success:
    mov  esp, ebp
    pop  ebp
    xor  eax, eax
    ret  4

.fail:
    mov  esp, ebp
    pop  ebp
    mov  eax, -1
    ret  4

; --------------------------------------------------------
; format_bytes
;   purpose: converts raw bytes into formatted string in buffer
;   input:   [ebp+8]  source pointer
;            [ebp+12] buffer pointer
;            [ebp+16] byte count
;            [ebp+20] base encoder
;   output:  eax = bytes written to buffer
;   trashes: ecx
;   saves:   ebx, edx, esi, edi
;   stack:   8 bytes (2 local slots)
;              ebp-4  = saved buffer start
;              ebp-8  = saved ecx across num_to_str
; --------------------------------------------------------
format_bytes:
    push ebp
    mov ebp, esp
    sub esp, 8

    push edi
    push esi
    push ebx
    push edx

    mov esi, [ebp+8]        ; source pointer
    mov edi, [ebp+12]       ; buffer pointer
    mov ebx, [ebp+16]       ; byte count
    mov edx, [ebp+20]       ; base encoder

    mov [ebp-4], edi        ; save buffer start

.byte_loop:
    mov [ebp-8], ecx        ; save ecx

    xor eax, eax
    mov al, [esi]
    push dword [pad_table + edx*4]
    push edx
    push edi
    push eax
    call num_to_str

    mov ecx, [ebp-8]
    mov edx, [ebp+20]       ; restore base from arg

    add edi, eax
    mov byte [edi], ' '
    inc edi

    inc esi
    dec ebx
    test ebx, ebx
    jnz .byte_loop

    ; compute bytes written
    mov eax, edi
    sub eax, [ebp-4]

    pop edx
    pop ebx
    pop esi
    pop edi

    mov esp, ebp
    pop ebp
    ret 16

; --------------------------------------------------------
; format_offset
;   purpose: converts offset value into buffer as hex string
;            preceded by four spaces and followed by two spaces
;   input:   [ebp+8]  buffer pointer
;            [ebp+12] offset value
;   output:  eax = bytes written
;   trashes: ecx
;   saves:   ebx, edx, esi, edi
;   stack:   4 bytes (1 local slot)
;              ebp-4  = saved buffer start
; --------------------------------------------------------
format_offset:
    push ebp
    mov ebp, esp
    sub esp, 4              ; allocate slot

    push edi
    push esi
    push ebx
    push edx

    mov edi, [ebp+8]        ; edi = buffer start
    mov [ebp-4], edi        ; save

    mov byte [edi], ' '
    inc edi
    mov byte [edi], ' '
    inc edi
    mov byte [edi], ' '
    inc edi
    mov byte [edi], ' '
    inc edi

    push dword 8
    push dword 16
    push edi                ; buffer position is already past the spaces
    push dword [ebp+12]
    call num_to_str         ; offset digits go after the spaces

    add edi, eax
    mov byte [edi], ' '
    inc edi
    mov byte [edi], ' '
    inc edi

    ; compute total bytes written
    mov eax, edi
    sub eax, [ebp+8]        ; eax = edi - buffer start

    pop edx
    pop ebx
    pop esi
    pop edi

    mov esp, ebp
    pop ebp
    ret 8

; --------------------------------------------------------
; format_line
;   purpose: converts one line of bytes into buffer
;   input:   [ebp+8]  source pointer
;            [ebp+12] buffer pointer
;            [ebp+16] byte count
;            [ebp+20] base encoder
;   output:  eax = bytes written to buffer
;   trashes: ecx
;   saves:   ebx, edx, esi, edi
;   stack:   16 bytes (2 local slots)
;              ebp-4  = saved buffer start
;              ebp-8  = saved ecx across num_to_str
; --------------------------------------------------------
format_line:
    push ebp
    mov ebp, esp
    sub esp, 16

    push edi
    push esi
    push ebx
    push edx

    mov esi, [ebp+8]        ; source pointer
    mov edi, [ebp+12]       ; buffer pointer
    mov ebx, [ebp+16]       ; byte count
    mov edx, [ebp+20]       ; base encoder

    mov [ebp-4], edi        ; save buffer start to compute length at end

.byte_loop:
    mov [ebp-8], ecx        ; save ecx

    xor eax, eax
    mov al, [esi]
    push dword [pad_table + edx*4]
    push edx
    push edi
    push eax
    call num_to_str

    mov ecx, [ebp-8]        ; restore
    mov edx, [ebp+20]       ; restore base from arg, not stack slot

    add edi, eax
    mov byte [edi], ' '
    inc edi

    inc esi
    dec ebx
    test ebx, ebx
    jnz .byte_loop

    ; compute bytes written
    mov eax, edi
    sub eax, [ebp-4]        ; eax = edi - buffer start

    pop edx
    pop ebx
    pop esi
    pop edi

    mov esp, ebp
    pop ebp
    ret 16

; --------------------------------------------------------
; dump_file
;   purpose: iterates over the mapped file and prints each
;            line of formatted hex/dec/oct/bin output to
;            stdout, handling both full and partial blocks
;   input:   none (reads file_view, file_size,
;                  base_encoder globals)
;   output:  eax = 0 on success, eax = -1 on failure
;   trashes: eax
;   saves:   ebx, edx, esi, edi
;   stack:   152 bytes (128 line buffer + 5 local slots)
;              ebp-128 = line buffer
;              ebp-132 = encoder base
;              ebp-136 = line width
;              ebp-140 = saved ecx
;              ebp-144 = saved edx
;              ebp-148 = offset counter
; --------------------------------------------------------
dump_file:
    push ebp
    mov ebp, esp
    sub esp, 152

    mov dword [ebp-148], 0

    push edi
    push esi
    push ebx
    push edx

    mov esi, dword [file_view]

    lea edi, [ebp-128]
    xor eax, eax
    mov ecx, 32
    rep stosd

    mov ecx, dword [file_size]

    mov edx, dword [base_encoder]
    mov ebx, 16
    cmp edx, 2
    jne .save
    mov ebx, 8
.save:
    mov [ebp-132], edx
    mov [ebp-136], ebx

.loop:
    lea edi, [ebp-128]          ; reset buffer

    mov ebx, [ebp-136]
    cmp ecx, ebx
    jb  .partial_block

.full_block:
    mov [ebp-140], ecx          ; save before format_offset

    ; format offset
    push dword [ebp-148]
    push edi
    call format_offset
    add edi, eax

    ; format bytes
    push dword [ebp-132]
    push ebx
    push edi
    push esi
    call format_bytes
    add esi, [ebp-136]
    add edi, eax

    mov ecx, [ebp-140]          ; restore here
    sub ecx, [ebp-136]

    jmp .print_line

.partial_block:
    test ecx, ecx
    jz .done

    ; format offset
    push dword [ebp-148]
    push edi
    call format_offset
    add edi, eax

    ; format bytes
    push dword [ebp-132]
    push ecx
    push edi
    push esi
    call format_bytes
    add edi, eax
    xor ecx, ecx

.print_line:
    mov byte [edi], 13
    inc edi
    mov byte [edi], 10
    inc edi

    lea eax, [ebp-128]
    sub edi, eax                ; edi = total length

    mov [ebp-140], ecx          ; save
    mov [ebp-144], edx          ; save

    push edi
    push eax
    push dword [stdout_handle]
    call write_console

    mov ecx, [ebp-140]          ; restore
    mov edx, [ebp-144]          ; restore
    
    test eax, eax
    jnz .fail                   ; not zero = failure

    mov eax, [ebp-136]
    add [ebp-148], eax          ; offset += line width

    jmp .loop

.done:
    pop edx
    pop ebx
    pop esi
    pop edi

    mov esp, ebp
    pop ebp

    xor eax, eax
    ret

.fail:
    pop edx
    pop ebx
    pop esi
    pop edi

    mov esp, ebp
    pop ebp

    mov eax, -1
    ret

; --------------------------------------------------------
; dump_footer
;   purpose: prints the closing footer line matching the
;            active base encoder format
;   input:   none (reads base_encoder global)
;   output:  eax = 0 on success, eax = -1 on failure
;   trashes: eax
;   saves:   none
; --------------------------------------------------------
dump_footer:
    push ebp
    mov  ebp, esp

    mov  eax, dword [base_encoder]

    cmp  eax, 16
    je   .hex
    cmp  eax, 10
    je   .dec
    cmp  eax, 8
    je   .oct
    cmp  eax, 2
    je   .bin
    jmp  .fail

.hex:
    push footer_hex_len
    push footer_hex
    push dword [stdout_handle]
    call write_console
    test eax, eax
    jnz  .fail
    jmp  .success

.dec:
    push footer_dec_len
    push footer_dec
    push dword [stdout_handle]
    call write_console
    test eax, eax
    jnz  .fail
    jmp  .success

.oct:
    push footer_oct_len
    push footer_oct
    push dword [stdout_handle]
    call write_console
    test eax, eax
    jnz  .fail
    jmp  .success

.bin:
    push footer_bin_len
    push footer_bin
    push dword [stdout_handle]
    call write_console
    test eax, eax
    jnz  .fail

.success:
    mov  esp, ebp
    pop  ebp
    xor  eax, eax
    ret

.fail:
    mov  esp, ebp
    pop  ebp
    mov  eax, -1
    ret

_main:
    ; --- Init process handles ---
    push dword stderr_handle
    push dword stdout_handle
    push dword stdin_handle
    call init_handles
    test eax, eax 
    jnz  .fail

    ; --- Parse command line arguments ---
    call _GetCommandLineA@0

    lea esi, dword [argv]

    push arg_t_size
    push esi
    push eax
    call build_arg_table
    cmp eax, -1 
    je  .fail

    cmp eax, 3          ; is argc == 3?
    jl .invalid_argv


    ; --- Null terminate file name ---
    mov  ecx, [esi + arg_t_size + arg_t.arg_end]
    mov  byte [ecx], 0

    ; --- Open and map file --
    push dword [esi + arg_t_size * 1 + arg_t.arg_start]     ; arg1 = filename ptr
    call open_file
    test eax, eax 
    jnz  .fail

    ; --- resolve dump mode flag ---
    push dword [esi + arg_t_size * 2 + arg_t.arg_start] ; arg2 = flag ptr
    call dump_header
    cmp eax, -1 
    je  .invalid_argv

    ; --- dump file --- 
    call dump_file
    test eax, eax
    jnz  .fail

    ; --- dump footer ---
    call dump_footer
    test eax, eax
    jnz  .fail


    ; --- Close file handles ---
    call close_file
    
    ; Return 0 for success
    push 0
    call _ExitProcess@4

.invalid_argv:
    push err_usage_msg_len
    push err_usage_msg
    push dword [stderr_handle]
    call write_console

.fail:
    call close_file

    ; Return 1 for failure
    push 1
    call _ExitProcess@4