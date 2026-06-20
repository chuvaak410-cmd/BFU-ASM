format ELF64 executable 3
entry start

segment readable writeable
input_name_ptr dq 0
output_name_ptr dq 0
input_fd dq 0
output_fd dq 0
bytes_read dq 0
payload_size dq 0
mem_size_var dq 0
file_size_var dq 0
msg_err db 'Error: ', 10
debug_msg db 'Unknown token: '
debug_len = $ - debug_msg

segment readable executable
start:
  pop rax
  cmp rax, 3
  jne .print_usage
  pop rax
  pop rsi
  pop rbx
  mov [input_name_ptr], rsi
  mov [output_name_ptr], rbx
  
  mov rax, 2
  mov rdi, [input_name_ptr]
  mov rsi, 0
  syscall
  test rax, rax
  js .error_exit
  mov [input_fd], rax
  
  mov rax, 0
  mov rdi, [input_fd]
  mov rsi, input_buffer
  mov rdx, 4096
  syscall
  test rax, rax
  js .error_exit
  mov [bytes_read], rax
  mov rax, 3
  mov rdi, [input_fd]
  syscall

  mov rsi, input_buffer
  mov rbx, elf_payload

.main_parse_loop:
  mov rax, rsi 
  sub rax, input_buffer
  cmp rax, [bytes_read]
  jge .writing_elf 
  call get_token 
  test rcx, rcx
  jz .next_line 
  mov r8, rdx
  mov r9, rcx

  ; NOP
  cmp r9, 3
  jne .check_syscall
  mov rsi, r8
  mov rdi, cmd_nop
  mov rcx, 3
  repe cmpsb
  jne .check_syscall
  mov byte [rbx], 0x90
  inc rbx
  jmp .main_parse_loop

.check_syscall:
  cmp r9, 7
  jne .check_mov
  mov rsi, r8
  mov rdi, cmd_syscall
  mov rcx, 7
  repe cmpsb
  jne .check_mov
  mov word [rbx], 0x050F
  add rbx, 2
  jmp .main_parse_loop

.check_mov:
  cmp r9, 3
  jne .error_exit
  mov rsi, r8
  mov rdi, cmd_mov
  mov rcx, 3
  repe cmpsb
  jne .error_exit
  call get_token
  mov r8, rdx
  mov r9, rcx
  mov rsi, r8
  mov rdi, reg_rax
  mov rcx, 3
  repe cmpsb
  jne .check_rdi_arg
  mov [reg_type], 0xB8 
  jmp .parse_imm
.check_rdi_arg:
  mov rsi, r8
  mov rdi, reg_rdi
  mov rcx, 3
  repe cmpsb
  jne .error_exit
  mov [reg_type], 0xBF
.parse_imm:
  call get_token
  call parse_number
  mov dl, [reg_type]
  mov [rbx], dl 
  mov dword [rbx+1], eax 
  add rbx, 5
  jmp .main_parse_loop

.next_line:
  inc rsi 
  jmp .main_parse_loop

.writing_elf:
  ; payload_size = rbx - elf_payload
  mov rax, rbx
  sub rax, elf_payload
  mov [payload_size], rax
  test rax, rax
  jz .error_exit

  ; file_size = 64 + 56 + payload_size = 120 + payload_size
  add rax, 120
  mov [file_size_var], rax

  ; патчим p_filesz / p_memsz
  mov [phdr_filesz], rax
  mov [phdr_memsz], rax

  ; open(output, O_CREAT|O_WRONLY|O_TRUNC, 0755)
  mov rax, 2
  mov rdi, [output_name_ptr]
  mov rsi, 1101o         ; O_WRONLY|O_CREAT|O_TRUNC
  mov rdx, 755o
  syscall
  test rax, rax
  js .error_exit
  mov [output_fd], rax

  ; write(fd, elf_header, file_size)
  mov rdi, [output_fd]
  mov rax, 1
  mov rsi, elf_header
  mov rdx, [file_size_var]
  syscall
  test rax, rax
  js .error_exit

  ; close(fd)
  mov rax, 3
  mov rdi, [output_fd]
  syscall

  ; exit(0)
  mov rax, 60
  xor rdi, rdi
  syscall
.print_usage:
  mov rax, 1
  mov rdi, 1
  mov rsi, msg_usage
  mov rdx, msg_usage_len
  syscall
  mov rax, 60
  mov rdi, 1
  syscall 

.error_exit:
  mov rax, 1
  mov rdi, 1
  mov rsi, msg_err
  mov rdx, 8
  syscall
  mov rax, 60
  mov rdi, 1
  syscall

get_token:
  xor rcx, rcx
.skip_spaces:
  cmp rsi, input_buffer + 4096
  jae .done
  mov al, [rsi]
  cmp al, 0
  je .done
  cmp al, ' '
  je .next_char
  cmp al, ','
  je .next_char
  cmp al, 10
  je .next_char
  cmp al, 13
  je .next_char
  jmp .find_end
.next_char:
  inc rsi
  jmp .skip_spaces
.find_end:
  mov rdx, rsi 
.loop_end:
  mov al, [rsi]
  cmp al, 0
  je .done
  cmp al, ' '
  je .done
  cmp al, ','
  je .done
  cmp al, 10
  je .done
  cmp al, 13
  je .done
  inc rcx
  inc rsi 
  jmp .loop_end
.done:
  ret

parse_number:
  mov r12, rsi
  mov r13, rbx
  mov rsi, rdx
  xor rax, rax
  xor rbx, rbx
  mov bl, [rsi + rcx - 1]
  cmp bl, 'h'
  je .hex_parser
.dec_parser:
  movzx rbx, byte [rsi]
  cmp rbx, '0'
  jb .dec_done
  cmp rbx, '9'
  ja .dec_done
  sub rbx, '0'
  imul rax, 10
  add rax, rbx
  inc rsi
  loop .dec_parser
  jmp .dec_done
.dec_done:
  mov rbx, r13
  mov rsi, r12
  ret
.hex_parser:
  dec rcx
.hex_loop:
  movzx rbx, byte [rsi]
  cmp bl, '0'
  jb .hex_next
  cmp bl, '9'
  jbe .hex_digit
  cmp bl, 'A'
  jb .hex_next
  cmp bl, 'F'
  jbe .hex_alpha
  cmp bl, 'a'
  jb .hex_next
  cmp bl, 'f'
  jbe .hex_alpha_low
  jmp .hex_next
.hex_digit:
  sub bl, '0'  
  jmp .hex_add
.hex_alpha:
  sub bl, 'A' - 10
  jmp .hex_add
.hex_alpha_low:
  sub bl, 'a' - 10
.hex_add:
  shl rax, 4
  add rax, rbx
.hex_next:
  inc rsi
  loop .hex_loop
  mov rbx, r13
  mov rsi, r12
  ret

segment readable writeable

align 16
elf_header:
  db 0x7F, 'ELF'
  db 2                    ; ELF64
  db 1                    ; little endian
  db 1                    ; version
  db 0                    ; SYSV
  db 0                    ; ABI version
  times 7 db 0            ; padding до 16 байт

  dw 2                    ; e_type = ET_EXEC
  dw 0x3E                 ; e_machine = x86-64
  dd 1                    ; e_version
  dq 0x400078             ; e_entry = 0x400000 + 0x78
  dq 64                   ; e_phoff
  dq 0                    ; e_shoff
  dd 0                    ; e_flags
  dw 64                   ; e_ehsize
  dw 56                   ; e_phentsize
  dw 1                    ; e_phnum
  dw 0                    ; e_shentsize
  dw 0                    ; e_shnum
  dw 0                    ; e_shstrndx

phdr:
  dd 1                    ; PT_LOAD
  dd 5                    ; PF_R | PF_X
  dq 0                    ; p_offset
  dq 0x400000             ; p_vaddr
  dq 0x400000             ; p_paddr
phdr_filesz:
  dq 0                    ; p_filesz (runtime patch)
phdr_memsz:
  dq 0                    ; p_memsz  (runtime patch)
  dq 0x1000               ; p_align

elf_payload:
  rb 4096

msg_usage db 'Usage: ./bfuasm input.asm output.elf', 10
msg_usage_len = $ - msg_usage
input_buffer rb 8192
cmd_nop db 'NOP'
cmd_syscall db 'SYSCALL'
cmd_mov db 'MOV'
reg_rax db 'RAX'
reg_rdi db 'RDI'
counter rq 1
reg_type rb 1