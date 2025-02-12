; Indirect syscall through NTDLL version
; This will make syscalls originate from NTDLL memory space
; and thus will not raise any flags on IntrumentationCallback

; Project -> Build customizations -> Check ".masm files"
; MagicFunctions.asm -> Right click -> Properties -> Item type on "Microsoft macro assembler"

.data
	axiomSSN DWORD 0h
	axiomQad QWORD 0h

.code
	AxiomSetJump PROC
		nop
		mov axiomQad, 000h
		mov axiomQad, rcx
		ret	
	AxiomSetJump ENDP

	AxiomCallSetup PROC
		nop
		mov axiomSSN, 000h
		mov axiomSSN, ecx
		ret
	AxiomCallSetup ENDP

	AxiomCall PROC
		mov r10, rcx
		mov eax, axiomSSN
		jmp qword ptr [axiomQad]
		ret
	AxiomCall ENDP
END
