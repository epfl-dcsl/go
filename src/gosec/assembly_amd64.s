// func asm_eenter(tcs, xcpt, rdi, rsi uint64)
TEXT gosec·asm_eenter(SB),$0-40
    MOVQ $2, AX				//EENTER
    MOVQ tcs+0(FP),BX
    MOVQ xcpt+8(FP), CX
    BYTE $0x0f; BYTE $0x01; BYTE $0xd7 //ENCLU EENTER
    MOVQ rdi+16(FP), AX
    MOVQ DI, (AX)
    MOVQ rdi+24(FP), AX
    MOVQ SI, (AX)
    RET

// func asm_exception()
TEXT gosec·asm_exception(SB),$0
    BYTE $0x0f; BYTE $0x01; BYTE $0xd7

// The goals is to push req *runtime.SpawnRequest on the stack before the call
// According to our current implementation, req is in SI 
// func asm_oentry() 
TEXT gosec·asm_oentry(SB),$8-8
	PUSHQ SI
	CALL gosec·spawnEnclaveThread(SB)
	POPQ SI
	RET
