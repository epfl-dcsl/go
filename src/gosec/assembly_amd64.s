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

// The goals is to push req *runtime.OExitRequest on the stack before the call
// According to our current implementation, req is in SI
// This function does the dispatch for the enclave
// func asm_oentry() 
TEXT gosec·asm_oentry(SB),$8-8
	PUSHQ SI
	MOVQ (SI), R9
	CMPQ R9, $1 // SpawnRequest (runtime/gosec.go)
	JNE futsleep
	CALL gosec·spawnEnclaveThread(SB)
	JMP end
futsleep:
	CMPQ R9, $2 // FutexSleepRequest (runtime/gosec.go)
	JNE futwake
	CALL runtime·futexsleepE(SB)
	JMP end
futwake:
	CALL runtime·futexwakeupE(SB)
end:
	POPQ SI
	RET
