// func asm_eenter(tcs, xcpt, rdi, rsi uint64)
TEXT gosec·asm_eenter(SB),$0-40
    MOVQ $2, AX
    MOVQ tcs+0(FP),BX
    MOVQ xcpt+8(FP), CX
    BYTE $0x0f; BYTE $0x01; BYTE $0xd7
    MOVQ rdi+16(FP), AX
    MOVQ DI, (AX)
    MOVQ rdi+24(FP), AX
    MOVQ SI, (AX)
    RET

// func asm_exception()
TEXT gosec·asm_exception(SB),$0
    BYTE $0x0f; BYTE $0x01; BYTE $0xd7
