#include "go_asm.h"
#include "go_tls.h"
#include "textflag.h"


#define SYS_arch_prctl		158
#define SIM_FLAG            0x050000000008

// set tls base to DI
TEXT runtime·sgxsettls(SB),NOSPLIT,$32

    // TODO remove afterwards (just for debuggin)
    MOVQ $0x050000000000, R8
    MOVQ $0x12, (R8)
    MOVQ $SIM_FLAG, R8
    MOVQ (R8), R9
    CMPQ R9, $1
    JNE fini

	ADDQ	$8, DI	// ELF wants to use -8(FS)
	MOVQ	DI, SI
	MOVQ	$0x1002, DI	// ARCH_SET_FS
	MOVQ	$SYS_arch_prctl, AX
	SYSCALL
	CMPQ	AX, $0xfffffffffffff001
	JLS	2(PC)
	MOVL	$0xf1, 0xf1  // crash
fini:
	RET
