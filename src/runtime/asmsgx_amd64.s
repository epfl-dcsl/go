#include "go_asm.h"
#include "go_tls.h"
#include "funcdata.h"
#include "textflag.h"

#define SIM_FLAG 0x050000000008
#define MSGX_ADDR 0x050000000020

TEXT runtime·sgx_rt0_go(SB),NOSPLIT,$0
	// copy arguments forward on an even stack
	MOVQ	DI, AX		// argc
	MOVQ	SI, BX		// argv
	SUBQ	$(4*8+7), SP		// 2args 2auto
	ANDQ	$~15, SP
	MOVQ	AX, 16(SP)
	MOVQ	BX, 24(SP)

	// create istack out of the given (operating system) stack.
	// _cgo_init may update stackguard.
	MOVQ	$runtime·g0(SB), DI
	LEAQ	(-64*1024+104)(SP), BX
	MOVQ	BX, g_stackguard0(DI)
	MOVQ	BX, g_stackguard1(DI)
	MOVQ	BX, (g_stack+stack_lo)(DI)
	MOVQ	SP, (g_stack+stack_hi)(DI)

	// find out information about the processor we're on
	MOVL	$0, AX
    // TODO Not allowed within the enclave; find a solution.
    //CPUID
    MOVL    $22, AX
    MOVL    $0x756E6547, BX
    MOVL    $0x6C65746E, CX
    MOVL    $0x49656E69, DX

	MOVL	AX, SI
	CMPL	AX, $0
	JE	nocpuinfo

	// Figure out how to serialize RDTSC.
	// On Intel processors LFENCE is enough. AMD requires MFENCE.
	// Don't know about the rest, so let's do MFENCE.
	CMPL	BX, $0x756E6547  // "Genu"
	JNE	notintel

	CMPL	DX, $0x49656E69  // "ineI"
	JNE	notintel

	CMPL	CX, $0x6C65746E  // "ntel"
	JNE	notintel

	MOVB	$1, runtime·isIntel(SB)
	MOVB	$1, runtime·lfenceBeforeRdtsc(SB)

notintel:
	// Load EAX=1 cpuid flags
	MOVL	$1, AX

    //TODO modified this because CPUID is not allowed
    //CPUID
    MOVL    $0x000806e9, AX
    MOVL    $0x01100800, BX
    MOVL    $0x7ffafbff, CX

    MOVL	AX, runtime·processorVersionInfo(SB)

	TESTL	$(1<<26), DX // SSE2
	SETNE	runtime·support_sse2(SB)

	TESTL	$(1<<9), CX // SSSE3
	SETNE	runtime·support_ssse3(SB)

	TESTL	$(1<<19), CX // SSE4.1
	SETNE	runtime·support_sse41(SB)

	TESTL	$(1<<20), CX // SSE4.2
	SETNE	runtime·support_sse42(SB)

	TESTL	$(1<<23), CX // POPCNT
	SETNE	runtime·support_popcnt(SB)

	TESTL	$(1<<25), CX // AES
	SETNE	runtime·support_aes(SB)

	TESTL	$(1<<27), CX // OSXSAVE
	SETNE	runtime·support_osxsave(SB)

	// If OS support for XMM and YMM is not present
	// support_avx will be set back to false later.
	TESTL	$(1<<28), CX // AVX
	SETNE	runtime·support_avx(SB)

eax7:
	// Load EAX=7/ECX=0 cpuid flags
	CMPL	SI, $7
	JLT	osavx
	MOVL	$7, AX
	MOVL	$0, CX

    // BX 0x029c6fbf
    // TODO not supported inside the enclave.
    //CPUID
    MOVL    $0x029c6fbf, BX

	TESTL	$(1<<3), BX // BMI1
	SETNE	runtime·support_bmi1(SB)

	// If OS support for XMM and YMM is not present
	// support_avx2 will be set back to false later.
	TESTL	$(1<<5), BX
	SETNE	runtime·support_avx2(SB)

	TESTL	$(1<<8), BX // BMI2
	SETNE	runtime·support_bmi2(SB)

	TESTL	$(1<<9), BX // ERMS
	SETNE	runtime·support_erms(SB)

    // TODO remove afterwards (just for debuggin)
    MOVQ $0x050000000000, R8
    MOVQ $0x0d, (R8)

osavx:
	CMPB	runtime·support_osxsave(SB), $1
	JNE	noavx

	MOVL	$0, CX
	// For XGETBV, OSXSAVE bit is required and sufficient
	XGETBV


	ANDL	$6, AX
	CMPL	AX, $6 // Check for OS support of XMM and YMM registers.
	JE nocpuinfo
noavx:
	MOVB $0, runtime·support_avx(SB)
	MOVB $0, runtime·support_avx2(SB)

nocpuinfo:
	// if there is an _cgo_init, call it.
	MOVQ	_cgo_init(SB), AX
	TESTQ	AX, AX
	JZ	needtls
	// g0 already in DI
	MOVQ	DI, CX	// Win64 uses CX for first parameter
	MOVQ	$setg_gcc<>(SB), SI
	CALL	AX

	// update stackguard after _cgo_init
	MOVQ	$runtime·g0(SB), CX
	MOVQ	(g_stack+stack_lo)(CX), AX
	ADDQ	$const__StackGuard, AX
	MOVQ	AX, g_stackguard0(CX)
	MOVQ	AX, g_stackguard1(CX)

#ifndef GOOS_windows
	JMP ok
#endif
needtls:
#ifdef GOOS_plan9
	// skip TLS setup on Plan 9
	JMP ok
#endif
#ifdef GOOS_solaris
	// skip TLS setup on Solaris
	JMP ok
#endif

	//TODO for debugging remove afterwards
	MOVQ $0x050000000000, R8
	MOVQ $0x19, (R8)

	//Set up the isEnclave variable.
	MOVB $1, runtime·isEnclave(SB)

	//Check if we are in simulation mode.
	MOVQ $SIM_FLAG, R9
	MOVQ (R9), R8
	CMPB R8, $1
	JNE nonsim

	//Set the runtime.isSim
	MOVB $1, runtime·isSimulation(SB)

	LEAQ	runtime·m0+m_tls(SB), DI
	CALL	runtime·sgxsettls(SB)

	// store through it, to make sure it works
	get_tls(BX)

	MOVQ	$0x123, g(BX)
	MOVQ	runtime·m0+m_tls(SB), AX

	CMPQ	AX, $0x123
	JEQ 2(PC)
	MOVL	AX, 0	// abort
	JMP nonsimend

nonsim:
	//Get the TLS address and put it inside msgx pointer.
	MOVQ $MSGX_ADDR, R9
	MOVQ (R9), R8
	MOVQ R8, runtime·msgx(SB)

	MOVQ $0x050000000008, R8
	MOVQ $m_tls, (R8)


nonsimend:

ok:
	// set the per-goroutine and per-mach "registers"
	get_tls(BX)
	LEAQ	runtime·g0(SB), CX
	MOVQ	CX, g(BX)
	LEAQ	runtime·m0(SB), AX

	// TODO remove afterwards (just for debuggin)
	MOVQ $0x050000000000, R8
	MOVQ $0x17, (R8)

	// save m->g0 = g0
	MOVQ	CX, m_g0(AX)
	// save m0 to g0->m
	MOVQ	AX, g_m(CX)

	// TODO remove afterwards (just for debuggin)
	MOVQ $0x050000000000, R8
	MOVQ $0x18, (R8)

	CLD				// convention is D is always left cleared
	CALL	runtime·check(SB)

	MOVL	16(SP), AX		// copy argc
	MOVL	AX, 0(SP)
	MOVQ	24(SP), AX		// copy argv
	MOVQ	AX, 8(SP)
	CALL	runtime·args(SB)
	CALL	runtime·osinit(SB)
	CALL	runtime·schedinit(SB)

	// create a new goroutine to start program
	MOVQ	$runtime·mainPC(SB), AX		// entry
	PUSHQ	AX
	PUSHQ	$0			// arg size
	CALL	runtime·newproc(SB)
	POPQ	AX
	POPQ	AX

	// start this M
	CALL	runtime·mstart(SB)

	MOVL	$0xf1, 0xf1  // crash
	RET

// void setg_gcc(G*); set g called from gcc.
TEXT setg_gcc<>(SB),NOSPLIT,$0
	get_tls(AX)
	MOVQ	DI, g(AX)
	RET
