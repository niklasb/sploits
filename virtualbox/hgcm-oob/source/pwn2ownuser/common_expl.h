#pragma once

#include <Windows.h>

//
// CR4 register bits
//
#define CR4_VME                     0x00000001      // V86 mode extensions
#define CR4_PVI                     0x00000002      // Protected mode virtual interrupts
#define CR4_TSD                     0x00000004      // Time stamp disable
#define CR4_DE                      0x00000008      // Debugging Extensions
#define CR4_PSE                     0x00000010      // Page size extensions
#define CR4_PAE                     0x00000020      // Physical address extensions
#define CR4_MCE                     0x00000040      // Machine check enable
#define CR4_PGE                     0x00000080      // Page global enable
#define CR4_FXSR                    0x00000200      // FXSR used by OS
#define CR4_XMMEXCPT                0x00000400      // XMMI used by OS
#define CR4_VMXE                    0x00002000
#define CR4_FSGSBASE                0x00010000
#define CR4_OSXSAVE                 0x00040000

//
// i386 Feature bit definitions
//
#define KF_V86_VIS                  0x00000001
#define KF_RDTSC                    0x00000002
#define KF_CR4                      0x00000004
#define KF_CMOV                     0x00000008
#define KF_GLOBAL_PAGE              0x00000010
#define KF_LARGE_PAGE               0x00000020
#define KF_MTRR                     0x00000040
#define KF_CMPXCHG8B                0x00000080
#define KF_MMX                      0x00000100
#define KF_WORKING_PTE              0x00000200
#define KF_PAT                      0x00000400
#define KF_FXSR                     0x00000800
#define KF_FAST_SYSCALL             0x00001000
#define KF_XMMI                     0x00002000
#define KF_3DNOW                    0x00004000
#define KF_AMDK6MTRR                0x00008000
#define KF_XMMI64                   0x00010000
#define KF_DTS                      0x00020000
#define KF_NOEXECUTE                0x20000000
#define KF_GLOBAL_32BIT_EXECUTE     0x40000000
#define KF_GLOBAL_32BIT_NOEXECUTE   0x80000000

//
// CPUID features bits
//
#define CPUID_VMX                   0x00000020
#define CPUID_OSXSAVE               0x08000000

//
// CPUID extended features bits
//
#define CPUID_FSGSBASE              0x00000001


typedef struct _HAL_DISPATCH
{
	ULONG   Version;

	PVOID   HalQuerySystemInformation;
	PVOID   HalSetSystemInformation;
	PVOID   HalQueryBusSlots;
	ULONG   Spare1;
	PVOID   HalExamineMBR;
	PVOID   HalIoAssignDriveLetters;
	PVOID   HalIoReadPartitionTable;
	PVOID   HalIoSetPartitionInformation;
	PVOID   HalIoWritePartitionTable;

	PVOID   HalReferenceHandlerForBus;
	PVOID   HalReferenceBusHandler;
	PVOID   HalDereferenceBusHandler;

	PVOID   HalInitPnpDriver;
	PVOID   HalInitPowerManagement;

	PVOID   HalGetDmaAdapter;
	PVOID   HalGetInterruptTranslator;

	PVOID   HalStartMirroring;
	PVOID   HalEndMirroring;
	PVOID   HalMirrorPhysicalMemory;
	PVOID   HalEndOfBoot;
	PVOID   HalMirrorVerify;

} HAL_DISPATCH,
*PHAL_DISPATCH;


DWORD64 VA_to_PT(DWORD64 Addr);
DWORD64 VA_to_PD(DWORD64 Addr);
DWORD64 VA_to_PDPT(DWORD64 Addr);
DWORD64 VA_to_PML4(DWORD64 Addr);

PVOID KernelGetModuleBase(char *lpszModuleName);
PVOID KernelGetProcAddr(char *lpszProcName);