#include "stdafx.h"
#include <Windows.h>
#include "libfwexpl.h"
#include "debug.h"
#include "memory.h"
#include "common.h"

extern HANDLE m_hDevice;
//--------------------------------------------------------------------------------------
#ifdef USE_RWDRV
//--------------------------------------------------------------------------------------
bool uefi_expl_virt_mem_read(unsigned long long address, int size, unsigned char *buff)
{
	unsigned long long phys_addr = 0;

	// get physical address
	if (uefi_expl_phys_addr(address, &phys_addr))
	{
		// read physical memory
		return uefi_expl_phys_mem_read(phys_addr, size, buff);
	}

	return false;
}
//--------------------------------------------------------------------------------------
bool uefi_expl_virt_mem_write(unsigned long long address, int size, unsigned char *buff)
{
	unsigned long long phys_addr = 0;

	// get physical address
	if (uefi_expl_phys_addr(address, &phys_addr))
	{
		// write physical memory
		return uefi_expl_phys_mem_write(phys_addr, size, buff, U32);
	}

	return false;
}
//--------------------------------------------------------------------------------------
bool uefi_expl_phys_mem_read(unsigned long long address, int size, unsigned char *buff)
{
	if (m_hDevice == NULL)
	{
		DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Not initialized\n");
		return false;
	}

#if 1
	UCHAR Request[0x100];
	ZeroMemory(&Request, sizeof(Request));

	*(PDWORD64)(Request + 0x00) = address;
	*(PDWORD64)(Request + 0x10) = (DWORD64)buff;
	*(PDWORD)(Request + 0x08) = size;
	*(PDWORD)(Request + 0x0c) = 2;

	bool bRet = false;
	DWORD dwBytes = 0;

	// write memory
	if (DeviceIoControl(
		m_hDevice, 0x222808,
		&Request, sizeof(Request), &Request, sizeof(Request),
		&dwBytes, NULL))
	{
		bRet = true;
	}
	else
	{
		DbgMsg(__FILE__, __LINE__, "DeviceIoControl() ERROR %d\n", GetLastError());
	}
	return bRet;
#else

	bool bRet = false;
	ZeroMemory(buff, size);

	// address and size for MmMapIoSpace() must be aligned by page boundary
	DWORD64 MapAddress = XALIGN_DOWN(address, PAGE_SIZE);
	DWORD MapSize = XALIGN_UP(size, PAGE_SIZE);

	PUCHAR Data = (PUCHAR)M_ALLOC(MapSize);
	if (Data)
	{
		DWORD dwBytes = 0;
		UCHAR Request[0x100];
		ZeroMemory(&Request, sizeof(Request));

		*(PDWORD64)(Request + 0x00) = MapAddress;
		*(PDWORD64)(Request + 0x10) = (DWORD64)Data;
		*(PDWORD)(Request + 0x08) = MapSize;
		*(PDWORD)(Request + 0x0c) = 2;

		// read memory
		if (DeviceIoControl(
			m_hDevice, 0x222808,
			&Request, sizeof(Request), &Request, sizeof(Request),
			&dwBytes, NULL))
		{
			// copy memory contents to caller buffer
			CopyMemory(
				buff,
				RVATOVA(Data, address - MapAddress),
				size
			);

			bRet = true;
		}
		else
		{
			DbgMsg(__FILE__, __LINE__, "DeviceIoControl() ERROR %d\n", GetLastError());
		}

		M_FREE(Data);
	}
	else
	{
		DbgMsg(__FILE__, __LINE__, "M_ALLOC() ERROR %d\n", GetLastError());
	}

	return bRet;
#endif
}
//--------------------------------------------------------------------------------------
bool uefi_expl_phys_mem_write(unsigned long long address, int size, unsigned char *buff, data_width alignment)
{
	if (m_hDevice == NULL)
	{
		DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Not initialized\n");
		return false;
	}

#if 1
	UCHAR Request[0x100];
	ZeroMemory(&Request, sizeof(Request));

	*(PDWORD64)(Request + 0x00) = address;
	*(PDWORD64)(Request + 0x10) = (DWORD64)buff;
	*(PDWORD)(Request + 0x08) = size;
	*(PDWORD)(Request + 0x0c) = (int)alignment;

	bool bRet = false;
	DWORD dwBytes = 0;

	// write memory
	if (DeviceIoControl(
		m_hDevice, 0x22280c,
		&Request, sizeof(Request), &Request, sizeof(Request),
		&dwBytes, NULL))
	{
		bRet = true;
	}
	else
	{
		DbgMsg(__FILE__, __LINE__, "DeviceIoControl() ERROR %d\n", GetLastError());
	}
	return bRet;
#endif


	// address and size for MmMapIoSpace() must be aligned by page boundary
	DWORD64 MapAddress = XALIGN_DOWN(address, PAGE_SIZE);
	DWORD MapSize = XALIGN_UP(size, PAGE_SIZE);

	PUCHAR Data = (PUCHAR)M_ALLOC(MapSize);
	if (Data)
	{
		// read original memory contents
		if (uefi_expl_phys_mem_read(MapAddress, MapSize, Data))
		{
			DWORD dwBytes = 0;
			UCHAR Request[0x100];
			ZeroMemory(&Request, sizeof(Request));

			// copy memory contents from caller buffer
			CopyMemory(
				RVATOVA(Data, address - MapAddress),
				buff,
				size
			);

			*(PDWORD64)(Request + 0x00) = MapAddress;
			*(PDWORD64)(Request + 0x10) = (DWORD64)Data;
			*(PDWORD)(Request + 0x08) = MapSize;
			*(PDWORD)(Request + 0x0c) = 2;

			// write memory
			if (DeviceIoControl(
				m_hDevice, 0x22280c,
				&Request, sizeof(Request), &Request, sizeof(Request),
				&dwBytes, NULL))
			{
				bRet = true;
			}
			else
			{
				DbgMsg(__FILE__, __LINE__, "DeviceIoControl() ERROR %d\n", GetLastError());
			}
		}

		M_FREE(Data);
	}
	else
	{
		DbgMsg(__FILE__, __LINE__, "M_ALLOC() ERROR %d\n", GetLastError());
	}

	return bRet;
}
//--------------------------------------------------------------------------------------
bool uefi_expl_port_read(unsigned short port, data_width size, unsigned long long *val)
{
	if (m_hDevice == NULL)
	{
		DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Not initialized\n");
		return false;
	}

	UCHAR Request[0x100];
	ZeroMemory(&Request, sizeof(Request));

	*(PWORD)(Request + 0x00) = port;

	DWORD dwBytes = 0;
	BOOL bStatus = FALSE;

	switch (size)
	{
	case U8:

		// send request to the driver
		bStatus = DeviceIoControl(
			m_hDevice, 0x222810,
			&Request, sizeof(Request), &Request, sizeof(Request),
			&dwBytes, NULL
		);

		break;

	case U16:

		// send request to the driver
		bStatus = DeviceIoControl(
			m_hDevice, 0x222818,
			&Request, sizeof(Request), &Request, sizeof(Request),
			&dwBytes, NULL
		);

		break;

	case U32:

		// send request to the driver
		bStatus = DeviceIoControl(
			m_hDevice, 0x222820,
			&Request, sizeof(Request), &Request, sizeof(Request),
			&dwBytes, NULL
		);

		break;

	default:

		DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Invalid data width %d\n", size);
		return false;
	}

	if (bStatus)
	{
		*val = *(PDWORD64)(Request + 0x04);

		return true;
	}
	else
	{
		DbgMsg(__FILE__, __LINE__, "DeviceIoControl() ERROR %d\n", GetLastError());
	}

	return false;
}
//--------------------------------------------------------------------------------------
bool uefi_expl_port_write(unsigned short port, data_width size, unsigned long long val)
{
	if (m_hDevice == NULL)
	{
		DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Not initialized\n");
		return false;
	}

	UCHAR Request[0x100];
	ZeroMemory(&Request, sizeof(Request));

	*(PWORD)(Request + 0x00) = port;
	*(PDWORD64)(Request + 0x04) = val;

	DWORD dwBytes = 0;
	BOOL bStatus = FALSE;

	switch (size)
	{
	case U8:

		// send request to the driver
		bStatus = DeviceIoControl(
			m_hDevice, 0x222814,
			&Request, sizeof(Request), &Request, sizeof(Request),
			&dwBytes, NULL
		);

		break;

	case U16:

		// send request to the driver
		bStatus = DeviceIoControl(
			m_hDevice, 0x22281c,
			&Request, sizeof(Request), &Request, sizeof(Request),
			&dwBytes, NULL
		);

		break;

	case U32:

		// send request to the driver
		bStatus = DeviceIoControl(
			m_hDevice, 0x222824,
			&Request, sizeof(Request), &Request, sizeof(Request),
			&dwBytes, NULL
		);

		break;

	default:

		DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Invalid data width %d\n", size);
		return false;
	}

	if (bStatus)
	{
		return true;
	}
	else
	{
		DbgMsg(__FILE__, __LINE__, "DeviceIoControl() ERROR %d\n", GetLastError());
	}

	return false;
}
//--------------------------------------------------------------------------------------
bool uefi_expl_pci_read_ex(unsigned int address, data_width size, unsigned long long *val)
{
	// set PCI device address
	if (uefi_expl_port_write(0xcf8, U32, 0 | address))
	{
		// read PCI config space
		return uefi_expl_port_read(0xcfc, size, val);
	}

	return false;
}
//--------------------------------------------------------------------------------------
bool uefi_expl_pci_write_ex(unsigned int address, data_width size, unsigned long long val)
{
	// set PCI device address
	if (uefi_expl_port_write(0xcf8, U32, 0 | address))
	{
		// write PCI config space
		return uefi_expl_port_write(0xcfc, size, val);
	}

	return false;
}
//--------------------------------------------------------------------------------------
bool uefi_expl_smi_invoke(unsigned char code)
{
	// trigger SMI using 0xB2 I/O port
	return uefi_expl_port_write(0xb2, U8, 0 | code);
}
//--------------------------------------------------------------------------------------
bool uefi_expl_mem_alloc(int size, unsigned long long *addr, unsigned long long *phys_addr)
{
	if (m_hDevice == NULL)
	{
		DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Not initialized\n");
		return false;
	}

	UCHAR Request[0x100];
	ZeroMemory(&Request, sizeof(Request));

	*(PDWORD)(Request + 0x00) = size;

	DWORD dwBytes = 0;

	// send request to the driver
	if (DeviceIoControl(
		m_hDevice, 0x222880,
		&Request, sizeof(Request), &Request, sizeof(Request),
		&dwBytes, NULL))
	{
		*addr = *(PDWORD64)(Request + 0x08);
		*phys_addr = 0x00 | *(PDWORD)(Request + 0x04);

		return true;
	}
	else
	{
		DbgMsg(__FILE__, __LINE__, "DeviceIoControl() ERROR %d\n", GetLastError());
	}

	return false;
}
//--------------------------------------------------------------------------------------
bool uefi_expl_mem_free(unsigned long long addr, int size)
{
	if (m_hDevice == NULL)
	{
		DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Not initialized\n");
		return false;
	}

	UCHAR Request[0x100];
	ZeroMemory(&Request, sizeof(Request));

	*(PDWORD)(Request + 0x00) = size;
	*(PDWORD64)(Request + 0x08) = addr;

	DWORD dwBytes = 0;

	// send request to the driver
	if (DeviceIoControl(
		m_hDevice, 0x222884,
		&Request, sizeof(Request), &Request, sizeof(Request),
		&dwBytes, NULL))
	{
		return true;
	}
	else
	{
		DbgMsg(__FILE__, __LINE__, "DeviceIoControl() ERROR %d\n", GetLastError());
	}

	return false;
}
//--------------------------------------------------------------------------------------
bool uefi_expl_get_control_regs(unsigned long long *cr0, unsigned long long *cr3, unsigned long long *cr4)
{
	if (m_hDevice == NULL)
	{
		DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Not initialized\n");
		return false;
	}

	UCHAR Request[0x100];
	ZeroMemory(&Request, sizeof(Request));

	if (cr0)
	{
		DWORD dwBytes = 0;

		*(PDWORD)(Request + 0x00) = 0;

		// send request to the driver
		if (DeviceIoControl(
			m_hDevice, 0x22286c,
			&Request, sizeof(Request), &Request, sizeof(Request),
			&dwBytes, NULL))
		{
			*cr0 = *(PDWORD64)(Request + 0x08);
		}
		else
		{
			DbgMsg(__FILE__, __LINE__, "DeviceIoControl() ERROR %d\n", GetLastError());
			return false;
		}
	}

	if (cr3)
	{
		DWORD dwBytes = 0;

		*(PDWORD)(Request + 0x00) = 3;

		// send request to the driver
		if (DeviceIoControl(
			m_hDevice, 0x22286c,
			&Request, sizeof(Request), &Request, sizeof(Request),
			&dwBytes, NULL))
		{
			*cr3 = *(PDWORD64)(Request + 0x08);
		}
		else
		{
			DbgMsg(__FILE__, __LINE__, "DeviceIoControl() ERROR %d\n", GetLastError());
			return false;
		}
	}

	if (cr4)
	{
		DWORD dwBytes = 0;

		*(PDWORD)(Request + 0x00) = 4;

		// send request to the driver
		if (DeviceIoControl(
			m_hDevice, 0x22286c,
			&Request, sizeof(Request), &Request, sizeof(Request),
			&dwBytes, NULL))
		{
			*cr4 = *(PDWORD64)(Request + 0x08);
		}
		else
		{
			DbgMsg(__FILE__, __LINE__, "DeviceIoControl() ERROR %d\n", GetLastError());
			return false;
		}
	}

	return true;
}
//--------------------------------------------------------------------------------------
// MSR registers
#define IA32_EFER 0xC0000080

// IA32_EFER.LME flag
#define IA32_EFER_LME 0x100                              

// CR* registers bits
#define CR0_PG  0x80000000
#define CR4_PAE 0x20

#define DbgMsgMem 

bool uefi_expl_phys_addr(unsigned long long addr, unsigned long long *phys_addr)
{
	bool bRet = false;
	DWORD64 PhysAddr = 0;

	unsigned long long Cr0 = 0, Cr3 = 0, Cr4 = 0;

	// get required control registers
	if (!uefi_expl_get_control_regs(&Cr0, &Cr3, &Cr4))
	{
		return false;
	}

	DWORD64 Efer = 0;

	// get IA32_EFER MSR
	if (!uefi_expl_msr_get(IA32_EFER, &Efer))
	{
		return false;
	}

	if (!(Cr0 & CR0_PG))
	{
		DbgMsg(__FILE__, __LINE__, "ERROR: CR0.PG is not set\r\n");
		return false;
	}

	if (!(Cr4 & CR4_PAE))
	{
		DbgMsg(__FILE__, __LINE__, "ERROR: CR4.PAE is not set\r\n");
		return false;
	}

	if (!(Efer & IA32_EFER_LME))
	{
		DbgMsg(__FILE__, __LINE__, "ERROR: IA32_EFER.LME is not set\r\n");
		return false;
	}

	X64_PAGE_MAP_AND_DIRECTORY_POINTER_2MB_4K PML4Entry;

	DbgMsgMem(__FILE__, __LINE__, __FUNCTION__"(): CR3 is 0x%llx, VA is 0x%llx\r\n", Cr3, addr);

	if (!uefi_expl_phys_mem_read(
		PML4_ADDRESS(Cr3) + PML4_INDEX(addr) * sizeof(DWORD64),
		sizeof(DWORD64), (unsigned char *)&PML4Entry.Uint64))
	{
		return false;
	}

	DbgMsgMem(
		__FILE__, __LINE__, "PML4E is at 0x%llx[0x%llx]: 0x%llx\r\n",
		PML4_ADDRESS(Cr3), PML4_INDEX(addr), PML4Entry.Uint64
	);

	if (PML4Entry.Bits.Present)
	{
		X64_PAGE_MAP_AND_DIRECTORY_POINTER_2MB_4K PDPTEntry;

		if (!uefi_expl_phys_mem_read(
			PFN_TO_PAGE(PML4Entry.Bits.PageTableBaseAddress) + PDPT_INDEX(addr) * sizeof(DWORD64),
			sizeof(DWORD64), (unsigned char *)&PDPTEntry.Uint64))
		{
			return false;
		}

		DbgMsgMem(
			__FILE__, __LINE__, "PDPTE is at 0x%llx[0x%llx]: 0x%llx\r\n",
			PFN_TO_PAGE(PML4Entry.Bits.PageTableBaseAddress), PDPT_INDEX(addr), PDPTEntry.Uint64
		);

		if (PDPTEntry.Bits.Present)
		{
			// check for page size flag
			if ((PDPTEntry.Uint64 & PDPTE_PDE_PS) == 0)
			{
				X64_PAGE_DIRECTORY_ENTRY_4K PDEntry;

				if (!uefi_expl_phys_mem_read(
					PFN_TO_PAGE(PDPTEntry.Bits.PageTableBaseAddress) + PDE_INDEX(addr) * sizeof(DWORD64),
					sizeof(DWORD64), (unsigned char *)&PDEntry.Uint64))
				{
					return false;
				}

				DbgMsgMem(
					__FILE__, __LINE__, "PDE is at 0x%llx[0x%llx]: 0x%llx\r\n",
					PFN_TO_PAGE(PDPTEntry.Bits.PageTableBaseAddress), PDE_INDEX(addr),
					PDEntry.Uint64
				);

				if (PDEntry.Bits.Present)
				{
					// check for page size flag
					if ((PDEntry.Uint64 & PDPTE_PDE_PS) == 0)
					{
						X64_PAGE_TABLE_ENTRY_4K PTEntry;

						if (!uefi_expl_phys_mem_read(
							PFN_TO_PAGE(PDEntry.Bits.PageTableBaseAddress) + PTE_INDEX(addr) * sizeof(DWORD64),
							sizeof(DWORD64), (unsigned char *)&PTEntry.Uint64))
						{
							return false;
						}

						DbgMsgMem(
							__FILE__, __LINE__, "PTE is at 0x%llx[0x%llx]: 0x%llx\r\n",
							PFN_TO_PAGE(PDEntry.Bits.PageTableBaseAddress), PTE_INDEX(addr),
							PTEntry.Uint64
						);

						if (PTEntry.Bits.Present)
						{
							PhysAddr = PFN_TO_PAGE(PTEntry.Bits.PageTableBaseAddress) + PAGE_OFFSET_4K(addr);

							bRet = true;
						}
						else
						{
							DbgMsg(
								__FILE__, __LINE__,
								"ERROR: PTE for 0x%llx is not present\r\n", addr
							);
						}
					}
					else
					{
						PhysAddr = PFN_TO_PAGE(PDEntry.Bits.PageTableBaseAddress) + PAGE_OFFSET_2M(addr);

						bRet = true;
					}
				}
				else
				{
					DbgMsg(__FILE__, __LINE__, "ERROR: PDE for 0x%llx is not present\r\n", addr);
				}
			}
			else
			{
				DbgMsg(__FILE__, __LINE__, "ERROR: 1Gbyte page\r\n");
			}
		}
		else
		{
			DbgMsg(__FILE__, __LINE__, "ERROR: PDPTE for 0x%llx is not present\r\n", addr);
		}
	}
	else
	{
		DbgMsg(__FILE__, __LINE__, "ERROR: PML4E for 0x%llx is not present\r\n", addr);
	}

	if (bRet)
	{
		*phys_addr = PhysAddr;
	}

	return bRet;
}
//--------------------------------------------------------------------------------------
bool uefi_expl_msr_get(unsigned int reg, unsigned long long *val)
{
	if (m_hDevice == NULL)
	{
		DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Not initialized\n");
		return false;
	}

	DWORD dwBytes = 0;
	UCHAR Request[0x100];
	ZeroMemory(&Request, sizeof(Request));

	*(PDWORD)(Request + 0x08) = reg;

	// send request to the driver
	if (DeviceIoControl(
		m_hDevice, 0x222848,
		&Request, sizeof(Request), &Request, sizeof(Request),
		&dwBytes, NULL))
	{
		LARGE_INTEGER Val;

		Val.HighPart = *(PDWORD)(Request + 0x0c);
		Val.LowPart = *(PDWORD)(Request + 0x00);

		*val = Val.QuadPart;

		return true;
	}
	else
	{
		DbgMsg(__FILE__, __LINE__, "DeviceIoControl() ERROR %d\n", GetLastError());
	}

	return false;
}
//--------------------------------------------------------------------------------------
bool uefi_expl_msr_set(unsigned int reg, unsigned long long val)
{
	if (m_hDevice == NULL)
	{
		DbgMsg(__FILE__, __LINE__, __FUNCTION__"() ERROR: Not initialized\n");
		return false;
	}

	DWORD dwBytes = 0;
	UCHAR Request[0x100];
	ZeroMemory(&Request, sizeof(Request));

	LARGE_INTEGER Val;
	Val.QuadPart = val;

	*(PDWORD)(Request + 0x08) = reg;
	*(PDWORD)(Request + 0x0c) = Val.HighPart;
	*(PDWORD)(Request + 0x00) = Val.LowPart;

	// send request to the driver
	if (DeviceIoControl(
		m_hDevice, 0x22284c,
		&Request, sizeof(Request), &Request, sizeof(Request),
		&dwBytes, NULL))
	{
		return true;
	}
	else
	{
		DbgMsg(__FILE__, __LINE__, "DeviceIoControl() ERROR %d\n", GetLastError());
	}

	return false;
}
//--------------------------------------------------------------------------------------
#endif // USE_RWDRV
//--------------------------------------------------------------------------------------
//
// EoF
//