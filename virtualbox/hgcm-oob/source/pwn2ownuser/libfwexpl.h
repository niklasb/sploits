#ifndef LIBFWEXPL_H
#define LIBFWEXPL_H

#include <Windows.h>
#include "ntdll_undocnt.h"

#undef _AMD64_
#define _AMD64_ 1
#define USE_RWDRV

// name of the driver to install
#ifdef _X86_

#ifdef USE_RWDRV
#error RwDrv is x64 only
#else
#define DRIVER_DEFAULT_NAME "fwexpl_i386.sys"
#endif

#else _AMD64_

#ifdef USE_RWDRV
#define DRIVER_DEFAULT_NAME "RwDrv.sys"
#else
#define DRIVER_DEFAULT_NAME "fwexpl_amd64.sys"
#define USE_DSE_BYPASS
#endif

#endif

#ifdef USE_RWDRV

// device name to communicate with the driver
#define DEVICE_NAME L"RwDrv"

// driver server name
#define SERVICE_NAME "RwDrv"

// file name of installed driver that will be created in system32/drivers
#define DRIVER_FILE_NAME "RwDrv.sys"

#else

// device name to communicate with the driver
#define DEVICE_NAME L"fwexpl"

// driver server name
#define SERVICE_NAME "fwexpl"

// file name of installed driver that will be created in system32/drivers
#define DRIVER_FILE_NAME "fwexpl.sys"

#endif 

#define USE_RWDRV
#define PAGE_SIZE 0x1000

#define MAX_SMI_NUM 255

// make PCI address from bus, device, function and register offset
#define PCI_ADDR(_bus_, _dev_, _func_, _addr_)  \
                                                \
    (unsigned int)(((_bus_) << 16) |            \
                   ((_dev_) << 11) |            \
                   ((_func_) << 8) |            \
                   ((_addr_) & 0xfc) | ((unsigned int)0x80000000))


typedef enum _data_width
{
	U8, U16, U32, U64

} data_width;

typedef void(*UEFI_EXPL_SMM_HANDLER)(void *context);

typedef struct _UEFI_EXPL_SMM_SHELLCODE_CONTEXT
{
	unsigned long long smi_count;
	unsigned long long user_handler;
	unsigned long long user_context;

	unsigned long long ptr_addr;
	unsigned long long ptr_val;

} UEFI_EXPL_SMM_SHELLCODE_CONTEXT,
*PUEFI_EXPL_SMM_SHELLCODE_CONTEXT;


#ifdef __cplusplus

extern "C"
{

#endif


	// initialize kernel driver
	bool uefi_expl_init(char *driver_path, bool use_dse_bypass);

	// unload kernel driver
	void uefi_expl_uninit(void);

	// check if kernel driver is initialized
	bool uefi_expl_is_initialized(void);


	// read virtual memory at given address
	bool uefi_expl_virt_mem_read(unsigned long long address, int size, unsigned char *buff);

	// write virtual memory at given address
	bool uefi_expl_virt_mem_write(unsigned long long address, int size, unsigned char *buff);

	// read physical memory at given address
	bool uefi_expl_phys_mem_read(unsigned long long address, int size, unsigned char *buff);

	// write physical memory at given address
	bool uefi_expl_phys_mem_write(unsigned long long address, int size, unsigned char *buff, data_width alignment);

	// read value from I/O port
	bool uefi_expl_port_read(unsigned short port, data_width size, unsigned long long *val);

	// write value to I/O port
	bool uefi_expl_port_write(unsigned short port, data_width size, unsigned long long val);


	// read value from PCI config space of specified device
	bool uefi_expl_pci_read(unsigned int address, data_width size, unsigned long long *val);

	// write value to PCI config space of specified device
	bool uefi_expl_pci_write(unsigned int address, data_width size, unsigned long long val);


	// generate software SMI using APMC I/O port 0xB2
	bool uefi_expl_smi_invoke(unsigned char code);


	// allocate continious physical memory
	bool uefi_expl_mem_alloc(int size, unsigned long long *addr, unsigned long long *phys_addr);

	// free memory that was allocated with uefi_expl_mem_alloc()
	bool uefi_expl_mem_free(unsigned long long addr, int size);

	// convert virtual address to physical memory address
	bool uefi_expl_phys_addr(unsigned long long addr, unsigned long long *phys_addr);


	// get model specific register value
	bool uefi_expl_msr_get(unsigned int reg, unsigned long long *val);

	// set model specific register value
	bool uefi_expl_msr_set(unsigned int reg, unsigned long long val);


#ifdef __cplusplus

}


#endif
#endif // LIBFWEXPL_H