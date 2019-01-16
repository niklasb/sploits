#pragma once
#include <Windows.h>

#define IOCTL_DRV_CONTROL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x01, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define DRV_CTL_NONE            0x00
#define DRV_CTL_VIRT_MEM_READ   0x01
#define DRV_CTL_VIRT_MEM_WRITE  0x02
#define DRV_CTL_PHYS_MEM_READ   0x03
#define DRV_CTL_PHYS_MEM_WRITE  0x04
#define DRV_CTL_PHYS_MEM_MAP    0x05
#define DRV_CTL_PORT_READ       0x06
#define DRV_CTL_PORT_WRITE      0x07
#define DRV_CTL_PCI_READ        0x08
#define DRV_CTL_PCI_WRITE       0x09
#define DRV_CTL_SMI_INVOKE      0x0a
#define DRV_CTL_MEM_ALLOC       0x0b
#define DRV_CTL_MEM_FREE        0x0c
#define DRV_CTL_PHYS_ADDR       0x0d
#define DRV_CTL_MSR_GET         0x0e
#define DRV_CTL_MSR_SET         0x0f

#define DRV_CTL_RESTORE_CR4     0x10

#pragma pack(push, 1)

typedef struct _PHYS_MEM_REGION
{
    ULONG64 Address;
    ULONG64 Size;

} PHYS_MEM_REGION,
*PPHYS_MEM_REGION;

typedef struct _REQUEST_BUFFER
{
    // operation code (see C_* definitions)
    ULONG Code;
    
    union
    {
        struct // for DRV_CTL_VIRT_MEM_READ and DRV_CTL_PHYS_MEM_READ
        {
            ULONG64 Address;
            ULONG Size;
            UCHAR Data[];

        } MemRead;

        struct // for DRV_CTL_VIRT_MEM_WRITE and DRV_CTL_PHYS_MEM_WRITE
        {
            ULONG64 Address;
            ULONG Size;
            UCHAR Data[];

        } MemWrite;

        struct // for DRV_CTL_PHYS_MEM_MAP
        {
            ULONG RegionsCount;
            PHYS_MEM_REGION Regions[];

        } MemMap;

        struct // for DRV_CTL_PORT_READ
        {            
            USHORT Port;
            ULONG Size;
            ULONG64 Val;

        } PortRead;

        struct // for DRV_CTL_PORT_WRITE
        {
            ULONG Port;
            ULONG Size;
            ULONG64 Val;

        } PortWrite;

        struct // for DRV_CTL_PCI_READ
        {
            ULONG Address;
            ULONG Size;
            ULONG64 Val;

        } PciRead;

        struct // for DRV_CTL_PCI_WRITE
        {
            ULONG Address;
            ULONG Size;
            ULONG64 Val;

        } PciWrite;

        struct // for DRV_CTL_SMI_INVOKE
        {
            UCHAR Code;            

        } SmiInvoke;

        struct // for DRV_CTL_MEM_ALLOC
        {
            ULONG64 Address;
            ULONG64 PhysicalAddress;
            ULONG Size;

        } MemAlloc;

        struct // for DRV_CTL_MEM_FREE
        {
            ULONG64 Address;

        } MemFree;

        struct // for DRV_CTL_PHYS_ADDR
        {
            ULONG64 Address;
            ULONG64 PhysicalAddress;

        } PhysAddr;

        struct // for DRV_CTL_MSR_GET
        {
            ULONG Register;
            ULONG64 Value;

        } MsrGet;

        struct // for DRV_CTL_MSR_SET
        {
            ULONG Register;
            ULONG64 Value;

        } MsrSet;
    };

} REQUEST_BUFFER,
*PREQUEST_BUFFER;

#pragma pack(pop)
