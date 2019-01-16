#include <ntddk.h>
#include <wdm.h>

typedef unsigned int uint32_t;
//#define LOG(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, fmt, __VA_ARGS__)

#define VERSION 1

NTSTATUS IrpNotImplementedHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;

	UNREFERENCED_PARAMETER(DeviceObject);
	PAGED_CODE();

	// Complete the request
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_NOT_SUPPORTED;
}

NTSTATUS IrpDeviceIoCtlHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
	ULONG IoControlCode = 0;
	PIO_STACK_LOCATION IrpSp = NULL;

	NTSTATUS Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	UNREFERENCED_PARAMETER(DeviceObject);
	PAGED_CODE();

	IrpSp = IoGetCurrentIrpStackLocation(Irp);
	IoControlCode = IrpSp->Parameters.DeviceIoControl.IoControlCode;

	auto InSize = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
	char* InBuf = Irp->AssociatedIrp.SystemBuffer;

	if (IrpSp) {
		switch (IoControlCode) {

		case CTL_CODE(FILE_DEVICE_UNKNOWN, 0x7331, METHOD_BUFFERED, FILE_ANY_ACCESS): {
			typedef struct {
				uint32_t* addr;
				volatile uint32_t* val1;
				volatile uint32_t* val2;
			} Req;
			Req *req = (Req*)InBuf;

			if (!InBuf || InSize < sizeof *req) {
				Status = STATUS_INVALID_BUFFER_SIZE;
				break;
			}

			static char* mmio;
			if (!mmio) {
				PHYSICAL_ADDRESS addr;
				addr.QuadPart = 0xf0804000ull;
				mmio = MmMapIoSpace(addr, 0x1000, 0);
			}

			uint32_t* addr = req->addr;
			volatile uint32_t *val1 = req->val1, *val2 = req->val2;
			for (int _ = 0; _ < 50000; ++_) {
				*addr = *val1;
				mmio[0x4c] = 1 << 1;
				*addr = *val2;
				mmio[0x4c] = 1 << 1;
			}
			break;
		}

		default:
			Status = STATUS_NOT_SUPPORTED;
			break;
		}
	}

	Irp->IoStatus.Status = Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return Status;
}

NTSTATUS IrpCreateCloseHandler(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;

	UNREFERENCED_PARAMETER(DeviceObject);
	PAGED_CODE();

	// Complete the request
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

/// <summary>
/// IRP Unload Handler
/// </summary>
/// <param name="DeviceObject">The pointer to DEVICE_OBJECT</param>
/// <returns>NTSTATUS</returns>
VOID IrpUnloadHandler(IN PDRIVER_OBJECT DriverObject) {
	UNICODE_STRING DosDeviceName = { 0 };

	PAGED_CODE();

	RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\VBoxPwn");

	// Delete the symbolic link
	IoDeleteSymbolicLink(&DosDeviceName);

	// Delete the device
	IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath) {
	UINT32 i = 0;
	PDEVICE_OBJECT DeviceObject = NULL;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	UNICODE_STRING DeviceName, DosDeviceName = { 0 };

	UNREFERENCED_PARAMETER(RegistryPath);
	PAGED_CODE();

	RtlInitUnicodeString(&DeviceName, L"\\Device\\VBoxPwn");
	RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\VBoxPwn");

	// Create the device
	Status = IoCreateDevice(DriverObject,
		0,
		&DeviceName,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&DeviceObject);

	if (!NT_SUCCESS(Status)) {
		if (DeviceObject) {
			// Delete the device
			IoDeleteDevice(DeviceObject);
		}
		return Status;
	}

	// Assign the IRP handlers
	for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
		DriverObject->MajorFunction[i] = IrpNotImplementedHandler;
	}

	// Assign the IRP handlers for Create, Close and Device Control
	DriverObject->MajorFunction[IRP_MJ_CREATE] = IrpCreateCloseHandler;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = IrpCreateCloseHandler;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IrpDeviceIoCtlHandler;

	// Assign the driver Unload routine
	DriverObject->DriverUnload = IrpUnloadHandler;

	// Set the flags
	DeviceObject->Flags |= DO_DIRECT_IO;
	DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

	// Create the symbolic link
	Status = IoCreateSymbolicLink(&DosDeviceName, &DeviceName);

	return Status;
}