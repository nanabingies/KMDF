#include "Hook.h"

UNICODE_STRING DevName = RTL_CONSTANT_STRING(L"\\Device\\KMDF");
UNICODE_STRING DosDevName = RTL_CONSTANT_STRING(L"\\DosDevices\\KMDF");

VOID DriverUnload(IN PDRIVER_OBJECT DriverObject) {
	DbgPrint("[+] %s called.\n", __FUNCTION__);
	IoDeleteSymbolicLink(&DosDevName);
	IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS DefaultDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP pIrp) {
	UNREFERENCED_PARAMETER(DeviceObject);

	DbgPrint("[+] %s called.\n", __FUNCTION__);
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IofCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegPath) {
	UNREFERENCED_PARAMETER(RegPath);

	DbgPrint("[+] %s called.\n", __FUNCTION__);
	PDEVICE_OBJECT DeviceObject;
	NTSTATUS rt = IoCreateDevice(DriverObject, 0, &DevName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN,
		FALSE, &DeviceObject);
	if (!NT_SUCCESS(rt)) {
		DbgPrint("[-] IoCreateDevice Failed.\n");
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	rt = IoCreateSymbolicLink(&DosDevName, &DevName);
	if (!NT_SUCCESS(rt)) {
		DbgPrint("[-] IoCreateSymbolicLink Failed.\n");
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
		DriverObject->MajorFunction[i] = DefaultDispatch;
	DriverObject->DriverUnload = DriverUnload;

	if (!NT_SUCCESS(HookOperation())) {
		DbgPrint("[-] Hook Operation Unsuccessful\n");
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	return STATUS_SUCCESS;
}