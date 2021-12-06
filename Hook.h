#pragma once
#include <ntddk.h>
#pragma warning(disable : 4100)

typedef NTSTATUS (*NtCreateFilePtr)(
	PHANDLE            FileHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK   IoStatusBlock,
	PLARGE_INTEGER     AllocationSize,
	ULONG              FileAttributes,
	ULONG              ShareAccess,
	ULONG              CreateDisposition,
	ULONG              CreateOptions,
	PVOID              EaBuffer,
	ULONG              EaLength
);

NTSTATUS HookNtCreateFile(PHANDLE            FileHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK   IoStatusBlock,
	PLARGE_INTEGER     AllocationSize,
	ULONG              FileAttributes,
	ULONG              ShareAccess,
	ULONG              CreateDisposition,
	ULONG              CreateOptions,
	PVOID              EaBuffer,
	ULONG              EaLength) {
	DbgPrint("[+] Successfully hooked NtCreateFile\n");
	return STATUS_SUCCESS;
}

NTSTATUS HookOperation() {
	DbgPrint("[+] %s called.\n", __FUNCTION__);

	CHAR JmpCode[] =
	{
		0x51,
		0x48, 0xB9,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x48, 0x87, 0x0C, 0x24,
		0xC3
	};

	UNICODE_STRING ZwAddress = RTL_CONSTANT_STRING(L"ZwCreateFile");
	PVOID RoutineAddress = MmGetSystemRoutineAddress(&ZwAddress);
	if (!RoutineAddress) {
		DbgPrint("[-] MmGetSystemRoutineAddress Failed.\n");
		return STATUS_UNSUCCESSFUL;
	}

	UINT64 HookAddress = (UINT64)&HookNtCreateFile;
	RtlCopyMemory(JmpCode + 0x3, &HookAddress, sizeof(PVOID));

	//NtCreateFilePtr NtCreateFile;
	PMDL pmdl;
	pmdl = IoAllocateMdl(RoutineAddress, sizeof(PVOID), FALSE, FALSE, NULL);
	if (!pmdl) {
		DbgPrint("[-] IoAllocateMdl Called.\n");
		return STATUS_UNSUCCESSFUL;
	}

	MmProbeAndLockPages(pmdl, KernelMode, IoReadAccess);
	PVOID VirtualAddress = MmMapLockedPagesSpecifyCache(pmdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
	if (!VirtualAddress) {
		DbgPrint("[-] MmMapLockedPagesSpecifyCache Failed.\n");
		IoFreeMdl(pmdl);
		return STATUS_UNSUCCESSFUL;
	}

	// make VA permissions RW
	MmProtectMdlSystemAddress(pmdl, PAGE_READWRITE);

	__try {
		RtlCopyMemory(VirtualAddress, JmpCode, sizeof(JmpCode));
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint("[-] Caught Exception\n");
	}

	MmUnlockPages(pmdl);
	IoFreeMdl(pmdl);

	return STATUS_SUCCESS;
}