#ifndef _ROOTKIT_H_
#define _ROOTKIT_H_

#define		ROOTKIT_WIN32_DEV_NAME		L"\\DosDevices\\rootkitDrv"
#define		ROOTKIT_DEV_NAME			L"\\Device\\rootkitDrv"



typedef struct {
	PVOID notused;
} ROOTKIT_EXT, *PROOTKIT_EXT;

typedef struct {
    ULONG   processName;
    ULONG   processPid;
    ULONG   activeProcessListOffset;
} NTOSKRNL_OFFSETS, *PNTOSKRNL_OFFSETS;

#endif
