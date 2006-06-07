
#include <ntddk.h>
#include "rk_Hook.h"

KIRQL RaiseIRQLevel()
{
	KIRQL currentIrql, oldIrql;

	currentIrql = KeGetCurrentIrql();
	oldIrql = currentIrql;
	if (currentIrql < DISPATCH_LEVEL)
		KeRaiseIrql( DISPATCH_LEVEL, &oldIrql);
	return oldIrql;
}

VOID LowerIRQLevel( KIRQL oldIrql )
{
	KeLowerIrql( oldIrql );
}

// this MUST be called inside DeviceEntry
ULONG GetProcessNameOffset()
{
	ULONG offset;
	PEPROCESS pProcess = PsGetCurrentProcess();
		 
	for ( offset = 0; offset < PAGE_SIZE;offset++) {
		if (!strncmp("System",(PCHAR)pProcess + offset,strlen("System")))
			return offset;
	}
	return 0;
}

PMODULE_INFO FindModuleByName( PMODULE_LIST pModuleList, PCHAR moduleName , ULONG moduleNameSize)
{
	ULONG i;
	for (i=0;i<pModuleList->d_modules; i++ ) {		
//		if ( _stricmp( pModuleList->a_moduleInfo[i].a_bPath + pModuleList->a_moduleInfo[i].w_NameOffset, moduleName) == 0) {
		if ( memcmp( pModuleList->a_moduleInfo[i].a_bPath + pModuleList->a_moduleInfo[i].w_NameOffset, moduleName, moduleNameSize) == 0) {
			return &pModuleList->a_moduleInfo[i];
		}
	}
	return NULL;
}
