#ifndef _RK_TOOLS_H_
#define _RK_TOOLS_H_

#include "rk_Hook.h"

VOID LowerIRQLevel( KIRQL oldIrql );
KIRQL RaiseIRQLevel();
ULONG GetProcessNameOffset();
PMODULE_INFO FindModuleByName( PMODULE_LIST pModuleList, PCHAR moduleName ,ULONG moduleNameSize);

#endif
