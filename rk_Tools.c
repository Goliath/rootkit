
#include <ntddk.h>
#include "rk_Tools.h"
#include "rk_Hook.h"

int uwcscat(PWCHAR buf, PUNICODE_STRING str) {
  WCHAR *p, *q;
  USHORT l;
  int elen=0;
  if (!str) return 0;
  p = buf;
  q = str->Buffer;
  l=(str->Length)/sizeof(WCHAR);
  if (!str->Buffer) return 0;
  while (*p++ != L'\0');
  --p;
  while(l-->0 && *q!=L'\0') { *p++ = *q++; ++elen; }
  *p = L'\0';
  return elen;
}

int getFullPath(PWCHAR buf, USHORT bufsize,
		POBJECT_ATTRIBUTES oa) {
  NTSTATUS rtn;
  PVOID Object;
  int curlen=0;

  buf[0]=L'\0';
  if (!oa) return 0;

  if (oa->RootDirectory != NULL) {
    rtn=
      ObReferenceObjectByHandle(oa->RootDirectory,
				0,
				0,
				KernelMode,
				&Object,
				NULL);

    if (rtn==STATUS_SUCCESS) {
      int bytes;
      rtn=ObQueryNameString(Object,
			    (PUNICODE_STRING)buf,
			    bufsize,
			    &bytes);
      ObDereferenceObject(Object);
      if (rtn==STATUS_SUCCESS) {
	WCHAR *p = ((PUNICODE_STRING)buf)->Buffer, *q=buf;
	USHORT len = (((PUNICODE_STRING)buf)->Length)/sizeof(WCHAR);
	if ((len+2)*sizeof(WCHAR)<bufsize) {
	  while (len-->0 && *p!=L'\0') {
	    *q++ = *p++;
	    ++curlen;
	  }
	  *q++=OBJ_NAME_PATH_SEPARATOR;
	  ++curlen;
	}
	*q = L'\0';
      }
    }
  }

  if (oa->ObjectName &&
      oa->Length+(curlen+1)*sizeof(WCHAR) < bufsize) {
    curlen += uwcscat(buf+curlen, oa->ObjectName);
  }
  else *buf = L'\0';
  return curlen;
}

ULONG getDirEntryLenToNext( 
		IN PVOID FileInformationBuffer,
        IN FILE_INFORMATION_CLASS FileInfoClass
)
{
	ULONG result = 0;
	switch(FileInfoClass){
		case FileDirectoryInformation:
			result = ((PFILE_DIRECTORY_INFORMATION)FileInformationBuffer)->NextEntryOffset;
			break;
		case FileFullDirectoryInformation:
			result = ((PFILE_FULL_DIR_INFORMATION)FileInformationBuffer)->NextEntryOffset;
			break;
		case FileIdFullDirectoryInformation:
			result = ((PFILE_ID_FULL_DIR_INFORMATION)FileInformationBuffer)->NextEntryOffset;
			break;
		case FileBothDirectoryInformation:
			result = ((PFILE_BOTH_DIR_INFORMATION)FileInformationBuffer)->NextEntryOffset;
			break;
		case FileIdBothDirectoryInformation:
			result = ((PFILE_ID_BOTH_DIR_INFORMATION)FileInformationBuffer)->NextEntryOffset;
			break;
		case FileNamesInformation:
			result = ((PFILE_NAMES_INFORMATION)FileInformationBuffer)->NextEntryOffset;
			break;
	}
	return result;
}

VOID setDirEntryLenToNext( 
		IN PVOID FileInformationBuffer,
        IN FILE_INFORMATION_CLASS FileInfoClass,
		IN ULONG value
)
{
	switch(FileInfoClass){
		case FileDirectoryInformation:
			((PFILE_DIRECTORY_INFORMATION)FileInformationBuffer)->NextEntryOffset = value;
			break;
		case FileFullDirectoryInformation:
			((PFILE_FULL_DIR_INFORMATION)FileInformationBuffer)->NextEntryOffset = value;
			break;
		case FileIdFullDirectoryInformation:
			((PFILE_ID_FULL_DIR_INFORMATION)FileInformationBuffer)->NextEntryOffset = value;
			break;
		case FileBothDirectoryInformation:
			((PFILE_BOTH_DIR_INFORMATION)FileInformationBuffer)->NextEntryOffset = value;
			break;
		case FileIdBothDirectoryInformation:
			((PFILE_ID_BOTH_DIR_INFORMATION)FileInformationBuffer)->NextEntryOffset = value;
			break;
		case FileNamesInformation:
			((PFILE_NAMES_INFORMATION)FileInformationBuffer)->NextEntryOffset = value;
			break;
	}
}
	
PVOID getDirEntryFileName( 
		IN PVOID FileInformationBuffer,
        IN FILE_INFORMATION_CLASS FileInfoClass
)
{
	PVOID result = 0;
	switch(FileInfoClass){
		case FileDirectoryInformation:
			result = (PVOID)&((PFILE_DIRECTORY_INFORMATION)FileInformationBuffer)->FileName[0];
			break;
		case FileFullDirectoryInformation:
			result =(PVOID)&((PFILE_FULL_DIR_INFORMATION)FileInformationBuffer)->FileName[0];
			break;
		case FileIdFullDirectoryInformation:
			result =(PVOID)&((PFILE_ID_FULL_DIR_INFORMATION)FileInformationBuffer)->FileName[0];
			break;
		case FileBothDirectoryInformation:
			result =(PVOID)&((PFILE_BOTH_DIR_INFORMATION)FileInformationBuffer)->FileName[0];
			break;
		case FileIdBothDirectoryInformation:
			result =(PVOID)&((PFILE_ID_BOTH_DIR_INFORMATION)FileInformationBuffer)->FileName[0];
			break;
		case FileNamesInformation:
			result =(PVOID)&((PFILE_NAMES_INFORMATION)FileInformationBuffer)->FileName[0];
			break;
	}
	return result;
}

ULONG getDirEntryFileLength( 
		IN PVOID FileInformationBuffer,
        IN FILE_INFORMATION_CLASS FileInfoClass
)
{
	ULONG result = 0;
	switch(FileInfoClass){
		case FileDirectoryInformation:
			result = (ULONG)((PFILE_DIRECTORY_INFORMATION)FileInformationBuffer)->FileNameLength;
			break;
		case FileFullDirectoryInformation:
			result =(ULONG)((PFILE_FULL_DIR_INFORMATION)FileInformationBuffer)->FileNameLength;
			break;
		case FileIdFullDirectoryInformation:
			result =(ULONG)((PFILE_ID_FULL_DIR_INFORMATION)FileInformationBuffer)->FileNameLength;
			break;
		case FileBothDirectoryInformation:
			result =(ULONG)((PFILE_BOTH_DIR_INFORMATION)FileInformationBuffer)->FileNameLength;
			break;
		case FileIdBothDirectoryInformation:
			result =(ULONG)((PFILE_ID_BOTH_DIR_INFORMATION)FileInformationBuffer)->FileNameLength;
			break;
		case FileNamesInformation:
			result =(ULONG)((PFILE_NAMES_INFORMATION)FileInformationBuffer)->FileNameLength;
			break;
	}
	return result;
}

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
