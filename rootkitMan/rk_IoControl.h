#ifndef _H_RK_IOCONTROL_
#define _H_RK_IOCONTROL_

#define		FILE_DEVICE_ROOTKIT_DRIVER	FILE_DEVICE_UNKNOWN

//IOCTL codes
#define		IOCTL_HIDE_PROCESS			(ULONG) CTL_CODE(FILE_DEVICE_ROOTKIT_DRIVER, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#endif