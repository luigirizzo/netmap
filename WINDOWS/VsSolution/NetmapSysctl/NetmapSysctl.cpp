// NetmapSysctl.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strsafe.h>
#include "..\..\NetmapLoader\sysinstall.h"
#include "..\..\win_glue.h"
#include "..\..\..\sys\net\netmap.h"


BOOLEAN ManageDriver(__in LPCTSTR  DriverName, __in LPCTSTR  ServiceName, __in USHORT   Function);
BOOLEAN SetupDriverName(__inout_bcount_full(BufferLength) PCHAR DriverLocation, __in ULONG BufferLength);

void PrintHelp()
{
	printf("Netmap.sys Sysctl sender - Help\n");
	printf("To set a sysctl variable : ");
	printf("  nmSysctl s <name> <value>");
	printf("To get a sysctl variable : ");
	printf("  nmSysctl g <name>");
}

int _tmain(int argc, _TCHAR* argv[])
{
	HANDLE hDevice;
	int result = 0;
	DWORD bRetur = 0;
	BOOL transactionResult = FALSE;
	DWORD ctlWord = NETMAP_GETSOCKOPT;
	struct sockopt sendData;

	if (argc < 3)
	{
		PrintHelp();
		return 0;
	}
	else{
		if ((argv[1][0] == 's') || (argv[1][0] == 'S'))
		{
			ctlWord = NETMAP_SETSOCKOPT;
			sendData.sopt_dir = SOPT_SET;
			//memcpy(&sendData.sopt_name, argv[2], strlen(argv[2]))
		}
		else if ((argv[1][0] == 'g') || (argv[1][0] == 'G'))
		{
			ctlWord = NETMAP_GETSOCKOPT;
			sendData.sopt_dir = SOPT_GET;
			if (argc < 4)
			{
				PrintHelp();
				return 0;
			}
		}
	}


	if ((hDevice = CreateFile(L"\\\\.\\netmap",
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL)) == INVALID_HANDLE_VALUE) {

		result = GetLastError();

		if (result == ERROR_FILE_NOT_FOUND) {
			printf("CreateFile failed!  ERROR_FILE_NOT_FOUND = %d\n", result);
			return -1;
		}
		else{
			printf("CreateFile ok!\n");
		}

	}

	transactionResult = DeviceIoControl(hDevice,
		ctlWord,
		NULL,
		0,
		NULL,
		0,
		&bRetur,
		NULL
		);

	CloseHandle(hDevice);
	return 0;
}

