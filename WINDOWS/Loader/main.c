/*
* Copyright (C) 2015 Universita` di Pisa. All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
*   1. Redistributions of source code must retain the above copyright
*      notice, this list of conditions and the following disclaimer.
*   2. Redistributions in binary form must reproduce the above copyright
*      notice, this list of conditions and the following disclaimer in the
*      documentation and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
* OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
* LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
* OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
* SUCH DAMAGE.
*/
#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strsafe.h>
#include "sysinstall.h"

BOOLEAN ManageDriver(__in LPCTSTR  DriverName, __in LPCTSTR  ServiceName, __in USHORT   Function);
BOOLEAN SetupDriverName(__inout_bcount_full(BufferLength) PCHAR DriverLocation,__in ULONG BufferLength);

void PrintHelp()
{
	printf("Netmap .sys Loader helper - Arguments list\n");
	printf("l Load the driver\n");
	printf("u Unload the driver\n");
};

void GetDriverUp()
{
	int errNum = 0;
	HANDLE hDevice;
	TCHAR driverLocation[MAX_PATH];
	memset(driverLocation, 0, sizeof(TCHAR)* MAX_PATH);

	if ((hDevice = CreateFile("\\\\.\\NetMap",
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL)) == INVALID_HANDLE_VALUE) {

		errNum = GetLastError();

		if (errNum != ERROR_FILE_NOT_FOUND) {
			printf("CreateFile failed!  ERROR_FILE_NOT_FOUND = %d\n", errNum);
			return;
		}
		else{
			printf("CreateFile ok!\n");
		}

		if (!SetupDriverName(driverLocation, sizeof(driverLocation))) {
			printf("SetupDriverName FAILED! (%s)\n", driverLocation);
			return;
		}

		if (!ManageDriver(DRIVER_NAME,
			driverLocation,
			DRIVER_FUNC_INSTALL
			)) {
			printf("Unable to install driver. \n");
			ManageDriver(DRIVER_NAME,
				driverLocation,
				DRIVER_FUNC_REMOVE
				);
			return;
		}
		printf("Driver correctly loaded\n");
	}
}

void BringDriverDown()
{
	int errNum = 0;
	HANDLE hDevice;
	TCHAR driverLocation[MAX_PATH];

	printf("Trying to unload the driver...\n");

	if ((hDevice = CreateFile("\\\\.\\NetMap",
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL)) == INVALID_HANDLE_VALUE)
	{
		printf("Closing handle...:\n");
		CloseHandle(hDevice);
		printf("Unloading driver...:\n");
		ManageDriver(DRIVER_NAME,
			driverLocation,
			DRIVER_FUNC_REMOVE
			);
	}
	else{
		errNum = GetLastError();
		if (errNum != 0)
		{
			printf("Failed to unload driver: %i", errNum);
		}
			
		if (!SetupDriverName(driverLocation, sizeof(driverLocation))) {
			return;
		}
		ManageDriver(DRIVER_NAME,
			driverLocation,
			DRIVER_FUNC_REMOVE
			);
		return;
	}
}

int _cdecl main(int argc, CHAR* argv[])
{
	if (argc < 2)
	{
		PrintHelp();
	}
	else{
		if ((argv[1][0] == 'l') || (argv[1][0] == 'L'))
		{
			GetDriverUp();
		}
		else if ((argv[1][0] == 'u') || (argv[1][0] == 'U'))
		{
			BringDriverDown();
		}
		else {
			PrintHelp();
		}
	}
}
