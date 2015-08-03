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

void PrintHelp(void)
{
	printf(".sys Loader helper - Arguments list\n");
	printf("l [driver name] Load the driver\n");
	printf("u [driver name] Unload the driver\n");
	exit(0);
};

void GetDriverUp(const char *name)
{
	int errNum = 0;
	HANDLE hDevice;
	TCHAR driverLocation[MAX_PATH];

	memset(driverLocation, 0, sizeof(TCHAR)* MAX_PATH);

	fprintf(stderr, "about to do CreateFile %s\n", name);
	hDevice = CreateFile("//./netmap",
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	fprintf(stderr, "CreateFile returns %p\n", hDevice);
	if (hDevice != INVALID_HANDLE_VALUE) {
		printf("module %s already loaded\n", name);
		return;
	}
	errNum = GetLastError();

	if (errNum != ERROR_FILE_NOT_FOUND) {
		printf("CreateFile failed!  error is not FILE_NOT_FOUND = %d\n", errNum);
		return;
	}

	if (!SetupDriverName(driverLocation, sizeof(driverLocation))) {
		printf("SetupDriverName FAILED! (%s)\n", driverLocation);
		return;
	}

	if (!ManageDriver(name, driverLocation, DRIVER_FUNC_INSTALL)) {
		printf("Unable to install driver. \n");
		ManageDriver(name, driverLocation, DRIVER_FUNC_REMOVE);
		return;
	}
	printf("Driver correctly loaded\n");
}

void BringDriverDown(const char *name)
{
	int errNum = 0;
	HANDLE hDevice;
	TCHAR driverLocation[MAX_PATH];

	printf("Trying to unload the driver %s...\n", name);

	hDevice = CreateFile("\\\\.\\netmap",
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hDevice == INVALID_HANDLE_VALUE) {
		printf("Closing handle...:\n");
		CloseHandle(hDevice);
		printf("Unloading driver...:\n");
		ManageDriver(name,
			driverLocation,
			DRIVER_FUNC_REMOVE
			);
	} else {
		errNum = GetLastError();
		if (errNum != 0) {
			printf("Failed to unload driver: %i", errNum);
		}
			
		if (!SetupDriverName(driverLocation, sizeof(driverLocation))) {
			return;
		}
		ManageDriver(name,
			driverLocation,
			DRIVER_FUNC_REMOVE
			);
		return;
	}
}

int _cdecl main(int argc, CHAR* argv[])
{
	char c;
	char *what = DRIVER_NAME;

	if (argc < 2 || argc > 3)
		PrintHelp();
	c = argv[1][0];
	if (argc == 3)
		what = argv[2];
	if (c == 'l' || c == 'L') {
		GetDriverUp(what);
	} else if (c == 'u' || c == 'U') {
		BringDriverDown(what);
	} else {
		PrintHelp();
	}
	return 0;
}
