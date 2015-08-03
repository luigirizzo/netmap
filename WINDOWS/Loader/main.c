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

#define DRIVER_NAME "netmap"	// default

#include <windows.h>


BOOLEAN RemoveDriver(_In_ SC_HANDLE  SchSCManager, _In_ LPCTSTR    name);
BOOLEAN StartDriver( _In_ SC_HANDLE  SchSCManager, _In_ LPCTSTR    name);
BOOLEAN StopDriver( _In_ SC_HANDLE  SchSCManager, _In_ LPCTSTR    name);

BOOLEAN
InstallDriver(_In_ SC_HANDLE  SchSCManager, _In_ LPCTSTR    name, _In_ LPCTSTR    ServiceExe)
{
    SC_HANDLE   schService;
    DWORD       err;

    // NOTE: This creates an entry for a standalone driver. If this
    //       is modified for use with a driver that requires a Tag,
    //       Group, and/or Dependencies, it may be necessary to
    //       query the registry for existing driver information
    //       (in order to determine a unique Tag, etc.).

    // Create a new a service object.

    schService = CreateService(SchSCManager,           // handle of service control manager database
                               name,             // address of name of service to start
                               name,             // address of display name
                               SERVICE_ALL_ACCESS,     // type of access to service
                               SERVICE_KERNEL_DRIVER,  // type of service
                               SERVICE_DEMAND_START,   // when to start service
                               SERVICE_ERROR_NORMAL,   // severity if service fails to start
                               ServiceExe,             // address of name of binary file
                               NULL,                   // service does not belong to a group
                               NULL,                   // no tag requested
                               NULL,                   // no dependency names
                               NULL,                   // use LocalSystem account
                               NULL                    // no password for service account
                               );

    if (schService == NULL) {
        err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) {
            fprintf(stderr, "CreateService %s: Service exists\n", name);
            return TRUE; // Ignore this error.
        } else {
            fprintf(stderr, "CreateService %s failed!  Error = %d\n", name, err );
            return  FALSE;
        }
    } else {
	fprintf(stderr, "CreateService %s success\n", name);
    }
    CloseServiceHandle(schService);
    return TRUE;
}

/* 'i'nstall or 'u'ninstall */
BOOLEAN
ManageDriver( _In_ LPCTSTR  name, _In_ LPCTSTR  path, _In_ USHORT fn)
{
    SC_HANDLE   schSCManager;
    BOOLEAN rCode = TRUE;

    //
    // Insure (somewhat) that the driver and service names are valid.
    // path is only used for uninstall
    //

    if (!name || !path) {
        fprintf(stderr, "Invalid Driver or Service provided to ManageDriver() \n");
        return FALSE;
    }

    // Connect to the Service Control Manager and open the Services database.

    schSCManager = OpenSCManager(NULL,                   // local machine
                                 NULL,                   // local database
                                 SC_MANAGER_ALL_ACCESS   // access required
                                 );

    if (!schSCManager) {
        fprintf(stderr, "Open SC Manager failed! Error = %d \n", GetLastError());
        return FALSE;
    }

    // Do the requested function.

    switch(fn) {
        case 'i':
        case 'l':	// Install the driver service.

            if (InstallDriver(schSCManager, name, path)) {
                // Start the driver service (i.e. start the driver).
                rCode = StartDriver(schSCManager, name);
            } else {
                rCode = FALSE; // Indicate an error.
            }
	    if (rCode == TRUE)
                break;
	    /* else fallthrough to undo */

        case 'r':
        case 'u':
	    // Stop the driver.
            StopDriver(schSCManager, name);
            // Remove the driver service.
            RemoveDriver(schSCManager, name);
            rCode = TRUE; // Ignore all errors.
            break;

        default:
            fprintf(stderr, "Unknown ManageDriver() function. \n");
            rCode = FALSE;
            break;
    }

    CloseServiceHandle(schSCManager);
    fprintf(stderr, "%s returns %s\n", __FUNCTION__, rCode ? "TRUE" : "FALSE");
    return rCode;
}   // ManageDriver


BOOLEAN
RemoveDriver( _In_ SC_HANDLE    SchSCManager, _In_ LPCTSTR      name)
{
    SC_HANDLE   schService;
    BOOLEAN     rCode = TRUE;

    schService = OpenService(SchSCManager, name, SERVICE_ALL_ACCESS);

    if (schService == NULL) {
        fprintf(stderr, "OpenService failed!  Error = %d \n", GetLastError());
        return FALSE; // Indicate error.
    }

    // Mark the service for deletion from the service control manager database.

    if (DeleteService(schService)) {
        fprintf(stderr, "%s %s success\n", __FUNCTION__, name);
        rCode = TRUE;
    } else {
        fprintf(stderr, "DeleteService failed!  Error = %d \n", GetLastError());
        rCode = FALSE;
    }
    CloseServiceHandle(schService);

    return rCode;
}   // RemoveDriver



BOOLEAN
StartDriver( _In_ SC_HANDLE    SchSCManager, _In_ LPCTSTR      name)
{
    SC_HANDLE   schService;
    DWORD       err;
    BOOLEAN     rCode = TRUE;

    schService = OpenService(SchSCManager, name, SERVICE_ALL_ACCESS);

    if (schService == NULL) {
        fprintf(stderr, "OpenService failed!  Error = %d \n", GetLastError());
        return FALSE; // Indicate failure.
    }

    // Start the execution of the service (i.e. start the driver).

    if (!StartService(schService,     // service identifier
                      0,              // number of arguments
                      NULL            // pointer to arguments
                      )) {
        err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING) {
            fprintf(stderr, "service %s already running\n", name);
            rCode = TRUE; // Ignore this error.
        } else {
		// 123 is ERROR_INVALID_NAME - should not be returned!
            fprintf(stderr, "StartService failure! Error = %d \n", err );
            rCode = FALSE;
        }
    }

    CloseServiceHandle(schService);
    return rCode;

}   // StartDriver



BOOLEAN
StopDriver( _In_ SC_HANDLE    SchSCManager, _In_ LPCTSTR      name)
{
    BOOLEAN         rCode;
    SC_HANDLE       schService;
    SERVICE_STATUS  serviceStatus;

    schService = OpenService(SchSCManager, name, SERVICE_ALL_ACCESS);

    if (schService == NULL) {
        fprintf(stderr, "OpenService failed!  Error = %d \n", GetLastError());
        return FALSE;
    }

    // Request that the service stop.

    if (ControlService(schService, SERVICE_CONTROL_STOP, &serviceStatus)) {
        rCode = TRUE; // Indicate success.
    } else {
        fprintf(stderr, "ControlService failed!  Error = %d \n", GetLastError() );
        // Indicate failure.  Fall through to properly close the service handle.
        rCode = FALSE;
    }
    CloseServiceHandle (schService);
    return rCode;
}   //  StopDriver

BOOLEAN
SetupDriverName(const TCHAR *name, const TCHAR *dir,
	_Inout_updates_bytes_all_(len) PCHAR s, _In_ ULONG len)
{
    HANDLE fileHandle;

    if (dir == NULL) {
	if (0 == GetCurrentDirectory(len, s)) {
	    fprintf(stderr, "GetCurrentDirectory failed!  Error = %d \n", GetLastError());
	    return FALSE;
	}
    } else {
	if (FAILED( StringCbPrintf(s, len, "%s", dir) )) {
	    fprintf(stderr, "StringCbPrintf failed!  Error = %d \n", GetLastError());
	    return FALSE;
	}
    }

    if (FAILED(StringCbPrintf(s, len, "%s/%s.sys", s, name))) {
        return FALSE;
    }

    // find driver file

    fileHandle = CreateFile(s, GENERIC_READ,
			     0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "%s.sys is not loaded.\n", name);
        return FALSE;
    } 
    fprintf(stderr, "file %s found.\n", s);
    CloseHandle(fileHandle);
    _fullpath(s, s, len); // XXX overwrites...
    return TRUE;
}   // SetupDriverName

static void PrintHelp(void)
{
	fprintf(stderr, ".sys Loader helper - Arguments list\n");
	fprintf(stderr, "l [drivername [dir]] Load the driver\n");
	fprintf(stderr, "u [drivername] Unload the driver\n");
	exit(0);
};

static void GetDriverUp(const char *name, const char *dir)
{
	int errNum;
	HANDLE hDevice;
	TCHAR s[MAX_PATH];

	fprintf(stderr, "load driver for %s\n", name);

	if (FAILED(StringCbPrintf(s, sizeof(s), "//./%s", name)) ) {
		fprintf(stderr, "invalid name %s\n", name);
		PrintHelp();
	}

	hDevice = CreateFile(s, GENERIC_READ | GENERIC_WRITE,
		0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hDevice != INVALID_HANDLE_VALUE) {
		fprintf(stderr, "module %s already loaded\n", name);
		return;
	}
	errNum = GetLastError();

	if (errNum != ERROR_FILE_NOT_FOUND) {
		fprintf(stderr, "CreateFile %s failed error %d\n", s, errNum);
		return;
	}

	if (!SetupDriverName(name, dir, s, sizeof(s))) {
		fprintf(stderr, "SetupDriverName FAILED! (%s)\n", s);
		return;
	}

	if (!ManageDriver(name, s, 'i')) {
		fprintf(stderr, "Unable to install driver. \n");
		// ManageDriver(name, s, 'r');
		return;
	}
	fprintf(stderr, "Driver %s correctly loaded\n", name);
}

static void BringDriverDown(const char *name)
{
	HANDLE hDevice;
	TCHAR s[MAX_PATH];

	if (FAILED(StringCbPrintf(s, sizeof(s), "//./%s", name)) ) {
		fprintf(stderr, "%s: invalid name %s\n", __FUNCTION__, name);
		PrintHelp();
	}

	hDevice = CreateFile(s, GENERIC_READ | GENERIC_WRITE,
		0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hDevice != INVALID_HANDLE_VALUE) {
		CloseHandle(hDevice);
		ManageDriver(name, s, 'u');
	} else {
		fprintf(stderr, "%s %s failed, Invalid Handle\n", __FUNCTION__, s);
#if 0 /* this part does not make sense */
		int errNum = GetLastError();
		if (errNum != 0) {
			fprintf(stderr, "Failed to unload driver: error %i\n", errNum);
		}

		if (!SetupDriverName(name, NULL, s, sizeof(s))) {
			return;
		}
		ManageDriver(name, s, 'r');
#endif
		return;
	}
}

int _cdecl main(int argc, CHAR* argv[])
{
	char c;
	const char *what = DRIVER_NAME, *where = NULL;

	if (argc < 2 || argc > 4)
		PrintHelp();
	c = argv[1][0];
	if (argc >= 3)
		what = argv[2];
	if (argc == 4)
		where = argv[3];
	if (c == 'l' || c == 'L') {
		GetDriverUp(what, where);
	} else if (c == 'u' || c == 'U') {
		if (where != NULL)
			PrintHelp();
		BringDriverDown(what);
	} else {
		PrintHelp();
	}
	return 0;
}
