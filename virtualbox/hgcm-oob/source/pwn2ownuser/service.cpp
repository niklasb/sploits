#include "stdafx.h"
#include <Windows.h>
#include "debug.h"
#include "service.h"
#include "common.h"
#include "ntdll_undocnt.h"

#define SERVICE_CONFIG_MAX_SIZE 0x1000
//--------------------------------------------------------------------------------------
BOOL DrvOpenDevice(PWSTR lpszDeviceName, HANDLE *phDevice)
{
    GET_NATIVE(NtOpenFile);

    IO_STATUS_BLOCK StatusBlock;
    OBJECT_ATTRIBUTES ObjAttr;
    UNICODE_STRING usName;

    UNICODE_FROM_WCHAR(&usName, lpszDeviceName);
    InitializeObjectAttributes(&ObjAttr, &usName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    #define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020

    NTSTATUS ns = f_NtOpenFile(
        phDevice,
        FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE,
        &ObjAttr,
        &StatusBlock,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_SYNCHRONOUS_IO_NONALERT
    );
    if (!NT_SUCCESS(ns))
    {
        DbgMsg(__FILE__, __LINE__, "NtOpenFile() fails; status: 0x%.8x\n", ns);
        return FALSE;
    }

    return TRUE;
}
//--------------------------------------------------------------------------------------
BOOL DrvServiceStart(char *lpszServiceName, char *lpszPath, PBOOL bAllreadyStarted)
{
    BOOL bRet = FALSE;
    SC_HANDLE hScm = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (hScm)
    {
        DbgMsg(__FILE__, __LINE__, "Creating service...\n");

        SC_HANDLE hService = CreateService(
            hScm, lpszServiceName, lpszServiceName, 
            SERVICE_START | DELETE | SERVICE_STOP, 
            SERVICE_KERNEL_DRIVER, 
            SERVICE_DEMAND_START, 
            SERVICE_ERROR_IGNORE, 
            lpszPath, 
            NULL, NULL, NULL, NULL, NULL
        );
        if (hService == NULL)
        {
            if (GetLastError() == ERROR_SERVICE_EXISTS)
            {
                if (hService = OpenService(hScm, lpszServiceName, SERVICE_START | DELETE | SERVICE_STOP))
                {
                    DbgMsg(__FILE__, __LINE__, "Allready exists\n");
                }
                else
                {
                    DbgMsg(__FILE__, __LINE__, "OpenService() ERROR %d\n", GetLastError());
                }
            }
            else
            {
                DbgMsg(__FILE__, __LINE__, "CreateService() ERROR %d\n", GetLastError());
            }
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, "OK\n");
        }

        if (hService)
        {                
            DbgMsg(__FILE__, __LINE__, "Starting service...\n");

            if (StartService(hService, 0, NULL))
            {
                DbgMsg(__FILE__, __LINE__, "OK\n");  

                bRet = TRUE;
            }
            else
            {
                if (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)
                {
                    DbgMsg(__FILE__, __LINE__, "Allready running\n");

                    if (bAllreadyStarted)
                    {
                        *bAllreadyStarted = TRUE;
                    }

                    bRet = TRUE;
                }
                else
                {
                    DbgMsg(__FILE__, __LINE__, "StartService() ERROR %d\n", GetLastError());
                }                    
            }            

            CloseServiceHandle(hService);
        }

        CloseServiceHandle(hScm);
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "OpenSCManager() ERROR %d\n", GetLastError());
    }

    return bRet;
}
//--------------------------------------------------------------------------------------
BOOL DrvServiceStop(char *lpszServiceName)
{
    BOOL bRet = FALSE;
    SC_HANDLE hScm = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (hScm)
    {
        DbgMsg(__FILE__, __LINE__, "Opening service...\n");

        SC_HANDLE hService = OpenService(hScm, lpszServiceName, SERVICE_ALL_ACCESS);
        if (hService)
        {
            SERVICE_STATUS ssStatus;

            DbgMsg(__FILE__, __LINE__, "OK\n");
            DbgMsg(__FILE__, __LINE__, "Stopping service...\n");
            
            if (!ControlService(hService, SERVICE_CONTROL_STOP, &ssStatus))
            {
                DbgMsg(__FILE__, __LINE__, "ControlService() ERROR %d\n", GetLastError());
            }
            else
            {
                DbgMsg(__FILE__, __LINE__, "OK\n");                
            }

            DbgMsg(__FILE__, __LINE__, "Deleting service...\n");

            if (DeleteService(hService))
            {
                DbgMsg(__FILE__, __LINE__, "OK\n");

                bRet = TRUE;
            }
            else
            {
                DbgMsg(__FILE__, __LINE__, "DeleteService() ERROR %d\n", GetLastError());                
            }

            CloseServiceHandle(hService);
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, "OpenService() ERROR %d\n", GetLastError());
        }

        CloseServiceHandle(hScm);
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "OpenSCManager() ERROR %d\n", GetLastError());

    }

    return bRet;
}
//--------------------------------------------------------------------------------------
DWORD DrvServiceGetStartType(char *lpszServiceName)
{
    DWORD dwRet = (DWORD)-1;
    SC_HANDLE hScm = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (hScm)
    {
        SC_HANDLE hService = OpenService(hScm, lpszServiceName, SERVICE_ALL_ACCESS);
        if (hService)
        {
            DWORD dwBytesNeeded = 0;
            char szBuff[SERVICE_CONFIG_MAX_SIZE];

            LPQUERY_SERVICE_CONFIG Config = (LPQUERY_SERVICE_CONFIG)&szBuff;
            ZeroMemory(Config, sizeof(szBuff));

            if (QueryServiceConfig(hService, Config, sizeof(szBuff), &dwBytesNeeded)) 
            {
                dwRet = Config->dwStartType;
            }
            else
            {
                DbgMsg(__FILE__, __LINE__, "QueryServiceConfig() ERROR %d\n", GetLastError());
            }
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, "OpenService() ERROR %d\n", GetLastError());
        }

        CloseServiceHandle(hScm);
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "OpenSCManager() ERROR %d\n", GetLastError());

    }

    return dwRet;
}
//--------------------------------------------------------------------------------------
BOOL DrvServiceSetStartType(char *lpszServiceName, DWORD dwStartType)
{
    BOOL bRet = FALSE;
    SC_HANDLE hScm = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (hScm)
    {
        SC_HANDLE hService = OpenService(hScm, lpszServiceName, SERVICE_ALL_ACCESS);
        if (hService)
        {            
            bRet = ChangeServiceConfig(
                hService,
                SERVICE_NO_CHANGE, dwStartType,
                SERVICE_NO_CHANGE, NULL, 
                (dwStartType == SERVICE_BOOT_START) ? "Boot Bus Extender" : "",
                NULL, NULL, NULL, NULL, NULL
            );
            if (!bRet)
            {
                DbgMsg(__FILE__, __LINE__, "ChangeServiceConfig() ERROR %d\n", GetLastError());
            }         
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, "OpenService() ERROR %d\n", GetLastError());
        }

        CloseServiceHandle(hScm);
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "OpenSCManager() ERROR %d\n", GetLastError());

    }

    return bRet;
}
//--------------------------------------------------------------------------------------
BOOL DrvRegisterBootService(char *lpszServiceName, char *lpszPath, PBOOL bAllreadyStarted)
{
    BOOL bRet = FALSE;

    if (bAllreadyStarted)
    {
        *bAllreadyStarted = FALSE;
    }

    SC_HANDLE hScm = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (hScm)
    {
        DbgMsg(__FILE__, __LINE__, "Creating service...\n");

        SC_HANDLE hService = CreateService(
            hScm, 
            lpszServiceName, lpszServiceName, 
            SERVICE_START | DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS, 
            SERVICE_KERNEL_DRIVER, SERVICE_BOOT_START, SERVICE_ERROR_IGNORE, 
            lpszPath, 
            "Boot Bus Extender", NULL, NULL, NULL, NULL
        );
        if (hService == NULL)
        {
            if (GetLastError() == ERROR_SERVICE_EXISTS)
            {
                if (hService = OpenService(
                    hScm, 
                    lpszServiceName, 
                    SERVICE_START | DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS))
                {
                    DbgMsg(__FILE__, __LINE__, "Allready exists\n");
                }
                else
                {
                    DbgMsg(__FILE__, __LINE__, "OpenService() ERROR %d\n", GetLastError());
                }
            }
            else
            {
                DbgMsg(__FILE__, __LINE__, "CreateService() ERROR %d\n", GetLastError());
            }
        }
        else
        {
            DbgMsg(__FILE__, __LINE__, "OK\n");
        }

        if (hService)
        {                
            SERVICE_STATUS ServiceStatus;

            if (QueryServiceStatus(hService, &ServiceStatus))
            {
                if (ServiceStatus.dwCurrentState == SERVICE_RUNNING)
                {
                    if (bAllreadyStarted)
                    {
                        *bAllreadyStarted = TRUE;
                    }
                }

                bRet = TRUE;
            }
            else
            {
                DbgMsg(__FILE__, __LINE__, "QueryServiceStatus() ERROR %d\n", GetLastError());
            }            

            CloseServiceHandle(hService);
        }

        CloseServiceHandle(hScm);
    }
    else
    {
        DbgMsg(__FILE__, __LINE__, "OpenSCManager() ERROR %d\n", GetLastError());
    }

    return bRet;
}
//--------------------------------------------------------------------------------------
// EoF
