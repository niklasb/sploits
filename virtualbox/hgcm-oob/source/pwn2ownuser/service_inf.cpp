#include "stdafx.h"
#include <Windows.h>
#include "common.h"
#include "debug.h"
#include "service.h"
#include "service_inf.h"

/*
Format string arguments:

#1 - Source binary path
#2, #3 - Service name
*/
#define INF_DATA                                            \
                                                            \
"[Version]\n"                                               \
"Signature = \"$Windows NT$\"\n"                            \
"Class = \"Driver\"\n"                                      \
"Provider = %%MSFT%%\n"                                     \
"DriverVer = 27/10/2010,1.0.0.0\n"                          \
                                                            \
"[DestinationDirs]\n"                                       \
"DefaultDestDir = 12\n"                                     \
                                                            \
"[DefaultInstall]\n"                                        \
"OptionDesc = %%ServiceDescription%%\n"                     \
                                                            \
"[DefaultInstall.Services]\n"                               \
"AddService = %%ServiceName%%,,Driver.Service\n"            \
                                                            \
"[Driver.Service]\n"                                        \
"DisplayName = %%ServiceName%%\n"                           \
"Description = %%ServiceDescription%%\n"                    \
"ServiceBinary = %s\n"                                      \
"ServiceType = 1\n"                                         \
"StartType = 3\n"                                           \
"ErrorControl = 1\n"                                        \
"AddReg = Driver.AddRegistry\n"                             \
                                                            \
"[Driver.AddRegistry]\n"                                    \
"HKLM,%%RegKey%%\n"                                         \
                                                            \
"[Strings]\n"                                               \
"ServiceName = \"%s\"\n"                                    \
"ServiceDescription = %%ServiceName%%\n"                    \
"RegKey = \"system\\currentcontrolset\\services\\%s\"\n"


// how long we should wait before termination of installation process
#define INF_PROCESS_TIMEOUT (10 * 1000)
//--------------------------------------------------------------------------------------
BOOL InfLoadDriver(char *lpszServiceName, char *lpszFilePath)
{
	BOOL bRet = FALSE;

	// allocate memory for the inf file contens
	char *lpszData = (char *)M_ALLOC(PAGE_SIZE);
	if (lpszData)
	{
		wsprintf(lpszData, INF_DATA, lpszFilePath, lpszServiceName, lpszServiceName);

#ifdef DBG

		OutputDebugStringA(lpszData);
#endif      
		char szInfPath[MAX_PATH];
		GetTempPath(MAX_PATH, szInfPath);
		wsprintf(szInfPath + strlen(szInfPath), "\\%.8x.tmp", GetTickCount());

		// save inf file to the disk
		if (DumpToFile(szInfPath, lpszData, lstrlen(lpszData)))
		{
			DWORD dwExitCode = 0;

			// install/uninstall kernl mode driver from inf file
			if (StartProcess(
				INF_PROCESS_TIMEOUT, &dwExitCode, "rundll32", "setupapi,InstallHinfSection %s 128 %s",
				"DefaultInstall", szInfPath))
			{
				DbgMsg(__FILE__, __LINE__, __FUNCTION__"(): Exit code = %d\n", dwExitCode);

				if (dwExitCode == 0)
				{
					// start service
					bRet = OpenAndStartService(lpszServiceName);
				}
			}

			DeleteFile(szInfPath);
		}

		M_FREE(lpszData);
	}

	return bRet;
}
//--------------------------------------------------------------------------------------
BOOL InfUnloadDriver(char *lpszServiceName)
{
	// stop and uninstall service
	return DrvServiceStop(lpszServiceName);
}
//--------------------------------------------------------------------------------------
// EoF