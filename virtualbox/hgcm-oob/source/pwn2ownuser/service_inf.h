#pragma once
#include <Windows.h>

BOOL InfLoadDriver(char *lpszServiceName, char *lpszFilePath);

BOOL InfUnloadDriver(char *lpszServiceName);