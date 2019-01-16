#pragma once

BOOL DrvOpenDevice(PWSTR lpszDeviceName, HANDLE *phDevice);
BOOL DrvServiceStart(char *lpszServiceName, char *lpszPath, PBOOL bAllreadyStarted);
BOOL DrvServiceStop(char *lpszServiceName);
BOOL DrvRegisterBootService(char *lpszServiceName, char *lpszPath, PBOOL bAllreadyStarted);
DWORD DrvServiceGetStartType(char *lpszServiceName);
BOOL DrvServiceSetStartType(char *lpszServiceName, DWORD dwStartType);
