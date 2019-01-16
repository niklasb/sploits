
#include "stdafx.h"
#include <Windows.h>
#include "common.h"

//--------------------------------------------------------------------------------------
void DbgMsg(char *lpszFile, int Line, char *lpszMsg, ...)
{
    va_list mylist;
    va_start(mylist, lpszMsg);

    int len = _vscprintf(lpszMsg, mylist) + 0x100;

    char *lpszBuff = (char *)M_ALLOC(len);
    if (lpszBuff == NULL)
    {
        va_end(mylist);
        return;
    }

    char *lpszOutBuff = (char *)M_ALLOC(len);
    if (lpszOutBuff == NULL)
    {
        M_FREE(lpszBuff);
        va_end(mylist);
        return;
    }

    vsprintf(lpszBuff, lpszMsg, mylist);
    va_end(mylist);

    sprintf(lpszOutBuff, "[%.5d] %s(%d) : %s", GetCurrentProcessId(), GetNameFromFullPath(lpszFile), Line, lpszBuff);

#ifdef DBG

    OutputDebugString(lpszOutBuff);

#endif

    HANDLE hStd = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hStd != INVALID_HANDLE_VALUE)
    {        
        DWORD dwWritten = 0;

        WriteFile(hStd, lpszBuff, lstrlen(lpszBuff), &dwWritten, NULL);
    }

    M_FREE(lpszOutBuff);
    M_FREE(lpszBuff);
}
//--------------------------------------------------------------------------------------
// EoF
