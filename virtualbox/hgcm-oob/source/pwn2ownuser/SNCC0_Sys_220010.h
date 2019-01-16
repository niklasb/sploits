#pragma once
#include <Windows.h>
#include "shellcode.h"
#include "libdsebypass.h"
#define SNCC0_DEVICE_PATH "\\\\.\\Global\\SNCC0_Sys"

BOOL expl_SNCC0_Sys_220010(KERNEL_EXPL_HANDLER Handler, PVOID HandlerContext);