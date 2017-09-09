#ifndef MEMORYHELPER
#define MEMORYHELPER

#include <windows.h>

DWORD FindProcess(BYTE* name);
DWORD SearchVirtualMemory(BYTE* text, DWORD length, DWORD pid, DWORD start);

#endif
 