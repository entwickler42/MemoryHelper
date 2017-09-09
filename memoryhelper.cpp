#include "memoryhelper.h"
#include <tlhelp32.h>

//---------------------------------------------------------------------------
DWORD FindProcess(BYTE* name)
{
   HANDLE h;
   PROCESSENTRY32 p_entry;
   int process_id = -1;

   h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);

   if(h != (HANDLE)-1)
   {
      p_entry.dwSize = sizeof(PROCESSENTRY32);

      if(Process32First(h,&p_entry))
      {
         if(strcmp(p_entry.szExeFile,name) == 0) process_id = p_entry.th32ProcessID;
         while(Process32Next(h,&p_entry) && process_id == -1)
            if(strcmp(p_entry.szExeFile,name) == 0) process_id = p_entry.th32ProcessID;
      }
   }

   CloseHandle(h);

   return process_id;
}
//---------------------------------------------------------------------------
DWORD SearchVirtualMemory(BYTE* text, DWORD length, DWORD pid, DWORD start)
{
   DWORD address = 0x0;
   HANDLE process;
   SYSTEM_INFO si;
   MEMORY_BASIC_INFORMATION mbi;

   GetSystemInfo(&si);

   process = OpenProcess(PROCESS_VM_READ|PROCESS_QUERY_INFORMATION|PROCESS_VM_OPERATION,false,pid);

   if(process != NULL)
   {
      LPCVOID addr;

      if(start != 0)  addr = (LPCVOID)start;
      else            addr = si.lpMinimumApplicationAddress;

      while(addr < si.lpMaximumApplicationAddress && address == 0x0)
      {
         mbi.RegionSize = 0;
         VirtualQueryEx(process,addr,&mbi,sizeof(MEMORY_BASIC_INFORMATION));
         addr = (LPCVOID)((DWORD)mbi.BaseAddress + mbi.RegionSize);

         if(mbi.State == MEM_COMMIT)
         {
            DWORD size;
            char *mem = new char[mbi.RegionSize];

            ReadProcessMemory(process,mbi.BaseAddress,mem,mbi.RegionSize,&size);

            if(size > 0 && size >= length)
               for(unsigned int i=0; i<size-length && address == 0x0; i++)
               {
                  bool match = true;

                  for(unsigned int j = 0; j<length && match; j++) match = ((mem+i)[j] == text[j]);

                  if(match)
                  {
                     address = ((unsigned long)mbi.BaseAddress + i);
                     if(address == start) address = 0x0;
                  }
               }
            delete mem;
         }
      }
      CloseHandle(process);
   }

   return address;
}