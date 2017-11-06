#include <windows.h>
#include <TlHelp32.h>
#include <DbgHelp.h>
#include "debugger.h"

HANDLE processHandle;
DWORD getPid(const char* pName) 
{
	PROCESSENTRY32 entry;
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE)
		return 0; // Return 0 if the handle is invalid
	entry.dwSize = sizeof(PROCESSENTRY32);
	Process32First(snap, &entry); // Get the first process information
	do 
	{
		if (strcmp(entry.szExeFile, pName) == 0) // If the process name is equal to the process name we are searching for
			return entry.th32ProcessID; // Return its process ID
	} while (Process32Next(snap, &entry)); // Check every process in a loop until there are none left and Process32Next returns 0
	CloseHandle(snap);
}
Debugger::Debugger(DWORD pid)
{
	processHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
		PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, false, pid); // Get the process handle
}
Debugger::Debugger(const char* processName)
{
	Debugger::Debugger(getPid(processName));
}
bool Debugger::InjectDLL(const char* path)
{
	DWORD dw;
	LPVOID addr = VirtualAllocEx(processHandle, 0, strlen(path) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); // Store the address where our memory has been allocated, we'll need it for a future call
	this->WriteMemory(addr, path, strlen(path) + 1); // Write our DLL path to the allocated address in the target process
	HANDLE thread = CreateRemoteThread(processHandle, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, addr, 0, 0); // Create a new thread in the target process that will load our DLL
	WaitForSingleObject(thread, INFINITE);
	if (thread == INVALID_HANDLE_VALUE)
		return false;
	return true;
}
BYTE* Debugger::ReadMemory(LPCVOID startAddr, int count)
{
	if (processHandle == INVALID_HANDLE_VALUE || !processHandle)
		return 0;
	BYTE *buffer = (BYTE *)GlobalAlloc(0, count);
	ReadProcessMemory(processHandle, startAddr, buffer, count, 0);
	return buffer;
}
bool Debugger::WriteMemory(LPVOID startAddr, LPCVOID buffer, int count)
{
	if (processHandle == INVALID_HANDLE_VALUE || !processHandle)
		return false;
	return WriteProcessMemory(processHandle, startAddr, buffer, count, 0);
}
HANDLE Debugger::GetProcessHandle()
{
	if (processHandle == INVALID_HANDLE_VALUE || !processHandle)
		return 0;
	return processHandle;
}