#include <windows.h>

class Debugger
{
	public:
		bool Debugger::InjectDLL(const char *path);
		Debugger::Debugger(DWORD pid);
		Debugger::Debugger(const char *processName);
		BYTE* Debugger::ReadMemory(LPCVOID startAddr, int count); // Reads target process memory
		bool Debugger::WriteMemory(LPVOID startAddr, LPCVOID buffer, int count); // Writes something to target process memory
		HANDLE Debugger::GetProcessHandle();
};