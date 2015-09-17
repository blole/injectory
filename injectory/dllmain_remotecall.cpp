#include "injectory/process.hpp"
#include "injectory/memoryarea.hpp"

typedef BOOL(__stdcall *DLLMAIN)(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved);

struct DLLMAINCALL
{
	DLLMAIN fpDllMain;
	HMODULE hModule;
	DWORD ul_reason_for_call;
	LPVOID lpReserved;
};

BOOL __stdcall DllMainWrapper(struct DLLMAINCALL *parameter)
{
	return parameter->fpDllMain(parameter->hModule, parameter->ul_reason_for_call, parameter->lpReserved);
}
void DllMainWrapper_end(void)
{
}

void Process::remoteDllMainCall(LPVOID lpModuleEntry, HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	struct DLLMAINCALL dllMainCall = { (DLLMAIN)lpModuleEntry, hModule, ul_reason_for_call, lpReserved };
	SIZE_T DllMainWrapperSize = (SIZE_T)DllMainWrapper_end - (SIZE_T)DllMainWrapper; 

	MemoryArea param          = alloc(sizeof(struct DLLMAINCALL));
	MemoryArea dllCallWrapper = alloc((SIZE_T)((DWORD_PTR)DllMainWrapper_end - (DWORD_PTR)DllMainWrapper));

	param.write((LPCVOID)&dllMainCall, sizeof(struct DLLMAINCALL));
	dllCallWrapper.write((LPCVOID)DllMainWrapper, DllMainWrapperSize);

	runInHiddenThread((LPTHREAD_START_ROUTINE)dllCallWrapper.address(), param.address());
}
