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

void Process::remoteDllMainCall(void* lpModuleEntry, HMODULE hModule, DWORD ul_reason_for_call, void* lpReserved)
{
	DLLMAINCALL dllMainCall = { (DLLMAIN)lpModuleEntry, hModule, ul_reason_for_call, lpReserved };
	SIZE_T DllMainWrapperSize = (SIZE_T)DllMainWrapper_end - (SIZE_T)DllMainWrapper; 

	MemoryAreaT<DLLMAINCALL> param = alloc<DLLMAINCALL>();
	MemoryArea dllCallWrapper = alloc(DllMainWrapperSize);

	param = dllMainCall;
	dllCallWrapper.write(DllMainWrapper);

	runInHiddenThread((PTHREAD_START_ROUTINE)dllCallWrapper.address(), param.address());
}
