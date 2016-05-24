#include "injectory/module.hpp"
#include "injectory/memoryarea.hpp"
#include <Psapi.h>

const Module& Module::exe()
{
	static Module m(GetModuleHandleW(nullptr), Process::current);
	return m;
}
const ModuleKernel32& Module::kernel32()
{
	static ModuleKernel32 m;
	return m;
}
const ModuleNtdll& Module::ntdll()
{
	static ModuleNtdll m;
	return m;
}

fs::path Module::path() const
{
	WCHAR buffer[MAX_PATH + 1] = {0};
	if (!GetModuleFileNameExW(process.handle(), handle(), buffer, MAX_PATH))
	{
		DWORD errcode = GetLastError();
		BOOST_THROW_EXCEPTION(ex_injection() << e_api_function("GetModuleFileNameEx") << e_process(process) << e_last_error(errcode));
	}
	return buffer;
}

wstring Module::mappedFilename(bool throwOnFail) const
{
	WCHAR buffer[500 + 1] = {0};
	if (!GetMappedFileNameW(process.handle(), handle(), buffer, 500) && throwOnFail)
	{
		DWORD errcode = GetLastError();
		BOOST_THROW_EXCEPTION(ex_injection() << e_api_function("GetMappedFileName") << e_process(process) << e_last_error(errcode));
	}
	return wstring(buffer);
}

void Module::eject()
{
	PTHREAD_START_ROUTINE freeLibrary = (PTHREAD_START_ROUTINE)Module::kernel32().getProcAddress("FreeLibrary");
	process.runInHiddenThread(freeLibrary, handle());
}

IMAGE_DOS_HEADER Module::dosHeader()
{
	return process.memory<IMAGE_DOS_HEADER>(handle());
}

IMAGE_NT_HEADERS Module::ntHeader()
{
	return process.memory<IMAGE_NT_HEADERS>((void*)((DWORD_PTR)handle() + dosHeader().e_lfanew));
}
