#include "injectory/module.hpp"
#include <Psapi.h>

const Module& Module::exe()
{
	static Module m(GetModuleHandleW(nullptr), Process::current);
	return m;
}
const Module& Module::kernel32()
{
	static Module m("kernel32");
	return m;
}
const Module& Module::ntdll()
{
	static Module m("ntdll");
	return m;
}

wstring Module::filename() const
{
	WCHAR buffer[MAX_PATH + 1] = {0};
	if (!GetModuleFileNameExW(process.handle(), handle(), buffer, MAX_PATH))
	{
		e_last_error lastError;
		BOOST_THROW_EXCEPTION(ex_injection() << e_text("GetModuleFileNameExW failed") << e_pid(process.id()) << lastError);
	}
	return wstring(buffer);
}

wstring Module::mappedFilename(bool throwOnFail) const
{
	WCHAR buffer[500 + 1] = {0};
	if (!GetMappedFileNameW(process.handle(), handle(), buffer, 500) && throwOnFail)
		BOOST_THROW_EXCEPTION(ex_injection() << e_text("GetMappedFileNameW failed") << e_pid(process.id()));
	return wstring(buffer);
}

void Module::eject()
{
	LPTHREAD_START_ROUTINE freeLibrary = (PTHREAD_START_ROUTINE)Module::kernel32().getProcAddress("FreeLibrary");
	process.runInHiddenThread(freeLibrary, handle());
}
