#include "injectory/module.hpp"
#include <Psapi.h>

const Module& Module::exe()
{
	static Module exe_(GetModuleHandleW(nullptr), Process::current);
	return exe_;
}
const Module Module::kernel32("kernel32");
const Module Module::ntdll("ntdll");

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
	WCHAR buffer[MAX_PATH + 1] = {0};
	if (!GetMappedFileNameW(process.handle(), handle(), buffer, MAX_PATH) && throwOnFail)
		BOOST_THROW_EXCEPTION(ex_injection() << e_text("GetMappedFileNameW failed") << e_pid(process.id()));
	return wstring(buffer);
}

void Module::eject()
{
	LPTHREAD_START_ROUTINE freeLibrary = (PTHREAD_START_ROUTINE)Module::kernel32.getProcAddress("FreeLibrary");
	process.runInHiddenThread(freeLibrary, handle());
}
