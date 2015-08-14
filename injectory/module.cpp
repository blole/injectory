#include "injectory/module.hpp"

const Module Module::kernel32("kernel32");
const Module Module::ntdll("ntdll");

wstring Module::ntFilename(bool throwOnFail)
{
	WCHAR mappedFileName_[MAX_PATH + 1] = {0};
	if (!GetMappedFileNameW(process.handle(), handle(), mappedFileName_, MAX_PATH) && throwOnFail)
		BOOST_THROW_EXCEPTION(ex_injection() << e_text("GetMappedFileNameW failed") << e_pid(process.id()));
	return wstring(mappedFileName_);
}

void Module::eject()
{
	LPTHREAD_START_ROUTINE freeLibrary = (PTHREAD_START_ROUTINE)Module::kernel32.getProcAddress("FreeLibrary");
	process.runInHiddenThread(freeLibrary, handle());
}
