#include "injectory/common.hpp"
#include "injectory/module.hpp"

void PrintErrorMsgA(char *format, ...)
{
	va_list ap;
	DWORD dwLastError = 0;
	va_start(ap, format);
	
	//printf("Error: ");
	vprintf(format, ap);
	va_end(ap);

	dwLastError = GetLastError();
	if(dwLastError)
	{
		printf(" [LastError: %d]", GetLastError());
	}
	SetLastError(0);
	printf("\n");
}

void PrintErrorMsgW(wchar_t *format, ...)
{
	va_list ap;
	DWORD dwLastError = 0;
	va_start(ap, format);
	
	//printf("Error: ");
	vwprintf(format, ap);
	va_end(ap);

	dwLastError = GetLastError();
	if(dwLastError)
	{
		printf(" [LastError: %d]", GetLastError());
	}
	SetLastError(0);
	printf("\n");
}

SYSTEM_INFO getSystemInfo()
{
	SYSTEM_INFO sys_info = { 0 };
	GetSystemInfo(&sys_info);
	return sys_info;
}

SYSTEM_INFO getNativeSystemInfo()
{
	SYSTEM_INFO systemInfo = { 0 };

	auto getNativeSystemInfo_ = Module::kernel32.getProcAddress<void, LPSYSTEM_INFO>("GetNativeSystemInfo");

	if (getNativeSystemInfo_)
		getNativeSystemInfo_(&systemInfo);
	else
		GetSystemInfo(&systemInfo);

	return systemInfo;
}

DWORD WaitForSingleObject_Throwing(HANDLE handle, DWORD millis)
{
	DWORD ret = WaitForSingleObject(handle, millis);
	if (ret == WAIT_FAILED)
		BOOST_THROW_EXCEPTION(ex_wait_for_single_object());
	else
		return ret;
}
