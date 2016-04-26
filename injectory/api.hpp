#pragma once
#include "injectory/common.hpp"
#include "injectory/module.hpp"
class Process;

inline SYSTEM_INFO getSystemInfo()
{
	SYSTEM_INFO sys_info = { 0 };
	GetSystemInfo(&sys_info);
	return sys_info;
}

inline SYSTEM_INFO getNativeSystemInfo()
{
	SYSTEM_INFO systemInfo = { 0 };

	auto getNativeSystemInfo_ = Module::kernel32().getProcAddress<void, LPSYSTEM_INFO>("GetNativeSystemInfo");

	if (getNativeSystemInfo_)
		getNativeSystemInfo_(&systemInfo);
	else
		GetSystemInfo(&systemInfo);

	return systemInfo;
}

inline void* VirtualAllocEx_Throwing(const Process& proc, void* address, SIZE_T size, DWORD allocationType, DWORD protect)
{
	void* area = VirtualAllocEx(proc.handle(), address, size, allocationType, protect);
	if (!area)
	{
		DWORD errcode = GetLastError();
		BOOST_THROW_EXCEPTION(ex_injection() << e_api_function("VirtualAllocEx") << e_text("could not allocate memory") << e_last_error(errcode) << e_pid(proc.id()));
	}
	return area;
}

inline void ReadProcessMemory_Throwing(const Process& process, void* address, void* out, SIZE_T size)
{
	SIZE_T numBytesRead = (SIZE_T)-1;
	if (!ReadProcessMemory(process.handle(), address, out, size, &numBytesRead))
	{
		DWORD errcode = GetLastError();
		BOOST_THROW_EXCEPTION(ex_injection() << e_api_function("ReadProcessMemory") << e_text("could not read memory") << e_last_error(errcode) << e_pid(process.id()));
	}
	if (numBytesRead != size)
		BOOST_THROW_EXCEPTION(ex_injection() << e_api_function("ReadProcessMemory") << e_text("only read " + to_string(numBytesRead) + "/" + to_string(size) + " //tes") << e_pid(process.id()));
}

inline void WriteProcessMemory_Throwing(const Process& process, void* dst, const void* src, SIZE_T size)
{
	SIZE_T numBytesWritten = 0;
	if (!WriteProcessMemory(process.handle(), dst, src, size, &numBytesWritten))
	{
		DWORD errcode = GetLastError();
		BOOST_THROW_EXCEPTION(ex_injection() << e_api_function("WriteProcessMemory") << e_text("could not write to memory in remote process") << e_last_error(errcode));
	}
	if (numBytesWritten != size)
		BOOST_THROW_EXCEPTION(ex_injection() << e_api_function("WriteProcessMemory") << e_text("only wrote " + to_string(numBytesWritten) + "/" + to_string(size) + " bytes"));
}

inline HANDLE GetStdHandle_Throwing(DWORD nStdHandle)
{
	HANDLE h = GetStdHandle(nStdHandle);
	if (h == INVALID_HANDLE_VALUE)
	{
		DWORD errcode = GetLastError();
		BOOST_THROW_EXCEPTION(ex_injection() << e_api_function("GetStdHandle") << e_text("error getting handle") << e_last_error(errcode));
	}
	return h;
}

