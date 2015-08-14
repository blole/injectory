#pragma once
#include "injectory/common.hpp"
#include "injectory/exception.hpp"
#include <Windows.h>

class Process;

class Module
{
private:
	HMODULE handle_;

public:
	Module(HMODULE module = nullptr)
		: handle_(module)
	{}

	Module(const wstring& moduleName)
		: handle_(GetModuleHandleW(moduleName.c_str()))
	{
		if (!handle_)
			BOOST_THROW_EXCEPTION(ex_get_module_handle() << e_text("could not get handle to '" + std::to_string(moduleName) + "'"));
	}

	Module(const string& moduleName)
		: Module(std::to_wstring(moduleName))
	{}

public:
	HMODULE handle() const
	{
		return handle_;
	}

public:
	FARPROC getProcAddress(string procName) const
	{
		FARPROC procAddress = GetProcAddress(handle_, procName.c_str());
		if (!procAddress)
			BOOST_THROW_EXCEPTION(ex_injection() << e_text("could not get the address of '"+procName+"'"));
		return procAddress;
	}

	template<class R, class... A>
	std::function<R(A...)> getProcAddress(string procName) const
	{
		return std::function<R(A...)>(reinterpret_cast<R (WINAPI *)(A...)>(getProcAddress(procName)));
	}

	wstring mappedFilename(const Process& process, bool throwOnFail = true);
public:
	static const Module kernel32;
	static const Module ntdll;
public:
	operator bool() const
	{
		return handle() != nullptr;
	}
};
