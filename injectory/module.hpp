#pragma once
#include "injectory/common.hpp"
#include "injectory/exception.hpp"
#include <winnt.h>

class Module
{
private:
	HMODULE hModule;

public:
	Module(const wstring& moduleName)
		: hModule(GetModuleHandleW(moduleName.c_str()))
	{
		if (!hModule)
			BOOST_THROW_EXCEPTION(ex_get_module_handle() << e_text("could not get handle to '" + std::to_string(moduleName) + "'"));
	}

	/*
	// this makes
	// WaitForSingleObject(loadLibraryThread, ...)
	// hang later on, for some reason...
	Module(const string& moduleName)
		: Module(std::to_wstring(moduleName))
	{}
	*/


public:
	FARPROC getProcAddress(string procName)
	{
		FARPROC procAddress = GetProcAddress(hModule, procName.c_str());
		if (!procAddress)
			BOOST_THROW_EXCEPTION(ex_injection() << e_text("ccould not get the address of '"+procName+"'"));
		return procAddress;
	}
};
