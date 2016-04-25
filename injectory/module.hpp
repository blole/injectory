#pragma once
#include "injectory/common.hpp"
#include "injectory/exception.hpp"
#include "injectory/process.hpp"

class Module : public Handle<HINSTANCE__>
{
	friend Module Process::isInjected(HMODULE);
	friend Module Process::isInjected(const Library&);
	friend Module Process::map(const File& file);
private:
	Process process;

private:
	Module(HMODULE handle, const Process& process)
		: Handle<HINSTANCE__>(handle)
		, process(process)
	{}

	template <class Deleter>
	Module(HMODULE handle, const Process& process, Deleter deleter)
		: Handle<HINSTANCE__>(handle, deleter)
		, process(process)
	{}

public:
	Module()
		: Module(nullptr, Process())
	{}

	Module(const wstring& moduleName)
		: Module(GetModuleHandleW(moduleName.c_str()), Process::current)
	{
		if (!handle())
		{
			DWORD errcode = GetLastError();
			BOOST_THROW_EXCEPTION(ex_get_module_handle() << e_api_function("GetModuleHandle") << e_text("could not get handle to module '" + to_string(moduleName) + "'") << e_last_error(errcode));
		}
	}

	Module(const string& moduleName)
		: Module(to_wstring(moduleName))
	{}

	static Module load(const wstring& moduleName, DWORD flags = 0, bool freeOnDestruction = true)
	{
		HMODULE handle_ = LoadLibraryExW(moduleName.c_str(), nullptr, flags);
		if (!handle_)
		{
			DWORD errcode = GetLastError();
			BOOST_THROW_EXCEPTION(ex_get_module_handle() << e_api_function("LoadLibraryEx") << e_text("could not load module '" + to_string(moduleName) + "' locally") << e_last_error(errcode));
		}
		Module module;
		if (freeOnDestruction)
			module = Module(handle_, Process::current, FreeLibrary);
		else
			module = Module(handle_, Process::current);
		return module;
	}

public:
	FARPROC getProcAddress(string procName) const
	{
		if (process != Process::current)
		{
			// load module locally without running it and calculate offset
			Module localModule = load(filename(), DONT_RESOLVE_DLL_REFERENCES);
			LONG_PTR funcOffset = (DWORD_PTR)localModule.getProcAddress(procName) - (DWORD_PTR)localModule.handle();
			return (FARPROC)((DWORD_PTR)handle() + funcOffset);
		}
		else
		{
			FARPROC procAddress = GetProcAddress(handle(), procName.c_str());
			if (!procAddress)
			{
				DWORD errcode = GetLastError();
				BOOST_THROW_EXCEPTION(ex_injection() << e_api_function("GetProcAddress") << e_text("could not get the address of '" + procName + "'") << e_last_error(errcode));
			}
			return procAddress;
		}
	}

	template<class R, class... A>
	function<R(A...)> getProcAddress(string procName) const
	{
		return function<R(A...)>(reinterpret_cast<R (WINAPI *)(A...)>(getProcAddress(procName)));
	}

	wstring filename() const;
	wstring mappedFilename(bool throwOnFail = true) const;
	void eject();
public:
	static const Module& exe();
	static const Module& kernel32();
	static const Module& ntdll();
};
