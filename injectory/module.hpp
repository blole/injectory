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
			BOOST_THROW_EXCEPTION(ex_get_module_handle() << e_text("could not get handle to module '" + std::to_string(moduleName) + "'"));
	}

	Module(const string& moduleName)
		: Module(std::to_wstring(moduleName))
	{}

	static Module load(const wstring& moduleName, DWORD flags = 0, bool freeOnDestruction = true)
	{
		HMODULE handle_ = LoadLibraryExW(moduleName.c_str(), nullptr, flags);
		Module module;
		if (freeOnDestruction)
			module = Module(handle_, Process::current, FreeLibrary);
		else
			module = Module(handle_, Process::current);
		if (!module)
			BOOST_THROW_EXCEPTION(ex_get_module_handle() << e_text("could not load module '" + std::to_string(moduleName) + "' locally"));
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
				BOOST_THROW_EXCEPTION(ex_injection() << e_text("could not get the address of '" + procName + "'"));
			return procAddress;
		}
	}

	template<class R, class... A>
	std::function<R(A...)> getProcAddress(string procName) const
	{
		return std::function<R(A...)>(reinterpret_cast<R (WINAPI *)(A...)>(getProcAddress(procName)));
	}

	wstring filename() const;
	wstring mappedFilename(bool throwOnFail = true) const;
	void eject();
public:
	static const Module& exe();
	static const Module& kernel32();
	static const Module& ntdll();
};
