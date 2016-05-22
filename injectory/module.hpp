#pragma once
#include "injectory/common.hpp"
#include "injectory/exception.hpp"
#include "injectory/process.hpp"

class ModuleKernel32;
class ModuleNtdll;

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

	static Module load(const wstring& moduleName, DWORD flags = 0, bool freeOnDestruction = true, bool throwing = true)
	{
		HMODULE handle_ = LoadLibraryExW(moduleName.c_str(), nullptr, flags);
		if (!handle_)
		{
			if (!throwing)
				return Module();

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

	wstring path() const;
	wstring mappedFilename(bool throwOnFail = true) const;
	void eject();

public:
	FARPROC getProcAddress(string procName, bool throwing = true) const
	{
		if (process != Process::current)
		{
			// load module locally without running it and calculate offset
			Module localModule = load(path(), DONT_RESOLVE_DLL_REFERENCES, true, throwing);

			if (!throwing && !localModule)
				return nullptr;

			LONG_PTR funcOffset = (DWORD_PTR)localModule.getProcAddress(procName) - (DWORD_PTR)localModule.handle();
			return (FARPROC)((DWORD_PTR)handle() + funcOffset);
		}
		else
		{
			FARPROC procAddress = GetProcAddress(handle(), procName.c_str());
			if (!procAddress)
			{
				if (!throwing)
					return nullptr;

				DWORD errcode = GetLastError();
				BOOST_THROW_EXCEPTION(ex_injection() << e_api_function("GetProcAddress") << e_text("could not get the address of '" + procName + "'") << e_last_error(errcode));
			}
			return procAddress;
		}
	}

private:
	template <typename T>
	struct TypeParser {};

	template <typename Ret, typename... Args>
	struct TypeParser<Ret(Args...)> {
		static std::function<Ret(Args...)> winapiFunction(const FARPROC lpfnGetProcessID) {
			return std::function<Ret(Args...)>(reinterpret_cast<Ret(WINAPI *)(Args...)>(lpfnGetProcessID));
		}
	};

public:
	template <typename T>
	function<T> getProcAddress(string procName, bool throwing = true) const
	{
		return TypeParser<T>::winapiFunction(getProcAddress(procName, throwing));
	}

public:
	static const Module& exe();
	static const ModuleKernel32& kernel32();
	static const ModuleNtdll& ntdll();
};



class ModuleKernel32 : public Module
{
public:
	// in 64bit systems, returns true for 32 bit processes.
	const function<BOOL(HANDLE, BOOL*)> isWow64Process_;
	// may be null
	const function<void(SYSTEM_INFO*)> getNativeSystemInfo;

public:
	ModuleKernel32()
		: Module("kernel32")
		, isWow64Process_(getProcAddress<BOOL(HANDLE, PBOOL)>("IsWow64Process"))
		, getNativeSystemInfo(getProcAddress<void(SYSTEM_INFO*)>("GetNativeSystemInfo", false))
	{}

	bool isWow64Process(HANDLE handle) const
	{
		BOOL isWow64 = false;
		if (!isWow64Process_(handle, &isWow64))
		{
			DWORD errcode = GetLastError();
			BOOST_THROW_EXCEPTION(ex_injection() << e_api_function("IsWow64Process") << e_last_error(errcode));
		}
		return !isWow64;
	}
};



class ModuleNtdll : public Module
{
public:
	enum MY_THREAD_INFORMATION_CLASS
	{
		ThreadBasicInformation,
		ThreadTimes,
		ThreadPriority,
		ThreadBasePriority,
		ThreadAffinityMask,
		ThreadImpersonationToken,
		ThreadDescriptorTableEntry,
		ThreadEnableAlignmentFaultFixup,
		ThreadEventPair,
		ThreadQuerySetWin32StartAddress,
		ThreadZeroTlsCell,
		ThreadPerformanceCount,
		ThreadAmILastThread,
		ThreadIdealProcessor,
		ThreadPriorityBoost,
		ThreadSetTlsArrayAddress,
		ThreadIsIoPending,
		ThreadHideFromDebugger
	};

public:
	const function<NTSTATUS(HANDLE)> ntResumeProcess_;
	const function<NTSTATUS(HANDLE)> ntSuspendProcess_;
	const function<NTSTATUS(HANDLE, MY_THREAD_INFORMATION_CLASS, PVOID, ULONG)> ntSetInformationThread_;

public:
	ModuleNtdll()
		: Module("ntdll")
		, ntResumeProcess_(getProcAddress<NTSTATUS(HANDLE)>("NtResumeProcess"))
		, ntSuspendProcess_(getProcAddress<NTSTATUS(HANDLE)>("NtSuspendProcess"))
		, ntSetInformationThread_(getProcAddress<NTSTATUS(HANDLE, MY_THREAD_INFORMATION_CLASS, PVOID, ULONG)>("NtSetInformationThread"))
	{}


	static bool NT_SUCCESS(NTSTATUS status)
	{
		return status >= 0;
	}


	void ntResumeProcess(const Process& proc) const
	{
		NTSTATUS status = ntResumeProcess_(proc.handle());
		if (!NT_SUCCESS(status))
			BOOST_THROW_EXCEPTION(ex_suspend_resume_process() << e_proc(proc) << e_api_function("NtResumeProcess") << e_text("error calling remote function") << e_nt_status(status));
	}

	void ntSuspendProcess(const Process& proc) const
	{
		NTSTATUS status = ntSuspendProcess_(proc.handle());
		if (!NT_SUCCESS(status))
			BOOST_THROW_EXCEPTION(ex_suspend_resume_process() << e_proc(proc) << e_api_function("NtSuspendProcess") << e_text("error calling remote function") << e_nt_status(status));
	}

	void ntSetInformationThread(const Thread& thread, MY_THREAD_INFORMATION_CLASS infoClass, void* info, unsigned long infoLength) const
	{
		NTSTATUS status = ntSetInformationThread_(thread.handle(), infoClass, info, infoLength);
		if (!NT_SUCCESS(status))
			BOOST_THROW_EXCEPTION(ex() << e_thread(thread) << e_api_function("NtSetInformationThread") << e_nt_status(status));
	}
};
