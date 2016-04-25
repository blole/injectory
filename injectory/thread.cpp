#include "injectory/thread.hpp"
#include "injectory/module.hpp"

using namespace std;

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

Thread Thread::open(const tid_t & tid, bool inheritHandle, DWORD desiredAccess)
{
	Thread thread(tid, OpenThread(desiredAccess, inheritHandle, tid));
	if (!thread.handle())
	{
		DWORD errcode = GetLastError();
		BOOST_THROW_EXCEPTION(ex_injection() << e_api_function("OpenThread") << e_text("could not get handle to thread") << e_tid(tid) << e_last_error(errcode));
	}
	else
		return thread;
}

void Thread::hideFromDebugger() const
{
	auto ntSetInformationThread = Module::ntdll().getProcAddress<LONG, HANDLE, MY_THREAD_INFORMATION_CLASS, PVOID, ULONG>("NtSetInformationThread");
	//LONG(HANDLE, MY_THREAD_INFORMATION_CLASS, ThreadInformation, ThreadInformationLength)

	LONG ntStatus = ntSetInformationThread(handle(), ThreadHideFromDebugger, nullptr, 0);
	if (!NT_SUCCESS(ntStatus))
		BOOST_THROW_EXCEPTION(ex_hide() << e_api_function("NtSetInformationThread") << e_text("could not hide thread") << e_nt_status(ntStatus) << e_tid(id()));
}

void Thread::setPriority(int priority)
{
	if (!SetThreadPriority(handle(), priority))
	{
		DWORD errcode = GetLastError();
		BOOST_THROW_EXCEPTION(ex_injection() << e_api_function("SetThreadPriority") << e_text("could not set thread priority") << e_last_error(errcode));
	}
}

DWORD Thread::waitForTermination()
{
	wait();
	DWORD exitCode;
	if (!GetExitCodeThread(handle(), &exitCode))
	{
		DWORD errcode = GetLastError();
		BOOST_THROW_EXCEPTION(ex_injection() << e_api_function("GetExitCodeThread") << e_text("could not get thread exit code") << e_last_error(errcode));
	}
	else
		return exitCode;
}
