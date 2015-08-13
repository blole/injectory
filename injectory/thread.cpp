#include "injectory/thread.hpp"
#include "injectory/module.hpp"
#include "injectory/injector_helper.hpp"

using namespace std;

Thread Thread::open(const tid_t & tid, bool inheritHandle, DWORD desiredAccess)
{
	Thread thread(tid, OpenThread(desiredAccess, inheritHandle, tid));
	if (!thread.handle())
		BOOST_THROW_EXCEPTION(ex_injection() << e_text("could not get handle to thread") << e_tid(tid));
	else
		return thread;
}

void Thread::hideFromDebugger() const
{
	//typedef LONG(HANDLE, MY_THREAD_INFORMATION_CLASS, ThreadInformation, ThreadInformationLength);
	auto ntSetInformationThread = Module::ntdll.getProcAddress<LONG, HANDLE, MY_THREAD_INFORMATION_CLASS, PVOID, ULONG>("NtSetInformationThread");

	LONG ntStatus = ntSetInformationThread(handle(), ThreadHideFromDebugger, 0, 0);
	if (!NT_SUCCESS(ntStatus))
		BOOST_THROW_EXCEPTION(ex_hide() << e_text("could not hide thread") << e_nt_status(ntStatus) << e_tid(id));
}

void Thread::setPriority(int priority)
{
	if (!SetThreadPriority(handle(), priority))
		BOOST_THROW_EXCEPTION(ex_injection() << e_text("could not set thread priority"));
}

DWORD Thread::waitForTermination(DWORD millis)
{
	DWORD exitCode;
	if (WaitForSingleObject(handle(), millis) == WAIT_FAILED)
		BOOST_THROW_EXCEPTION(ex_injection() << e_text("WaitForSingleObject failed"));
	if (!GetExitCodeThread(handle(), &exitCode))
		BOOST_THROW_EXCEPTION(ex_injection() << e_text("could not get thread exit code"));
	return exitCode;
}
