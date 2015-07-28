#include "injectory/thread.hpp"
#include "injectory/process.hpp"
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

Thread Thread::createRemote(
	const Process& proc,
	LPSECURITY_ATTRIBUTES attr,
	SIZE_T stackSize,
	LPTHREAD_START_ROUTINE startAddr,
	LPVOID parameter,
	DWORD creationFlags)
{
	DWORD tid;
	handle_t handle = CreateRemoteThread(proc.handle(), attr, stackSize, startAddr, parameter, creationFlags, &tid);

	if (!handle)
		BOOST_THROW_EXCEPTION(ex_injection() << e_text("could not create thread in remote process") << e_pid(proc.id));
	else
		return Thread(tid, handle);
}

void Thread::hideFromDebugger() const
{
	typedef LONG(NTAPI* func)(HANDLE, MY_THREAD_INFORMATION_CLASS, PVOID ThreadInformation, ULONG ThreadInformationLength);

	Module ntDll(L"ntdll");
	func ntSetInformationThread = (func) ntDll.getProcAddress("NtSetInformationThread");

	LONG ntStatus = (*ntSetInformationThread)(handle(), ThreadHideFromDebugger, 0, 0);
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
