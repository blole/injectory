#include "injectory/thread.hpp"
#include "injectory/module.hpp"

using namespace std;

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
	try
	{
		Module::ntdll().ntSetInformationThread(*this, ModuleNtdll::ThreadHideFromDebugger, nullptr, 0);
	}
	catch (...)
	{
		BOOST_THROW_EXCEPTION(ex("could not hide thread from debugger") << boost::errinfo_nested_exception(boost::current_exception()));
	}
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
