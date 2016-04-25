#include "injectory/winhandle.hpp"

HANDLE GetStdHandle_Throwing(DWORD nStdHandle)
{
	HANDLE h = GetStdHandle(nStdHandle);
	if (h == INVALID_HANDLE_VALUE)
	{
		DWORD errcode = GetLastError();
		BOOST_THROW_EXCEPTION(ex_injection() << e_api_function("GetStdHandle") << e_text("error getting handle") << e_last_error(errcode));
	}
	return h;
}

const WinHandle& WinHandle::std_in()
{
	static const WinHandle h(GetStdHandle_Throwing(STD_INPUT_HANDLE));
	return h;
}
const WinHandle& WinHandle::std_out()
{
	static const WinHandle h(GetStdHandle_Throwing(STD_OUTPUT_HANDLE));
	return h;
}
const WinHandle& WinHandle::std_err()
{
	static const WinHandle h(GetStdHandle_Throwing(STD_ERROR_HANDLE));
	return h;
}
