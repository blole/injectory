#include "injectory/handle.hpp"

HANDLE GetStdHandle_Throwing(DWORD nStdHandle)
{
	HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
	if (h == INVALID_HANDLE_VALUE)
	{
		e_last_error last_error;
		BOOST_THROW_EXCEPTION(ex_injection() << e_text("error getting handle") << last_error);
	}
	return h;
}

Handle Handle::std_in()  { return Handle(GetStdHandle_Throwing(STD_INPUT_HANDLE)); }
Handle Handle::std_out() { return Handle(GetStdHandle_Throwing(STD_OUTPUT_HANDLE)); }
Handle Handle::std_err() { return Handle(GetStdHandle_Throwing(STD_ERROR_HANDLE)); }
