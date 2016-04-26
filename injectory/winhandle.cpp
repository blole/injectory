#include "injectory/winhandle.hpp"
#include "injectory/api.hpp"

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
