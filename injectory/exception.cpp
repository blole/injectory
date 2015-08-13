#include "injectory/exception.hpp"
#include "injectory/library.hpp"
#include <boost/algorithm/string/trim.hpp>

e_library::e_library(const Library& lib)
	: error_info(lib.path)
{
}

string e_last_error::getLastError(DWORD hresult)
{
	LPVOID lpMsgBuf = nullptr;
	FormatMessageA(
		// use system message tables to retrieve error text
		FORMAT_MESSAGE_FROM_SYSTEM
		// allocate buffer on local heap for error text
		| FORMAT_MESSAGE_ALLOCATE_BUFFER
		// Important! will fail otherwise, since we're not 
		// (and CANNOT) pass insertion parameters
		| FORMAT_MESSAGE_IGNORE_INSERTS,
		nullptr,    // unused with FORMAT_MESSAGE_FROM_SYSTEM
		hresult,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPSTR)&lpMsgBuf,  // output 
		0, // minimum size for output buffer
		nullptr);   // arguments - see note 

	if (lpMsgBuf)
	{
		string errorString((LPSTR)lpMsgBuf);
		LocalFree(lpMsgBuf);
		boost::algorithm::trim(errorString);
		return errorString;
	}
	else
		return "GetLastError()=" + std::to_string(hresult) + " but no info from FormatMessage()";
}
