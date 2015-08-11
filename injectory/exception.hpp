#pragma once
#include "injectory/common.hpp"

#include <winnt.h>
#include <boost/exception/all.hpp>
#include <boost/algorithm/string/trim.hpp>


struct exception_base : virtual std::exception, virtual boost::exception { };

struct ex_target_bit_mismatch		: virtual exception_base { };
struct ex_hide						: virtual exception_base { };
struct ex_set_se_debug_privilege	: virtual exception_base { };
struct ex_fix_iat					: virtual exception_base { };
struct ex_map_remote				: virtual exception_base { };
struct ex_injection					: virtual exception_base { };
struct ex_suspend_resume_thread		: virtual exception_base { };
struct ex_suspend_resume_process	: virtual exception_base { };
struct ex_wait_for_input_idle		: virtual exception_base { };
struct ex_wait_for_exit				: virtual exception_base { };
struct ex_get_module_handle			: virtual exception_base { };

typedef boost::error_info<struct tag_text, string> e_text;
typedef boost::error_info<struct tag_file_path, path> e_file_path;
typedef boost::error_info<struct tag_file_path, path> e_library;
typedef boost::error_info<struct tag_module, path> e_module;
typedef boost::error_info<struct tag_target_process_id, pid_t> e_pid;
typedef boost::error_info<struct tag_target_thread_id, tid_t> e_tid;
typedef boost::error_info<struct tag_nt_status, LONG> e_nt_status;

class e_last_error : public boost::error_info<struct tag_last_error, string>
{
public:
	e_last_error(DWORD hresult = GetLastError())
		: error_info(getLastError(hresult))
	{}
	static string getLastError(DWORD hresult)
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
};
