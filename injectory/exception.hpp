#pragma once
#include "injectory/common.hpp"

#include <winnt.h>
#include <boost/exception/all.hpp>

class Library;


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
struct ex_wait_for_single_object	: virtual exception_base { };
struct ex_wait_for_multiple_objects	: virtual exception_base { };
struct ex_get_module_handle			: virtual exception_base { };
struct ex_file_not_found			: virtual exception_base { };

typedef boost::error_info<struct tag_text, string> e_text;
typedef boost::error_info<struct tag_file_path, path> e_file_path;
typedef boost::error_info<struct tag_module, path> e_module;
typedef boost::error_info<struct tag_target_process_id, pid_t> e_pid;
typedef boost::error_info<struct tag_target_thread_id, tid_t> e_tid;
typedef boost::error_info<struct tag_nt_status, LONG> e_nt_status;

class e_library : public boost::error_info<struct tag_library, path>
{
public:
	e_library(const Library& lib);
};

class e_last_error : public boost::error_info<struct tag_last_error, string>
{
public:
	e_last_error(DWORD hresult = GetLastError())
		: error_info(getLastErrorString(hresult))
	{}
	static string getLastErrorString(DWORD hresult);
};
