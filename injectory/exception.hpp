#pragma once
#include "injectory/common.hpp"
#include <winnt.h>
#include <boost/exception/all.hpp>

class Process;
class Library;
class Thread;

string GetLastErrorString(DWORD errcode = GetLastError());

struct exception_base : virtual std::exception, virtual boost::exception
{
	using std::exception::exception;
};

struct ex : virtual exception_base
{
	using exception_base::exception_base;
	ex()
	{}
	ex(const std::string& message)
		: ex(message.c_str())
	{}
};
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
struct ex_job						: virtual exception_base { };

typedef boost::error_info<struct tag_text, string> e_text;
typedef boost::error_info<struct tag_file, fs::path> e_file;
typedef boost::error_info<struct tag_module, fs::path> e_module;
typedef boost::error_info<struct tag_module, fs::path> e_library;
typedef boost::error_info<struct tag_process_id, pid_t> e_pid;
typedef boost::error_info<struct tag_target_thread_id, tid_t> e_tid;
typedef boost::error_info<struct tag_handle, handle_t> e_handle;
typedef boost::error_info<struct tag_handles, vector<handle_t>> e_handles;
typedef boost::error_info<struct tag_process, Process> e_proc;
typedef boost::error_info<struct tag_process, Thread> e_thread;
typedef boost::error_info<struct tag_nt_status, LONG> e_nt_status;
typedef boost::error_info<struct tag_last_error, DWORD> e_last_error;
using e_api_function = boost::errinfo_api_function;

namespace boost
{
	string to_string(const e_last_error& x);
	string to_string(const e_proc& x);
}
