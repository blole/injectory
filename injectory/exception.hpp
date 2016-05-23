#pragma once
#include "injectory/common.hpp"
#include <winnt.h>
#include <boost/exception/all.hpp>

class Process;
class Library;
class Thread;

string formatMessage(DWORD messageId
	, DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS // these cannot be unset
	, LPCVOID source = nullptr
	, DWORD languageId = MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT)
	, va_list* args = nullptr);

string GetLastErrorString(DWORD errcode = GetLastError());
string GetNTStatusString(DWORD nt_status);

struct exception_base : std::exception, virtual boost::exception
{
	using std::exception::exception;
};

struct ex : exception_base
{
	using exception_base::exception_base;
};
struct ex_target_bit_mismatch		: virtual exception_base { };
struct ex_hide						: virtual exception_base { };
struct ex_set_se_debug_privilege	: virtual exception_base { };
struct ex_fix_iat					: virtual exception_base { };
struct ex_map_remote				: virtual exception_base { };
struct ex_injection					: virtual exception_base { };
struct ex_suspend_resume_thread		: virtual exception_base { };
struct ex_wait_for_input_idle		: virtual exception_base { };
struct ex_wait_for_single_object	: virtual exception_base { };
struct ex_wait_for_multiple_objects	: virtual exception_base { };
struct ex_get_module_handle			: virtual exception_base { };
struct ex_file_not_found			: virtual exception_base { };
struct ex_job						: virtual exception_base { };

typedef boost::error_info<struct errinfo_text_, string> e_text;
typedef boost::error_info<struct errinfo_file_, fs::path> e_file;
typedef boost::error_info<struct errinfo_module_, fs::path> e_module;
typedef boost::error_info<struct errinfo_library_, fs::path> e_library;
typedef boost::error_info<struct errinfo_process_id_, pid_t> e_pid;
typedef boost::error_info<struct errinfo_thread_id_, tid_t> e_tid;
typedef boost::error_info<struct errinfo_handle_, handle_t> e_handle;
typedef boost::error_info<struct errinfo_handles_, vector<handle_t>> e_handles;
typedef boost::error_info<struct errinfo_process_, Process> e_process;
typedef boost::error_info<struct errinfo_thread_, Thread> e_thread;
typedef boost::error_info<struct errinfo_nt_status_, LONG> e_nt_status;
typedef boost::error_info<struct errinfo_last_error_, DWORD> e_last_error;
using e_api_function = boost::errinfo_api_function;

namespace boost
{
	string to_string(const e_last_error& x);
	string to_string(const e_nt_status& x);
	string to_string(const e_process& x);
}

void print_exception(std::exception_ptr e, const std::string& prefix = "", int level = 0);
