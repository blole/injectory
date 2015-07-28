#pragma once
#include "injectory/common.hpp"

#include <winnt.h>
#include <boost/exception/all.hpp>


struct exception_base : virtual std::exception, virtual boost::exception { };

struct ex_target_bit_mismatch		: virtual exception_base { };
struct ex_hide						: virtual exception_base { };
struct ex_no_library_path			: virtual exception_base { };
struct ex_set_se_debug_privilege	: virtual exception_base { };
struct ex_fix_iat					: virtual exception_base { };
struct ex_map_remote				: virtual exception_base { };
struct ex_injection					: virtual exception_base { };
struct ex_suspend_resume_thread		: virtual exception_base { };
struct ex_suspend_resume_process	: virtual exception_base { };
struct ex_wait_for_input_idle		: virtual exception_base { };
struct ex_get_module_handle			: virtual exception_base { };

typedef boost::error_info<struct tag_text, std::string> e_text;
typedef boost::error_info<struct tag_file_path, path> e_file_path;
typedef boost::error_info<struct tag_target_process_id, pid_t> e_pid;
typedef boost::error_info<struct tag_target_thread_id, tid_t> e_tid;
typedef boost::error_info<struct tag_nt_status, LONG> e_nt_status;
