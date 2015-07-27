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

typedef boost::error_info<struct tag_text, std::string> e_text;
typedef boost::error_info<struct tag_file_path, path> e_file_path;
typedef boost::error_info<struct tag_target_process_id, pid_t> e_pid;
typedef boost::error_info<struct tag_target_thread_id, tid_t> e_tid;
typedef boost::error_info<struct tag_nt_status, LONG> e_nt_status;


#if defined(_WIN64)
	#define CHECK_TARGET_PROC(pid) IsProcess64(pid) != 0
	#define BIT_ERROR_STRING	"injectory.x64 doesn't support x86 processes"
#elif defined(_WIN32)
	#define CHECK_TARGET_PROC(pid) IsProcess64(pid) != 1
	#define BIT_ERROR_STRING	"injectory.x86 doesn't support x64 processes"
#endif

#define PRINT_TARGET_PROC_ERROR(pid) printf("error: " BIT_ERROR_STRING " (%d).\n", pid)
