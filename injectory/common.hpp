#pragma once
#include <Windows.h>

#include <boost/filesystem.hpp>
namespace fs = boost::filesystem;
#include <optional>
using std::optional;
using std::nullopt;
#include <boost/format.hpp>
using boost::format;

#include <locale>
#include <codecvt>
using std::shared_ptr;
#include <string>
using std::string;
using std::wstring;
#include <vector>
using std::vector;
#include <map>
using std::map;
#include <unordered_map>
using std::unordered_map;
#include <iostream>
using std::cout;
using std::cerr;
using std::cin;
using std::endl;
using std::function;

#if defined(_WIN64)
	const bool is64bit = true;
#elif defined(_WIN32)
	const bool is64bit = false;
#endif


// a process id
typedef DWORD pid_t;
// a thread id
typedef DWORD tid_t;
// a handle
typedef HANDLE handle_t;

namespace std
{
	inline string to_string(const wstring& s)
	{
		static std::wstring_convert<std::codecvt_utf8<wchar_t>> to_wstring_converter;
		return to_wstring_converter.to_bytes(s);
	}
	inline wstring to_wstring(const string& s)
	{
		static std::wstring_convert<std::codecvt_utf8<wchar_t>> to_wstring_converter;
		return to_wstring_converter.from_bytes(s);
	}
	template <typename T>
	inline string to_string(const vector<T>& v)
	{
		std::ostringstream ss;
		ss << "[";
		if (v.size() != 0)
			ss << v[0];
		for (unsigned int i = 1; i < v.size(); ++i)
			ss << "," << v[i];
		ss << "]";
		return ss.str();
	}
}
using std::to_string;
using std::to_wstring;

