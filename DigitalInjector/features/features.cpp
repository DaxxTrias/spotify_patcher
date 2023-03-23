#include <Windows.h>
#include <TlHelp32.h>
#include "features.h"

void features::error_log( const char* message ) {
	std::cout << message << std::endl;
	system( "pause" );
	exit( 0 );
}

std::string features::random_string( const size_t length ) {
	std::string r;
	static constexpr char bet[] = { "ABCDEFGHIJKLMNOPQRSTUVWXYabcdefghijklmnopqrstuvwxyzZ1234567890" };
	srand( static_cast< unsigned >( time( nullptr ) ) * 5 );
	for ( int i = 0; i < length; ++i ) {
		r += bet[ rand( ) % ( sizeof bet - 1 ) ];
	}
	return r;
}

errno_t features::does_file_exist(const char* name) {
	FILE* file;
	errno_t err = fopen_s(&file, name, "r");
	if (err == 0 && file != nullptr)
	{
		fclose(file);
		return true;
	}
	return false;
}

DWORD features::get_process_id(const char* process_name) {
	const HANDLE h_snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	PROCESSENTRY32 pe32{};
	pe32.dwSize = sizeof pe32;

	if (!Process32First(h_snap, &pe32))
		return NULL;

	do {
		wchar_t w_process_name[MAX_PATH];
		size_t num_converted;
		mbstowcs_s(&num_converted, w_process_name, process_name, MAX_PATH);
		if (!_wcsicmp(pe32.szExeFile, w_process_name)) {
			CloseHandle(h_snap);
			return pe32.th32ProcessID;
		}
	} while (Process32Next(h_snap, &pe32));

	CloseHandle(h_snap);
	return NULL;
}



uintptr_t features::get_module_base_address(const DWORD pid, const wchar_t* mod_name) {
	const HANDLE h_snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
	if (h_snap != INVALID_HANDLE_VALUE) {
		MODULEENTRY32 mod_entry{};
		mod_entry.dwSize = sizeof mod_entry;
		if (Module32First(h_snap, &mod_entry)) {
			do {
				if (!_wcsicmp(mod_entry.szModule, mod_name)) {
					CloseHandle(h_snap);
					return reinterpret_cast<uintptr_t>(mod_entry.modBaseAddr);
				}
			} while (Module32Next(h_snap, &mod_entry));
		}
	}
	return 0;
}

bool features::inject( const DWORD process_id, const char* dll ) {
	if ( process_id == NULL )
		return false;

	char custom_dll[ MAX_PATH ];
	GetFullPathNameA( dll, MAX_PATH, custom_dll, nullptr );

	const HANDLE h_process = OpenProcess( PROCESS_ALL_ACCESS, FALSE, process_id );
	const LPVOID allocated_mem = VirtualAllocEx( h_process, nullptr, sizeof custom_dll, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE );

	if ( WriteProcessMemory( h_process, allocated_mem, custom_dll, sizeof custom_dll, nullptr ) ) {
		CreateRemoteThread( h_process, nullptr, 0, reinterpret_cast< LPTHREAD_START_ROUTINE >( LoadLibrary ),
							allocated_mem, 0, nullptr );

		if ( h_process )
			CloseHandle( h_process );

		return TRUE;
	}
	return FALSE;
}
