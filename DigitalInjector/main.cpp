﻿#include "features/features.h"

int setup() {
	SetConsoleTitleA(features::random_string(26).c_str());

	const DWORD process_id = features::get_process_id("Spotify.exe");
	if (!process_id)
		features::error_log("[!] Spotify.exe not found.\n");

	std::wcout << L"[+] Spotify.exe found. PID: " << std::dec << process_id << std::endl;

	const HANDLE game = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
	if (!game)
		features::error_log("OpenProcess error\n");

	features::error_log(features::inject(process_id, "patcher.dll") ? "[+] Injected.\n" : "[!] Injection Failed.\n");

	return 0;
}

int main( ) {
	setup( );
	return 0;
}