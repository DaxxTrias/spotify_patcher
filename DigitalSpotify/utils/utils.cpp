#include "utils.h"

void utils::open_console( ) {
	AllocConsole( );
	freopen( "CONOUT$", "w", stdout );
}

void utils::shutdown( ) {
	/*FreeConsole();
	hooks::disable_all_hooks();
	FreeLibrary(ctx::modules::m_module_handle);*/
}

void utils::update_target_track( char* v31, int arg2, unsigned int arg3 ) {
	static const auto sub = reinterpret_cast < void* ( __cdecl* )( int, int, unsigned int ) > ( utils::find_sig( ctx::modules::m_spotify_image, "55 8B EC 33 D2 56 8B 75 08 39 55 10 76 2A 57 8B 7D 0C 0F B6 0C 3A 8B C1 83 E1 0F C1 E8 04 8A 89" ) );
	sub( reinterpret_cast< int >( v31 ), arg2, arg3 );
}

void utils::init_modules( const HMODULE base ) {
	ctx::modules::m_module_handle = base;
	printf( "[ ctx ] self module: 0x%p\n", ctx::modules::m_module_handle );

	ctx::modules::m_spotify_image = GetModuleHandleA( nullptr );
	printf( "[ ctx ] spotify module: 0x%p\n", ctx::modules::m_spotify_image );
}

std::uint8_t* utils::find_sig( const HMODULE module, const std::string& byte_array ) {
	if ( !module )
		return nullptr;

	static const auto pattern_to_byte = []( const char* pattern ) {
		auto bytes = std::vector<int>{};
		const auto start = const_cast< char* >( pattern );
		const auto end = const_cast< char* >( pattern ) + std::strlen( pattern );

		for ( auto current = start; current < end; ++current ) {
			if ( *current == '?' ) {
				++current;

				if ( *current == '?' )
					++current;

				bytes.push_back( -1 );
			}
			else {
				bytes.push_back( std::strtoul( current, &current, 16 ) );
			}
		}
		return bytes;
	};

	const auto dos_header = reinterpret_cast< PIMAGE_DOS_HEADER >( module );
	const auto nt_headers =
		reinterpret_cast< PIMAGE_NT_HEADERS >( reinterpret_cast< std::uint8_t* >( module ) + dos_header->e_lfanew );

	const auto size_of_image = nt_headers->OptionalHeader.SizeOfImage;
	const auto pattern_bytes = pattern_to_byte( byte_array.c_str( ) );
	const auto scan_bytes = reinterpret_cast< std::uint8_t* >( module );

	const auto pattern_size = pattern_bytes.size( );
	const auto pattern_data = pattern_bytes.data( );

	for ( auto i = 0ul; i < size_of_image - pattern_size; ++i ) {
		auto found = true;

		for ( auto j = 0ul; j < pattern_size; ++j ) {
			if ( scan_bytes[ i + j ] == pattern_data[ j ] || pattern_data[ j ] == -1 )
				continue;
			found = false;
			break;
		}
		if ( !found )
			continue;
		return &scan_bytes[ i ];
	}

	return nullptr;
}

const char* utils::get_type( const int a1 ) {
	switch ( a1 ) {
	case 0:
		return "none";
	case 1:
		return "track";
	case 2:
		return "album";
	default: return "unknown";
	}
}

const char* utils::get_stream_type( const int a1 ) {
	return !a1 ? "default" : a1 == 1 ? "alarm" : "unknown";
}

const char* utils::get_urgency( const int a1 ) {
	switch ( a1 ) {
	case 0:
		return "paused";
	case 1:
		return "soon";
	case 2:
		return "playing";
	default: return "unknown";
	}
}

const char* utils::get_transition( const int a1 ) {
	switch ( a1 ) {
	case 0:
		return "none";
	case 1:
		return "gapless";
	case 2:
		return "crossfade";
	case 3:
		return "at duration";
	default: return "unknown";
	}
}