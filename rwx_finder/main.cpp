#include <windows.h>
#include <execution>
#include <wintrust.h>

#include "safe_handle.h"

#include <iostream>
#include <string>
#include <filesystem>
#include <Softpub.h>
#include <sstream>

#pragma comment (lib, "wintrust")

auto main() -> int
{
	std::cout << "> type in the start path" << std::endl;

	std::string start_path;

	std::getline( std::cin, start_path );

	std::cout << std::endl;

	if ( std::filesystem::is_directory( start_path ) )
		for ( auto& p : std::filesystem::recursive_directory_iterator( start_path, std::filesystem::directory_options::skip_permission_denied ) )
		{
			if ( p.path().has_extension() == false || p.path().extension() != ".dll")
				continue;

			auto file_handle = safe_handle( CreateFileW( p.path().c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr ) );
			if ( file_handle.is_valid() == false )
				continue;

			auto file_mapping = safe_handle( CreateFileMappingW( file_handle, nullptr, PAGE_READONLY, 0, 0, nullptr ) );
			if ( file_mapping == nullptr || file_mapping.is_valid() == false )
				continue;

			auto file_base = MapViewOfFile( file_mapping, FILE_MAP_READ, 0, 0, 0 );
			if ( file_base == nullptr )
				continue;

			auto dos_header = PIMAGE_DOS_HEADER( file_base );
			if ( dos_header == nullptr || dos_header->e_magic != IMAGE_DOS_SIGNATURE )
				continue;

			auto nt_header = PIMAGE_NT_HEADERS( __int64( dos_header ) + dos_header->e_lfanew );
			if ( nt_header->Signature != IMAGE_NT_SIGNATURE )
				continue;

			auto optional_header = nt_header->OptionalHeader;
			auto section_header = IMAGE_FIRST_SECTION( nt_header );

			for ( auto i = 0; i < nt_header->FileHeader.NumberOfSections; i++ )
			{
				const auto is_executable = bool( section_header->Characteristics & IMAGE_SCN_MEM_EXECUTE );
				const auto is_readable = bool( section_header->Characteristics & IMAGE_SCN_MEM_READ );
				const auto is_writeable = bool( section_header->Characteristics & IMAGE_SCN_MEM_WRITE );
				const auto is_signed = [ & ]() -> bool
				{
					WINTRUST_FILE_INFO file_info;
					std::memset( &file_info, 0, sizeof( WINTRUST_FILE_INFO ) );
					file_info.cbStruct = sizeof( WINTRUST_FILE_INFO );
					file_info.pcwszFilePath = p.path().c_str();
					file_info.hFile = nullptr;
					file_info.pgKnownSubject = nullptr;

					WINTRUST_DATA wintrust_data;
					std::memset( &wintrust_data, 0, sizeof( WINTRUST_DATA ) );
					wintrust_data.cbStruct = sizeof( WINTRUST_DATA );
					wintrust_data.pPolicyCallbackData = nullptr;
					wintrust_data.pSIPClientData = nullptr;
					wintrust_data.dwUIChoice = WTD_UI_NONE;
					wintrust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
					wintrust_data.dwUnionChoice = WTD_CHOICE_FILE;
					wintrust_data.dwStateAction = WTD_STATEACTION_VERIFY;
					wintrust_data.hWVTStateData = nullptr;
					wintrust_data.pwszURLReference = nullptr;
					wintrust_data.dwUIContext = 0;
					wintrust_data.pFile = &file_info;

					auto policy_guid = GUID( WINTRUST_ACTION_GENERIC_VERIFY_V2 );
					auto is_signed = false;

					switch( WinVerifyTrust( nullptr, &policy_guid, &wintrust_data ) )
					{
						case ERROR_SUCCESS:
						case TRUST_E_SUBJECT_NOT_TRUSTED: // :shrug:
							is_signed = true;
							break;
						default:
							break;
					}

					wintrust_data.dwStateAction = WTD_STATEACTION_CLOSE;
					WinVerifyTrust( nullptr, &policy_guid, &wintrust_data );

					return is_signed;
				};

				if ( ( is_executable & is_readable & is_writeable ) && is_signed() )
				{
					std::stringstream msg{};

					msg << "[Found signed Module with RWX Section: " << p.path().filename() << "]" << std::endl
						<< "- Path: " << p.path().parent_path() << std::endl
						<< "- Magic: " << (optional_header.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ? "x64" : "x32") << std::endl
						<< "- Section Name: " << section_header->Name << std::endl
						<< "- Virtual Size: 0x" << section_header->Misc.VirtualSize << std::endl
						<< "- Raw Size: 0x" << section_header->SizeOfRawData << std::endl
						<< std::endl;

					std::cout << msg.str();
				}

				section_header++;
			}
		}
	else
		std::cout << "thats not a path!" << std::endl;

	std::cout << "finished" << std::endl;

	std::cin.get();

	return NULL;
}