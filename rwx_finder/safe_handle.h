#pragma once

#include <handleapi.h>
#include <memory>

class safe_handle : public std::unique_ptr< std::remove_pointer< HANDLE >::type, void( * )( HANDLE ) >
{
public:
	safe_handle( HANDLE handle ) : unique_ptr( handle, &safe_handle::close_handle )
	{
		//
	}

	bool is_valid() const
	{
		return get() != INVALID_HANDLE_VALUE;
	}

	operator HANDLE() const
	{
		return get();
	}

private:
	static auto close_handle( HANDLE handle ) noexcept -> void
	{
		if ( handle != INVALID_HANDLE_VALUE )
			CloseHandle( handle );
	}
};
