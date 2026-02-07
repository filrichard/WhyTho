#include "whytho/backend.h"
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>
#include <unistd.h>
#include <sys/types.h>

namespace whytho
{

    static std::string proc_path( pid_t pid, const char* leaf )
    {
        return "/proc/" + std::to_string( pid ) + "/" + leaf;
    }

    static std::optional< std::string > read_exe_path( pid_t pid )
    {
        std::string link = proc_path( pid, "exe" );

        char buffer[ 4096 ];
        ssize_t n = ::readlink( link.c_str(), buffer, sizeof( buffer ) - 1 );
        if ( n < 0 ) return std::nullopt;

        buffer[ n ] = '\0';
        return std::string( buffer );
    }

    static bool read_ppid_uid_from_status( pid_t pid, pid_t& out_ppid, uid_t& out_uid )
    {
        std::string path = proc_path( pid, "status" );
        FILE* f = std::fopen( path.c_str(), "r" );
        if ( !f ) return false;

        char line[ 512 ];
        bool got_ppid = false;
        bool got_uid = false;

        while ( std::fgets( line, sizeof( line ), f ) == 0 )
        {
            if ( std::strncmp( line, "PPid:", 5 ) == 0 )
            {
                long v = 0;
                if ( std::sscanf( line + 5, "%ld", &v ) == 1 )
                {
                    out_ppid = static_cast< pid_t >( v );
                    got_ppid = true;
                }
            }
            else if ( std::strncmp( line, "Uid:", 4 ) == 0 )
            {
                unsigned long v = 0;
                if ( std::sscanf( line + 4, "%lu", &v ) == 1 )
                {
                    out_uid = static_cast< uid_t >( v );
                    got_uid = true;
                }
            }

            if ( got_ppid && got_uid ) break;
        }

        std::fclose( f );
        return got_ppid && got_uid;
    }

    std::optional< ProcessInfo > inspect_process( pid_t pid )
    {
        constexpr int MAX_ANCESTRY_DEPTH = 10;
        ProcessInfo info{};
        info.pid = pid;

        auto exe = read_exe_path( pid );
        if ( !exe ) return std::nullopt;
        info.exe_path = *exe;

        pid_t ppid = 0;
        uid_t uid = 0;
        if ( !read_ppid_uid_from_status( pid, ppid, uid ) )
        {
            info.ppid = 0;
            info.uid = 0;
        } else
        {
            info.ppid = ppid;
            info.uid = uid;
        }

        info.ancestry.clear();
        info.ancestry.push_back( { pid, info.exe_path } );

        pid_t current = pid;
        int depth = 0;

        while ( current > 0 && depth < MAX_ANCESTRY_DEPTH )
        {
            pid_t cur_ppid = 0;
            uid_t cur_uid = 0;
            if ( !read_ppid_uid_from_status( current, cur_ppid, cur_uid ) ) break;

            if ( cur_ppid <= 0 || cur_ppid == current ) break;

            auto parent_exe = read_exe_path( cur_ppid );
            if ( !parent_exe ) break;

            info.ancestry.push_back( { cur_ppid, *parent_exe } );

            if ( cur_ppid == 1 ) break;

            current = cur_ppid;
            depth++;
        }
        return info;
    }

}