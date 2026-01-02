#include "whytho/backend.h"
#include <libproc.h>
#include <vector>

namespace whytho
{

    constexpr int MAX_ANCESTRY_DEPTH = 10;

    std::optional< ProcessInfo > inspect_process( pid_t pid )
    {
        ProcessInfo info{};
        info.pid = pid;

        char pathbuf[ PROC_PIDPATHINFO_MAXSIZE ];
        if ( proc_pidpath( pid, pathbuf, sizeof( pathbuf ) ) <= 0 )
            return std::nullopt;

        info.exe_path = pathbuf;

        proc_bsdinfo bsd{};
        int bytes = proc_pidinfo( pid, PROC_PIDTBSDINFO, 0, &bsd, sizeof( bsd ) );
        if ( bytes == static_cast< int >( sizeof(bsd ) ) )
        {
            info.ppid = static_cast< pid_t >( bsd.pbi_ppid );
            info.uid = static_cast< uid_t >( bsd.pbi_uid );
        } else
        {
            info.ppid = 0;
            info.uid = 0;
        }

        pid_t current = pid;
        int depth = 0;

        while ( current > 0 && depth < MAX_ANCESTRY_DEPTH )
        {
            char buf[ PROC_PIDPATHINFO_MAXSIZE ];
            if ( proc_pidpath( current, buf, sizeof( buf ) ) <= 0 )
                break;
            
            info.ancestry.push_back( { current, buf } );

            proc_bsdinfo bsdinfo{};
            int bytes = proc_pidinfo( current, PROC_PIDTBSDINFO, 0, &bsdinfo, sizeof( bsdinfo ) );
            if ( bytes != static_cast< int >( sizeof( bsdinfo ) ) )
                break;
            
            pid_t parent = static_cast< pid_t >( bsdinfo.pbi_ppid );

            if ( parent <= 0 || parent == current )
                break;
            
            if ( parent == 1 )
            {
                char pbuf[ PROC_PIDPATHINFO_MAXSIZE ];
                if ( proc_pidpath( parent, pbuf, sizeof( pbuf ) ) > 0 )
                    info.ancestry.push_back( { parent, pbuf } );
                break;
            }
            current = parent;
            ++depth;
        }

        return info;
    }

}