#include "whytho/backend.h"
#include <libproc.h>
#include <vector>

namespace whytho
{

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

        char parent_buf[ PROC_PIDPATHINFO_MAXSIZE ];
        if ( proc_pidpath( info.ppid, parent_buf, sizeof( parent_buf ) ) > 0 )
            info.parent_exe = parent_buf;

        return info;
    }

}