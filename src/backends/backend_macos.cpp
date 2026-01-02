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
        return info;
    }

}