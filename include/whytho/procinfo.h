#pragma once
#include <string>
#include <vector>
#include <sys/types.h>

namespace whytho
{

    struct Ancestor
    {
        pid_t pid;
        std::string exe;
    };

    struct ProcessInfo
    {
        pid_t pid{};
        pid_t ppid{};
        uid_t uid{};
        std::string exe_path;
        std::string parent_exe;
        std::vector< Ancestor > ancestry;
    };

}