#pragma once
#include <string>
#include <sys/types.h>

namespace whytho
{

    struct ProcessInfo
    {
        pid_t pid{};
        pid_t ppid{};
        uid_t uid{};
        std::string exe_path;
        std::string parent_exe;
    };

}