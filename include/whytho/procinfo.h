#pragma once
#include <optional>
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

    struct CodeSignInfo
    {
        bool is_signed          = false;
        bool is_valid           = false;
        bool is_apple_signed    = false;
        bool is_hardened        = false;
        bool is_notarized       = false;
        std::string team_id;
        std::string signing_id;
    };

    struct ProcessInfo
    {
        pid_t pid{};
        pid_t ppid{};
        uid_t uid{};
        std::string exe_path;
        std::string parent_exe;
        std::vector< Ancestor > ancestry;
        std::optional< CodeSignInfo > code_sign;
        std::optional< std::string > bundle_id;
    };

}