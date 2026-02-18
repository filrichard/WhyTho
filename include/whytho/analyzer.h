#pragma once
#include "procinfo.h"
#include <string>
#include <vector>

namespace whytho
{

    enum class Severity
    {
        Info,
        Low,
        Medium,
        High
    };

    enum class LaunchKind
    {
        AppleSystem,
        SystemService,
        UserAgent,
        UserSession,
        InteractiveShell,
        AppChild,
        Unknown
    };

    struct Finding
    {
        Severity    severity;
        std::string category;
        std::string message;
    };

    std::vector< Finding > analyze( const ProcessInfo& p );

}