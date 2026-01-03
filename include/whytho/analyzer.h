#pragma once
#include "procinfo.h"
#include <string>
#include <vector>

namespace whytho
{

    enum class Severity { Info, Low, Medium, High };

    enum class LaunchKind
    {
        SystemService,
        UserSession,
        InteractiveShell,
        AppChild,
        Unknown
    };

    struct Finding
    {
        Severity severity;
        std::string message;
    };

    std::vector< Finding > analyze( const ProcessInfo& p );

}