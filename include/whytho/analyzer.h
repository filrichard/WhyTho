#pragma once
#include "procinfo.h"
#include <string>
#include <vector>

namespace whytho
{

    enum class Severity { Info, Error };

    struct Finding
    {
        Severity severity;
        std::string message;
    };

    std::vector< Finding > analyze( const ProcessInfo& p );

}