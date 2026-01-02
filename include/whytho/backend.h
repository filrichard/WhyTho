#pragma once
#include "procinfo.h"
#include <optional>

namespace whytho
{

    std::optional< ProcessInfo > inspect_process( pid_t pid );

}