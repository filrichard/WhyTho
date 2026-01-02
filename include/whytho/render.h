#pragma once
#include "procinfo.h"
#include "analyzer.h"
#include <vector>

namespace whytho
{

    void render_human( const ProcessInfo& p, const std::vector< Finding >& findings );
    void render_json( const ProcessInfo& p, const std::vector< Finding >& findings );

}