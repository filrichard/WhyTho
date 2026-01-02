#include "whytho/analyzer.h"

namespace whytho
{

    std::vector< Finding > analyze( const ProcessInfo& p )
    {
        std::vector< Finding > out;

        if ( p.ppid == 1 )
            out.push_back( { Severity::Info, "Likely service-managed or launched at boot / login by PID 1" } );
        else if ( !p.parent_exe.empty() )
            out.push_back( { Severity::Info, "Launched by parent process: " + p.parent_exe } );
        else
            out.push_back( { Severity::Error, "Parent could not be identified" } );

        return out;
    }

}