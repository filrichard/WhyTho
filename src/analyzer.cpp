#include "whytho/analyzer.h"

namespace whytho
{

    std::vector< Finding > analyze( const ProcessInfo& p )
    {
        std::vector< Finding > out;

        if ( p.ppid == 0 )
            out.push_back( { Severity::Error, "Parent could not be identified" } );
        else if ( p.ppid == 1 )
            out.push_back( { Severity::Info, "Likely service-managed or launched at boot / login." } );
        else
            out.push_back( { Severity::Info, "Likely started by another user or service process." } );
        
        return out;
    }

}