#include "whytho/analyzer.h"

namespace whytho
{

    static bool has_pid1( const ProcessInfo& p )
    {
        for ( const auto& a : p.ancestry )
        {
            if ( a.pid == 1 )
                return true;
        }
        return false;
    }

    std::vector< Finding > analyze( const ProcessInfo& p )
    {
        std::vector< Finding > out;

        if ( has_pid1( p ) )
        {
            if ( p.uid == 0 )
                out.push_back( { Severity::Info, "Likely a system-managed service (root + launchd ancestry)" } );
            else
                out.push_back( { Severity::Info, "Likely started under a user login session (launchd ancestry)" } );
        }

        if ( p.ancestry.size() >= 2 )
        {
            const auto& parent = p.ancestry[ 1 ].exe;
            out.push_back( { Severity::Info, "Child/helper process of: " + parent } );
        }

        if ( p.exe_path.rfind( "/tmp/", 0 ) == 0 || p.exe_path.rfind( "/private/tmp", 0 ) == 0 )
        {
            out.push_back( { Severity::Low, "Executable loaded in a temporary directory (unusual for installed applications)" } );
        }

        return out;
    }

}