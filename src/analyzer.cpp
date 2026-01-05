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

    static bool looks_like_shell( const std::string& exe )
    {
        return exe == "/bin/bash" || exe == "/bin/zsh" || exe == "/bin/sh" || exe == "/usr/bin/zsh";
    }

    static LaunchKind classify_launch( const ProcessInfo& p )
    {
        const bool pid1 = has_pid1( p );

        if ( pid1 && p.uid == 0 ) { return LaunchKind::SystemService; }
        if ( pid1 && p.uid != 0 )
        {
            for ( const auto& a : p.ancestry )
            {
                if ( looks_like_shell( a.exe ) ) return LaunchKind::InteractiveShell;
            }
            if ( p.ancestry.size() >= 2 )
            {
                const auto& parent = p.ancestry[ 1 ].exe;
                if ( parent.rfind( "/Applications/", 0 ) == 0 ) return LaunchKind::AppChild;
            }
            return LaunchKind::UserSession;
        }
        return LaunchKind::Unknown;
    }

    static std::string basename_of( const std::string& path )
    {
        auto pos = path.find_last_of( '/' );
        return ( pos == std::string::npos ) ? path : path.substr( pos + 1 );
    }

    static std::string lineage_string( const ProcessInfo& p )
    {
        if ( p.ancestry.empty() ) return "unknown";

        std::string out;
        for ( size_t i = p.ancestry.size(); i-- > 0; )
        {
            if ( !out.empty() ) out += " \u2192 "; // → UTF-8 arrow
            out += basename_of( p.ancestry[ i ].exe );
        }
        return out;
    }

    std::vector< Finding > analyze( const ProcessInfo& p )
    {
        std::vector< Finding > out;
        const auto kind = classify_launch( p );
        
        switch ( kind )
        {
            case LaunchKind::SystemService:
            {
                out.push_back( { Severity::Info, "Likely a system-managed service (root + launchd ancestry)." } );
                break;
            }
            case LaunchKind::UserSession:
            {
                out.push_back( { Severity::Info, "Likely started under a user login session (launchd ancestry)." } );
                break;
            }
            case LaunchKind::InteractiveShell:
            {
                std::string shell = "shell";
                for ( const auto& a : p.ancestry )
                {
                    if ( looks_like_shell( a.exe ) ) { shell = basename_of( a.exe ); break; }
                }
                out.push_back( { Severity::Info, "Likely started under a user login session (launchd ancestry)." } );
                out.push_back( { Severity::Info, "Launched from an interactive shell: " + shell } );
                break;
            }
            case LaunchKind::AppChild:
            {
                if ( p.ancestry.size() >= 2 )
                {
                    out.push_back( { Severity::Info, "Likely started under a user login session (launchd ancestry)." } );
                    out.push_back( { Severity::Info,
                        "Application child process: " + basename_of( p.ancestry[ 1 ].exe ) +
                        " \u2192 " + basename_of( p.ancestry[ 0 ].exe )
                    } );
                } else
                {
                    out.push_back( { Severity::Info, "Likely started under a user login session (launchd ancestry)." } );
                }
                break;
            }
            case LaunchKind::Unknown:
            {
                out.push_back( { Severity::Info, "Launch context could not be classified from available evidence." } );
                break;
            }
        }

        out.push_back( { Severity::Info, "Lineage: " + lineage_string( p ) } );

        return out;
    }

}