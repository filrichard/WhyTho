#include "whytho/render.h"
#include <iostream>

namespace whytho
{

    static const char* sev_to_str( Severity s )
    {
        switch (s)
        {
            case Severity::Info: return "INFO";
            case Severity::Low: return "LOW";
            case Severity::Medium: return "MEDIUM";
            case Severity::High: return "HIGH";
        }
        return "UNKNOWN";
    }

    void render_human( const ProcessInfo& p, const std::vector< Finding >& findings )
    {
        std::cout << "PID: " << p.pid << "\n";
        std::cout << "PPID: " << p.ppid << "\n";
        std::cout << "UID: " << p.uid << "\n";
        std::cout << "Executable: " << p.exe_path << "\n";

        std::cout << "Ancestry:\n";
        for ( const auto& a : p.ancestry )
        {
            std::cout << "  [" << a.pid << "] " << a.exe << "\n";
        }

        if ( !findings.empty() )
        {
            std::cout << "Findings:\n";
            for ( const auto& f : findings )
            {
                std::cout << "  [" << sev_to_str(f.severity) << "] " << f.message << "\n";
            }
        }
    }
}