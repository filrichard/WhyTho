#include "whytho/render.h"
#include <iostream>
#include <string>

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

    static std::string json_escape( const std::string& in )
    {
        std::string out;
        out.reserve( in.size() + 8 );

        for ( char ch : in )
        {
            const unsigned char c = static_cast< unsigned char >( ch );
            switch ( c )
            {
            case '\"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if ( c < 0x20 )
                {
                    static const char* hex = "0123456789abcdef";
                    out += "\\u00";
                    out += hex[ ( c >> 4 ) & 0xF ];
                    out += hex[ c & 0xF ];
                } else
                {
                    out += static_cast< char >( c );
                }
            }
        }
        return out;
    }

    static void json_string_or_null( const std::string& s )
    {
        if ( s.empty() )
            std::cout << "null";
        else
            std::cout << "\"" << json_escape( s ) << "\"";
    }

    void render_human( const ProcessInfo& p, const std::vector<Finding>& findings )
    {
        std::cout << "Process: ";
        if ( !p.ancestry.empty() )
            std::cout << p.ancestry.front().exe;
        else
            std::cout << "(unknown)";
        std::cout << "\n\n";

        std::cout << "PID: " << p.pid
                << "    User: " << p.uid << "\n";

        std::cout << "Executable: " << p.exe_path << "\n\n";

        if ( !findings.empty() )
        {
            std::cout << "Why it's running:\n";
            for ( const auto& f : findings )
            {
                std::cout << "  • " << f.message << "\n";
            }
            std::cout << "\n";
        }

        if ( !p.ancestry.empty() )
        {
            std::cout << "Ancestry:\n";
            for ( const auto& a : p.ancestry )
            {
                std::cout << "  [" << a.pid << "] " << a.exe << "\n";
            }
        }
    }

    void render_json( const ProcessInfo& p, const std::vector<Finding>& findings )
    {
        std::cout << "{";

        std::cout << "\"pid\":" << p.pid << ",";
        std::cout << "\"ppid\":" << p.ppid << ",";
        std::cout << "\"uid\":" << p.uid << ",";
        std::cout << "\"executable\":";
        json_string_or_null( p.exe_path );
        std::cout << ",";

        std::cout << "\"ancestry\":[";
        for ( size_t i = 0; i < p.ancestry.size(); ++i )
        {
            const auto& a = p.ancestry[ i ];
            if ( i ) std::cout << ",";
            std::cout << "{"
                    << "\"pid\":" << a.pid << ","
                    << "\"executable\":";
            json_string_or_null( a.exe );
            std::cout << "}";
        }
        std::cout << "],";

        std::cout << "\"findings\":[";
        for ( size_t i = 0; i < findings.size(); ++i )
        {
            const auto& f = findings[ i ];
            if ( i ) std::cout << ",";
            std::cout << "{"
                    << "\"severity\":\"" << sev_to_str( f.severity ) << "\","
                    << "\"message\":";
            json_string_or_null( f.message );
            std::cout << "}";
        }
        std::cout << "]";

        std::cout << "}\n";
    }

}