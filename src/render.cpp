#include "whytho/render.h"
#include <iostream>
#include <string>
#include <unistd.h>

static const char* C_RESET  = "\033[0m";
static const char* C_BOLD   = "\033[1m";
static const char* C_DIM    = "\033[2m";
static const char* C_CYAN   = "\033[36m";
static const char* C_GREEN  = "\033[32m";

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

    static std::string basename_of( const std::string& path )
    {
        auto pos = path.find_last_of( '/' );
        return ( pos == std::string::npos ) ? path : path.substr( pos + 1 );
    }

    static bool use_color()
    {
        return isatty( STDOUT_FILENO );
    }

    static void print_banner()
    {
        if ( !use_color() ) return;
        std::cout << "\n";
        std::cout << "\033[1mwhytho\033[0m  •  explain why a process is running\n";
        std::cout << "\n";
    }

    void render_human( const ProcessInfo& p, const std::vector< Finding >& findings )
    {
        print_banner();
        if ( use_color() ) std::cout << C_BOLD << C_CYAN;
        std::cout << "Process: " << basename_of( p.exe_path ) << "\n";
        if ( use_color() ) std::cout << C_RESET;
        std::cout << "\n";

        std::cout << "PID: " << p.pid
                << "    User: " << p.uid << "\n";

        std::cout << "Executable: " << p.exe_path << "\n\n";

        if ( !findings.empty() )
        {
            std::cout << "Why it's running:\n";
            for ( const auto& f : findings )
            {
                if ( use_color() ) std::cout << C_GREEN;
                std::cout << "  • " << f.message;
                if ( use_color() ) std::cout << C_RESET;
                std::cout << "\n";
            }
            std::cout << "\n";
        }

        if ( !p.ancestry.empty() )
        {
            std::cout << "Ancestry:\n";
            for ( const auto& a : p.ancestry )
            {
                if ( use_color() ) std::cout << C_DIM;
                std::cout << "  [" << a.pid << "] " << a.exe;
                if ( use_color() ) std::cout << C_RESET;
                std::cout << "\n";
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