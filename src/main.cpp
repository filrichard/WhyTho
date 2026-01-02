#include <iostream>
#include <cstdlib>
#include <cerrno>
#include <cstring>
#include <unistd.h>
#include "whytho/backend.h"
#include "whytho/analyzer.h"
#include "whytho/render.h"
#define WHYTHO_VERSION "0.1.0"

static bool parse_pid( const char* s, pid_t& out )
{

    if ( std::string( s ) == "self" )
    {
        out = getpid();
        return true;
    }

    errno = 0;
    char* end = nullptr;
    long val = std::strtol( s, &end, 10 );

    if ( errno != 0 || end == s || *end != '\0' )
        return false;
    
    if ( val <= 0 )
        return 0;
    
    out = static_cast< pid_t >( val );
    return true;
}

static void print_help()
{
    std::cout <<
        "whytho — explains why a process is running\n\n"
        "Usage:\n"
        "  whytho <pid>\n\n"
        "Options:\n"
        "  --help       Show this help message\n"
        "  --version    Show version information\n"
        "  --json       Renders output in JSON\n"
        "  self         Shows information about the \"WhyTho\" process\n";
}

int main ( int argc, char** argv )
{
    if ( argc < 2 )
    {
        std::cerr << "Usage: whytho <pid>\nTry: whytho --help\n";
        return 1;
    }

    bool json = false;
    std::string target;

    for ( int i = 1; i < argc; ++i )
    {
        std::string arg = argv[ i ];

        if ( arg == "--help" ) { print_help(); return 0; }
        if ( arg == "--version" ) { std::cout << "WhyTho Version " << WHYTHO_VERSION << "\n"; return 0; }
        if ( arg == "--json" ) { json = true; continue; }

        if ( target.empty() )
            target = arg;
        else
        {
            std::cerr << "Error: unexpected argument " << arg << "\n";
            return 1;
        }
    }

    pid_t pid{};
    
    if ( !parse_pid( argv[ 1 ], pid ) )
    {
        std::cerr << "Error: invalid PID: " << argv[ 1 ] << "\n";
        return 1;
    }

    auto info = whytho::inspect_process( pid );

    if ( !info )
    {
        std::cerr << "Error: process " << pid << " does not exist or cannot be inspected\n";
        return 1;
    }

    std::vector< whytho::Finding > analysis = whytho::analyze( *info );

    if ( json ) whytho::render_json( *info, analysis );
    else        whytho::render_human( *info, analysis );

    return 0;
}