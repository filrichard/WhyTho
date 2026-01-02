#include <iostream>
#include <cstdlib>
#include "whytho/backend.h"
#include "whytho/analyzer.h"
#include "whytho/render.h"

int main ( int argc, char** argv )
{
    if ( argc != 2 )
    {
        std::cerr << "Usage: whytho <pid>\n";
        return 1;
    }

    pid_t pid = static_cast< pid_t >( std::atoi( argv[ 1 ] ) );
    auto info = whytho::inspect_process( pid );

    if ( !info )
    {
        std::cerr << "Error inspecting process " << pid << "\n";
        return 1;
    }

    std::vector< whytho::Finding > analysis = whytho::analyze( *info );

    whytho::render_human( *info, analysis );

    return 0;
}