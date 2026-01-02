#include <iostream>
#include <cstdlib>
#include <whytho/backend.h>
#include <whytho/analyzer.h>

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

    std::cout << "PID: " << info->pid << "\n";
    std::cout << "PPID: " << info->ppid << "\n";
    std::cout << "UID: " << info->uid << "\n";
    std::cout << "Executable: " << info->exe_path << "\n";
    if ( !info->parent_exe.empty() )
        std::cout << "Parent executable: " << info->parent_exe << "\n";
    std::cout << analysis[ 0 ].message << "\n";

    return 0;
}