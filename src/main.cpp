#include <iostream>
#include <cstdlib>
#include <whytho/backend.h>

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

    std::cout << "PID: " << info->pid << "\n";
    std::cout << "PPID: " << info->ppid << "\n";
    std::cout << "UID: " << info->uid << "\n";
    std::cout << "Executable: " << info->exe_path << "\n";

    return 0;
}