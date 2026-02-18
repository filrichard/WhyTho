#include "whytho/analyzer.h"
#include <algorithm>
#include <array>
#include <string_view>

namespace whytho
{

static std::string basename_of( const std::string& path )
{
    const auto pos = path.find_last_of( '/' );
    return ( pos == std::string::npos ) ? path : path.substr( pos + 1 );
}

static bool has_prefix( const std::string& path, std::string_view prefix )
{
    return path.compare( 0, prefix.size(), prefix.data(), prefix.size() ) == 0;
}

static bool path_contains( const std::string& path, std::string_view needle )
{
    return path.find( needle ) != std::string::npos;
}

static bool looks_like_shell( const std::string& exe )
{
    static constexpr std::array known_shells {
        std::string_view{ "/bin/sh"   },
        std::string_view{ "/bin/bash" },
        std::string_view{ "/bin/zsh"  },
        std::string_view{ "/bin/ksh"  },
        std::string_view{ "/bin/dash" },
        std::string_view{ "/bin/csh"  },
        std::string_view{ "/bin/tcsh" },
        // Homebrew Intel
        std::string_view{ "/usr/local/bin/bash" },
        std::string_view{ "/usr/local/bin/zsh"  },
        std::string_view{ "/usr/local/bin/fish" },
        std::string_view{ "/usr/local/bin/ksh"  },
        // Homebrew Apple Silicon
        std::string_view{ "/opt/homebrew/bin/bash" },
        std::string_view{ "/opt/homebrew/bin/zsh"  },
        std::string_view{ "/opt/homebrew/bin/fish" },
        std::string_view{ "/opt/homebrew/bin/ksh"  },
        // Xcode / system zsh alias
        std::string_view{ "/usr/bin/zsh" },
        std::string_view{ "/usr/bin/bash" },
    };
    for ( const auto sv : known_shells )
        if ( exe == sv ) return true;
    return false;
}

struct AncestrySnapshot
{
    bool        has_launchd   = false;
    bool        has_shell     = false;
    std::string shell_name;
    std::string nearest_app_exe;
};

static AncestrySnapshot scan_ancestry( const ProcessInfo& p )
{
    AncestrySnapshot snap;
    for ( const auto& a : p.ancestry )
    {
        if ( a.pid == 1 )
            snap.has_launchd = true;

        if ( !snap.has_shell && looks_like_shell( a.exe ) )
        {
            snap.has_shell  = true;
            snap.shell_name = basename_of( a.exe );
        }

        if ( snap.nearest_app_exe.empty() )
        {
            if ( has_prefix( a.exe, "/Applications/"         ) ||
                 has_prefix( a.exe, "/System/Applications/"  ) ||
                 path_contains( a.exe, "/Applications/"      ) )
            {
                snap.nearest_app_exe = a.exe;
            }
        }
    }
    return snap;
}

static LaunchKind classify_launch( const ProcessInfo& p, const AncestrySnapshot& snap )
{
    if ( !snap.has_launchd )
        return LaunchKind::Unknown;

    if ( p.uid == 0 )
    {
        // Apple's own system binaries live under /System or /usr
        if ( has_prefix( p.exe_path, "/System/" ) ||
             has_prefix( p.exe_path, "/usr/libexec/" ) ||
             has_prefix( p.exe_path, "/usr/sbin/" ) )
            return LaunchKind::AppleSystem;

        return LaunchKind::SystemService;
    }

    if ( snap.has_shell )
        return LaunchKind::InteractiveShell;

    if ( !snap.nearest_app_exe.empty() )
        return LaunchKind::AppChild;

    if ( !p.ancestry.empty() && p.ancestry[0].pid == 1 )
        return LaunchKind::UserAgent;

    return LaunchKind::UserSession;
}

static std::string lineage_string( const ProcessInfo& p )
{
    if ( p.ancestry.empty() ) return "(no ancestry available)";

    std::string out;
    for ( std::size_t i = p.ancestry.size(); i-- > 0; )
    {
        if ( !out.empty() ) out += " \u2192 ";
        out += basename_of( p.ancestry[i].exe );
        out += '[';
        out += std::to_string( p.ancestry[i].pid );
        out += ']';
    }
    return out;
}

static void analyze_origin( const ProcessInfo& p,
                             const AncestrySnapshot& snap,
                             LaunchKind kind,
                             std::vector< Finding >& out )
{
    switch ( kind )
    {
        case LaunchKind::AppleSystem:
            out.push_back( { Severity::Info, "origin",
                "Apple system binary running as a launchd-managed service (SIP-protected path)." } );
            break;

        case LaunchKind::SystemService:
            out.push_back( { Severity::Info, "origin",
                "Third-party root-owned launchd service (likely from /Library/LaunchDaemons)." } );
            break;

        case LaunchKind::UserAgent:
            out.push_back( { Severity::Info, "origin",
                "User-space launchd agent — direct child of launchd under a user session." } );
            break;

        case LaunchKind::UserSession:
            out.push_back( { Severity::Info, "origin",
                "Launched under a user login session (launchd ancestry, not a registered agent)." } );
            break;

        case LaunchKind::InteractiveShell:
            out.push_back( { Severity::Info, "origin",
                "Launched from an interactive shell (" + snap.shell_name + ")." } );
            break;

        case LaunchKind::AppChild:
        {
            const std::string app_name = basename_of( snap.nearest_app_exe );
            out.push_back( { Severity::Info, "origin",
                "Subprocess of application bundle: " + app_name + "." } );
            break;
        }

        case LaunchKind::Unknown:
            out.push_back( { Severity::Low, "origin",
                "Launch context could not be classified — process has no launchd ancestry. "
                "Could be an orphan, a container child, or a process whose parent already exited." } );
            break;
    }

    out.push_back( { Severity::Info, "lineage", "Lineage: " + lineage_string( p ) } );
}

static void analyze_exec_path( const ProcessInfo& p, std::vector< Finding >& out )
{
    const auto& exe = p.exe_path;

    if ( exe.empty() )
    {
        out.push_back( { Severity::Medium, "exec-path",
            "Executable path is empty — binary may have been deleted or the path could not be resolved." } );
        return;
    }

    if ( path_contains( exe, " (deleted)" ) )
    {
        out.push_back( { Severity::High, "exec-path",
            "Executable appears to have been deleted from disk while the process is still running. "
            "This is a common malware technique to evade detection." } );
    }

    static constexpr std::array suspicious_prefixes {
        std::string_view{ "/tmp/"          },
        std::string_view{ "/var/tmp/"      },
        std::string_view{ "/private/tmp/"  },
        std::string_view{ "/var/folders/"  },
        std::string_view{ "/dev/shm/"      },
    };
    for ( const auto sv : suspicious_prefixes )
    {
        if ( has_prefix( exe, sv ) )
        {
            out.push_back( { Severity::High, "exec-path",
                "Executable is running from a temporary directory (" + exe + "). "
                "Legitimate software rarely executes from temp paths; this is a strong malware indicator." } );
            break;
        }
    }

    if ( path_contains( exe, "/." ) )
    {
        out.push_back( { Severity::Medium, "exec-path",
            "Executable path contains a hidden component (dotfile/dotdir): " + exe + ". "
            "Malware frequently hides binaries inside hidden directories." } );
    }

    if ( has_prefix( exe, "/Users/" ) )
    {
        const bool in_apps    = path_contains( exe, "/Applications/" );
        const bool in_library = path_contains( exe, "/Library/"      );
        if ( !in_apps && !in_library )
        {
            out.push_back( { Severity::Low, "exec-path",
                "Executable is running directly from a user home directory subtree outside "
                "~/Applications or ~/Library: " + exe + ". "
                "This is unusual for established software." } );
        }
    }

    static constexpr std::array trusted_prefixes {
        std::string_view{ "/System/"                 },
        std::string_view{ "/usr/bin/"                },
        std::string_view{ "/usr/sbin/"               },
        std::string_view{ "/usr/libexec/"            },
        std::string_view{ "/usr/lib/"                },
        std::string_view{ "/Library/Apple/"          },
        std::string_view{ "/Applications/"           },
        std::string_view{ "/System/Applications/"    },
        std::string_view{ "/opt/homebrew/bin/"       },
        std::string_view{ "/opt/homebrew/sbin/"      },
        std::string_view{ "/opt/homebrew/Cellar/"    },
        std::string_view{ "/usr/local/bin/"          },
        std::string_view{ "/usr/local/sbin/"         },
        std::string_view{ "/usr/local/Cellar/"       },
    };
    bool in_trusted = false;
    for ( const auto sv : trusted_prefixes )
    {
        if ( has_prefix( exe, sv ) ) { in_trusted = true; break; }
    }
    if ( in_trusted )
    {
        out.push_back( { Severity::Info, "exec-path",
            "Executable resides in a standard trusted location: " + exe + "." } );
    }
    else
    {
        bool already_flagged = false;
        for ( const auto sv : suspicious_prefixes )
            if ( has_prefix( exe, sv ) ) { already_flagged = true; break; }

        if ( !already_flagged )
        {
            out.push_back( { Severity::Low, "exec-path",
                "Executable is not in a standard system or application directory: " + exe + ". "
                "Verify you recognise this software." } );
        }
    }
}

static void analyze_code_sign( const ProcessInfo& p, std::vector< Finding >& out )
{
    if ( !p.code_sign.has_value() )
    {
        out.push_back( { Severity::Info, "code-sign",
            "Code-signing information was not collected for this process." } );
        return;
    }

    const auto& cs = *p.code_sign;

    if ( !cs.is_signed )
    {
        out.push_back( { Severity::Medium, "code-sign",
            "Executable is unsigned. On modern macOS, legitimate software is expected to be signed. "
            "This may indicate a home-built tool, old software, or a potentially unwanted program." } );
        return;
    }

    if ( !cs.is_valid )
    {
        out.push_back( { Severity::High, "code-sign",
            "Executable carries a code signature that does not verify — the binary may have been "
            "tampered with after signing." } );
        return;
    }

    if ( cs.is_apple_signed )
    {
        out.push_back( { Severity::Info, "code-sign",
            "Signed by Apple (" + ( cs.signing_id.empty() ? "no signing ID" : cs.signing_id ) + ")." } );
    }
    else
    {
        std::string detail = "Valid third-party signature";
        if ( !cs.team_id.empty()    ) detail += " — Team ID: " + cs.team_id;
        if ( !cs.signing_id.empty() ) detail += ", Signing ID: " + cs.signing_id;
        detail += '.';
        out.push_back( { Severity::Info, "code-sign", detail } );
    }

    if ( !cs.is_hardened )
    {
        out.push_back( { Severity::Low, "code-sign",
            "Hardened runtime is not enabled. The process may be susceptible to code-injection attacks "
            "via DYLD environment variables or library validation bypasses." } );
    }

    if ( !cs.is_notarized && !cs.is_apple_signed )
    {
        out.push_back( { Severity::Low, "code-sign",
            "Executable has not been notarized by Apple. Gatekeeper will block it on first launch "
            "unless the user explicitly approves it." } );
    }
}

std::vector< Finding > analyze( const ProcessInfo& p )
{
    std::vector< Finding > out;

    const AncestrySnapshot snap = scan_ancestry( p );
    const LaunchKind       kind = classify_launch( p, snap );

    analyze_origin(    p, snap, kind, out );
    analyze_exec_path( p,             out );
    analyze_code_sign( p,             out );

    std::stable_sort( out.begin(), out.end(), []( const Finding& a, const Finding& b )
    {
        return static_cast< int >( a.severity ) > static_cast< int >( b.severity );
    } );

    return out;
}

}