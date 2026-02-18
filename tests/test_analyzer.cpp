#include "whytho/analyzer.h"
#include <cassert>
#include <iostream>
#include <string>
#include <vector>

static int g_tests_run    = 0;
static int g_tests_passed = 0;
static int g_tests_failed = 0;

#define TEST( name )                                                \
    static void test_##name();                                      \
    static struct TestRegistrar_##name {                            \
        TestRegistrar_##name() {                                    \
            std::cout << "[TEST] " << #name << std::endl;           \
            g_tests_run++;                                          \
            try {                                                   \
                test_##name();                                      \
                g_tests_passed++;                                   \
                std::cout << "  ✓ PASS\n" << std::endl;            \
            } catch ( const std::exception& e ) {                   \
                g_tests_failed++;                                   \
                std::cerr << "  ✗ FAIL: " << e.what() << "\n" << std::endl; \
            }                                                       \
        }                                                           \
    } g_test_registrar_##name;                                      \
    static void test_##name()

#define ASSERT( cond ) \
    do { if ( !(cond) ) throw std::runtime_error( "Assertion failed: " #cond " at line " + std::to_string(__LINE__) ); } while(0)

#define ASSERT_EQ( a, b ) \
    do { if ( (a) != (b) ) throw std::runtime_error( "Expected " #a " == " #b " at line " + std::to_string(__LINE__) ); } while(0)

static int count_severity( const std::vector< whytho::Finding >& findings, whytho::Severity sev )
{
    int count = 0;
    for ( const auto& f : findings )
        if ( f.severity == sev ) ++count;
    return count;
}

static bool has_message_containing( const std::vector< whytho::Finding >& findings,
                                     const std::string& needle )
{
    for ( const auto& f : findings )
        if ( f.message.find( needle ) != std::string::npos )
            return true;
    return false;
}

static bool has_category( const std::vector< whytho::Finding >& findings,
                          const std::string& cat )
{
    for ( const auto& f : findings )
        if ( f.category == cat )
            return true;
    return false;
}

static const whytho::Finding* find_first_severity( const std::vector< whytho::Finding >& findings,
                                                    whytho::Severity sev )
{
    for ( const auto& f : findings )
        if ( f.severity == sev )
            return &f;
    return nullptr;
}

TEST( apple_system_binary )
{
    whytho::ProcessInfo p;
    p.pid      = 100;
    p.ppid     = 1;
    p.uid      = 0;
    p.exe_path = "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow";
    p.ancestry = {
        { 1, "/sbin/launchd" }
    };

    const auto findings = whytho::analyze( p );

    ASSERT( !findings.empty() );
    ASSERT( has_message_containing( findings, "Apple system binary" ) );
    ASSERT( has_message_containing( findings, "SIP-protected" ) );
    ASSERT( has_category( findings, "origin" ) );
}

TEST( third_party_system_service )
{
    whytho::ProcessInfo p;
    p.pid      = 200;
    p.ppid     = 1;
    p.uid      = 0;
    p.exe_path = "/Library/PrivilegedHelperTools/com.example.daemon";
    p.ancestry = {
        { 1, "/sbin/launchd" }
    };

    const auto findings = whytho::analyze( p );

    ASSERT( has_message_containing( findings, "Third-party root-owned" ) );
    ASSERT( has_message_containing( findings, "launchd service" ) );
}

TEST( user_agent_direct_launchd_child )
{
    whytho::ProcessInfo p;
    p.pid      = 300;
    p.ppid     = 1;
    p.uid      = 501;
    p.exe_path = "/Applications/MyApp.app/Contents/MacOS/MyApp";
    p.ancestry = {
        { 1, "/sbin/launchd" }
    };

    const auto findings = whytho::analyze( p );

    ASSERT( has_message_containing( findings, "User-space launchd agent" ) );
    ASSERT( has_message_containing( findings, "direct child of launchd" ) );
}

TEST( user_session_process )
{
    whytho::ProcessInfo p;
    p.pid      = 400;
    p.ppid     = 350;
    p.uid      = 501;
    p.exe_path = "/usr/bin/some-user-tool";
    p.ancestry = {
        { 350, "/usr/libexec/some-parent" },
        { 1,   "/sbin/launchd" }
    };

    const auto findings = whytho::analyze( p );

    ASSERT( has_message_containing( findings, "user login session" ) );
    ASSERT( has_message_containing( findings, "not a registered agent" ) );
}

TEST( interactive_shell_launch )
{
    whytho::ProcessInfo p;
    p.pid      = 500;
    p.ppid     = 450;
    p.uid      = 501;
    p.exe_path = "/usr/local/bin/mytool";
    p.ancestry = {
        { 450, "/bin/zsh" },
        { 400, "/Applications/iTerm.app/Contents/MacOS/iTerm2" },
        { 1,   "/sbin/launchd" }
    };

    const auto findings = whytho::analyze( p );

    ASSERT( has_message_containing( findings, "interactive shell" ) );
    ASSERT( has_message_containing( findings, "zsh" ) );
}

TEST( app_child_subprocess )
{
    whytho::ProcessInfo p;
    p.pid      = 600;
    p.ppid     = 550;
    p.uid      = 501;
    p.exe_path = "/Applications/MyApp.app/Contents/Helpers/helper";
    p.ancestry = {
        { 550, "/Applications/MyApp.app/Contents/MacOS/MyApp" },
        { 1,   "/sbin/launchd" }
    };

    const auto findings = whytho::analyze( p );

    ASSERT( has_message_containing( findings, "Subprocess of application bundle" ) );
    ASSERT( has_message_containing( findings, "MyApp" ) );
}

TEST( unknown_no_launchd_ancestry )
{
    whytho::ProcessInfo p;
    p.pid      = 700;
    p.ppid     = 650;
    p.uid      = 501;
    p.exe_path = "/usr/bin/orphan";
    p.ancestry = {
        { 650, "/usr/bin/some-parent" }
    };

    const auto findings = whytho::analyze( p );

    ASSERT( has_message_containing( findings, "could not be classified" ) );
    ASSERT( has_message_containing( findings, "no launchd ancestry" ) );
    ASSERT( count_severity( findings, whytho::Severity::Low ) >= 1 );
}

TEST( exec_path_deleted_binary )
{
    whytho::ProcessInfo p;
    p.pid      = 800;
    p.ppid     = 1;
    p.uid      = 501;
    p.exe_path = "/tmp/malware (deleted)";
    p.ancestry = { { 1, "/sbin/launchd" } };

    const auto findings = whytho::analyze( p );

    ASSERT( count_severity( findings, whytho::Severity::High ) >= 1 );
    ASSERT( has_message_containing( findings, "deleted from disk" ) );
    ASSERT( has_message_containing( findings, "common malware technique" ) );
}

TEST( exec_path_tmp_directory )
{
    whytho::ProcessInfo p;
    p.pid      = 900;
    p.ppid     = 1;
    p.uid      = 501;
    p.exe_path = "/tmp/evil.sh";
    p.ancestry = { { 1, "/sbin/launchd" } };

    const auto findings = whytho::analyze( p );

    ASSERT( count_severity( findings, whytho::Severity::High ) >= 1 );
    ASSERT( has_message_containing( findings, "temporary directory" ) );
    ASSERT( has_message_containing( findings, "strong malware indicator" ) );
}

TEST( exec_path_var_tmp )
{
    whytho::ProcessInfo p;
    p.pid      = 1000;
    p.ppid     = 1;
    p.uid      = 501;
    p.exe_path = "/var/tmp/sketchy";
    p.ancestry = { { 1, "/sbin/launchd" } };

    const auto findings = whytho::analyze( p );

    ASSERT( count_severity( findings, whytho::Severity::High ) >= 1 );
    ASSERT( has_message_containing( findings, "temporary directory" ) );
}

TEST( exec_path_hidden_component )
{
    whytho::ProcessInfo p;
    p.pid      = 1100;
    p.ppid     = 1;
    p.uid      = 501;
    p.exe_path = "/Users/alice/.hidden/tool";
    p.ancestry = { { 1, "/sbin/launchd" } };

    const auto findings = whytho::analyze( p );

    ASSERT( count_severity( findings, whytho::Severity::Medium ) >= 1 );
    ASSERT( has_message_containing( findings, "hidden component" ) );
    ASSERT( has_message_containing( findings, "dotfile" ) );
}

TEST( exec_path_user_home_outside_standard_dirs )
{
    whytho::ProcessInfo p;
    p.pid      = 1200;
    p.ppid     = 1;
    p.uid      = 501;
    p.exe_path = "/Users/bob/Downloads/installer.sh";
    p.ancestry = { { 1, "/sbin/launchd" } };

    const auto findings = whytho::analyze( p );

    ASSERT( count_severity( findings, whytho::Severity::Low ) >= 1 );
    ASSERT( has_message_containing( findings, "user home directory subtree" ) );
    ASSERT( has_message_containing( findings, "outside" ) );
}

TEST( exec_path_user_applications_ok )
{
    whytho::ProcessInfo p;
    p.pid      = 1250;
    p.ppid     = 1;
    p.uid      = 501;
    p.exe_path = "/Users/carol/Applications/MyTool.app/Contents/MacOS/MyTool";
    p.ancestry = { { 1, "/sbin/launchd" } };

    const auto findings = whytho::analyze( p );

    ASSERT( !has_message_containing( findings, "user home directory subtree" ) );
}

TEST( exec_path_trusted_location )
{
    whytho::ProcessInfo p;
    p.pid      = 1300;
    p.ppid     = 1;
    p.uid      = 0;
    p.exe_path = "/usr/bin/some-tool";
    p.ancestry = { { 1, "/sbin/launchd" } };

    const auto findings = whytho::analyze( p );

    ASSERT( has_message_containing( findings, "standard trusted location" ) );
    ASSERT( has_category( findings, "exec-path" ) );
}

TEST( exec_path_homebrew_intel )
{
    whytho::ProcessInfo p;
    p.pid      = 1400;
    p.ppid     = 1;
    p.uid      = 501;
    p.exe_path = "/usr/local/bin/fish";
    p.ancestry = { { 1, "/sbin/launchd" } };

    const auto findings = whytho::analyze( p );

    ASSERT( has_message_containing( findings, "standard trusted location" ) );
}

TEST( exec_path_homebrew_apple_silicon )
{
    whytho::ProcessInfo p;
    p.pid      = 1500;
    p.ppid     = 1;
    p.uid      = 501;
    p.exe_path = "/opt/homebrew/bin/zsh";
    p.ancestry = { { 1, "/sbin/launchd" } };

    const auto findings = whytho::analyze( p );

    ASSERT( has_message_containing( findings, "standard trusted location" ) );
}

TEST( exec_path_non_standard_but_benign )
{
    whytho::ProcessInfo p;
    p.pid      = 1600;
    p.ppid     = 1;
    p.uid      = 501;
    p.exe_path = "/opt/custom/bin/mytool";
    p.ancestry = { { 1, "/sbin/launchd" } };

    const auto findings = whytho::analyze( p );

    ASSERT( count_severity( findings, whytho::Severity::Low ) >= 1 );
    ASSERT( has_message_containing( findings, "not in a standard system" ) );
    ASSERT( has_message_containing( findings, "Verify you recognise" ) );
}

TEST( exec_path_empty )
{
    whytho::ProcessInfo p;
    p.pid      = 1700;
    p.ppid     = 1;
    p.uid      = 501;
    p.exe_path = "";
    p.ancestry = { { 1, "/sbin/launchd" } };

    const auto findings = whytho::analyze( p );

    ASSERT( count_severity( findings, whytho::Severity::Medium ) >= 1 );
    ASSERT( has_message_containing( findings, "Executable path is empty" ) );
}

TEST( code_sign_not_collected )
{
    whytho::ProcessInfo p;
    p.pid      = 1800;
    p.ppid     = 1;
    p.uid      = 501;
    p.exe_path = "/usr/bin/tool";
    p.ancestry = { { 1, "/sbin/launchd" } };

    const auto findings = whytho::analyze( p );

    ASSERT( has_message_containing( findings, "Code-signing information was not collected" ) );
    ASSERT( count_severity( findings, whytho::Severity::Info ) >= 1 );
}

TEST( code_sign_unsigned )
{
    whytho::ProcessInfo p;
    p.pid      = 1900;
    p.ppid     = 1;
    p.uid      = 501;
    p.exe_path = "/usr/local/bin/unsigned-tool";
    p.ancestry = { { 1, "/sbin/launchd" } };

    whytho::CodeSignInfo cs;
    cs.is_signed = false;
    p.code_sign  = cs;

    const auto findings = whytho::analyze( p );

    ASSERT( count_severity( findings, whytho::Severity::Medium ) >= 1 );
    ASSERT( has_message_containing( findings, "Executable is unsigned" ) );
    ASSERT( has_message_containing( findings, "legitimate software is expected to be signed" ) );
}

TEST( code_sign_invalid_signature )
{
    whytho::ProcessInfo p;
    p.pid      = 2000;
    p.ppid     = 1;
    p.uid      = 501;
    p.exe_path = "/Applications/Tampered.app/Contents/MacOS/Tampered";
    p.ancestry = { { 1, "/sbin/launchd" } };

    whytho::CodeSignInfo cs;
    cs.is_signed = true;
    cs.is_valid  = false;
    p.code_sign  = cs;

    const auto findings = whytho::analyze( p );

    ASSERT( count_severity( findings, whytho::Severity::High ) >= 1 );
    ASSERT( has_message_containing( findings, "does not verify" ) );
    ASSERT( has_message_containing( findings, "tampered with" ) );
}

TEST( code_sign_apple_signed )
{
    whytho::ProcessInfo p;
    p.pid      = 2100;
    p.ppid     = 1;
    p.uid      = 0;
    p.exe_path = "/usr/bin/Safari";
    p.ancestry = { { 1, "/sbin/launchd" } };

    whytho::CodeSignInfo cs;
    cs.is_signed       = true;
    cs.is_valid        = true;
    cs.is_apple_signed = true;
    cs.is_hardened     = true;
    cs.signing_id      = "com.apple.Safari";
    p.code_sign        = cs;

    const auto findings = whytho::analyze( p );

    ASSERT( has_message_containing( findings, "Signed by Apple" ) );
    ASSERT( has_message_containing( findings, "com.apple.Safari" ) );
    const auto* high = find_first_severity( findings, whytho::Severity::High );
    if ( high ) {
        ASSERT( high->category != "code-sign" );
    }
}

TEST( code_sign_third_party_valid )
{
    whytho::ProcessInfo p;
    p.pid      = 2200;
    p.ppid     = 1;
    p.uid      = 501;
    p.exe_path = "/Applications/MyApp.app/Contents/MacOS/MyApp";
    p.ancestry = { { 1, "/sbin/launchd" } };

    whytho::CodeSignInfo cs;
    cs.is_signed       = true;
    cs.is_valid        = true;
    cs.is_apple_signed = false;
    cs.is_hardened     = true;
    cs.is_notarized    = true;
    cs.team_id         = "ABC123XYZ";
    cs.signing_id      = "com.example.MyApp";
    p.code_sign        = cs;

    const auto findings = whytho::analyze( p );

    ASSERT( has_message_containing( findings, "Valid third-party signature" ) );
    ASSERT( has_message_containing( findings, "ABC123XYZ" ) );
    ASSERT( has_message_containing( findings, "com.example.MyApp" ) );
}

TEST( code_sign_not_hardened )
{
    whytho::ProcessInfo p;
    p.pid      = 2300;
    p.ppid     = 1;
    p.uid      = 501;
    p.exe_path = "/Applications/OldApp.app/Contents/MacOS/OldApp";
    p.ancestry = { { 1, "/sbin/launchd" } };

    whytho::CodeSignInfo cs;
    cs.is_signed       = true;
    cs.is_valid        = true;
    cs.is_apple_signed = false;
    cs.is_hardened     = false;
    cs.is_notarized    = false;
    cs.team_id         = "XYZ789ABC";
    p.code_sign        = cs;

    const auto findings = whytho::analyze( p );

    ASSERT( count_severity( findings, whytho::Severity::Low ) >= 1 );
    ASSERT( has_message_containing( findings, "Hardened runtime is not enabled" ) );
    ASSERT( has_message_containing( findings, "code-injection attacks" ) );
}

TEST( code_sign_not_notarized )
{
    whytho::ProcessInfo p;
    p.pid      = 2400;
    p.ppid     = 1;
    p.uid      = 501;
    p.exe_path = "/Applications/Unnotarized.app/Contents/MacOS/Unnotarized";
    p.ancestry = { { 1, "/sbin/launchd" } };

    whytho::CodeSignInfo cs;
    cs.is_signed       = true;
    cs.is_valid        = true;
    cs.is_apple_signed = false;
    cs.is_hardened     = true;
    cs.is_notarized    = false;
    cs.team_id         = "DEF456GHI";
    p.code_sign        = cs;

    const auto findings = whytho::analyze( p );

    ASSERT( count_severity( findings, whytho::Severity::Low ) >= 1 );
    ASSERT( has_message_containing( findings, "not been notarized" ) );
    ASSERT( has_message_containing( findings, "Gatekeeper will block" ) );
}

TEST( findings_sorted_by_severity )
{
    whytho::ProcessInfo p;
    p.pid      = 2500;
    p.ppid     = 1;
    p.uid      = 501;
    p.exe_path = "/tmp/evil (deleted)";
    p.ancestry = { { 1, "/sbin/launchd" } };

    whytho::CodeSignInfo cs;
    cs.is_signed       = true;
    cs.is_valid        = false;
    p.code_sign        = cs;

    const auto findings = whytho::analyze( p );

    ASSERT( count_severity( findings, whytho::Severity::High ) >= 2 );

    ASSERT( !findings.empty() );
    ASSERT_EQ( findings[0].severity, whytho::Severity::High );

    bool seen_non_high = false;
    for ( const auto& f : findings )
    {
        if ( f.severity != whytho::Severity::High )
            seen_non_high = true;
        else if ( seen_non_high )
            throw std::runtime_error( "High-severity finding found after non-High finding" );
    }
}

TEST( shell_detection_fish )
{
    whytho::ProcessInfo p;
    p.pid      = 2600;
    p.ppid     = 2550;
    p.uid      = 501;
    p.exe_path = "/usr/local/bin/mytool";
    p.ancestry = {
        { 2550, "/usr/local/bin/fish" },
        { 1,    "/sbin/launchd" }
    };

    const auto findings = whytho::analyze( p );

    ASSERT( has_message_containing( findings, "interactive shell" ) );
    ASSERT( has_message_containing( findings, "fish" ) );
}

TEST( shell_detection_homebrew_apple_silicon_zsh )
{
    whytho::ProcessInfo p;
    p.pid      = 2700;
    p.ppid     = 2650;
    p.uid      = 501;
    p.exe_path = "/usr/bin/tool";
    p.ancestry = {
        { 2650, "/opt/homebrew/bin/zsh" },
        { 1,    "/sbin/launchd" }
    };

    const auto findings = whytho::analyze( p );

    ASSERT( has_message_containing( findings, "interactive shell" ) );
    ASSERT( has_message_containing( findings, "zsh" ) );
}

TEST( shell_detection_ksh )
{
    whytho::ProcessInfo p;
    p.pid      = 2800;
    p.ppid     = 2750;
    p.uid      = 501;
    p.exe_path = "/usr/bin/script";
    p.ancestry = {
        { 2750, "/bin/ksh" },
        { 1,    "/sbin/launchd" }
    };

    const auto findings = whytho::analyze( p );

    ASSERT( has_message_containing( findings, "interactive shell" ) );
    ASSERT( has_message_containing( findings, "ksh" ) );
}

TEST( lineage_includes_pids )
{
    whytho::ProcessInfo p;
    p.pid      = 2900;
    p.ppid     = 100;
    p.uid      = 501;
    p.exe_path = "/usr/bin/child";
    p.ancestry = {
        { 100, "/usr/bin/parent" },
        { 1,   "/sbin/launchd" }
    };

    const auto findings = whytho::analyze( p );

    ASSERT( has_message_containing( findings, "launchd[1]" ) );
    ASSERT( has_message_containing( findings, "parent[100]" ) );
}

TEST( lineage_empty_ancestry )
{
    whytho::ProcessInfo p;
    p.pid      = 3000;
    p.ppid     = 0;
    p.uid      = 501;
    p.exe_path = "/usr/bin/orphan";
    p.ancestry = {};

    const auto findings = whytho::analyze( p );

    ASSERT( has_message_containing( findings, "no ancestry available" ) );
}

TEST( multiple_high_severity_issues )
{
    whytho::ProcessInfo p;
    p.pid      = 3100;
    p.ppid     = 1;
    p.uid      = 501;
    p.exe_path = "/tmp/.hidden/evil (deleted)";
    p.ancestry = { { 1, "/sbin/launchd" } };

    whytho::CodeSignInfo cs;
    cs.is_signed = true;
    cs.is_valid  = false;
    p.code_sign  = cs;

    const auto findings = whytho::analyze( p );

    ASSERT( count_severity( findings, whytho::Severity::High ) >= 3 );
}

TEST( all_findings_have_category )
{
    whytho::ProcessInfo p;
    p.pid      = 3200;
    p.ppid     = 1;
    p.uid      = 501;
    p.exe_path = "/usr/bin/tool";
    p.ancestry = { { 1, "/sbin/launchd" } };

    whytho::CodeSignInfo cs;
    cs.is_signed = true;
    cs.is_valid  = true;
    p.code_sign  = cs;

    const auto findings = whytho::analyze( p );

    for ( const auto& f : findings )
    {
        ASSERT( !f.category.empty() );
    }
}

TEST( categories_are_distinct )
{
    whytho::ProcessInfo p;
    p.pid      = 3300;
    p.ppid     = 1;
    p.uid      = 501;
    p.exe_path = "/usr/bin/tool";
    p.ancestry = { { 1, "/sbin/launchd" } };

    whytho::CodeSignInfo cs;
    cs.is_signed = true;
    cs.is_valid  = true;
    p.code_sign  = cs;

    const auto findings = whytho::analyze( p );

    ASSERT( has_category( findings, "origin" ) );
    ASSERT( has_category( findings, "exec-path" ) );
    ASSERT( has_category( findings, "code-sign" ) );
    ASSERT( has_category( findings, "lineage" ) );
}

int main()
{
    std::cout << "\n=============================================================\n";
    std::cout << "  whytho::analyzer test suite\n";
    std::cout << "=============================================================\n\n";

    std::cout << "\n=============================================================\n";
    std::cout << "  Summary\n";
    std::cout << "=============================================================\n";
    std::cout << "  Tests run:    " << g_tests_run << "\n";
    std::cout << "  Tests passed: " << g_tests_passed << "\n";
    std::cout << "  Tests failed: " << g_tests_failed << "\n";

    if ( g_tests_failed == 0 )
    {
        std::cout << "\n  ✓ All tests passed!\n" << std::endl;
        return 0;
    }
    else
    {
        std::cout << "\n  ✗ Some tests failed.\n" << std::endl;
        return 1;
    }
}