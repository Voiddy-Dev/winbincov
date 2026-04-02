#include <iostream>
#include <Windows.h>
#include "Debugger.h"
#include <atomic>
#include <chrono>
#include <string>
#include <thread>

#include "spdlog/spdlog.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "spdlog/sinks/stdout_color_sinks.h"

static Debugger *g_dbg = nullptr;
static std::atomic<bool> g_is_exiting = false;

BOOL WINAPI CtrlHandler(DWORD dwCtrlType)
{
    switch (dwCtrlType)
    {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
        std::cout << "\n[INFO] CTRL-C detected. Requesting debugger stop...\n";
        if (g_dbg && !g_is_exiting.exchange(true))
        {
            // Signal the run loop to exit. With the timed WaitForDebugEvent
            // the loop will pick this up within ~100ms and clean up normally.
            g_dbg->stop();
        }
        return TRUE;
    }
    return FALSE;
}

void exit_with_usage(const char *progname)
{
    std::cout << "Usage: " << progname << " --breakpoints <path> --out-dir <path> --pid <pid> \n";
    exit(1);
}

int main(int argc, char **argv)
{
    if (!SetConsoleCtrlHandler(CtrlHandler, TRUE))
    {
        std::cout << "[ERROR] Could not set control handler.\n";
        return 1;
    }

    DWORD pid = 0;
    std::string breakpoints_file;
    std::string outdir;

    // Argument parsing
    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];
        if (arg == "--pid")
        {
            if (i + 1 < argc)
            {
                try
                {
                    pid = std::stoi(argv[++i]);
                }
                catch (const std::exception &e)
                {
                    std::cout << "[ERROR] Invalid PID provided: " << e.what() << "\n";
                    return 1;
                }
            }
            else
            {
                std::cout << "[ERROR] --pid argument provided but no PID specified.\n";
                return 1;
            }
        }
        else if (arg == "--breakpoints")
        {
            if (i + 1 < argc)
            {
                breakpoints_file = argv[++i];
            }
            else
            {
                std::cout << "[ERROR] --breakpoints argument provided but no file path specified.\n";
                return 1;
            }
        }
        else if (arg == "--out-dir")
        {
            if (i + 1 < argc)
            {
                outdir = argv[++i];
            }
            else
            {
                std::cout << "[ERROR] --out-dir argument provided but no directory specified.\n";
                return 1;
            }
        }
        else
        {
            exit_with_usage(argv[0]);
        }
    }
    if (pid == 0 || breakpoints_file.empty() || outdir.empty())
    {
        exit_with_usage(argv[0]);
    }

    std::string log_file_path = outdir + "\\log.txt";

    // Initialize logger
    try
    {
        // 1. Create the Console Sink (Color)
        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        // Pattern with colors: %^ starts color, %$ ends color
        console_sink->set_pattern("[%H:%M:%S] [%^%l%$] %v");

        // 2. Create the File Sink
        auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(log_file_path, true);
        file_sink->set_pattern("[%H:%M:%S] [%l] %v");

        // 3. Create a logger that contains BOTH sinks
        std::vector<spdlog::sink_ptr> sinks{console_sink, file_sink};
        auto combined_logger = std::make_shared<spdlog::logger>("multi_sink", sinks.begin(), sinks.end());

        // 4. Configure global settings
        combined_logger->flush_on(spdlog::level::info);

        // 5. Set as default
        spdlog::set_default_logger(combined_logger);

        spdlog::info("Logger initialized. Outputting to Console and {}", log_file_path);
    }
    catch (const spdlog::spdlog_ex &ex)
    {
        std::cout << "Log initialization failed: " << ex.what() << std::endl;
    }
    g_dbg = Debugger::attach(pid, outdir);
    if (g_dbg)
    {
        g_dbg->load_breakpoints_from_file(breakpoints_file);
        g_dbg->run();
        g_is_exiting = true; // Signal that we are exiting normally
    }
    Debugger::detach(g_dbg);
    g_dbg = nullptr;

    return 0;
}
