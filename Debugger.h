#pragma once

#define NOMINMAX
#include <windows.h>
#include <DbgHelp.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <iostream>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>


#include "spdlog/async.h"
#include "spdlog/sinks/basic_file_sink.h"
#include "spdlog/spdlog.h"


enum BreakpointType {
  FREQ,  // Re-arm after every hit (frequency tracking)
  SINGLE // Remove after first hit
};

struct Breakpoint {
  size_t offset;
  BYTE original_byte;
  BOOL enabled;
  BreakpointType type;
  DWORD hit_count;
  std::string module_name;
  std::string function_name;
  size_t function_offset;
  std::pair<size_t, size_t> address_range;
};

class Debugger {
public:
  static Debugger *attach(DWORD pid, std::string outdir = "");
  static void detach(Debugger *dbg);
  void init_thread_coverage_logger();

  // Format: module_name!function_name+0xfunction_offset
  void register_breakpoints_to_suspend_on_breakpoint(
      const std::string &breakpoint_name);

  bool load_breakpoints_from_file(const std::string &filepath);
  void stop();
  void run();
  void set_out_directory(const std::string &outdir) {
    this->out_directory = outdir;
    CreateDirectoryA(outdir.c_str(), NULL);
  }
  void set_on_initial_breakpoint_cb(std::function<void()> cb) {
    this->on_initial_breakpoint_cb = cb;
  }
  bool has_process_exited() const { return process_exited_.load(); }

private:
  DWORD pid_;
  BOOL hit_initial_breakpoint = FALSE;
  HANDLE process_handle = nullptr;
  std::unordered_map<DWORD, HANDLE> thread_handles;
  // Module name -> base address
  std::unordered_map<std::string, LPVOID> modules;
  BOOL stop_requested = FALSE;
  std::atomic<bool> process_exited_{false};
  // Pending breakpoints keyed by module name, applied when the module loads
  std::unordered_map<std::string, std::vector<Breakpoint>> target_breakpoints;
  // Min/max breakpoint offset per module for batch memory operations
  std::unordered_map<std::string, std::pair<size_t, size_t>> minmax_breakpoint;
  LARGE_INTEGER performance_frequency_;
  // Active breakpoints keyed by absolute address in target process
  std::unordered_map<LPVOID, Breakpoint> breakpoints;
  // TIDs actively single-stepping, mapped to the address they stepped from
  std::unordered_map<DWORD, LPVOID> single_step_tids;

  std::string out_directory;

  // Coverage data: addr -> (module, offset, symbol+offset, frequency)
  std::unordered_map<LPVOID,
                     std::tuple<std::string, size_t, std::string, DWORD>>
      coverage_data;

  std::shared_ptr<spdlog::logger> coverage_logger_;

  // Periodic coverage flush tracking
  std::chrono::steady_clock::time_point last_coverage_flush_;

  bool suspend_target_thread(DWORD thread_id);
  bool resume_target_thread(DWORD thread_id);
  std::vector<std::string> breakpoints_to_suspend_when_hit;

  std::function<void()> on_initial_breakpoint_cb = nullptr;

  void save_binja_coverage_data_to_file();
  void save_coverage_data_to_file();
  void save_coverage_data();

  Debugger(DWORD pid, std::string outdir);
  ~Debugger();
  static Debugger *attach_internal(DWORD pid, std::string outdir);

  // Verify the target process matches our bitness (both 32- or both 64-bit)
  static bool check_bitness(DWORD pid);

  void create_minidump(const DEBUG_EVENT &debug_event);

  DWORD handle_exception_debug_event(const DEBUG_EVENT &debug_event);
  void handle_breakpoint_exception(const DEBUG_EVENT &debug_event);
  void handle_single_step(const DEBUG_EVENT &debug_event);
  void handle_access_violation(const DEBUG_EVENT &debug_event);
  void handle_create_process_event(const DEBUG_EVENT &debug_event);
  DWORD handle_load_dll_event(const DEBUG_EVENT &debug_event);
  void handle_unload_dll_event(const DEBUG_EVENT &debug_event);

  std::string filename_from_module_base(LPVOID base);
  void register_module(LPVOID base);
  void unregister_module(LPVOID base);

  void flush_instruction_caches();

  void register_target_breakpoint(std::string module_name, size_t offset,
                                  BreakpointType type,
                                  std::string function_name,
                                  size_t function_offset,
                                  std::pair<size_t, size_t> address_range);
  // Read the full breakpoint region from memory, patch all INT3s in one bulk
  // write (like Mesos). Much faster than per-breakpoint syscalls.
  bool enable_breakpoints(LPVOID base);
  // Restore all original bytes in bulk, then clear the breakpoints map
  void remove_all_breakpoints();
};
