#include "Debugger.h"
#include <DbgHelp.h>
#include <Psapi.h>
#include <algorithm>
#include <fstream>
#include <shlobj.h>
#include <sstream>
#include <string>
#include <time.h>

#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Psapi.lib")

bool EnableDebugPrivilege()
{
  HANDLE hToken;
  if (!OpenProcessToken(GetCurrentProcess(),
                        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
  {
    return false;
  }

  TOKEN_PRIVILEGES tkp;
  if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid))
  {
    CloseHandle(hToken);
    return false;
  }

  tkp.PrivilegeCount = 1;
  tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

  if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL,
                             (PDWORD)NULL))
  {
    CloseHandle(hToken);
    return false;
  }

  if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
  {
    CloseHandle(hToken);
    return false;
  }

  CloseHandle(hToken);
  return true;
}

void Debugger::init_thread_coverage_logger()
{
  this->coverage_logger_ = spdlog::basic_logger_mt<spdlog::async_factory>(
      "coverage_logger", this->out_directory +
                             (this->out_directory.empty() ? "" : "\\") +
                             "thread_coverage_data.txt");
  this->coverage_logger_->set_pattern("%v");
  this->coverage_logger_->info("timestamp,thread_id,module_name,breakpoint_offset,func_offset_str");
}
void Debugger::register_module(LPVOID base)
{
  std::string dllname = filename_from_module_base(base);
  this->modules[dllname] = base;
  spdlog::info("Registered module: {} at base address: {}", dllname, base);
}

void Debugger::unregister_module(LPVOID base)
{
  std::string dllname = filename_from_module_base(base);
  auto mod_it = this->modules.find(dllname);
  if (mod_it == this->modules.end())
  {
    spdlog::warn("Attempted to unregister unknown module: {}", dllname);
    return;
  }

  // Remove any active breakpoints that belong to this module.
  // Use the min/max range to efficiently identify them by address.
  auto mm_it = this->minmax_breakpoint.find(dllname);
  if (mm_it != this->minmax_breakpoint.end())
  {
    size_t start_addr = (size_t)base + mm_it->second.first;
    size_t end_addr = (size_t)base + mm_it->second.second;

    size_t removed = 0;
    for (auto it = this->breakpoints.begin(); it != this->breakpoints.end();)
    {
      size_t addr = (size_t)it->first;
      if (addr >= start_addr && addr <= end_addr)
      {
        it = this->breakpoints.erase(it);
        removed++;
      }
      else
      {
        ++it;
      }
    }

    if (removed > 0)
    {
      spdlog::info("Evicted {} stale breakpoints for unloaded module {}",
                   removed, dllname);
    }
  }

  this->modules.erase(mod_it);
  spdlog::info("Unregistered module: {}", dllname);
}

std::string Debugger::filename_from_module_base(LPVOID base)
{
  // Fallback for when we only have the base address.
  // Use GetMappedFileNameW which is generally more reliable than
  // EnumProcessModules.
  wchar_t szModName[MAX_PATH];
  if (GetMappedFileNameW(this->process_handle, base, szModName, MAX_PATH) ==
      0)
  {
    // This can fail if the module is being loaded and not yet fully mapped.
    spdlog::warn("GetMappedFileNameW failed for base address: {} Error: {}",
                 base, GetLastError());
    return std::string("[Unknown DLL Module]");
  }

  // We just need the filename at the end.
  std::wstring fullPath(szModName);
  size_t last_slash_idx = fullPath.find_last_of(L"\\/");
  if (std::string::npos != last_slash_idx)
  {
    std::wstring filename = fullPath.substr(last_slash_idx + 1);
    // Safely convert wstring to string
    if (filename.empty())
      return std::string();
    int size_needed = WideCharToMultiByte(
        CP_UTF8, 0, &filename[0], (int)filename.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &filename[0], (int)filename.size(),
                        &strTo[0], size_needed, NULL, NULL);
    return strTo;
  }

  // Also fix the conversion for the warning message
  if (!fullPath.empty())
  {
    int size_needed = WideCharToMultiByte(
        CP_UTF8, 0, &fullPath[0], (int)fullPath.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &fullPath[0], (int)fullPath.size(),
                        &strTo[0], size_needed, NULL, NULL);
    spdlog::warn("Could not extract filename from module path: {}", strTo);
  }
  else
  {
    spdlog::warn("Could not extract filename from empty module path.");
  }
  return std::string("[Unknown DLL Module]");
}

void Debugger::register_target_breakpoint(
    std::string module_name, size_t offset, BreakpointType type,
    std::string function_name, size_t function_offset,
    std::pair<size_t, size_t> address_range)
{
  Breakpoint bp = {};
  bp.offset = offset;
  bp.type = type;
  bp.module_name = module_name;
  bp.function_name = function_name;
  bp.function_offset = function_offset;
  bp.address_range = address_range;
  bp.original_byte = 0x00;
  bp.enabled = FALSE;
  bp.hit_count = 0;

  // Track min/max offset per module for batch memory operations
  auto it = this->minmax_breakpoint.find(module_name);
  if (it == this->minmax_breakpoint.end())
  {
    this->minmax_breakpoint[module_name] = {offset, offset};
  }
  else
  {
    it->second.first = std::min(it->second.first, offset);
    it->second.second = std::max(it->second.second, offset);
  }

  this->target_breakpoints[module_name].push_back(bp);
}

bool Debugger::enable_breakpoints(LPVOID base)
{
  std::string module_name = filename_from_module_base(base);
  auto it = this->target_breakpoints.find(module_name);
  if (it == this->target_breakpoints.end())
  {
    return false;
  }

  auto mm_it = this->minmax_breakpoint.find(module_name);
  if (mm_it == this->minmax_breakpoint.end())
  {
    return false;
  }

  size_t min_off = mm_it->second.first;
  size_t max_off = mm_it->second.second;
  // +1 because max_off is inclusive (the last breakpoint byte itself)
  size_t region_size = (max_off - min_off) + 1;

  // Bulk-read the entire breakpoint region in one syscall
  std::vector<BYTE> contents(region_size);
  SIZE_T bytes_read = 0;
  LPVOID region_start = (LPVOID)((size_t)base + min_off);

  if (!ReadProcessMemory(this->process_handle, region_start,
                         contents.data(), region_size, &bytes_read) ||
      bytes_read == 0)
  {
    spdlog::error("Failed to read breakpoint region for module {} "
                  "(base={}, offset=0x{:X}, size={})",
                  module_name, base, min_off, region_size);
    return false;
  }

  size_t start_count = this->breakpoints.size();

  // Patch all breakpoints into the buffer
  for (auto &bp : it->second)
  {
    size_t buf_offset = bp.offset - min_off;
    if (buf_offset >= bytes_read)
    {
      // Beyond what we could read — skip
      continue;
    }

    LPVOID breakpoint_address = (LPVOID)((size_t)base + bp.offset);

    // Don't overwrite an already-applied breakpoint at the same address
    if (this->breakpoints.count(breakpoint_address))
    {
      continue;
    }

    // Save the original byte and patch in INT 3
    bp.original_byte = contents[buf_offset];
    bp.enabled = TRUE;
    contents[buf_offset] = 0xCC;

    this->breakpoints[breakpoint_address] = bp;
  }

  // Bulk-write all patched breakpoints back in one syscall
  SIZE_T bytes_written = 0;
  WriteProcessMemory(this->process_handle, region_start,
                     contents.data(), bytes_read, &bytes_written);
  flush_instruction_caches();

  size_t applied = this->breakpoints.size() - start_count;
  spdlog::info("Applied {} breakpoints ({} total) for module {}",
               applied, this->breakpoints.size(), module_name);
  return true;
}

void Debugger::remove_all_breakpoints()
{
  if (this->breakpoints.empty())
    return;

  // Batch-restore original bytes per module, matching the Mesos approach:
  // read the full breakpoint region, restore original bytes in the buffer,
  // write it back in one call per module.
  for (const auto &mod : this->modules)
  {
    const std::string &module_name = mod.first;
    LPVOID base = mod.second;

    auto mm_it = this->minmax_breakpoint.find(module_name);
    if (mm_it == this->minmax_breakpoint.end())
      continue;

    size_t min_off = mm_it->second.first;
    size_t max_off = mm_it->second.second;
    size_t region_size = (max_off - min_off) + 1;

    LPVOID region_start = (LPVOID)((size_t)base + min_off);
    std::vector<BYTE> contents(region_size);
    SIZE_T bytes_read = 0;

    if (!ReadProcessMemory(this->process_handle, region_start,
                           contents.data(), region_size, &bytes_read) ||
        bytes_read == 0)
    {
      continue;
    }

    size_t removed = 0;
    for (auto &bp_pair : this->breakpoints)
    {
      Breakpoint &bp = bp_pair.second;
      if (bp.module_name != module_name)
        continue;

      size_t buf_offset = bp.offset - min_off;
      if (buf_offset < bytes_read)
      {
        contents[buf_offset] = bp.original_byte;
        bp.enabled = FALSE;
        removed++;
      }
    }

    if (removed > 0)
    {
      WriteProcessMemory(this->process_handle, region_start,
                         contents.data(), bytes_read, nullptr);
      flush_instruction_caches();
      spdlog::info("Removed {} breakpoints in {}", removed, module_name);
    }
  }

  this->breakpoints.clear();
}

void Debugger::flush_instruction_caches()
{
  FlushInstructionCache(this->process_handle, nullptr, 0);
}

/**
 * @brief Loads breakpoint definitions from a CSV file.
 * @param filepath Path to the CSV file generated by Binary Ninja.
 * @return true if loading was successful, false otherwise.
 */
bool Debugger::load_breakpoints_from_file(const std::string &filepath)
{
  std::ifstream file(filepath);
  if (!file.is_open())
  {
    spdlog::error("Error: Could not open breakpoint file: {}", filepath);
    return false;
  }

  std::string line;
  int line_count = 0;

  // Read and discard the header line
  if (!std::getline(file, line))
  {

    spdlog::error("Breakpoint file is empty.");
    return false;
  }
  line_count++;

  std::string last_module_name;
  size_t loaded_count = 0;

  while (std::getline(file, line))
  {
    line_count++;
    std::stringstream ss(line);
    std::string token;
    std::vector<std::string> tokens;

    // Split the line by Tab instead of comma
    while (std::getline(ss, token, '\t'))
    {
      tokens.push_back(token);
    }

    if (tokens.size() != 7)
    {
      spdlog::warn("Skipping malformed line {}: {}", line_count, line);
      continue;
    }

    try
    {
      std::string module_name = tokens[0];
      // Let's remove the Binary Ninja Database string ending
      std::string suffix = ".bndb";
      if (module_name.size() >= suffix.size() &&
          module_name.compare(module_name.size() - suffix.size(), suffix.size(), suffix) == 0)
      {
        module_name.erase(module_name.size() - suffix.size());
      }

      size_t offset = std::stoull(tokens[1]);
      BreakpointType type = (tokens[2] == "SINGLE") ? SINGLE : FREQ;
      std::string function_name = tokens[3];
      size_t function_offset = std::stoull(tokens[4]);
      size_t range_start = std::stoull(tokens[5]);
      size_t range_end = std::stoull(tokens[6]);

      std::pair<size_t, size_t> address_range = {range_start, range_end};

      this->register_target_breakpoint(module_name, offset, type, function_name,
                                       function_offset, address_range);

      last_module_name = module_name;
      loaded_count++;
    }
    catch (const std::exception &e)
    {
      spdlog::warn("Skipping line {} (parse error): {}", line_count, e.what());
    }
  }

  file.close();
  if (loaded_count > 0)
  {
    spdlog::info("Successfully loaded {} breakpoints for module {}",
                 loaded_count, last_module_name);
  }
  else
  {

    spdlog::warn("No breakpoints were loaded.");
  }
  return true;
}

bool Debugger::check_bitness(DWORD pid)
{
  HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (!hProcess)
  {
    spdlog::error("OpenProcess failed for bitness check. Error: {}",
                  GetLastError());
    return false;
  }

  BOOL target_is_wow64 = FALSE;
  BOOL self_is_wow64 = FALSE;

  if (!IsWow64Process(hProcess, &target_is_wow64))
  {
    spdlog::error("IsWow64Process failed for target. Error: {}", GetLastError());
    CloseHandle(hProcess);
    return false;
  }

  if (!IsWow64Process(GetCurrentProcess(), &self_is_wow64))
  {
    spdlog::error("IsWow64Process failed for self. Error: {}", GetLastError());
    CloseHandle(hProcess);
    return false;
  }

  CloseHandle(hProcess);

  bool self_64 = (self_is_wow64 == FALSE);
  bool target_64 = (target_is_wow64 == FALSE);

  spdlog::info("winbincov is 64-bit: {}", self_64 ? "yes" : "no");
  spdlog::info("Target    is 64-bit: {}", target_64 ? "yes" : "no");

  if (self_64 != target_64)
  {
    spdlog::error("Bitness mismatch: winbincov is {}-bit but target PID {} is {}-bit. "
                  "Use the matching build.",
                  self_64 ? 64 : 32, pid, target_64 ? 64 : 32);
    return false;
  }

  return true;
}

Debugger *Debugger::attach(DWORD pid, std::string outdir)
{
  if (!EnableDebugPrivilege())
  {
    spdlog::error("Failed to enable debug privilege.");
    return nullptr;
  }

  if (!check_bitness(pid))
  {
    return nullptr;
  }

  return attach_internal(pid, outdir);
}

Debugger *Debugger::attach_internal(DWORD pid, std::string outdir)
{
  return new Debugger(pid, outdir);
}

void Debugger::detach(Debugger *dbg) { delete dbg; }

void Debugger::stop()
{
  this->stop_requested = TRUE;
  remove_all_breakpoints();
  save_coverage_data();
  spdlog::info("Stop Requested. Stopping debugger...");
  this->process_exited_.store(true);
}

Debugger::Debugger(DWORD pid, std::string outdir)
{
  this->set_out_directory(outdir);
  this->init_thread_coverage_logger();

  if (DebugActiveProcess(pid))
  {
    this->pid_ = pid;
    QueryPerformanceFrequency(&this->performance_frequency_);
    spdlog::info("Attached to process {} successfully.", pid);
  }
  else
  {
    this->pid_ = 0;
    spdlog::error("DebugActiveProcess failed. Error code: {}", GetLastError());
  }
}

Debugger::~Debugger()
{
  spdlog::info("Cleaning up debugger resources...");

  // Log the final message using the member variable we created in the
  // optimization step
  if (this->coverage_logger_)
  {
    // 1. FORCE FLUSH: Writes all pending data in the queue to the disk
    this->coverage_logger_->flush();
  }

  remove_all_breakpoints();
  save_coverage_data();

  // Shutdown the logger registry. This flushes and closes all loggers.
  // Since we manage the thread pool in main(), we don't call spdlog::shutdown()
  // here.

  spdlog::drop("coverage_logger");
  this->coverage_logger_.reset();

  DebugActiveProcessStop(this->pid_);

  spdlog::info("Debugger detached from process {}.", this->pid_);
}

// Returns true if successful, false if thread not found or API failed
bool Debugger::suspend_target_thread(DWORD thread_id)
{
  auto it = this->thread_handles.find(thread_id);
  if (it == this->thread_handles.end())
  {
    spdlog::error("Attempted to suspend unknown thread ID: {}", thread_id);
    return false;
  }

  HANDLE hThread = it->second;

  // SuspendThread returns the previous suspend count.
  // If it returns (DWORD)-1, an error occurred.
  DWORD suspend_count = SuspendThread(hThread);

  if (suspend_count == (DWORD)-1)
  {
    spdlog::error("SuspendThread failed for TID {}. Error: {}", thread_id,
                  GetLastError());
    return false;
  }

  spdlog::info(
      "Successfully suspended Thread ID: {}. Previous suspend count: {}",
      thread_id, suspend_count);
  return true;
}

// Returns true if successful
bool Debugger::resume_target_thread(DWORD thread_id)
{
  auto it = this->thread_handles.find(thread_id);
  if (it == this->thread_handles.end())
  {
    spdlog::error("Attempted to resume unknown thread ID: {}", thread_id);
    return false;
  }

  HANDLE hThread = it->second;

  // ResumeThread decrements the suspend count.
  // The thread executes only when the count is 0.
  DWORD suspend_count = ResumeThread(hThread);

  if (suspend_count == (DWORD)-1)
  {
    spdlog::error("ResumeThread failed for TID {}. Error: {}", thread_id,
                  GetLastError());
    return false;
  }

  spdlog::info("Successfully resumed Thread ID: {}. Previous suspend count: {}",
               thread_id, suspend_count);
  return true;
}

void Debugger::create_minidump(const DEBUG_EVENT &debug_event)
{
  // Get thread context
  CONTEXT context = {};
  context.ContextFlags = CONTEXT_FULL;
  HANDLE hThread = this->thread_handles[debug_event.dwThreadId];
  if (!GetThreadContext(hThread, &context))
  {
    spdlog::error("GetThreadContext failed. Error: 0x{:X}", GetLastError());
  }

  EXCEPTION_POINTERS exception_pointers = {};
  exception_pointers.ExceptionRecord =
      const_cast<PEXCEPTION_RECORD>(&debug_event.u.Exception.ExceptionRecord);
  exception_pointers.ContextRecord = &context;

  MINIDUMP_EXCEPTION_INFORMATION minidump_exception = {};
  minidump_exception.ThreadId = debug_event.dwThreadId;
  minidump_exception.ExceptionPointers = &exception_pointers;
  minidump_exception.ClientPointers = FALSE;

  // Generate a filename with a timestamp
  char base_filename[MAX_PATH];
  time_t now = time(NULL);
  struct tm tmBuf = {};
  if (localtime_s(&tmBuf, &now) != 0)
  {
    // fallback to zeroed tmBuf on failure
  }
  sprintf_s(base_filename, MAX_PATH,
            "minidump_%lu.%04d%02d%02d_%02d%02d%02d.dmp", this->pid_,
            tmBuf.tm_year + 1900, tmBuf.tm_mon + 1, tmBuf.tm_mday,
            tmBuf.tm_hour, tmBuf.tm_min, tmBuf.tm_sec);

  std::string full_path_str = this->out_directory.empty()
                                  ? base_filename
                                  : this->out_directory + "\\" + base_filename;

  HANDLE hFile = CreateFileA(full_path_str.c_str(), GENERIC_WRITE, 0, NULL,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hFile == INVALID_HANDLE_VALUE)
  {
    spdlog::error("Could not create minidump file. Error: 0x{:X}",
                  GetLastError());
    return;
  }
  spdlog::info("Writing minidump for process {} to {}", this->pid_,
               full_path_str);

  MINIDUMP_TYPE dump_type =
      (MINIDUMP_TYPE)(MiniDumpWithFullMemory | MiniDumpWithHandleData);

  BOOL success = MiniDumpWriteDump(this->process_handle, this->pid_, hFile,
                                   dump_type, &minidump_exception, NULL, NULL);

  if (!success)
  {
    DWORD dwErr = GetLastError();
    if (dwErr == ERROR_PARTIAL_COPY)
    {
      std::wcout << L"[WARNING] Minidump was only partially written, but "
                    L"should still be usable.\n";
      spdlog::warn(
          "Minidump was only partially written, but should still be usable.");
    }
    else
    {
      spdlog::error("MiniDumpWriteDump failed. Error: 0x{:X}", dwErr);
    }

    LPVOID lpMsgBuf;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                       FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL, dwErr, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                   (LPSTR)&lpMsgBuf, 0, NULL);
    if (lpMsgBuf)
    {

      spdlog::error("{}", (LPCSTR)lpMsgBuf);
      LocalFree(lpMsgBuf);
    }
  }
  CloseHandle(hFile);
}

void Debugger::register_breakpoints_to_suspend_on_breakpoint(
    const std::string &breakpoint_name)
{
  this->breakpoints_to_suspend_when_hit.push_back(breakpoint_name);
  spdlog::info("Registered breakpoint to suspend on hit: {}", breakpoint_name);
}

void Debugger::save_binja_coverage_data_to_file()
{
  std::string filename = "binja_coverage_data.txt";
  std::string path = this->out_directory.empty()
                         ? filename
                         : this->out_directory + "\\" + filename;

  std::ofstream file(path);
  if (!file.is_open())
  {
    spdlog::warn("Failed to open binja coverage file at: {}. Attempting to save "
                 "in current directory.",
                 path);
    file.open(filename);
    if (!file.is_open())
    {
      spdlog::error("Failed to open binja coverage file in current directory. Cannot save.");
      return;
    }
    path = filename;
  }
  for (const auto &entry : this->coverage_data)
  {
    std::string module_name = std::get<0>(entry.second);
    size_t offset = std::get<1>(entry.second);
    file << module_name << "+" << std::hex << offset << "\n";
  }
  file.close();
  spdlog::info("Binja coverage data saved to {}", path);
}

void Debugger::save_coverage_data_to_file()
{
  std::string filename = "coverage_data.txt";
  std::string path = this->out_directory.empty()
                         ? filename
                         : this->out_directory + "\\" + filename;

  std::ofstream file(path);
  if (!file.is_open())
  {
    spdlog::warn("Failed to open coverage file at: {}. Attempting to save "
                 "in current directory.",
                 path);
    file.open(filename);
    if (!file.is_open())
    {
      spdlog::error("Failed to open coverage file in current directory. Cannot save.");
      return;
    }
    path = filename;
  }
  for (const auto &entry : this->coverage_data)
  {
    std::string module_name = std::get<0>(entry.second);
    std::string func_offset = std::get<2>(entry.second);
    DWORD hit_count = std::get<3>(entry.second);
    file << module_name << "!" << func_offset << "\t" << hit_count << "\n";
  }
  file.close();
  spdlog::info("Coverage data saved to {}", path);
}

void Debugger::save_coverage_data()
{
  save_binja_coverage_data_to_file();
  save_coverage_data_to_file();
}

void Debugger::handle_breakpoint_exception(const DEBUG_EVENT &debug_event)
{
  DWORD thread_id = debug_event.dwThreadId;
  HANDLE hThread = this->thread_handles[thread_id];

  PVOID exception_addr =
      debug_event.u.Exception.ExceptionRecord.ExceptionAddress;
  auto it = this->breakpoints.find(exception_addr);
  if (it == this->breakpoints.end())
  {
    spdlog::warn("Breakpoint hit at unknown address: {}", exception_addr);
    return;
  }

  Breakpoint &bp = it->second;
  bp.hit_count++;

  // function offset = function_name+0xfunction_offset
  std::stringstream func_offset;
  func_offset << bp.function_name << "+0x" << std::hex << bp.function_offset;
  std::string func_offset_str = func_offset.str();

  // Update coverage data
  coverage_data[exception_addr] =
      std::make_tuple(bp.module_name, bp.offset, func_offset_str, bp.hit_count);

  LARGE_INTEGER timestamp;
  QueryPerformanceCounter(&timestamp);

  // Get the logger
  this->coverage_logger_->info("{:x},{:x},{},{:x},{}",
                               timestamp.QuadPart, thread_id, bp.module_name, bp.offset,
                               func_offset_str);

  // Restore original byte
  SIZE_T bytes_written;
  DWORD oldProtect;
  VirtualProtectEx(this->process_handle, exception_addr, sizeof(BYTE),
                   PAGE_EXECUTE_READWRITE, &oldProtect);

  if (!WriteProcessMemory(this->process_handle, exception_addr,
                          &bp.original_byte, sizeof(BYTE), &bytes_written) ||
      bytes_written != sizeof(BYTE))
  {
    spdlog::error("Failed to restore original byte at breakpoint address: {}",
                  exception_addr);
    if (oldProtect != 0)
      VirtualProtectEx(this->process_handle, exception_addr, sizeof(BYTE),
                       oldProtect, &oldProtect);
    return;
  }
  if (oldProtect != 0)
    VirtualProtectEx(this->process_handle, exception_addr, sizeof(BYTE),
                     oldProtect, &oldProtect);
  flush_instruction_caches();

  CONTEXT context = {};
  context.ContextFlags = CONTEXT_FULL;
  if (!GetThreadContext(hThread, &context))
  {
    spdlog::error(
        "GetThreadContext failed in breakpoint handler. Error: 0x{:X}",
        GetLastError());
    return;
  }

  // Adjust EIP/RIP to re-execute the instruction
#ifdef _M_X64
  context.Rip = (DWORD64)exception_addr;
#else
  context.Eip = (DWORD)(size_t)exception_addr;
#endif

  // If it's a SINGLE breakpoint, disable it
  if (bp.type == SINGLE)
  {
    bp.enabled = FALSE;
    this->breakpoints.erase(exception_addr);
    spdlog::info("SINGLE breakpoint at {} disabled after hit.", exception_addr);
  }
  else // FREQ breakpoint, re-set the breakpoint after resuming
  {
    // Set the trap flag
    context.EFlags |= 1 << 8; // TF is the 8th bit in EFlags
    this->single_step_tids[thread_id] = exception_addr;
  }

  if (!SetThreadContext(hThread, &context))
  {
    spdlog::error(
        "SetThreadContext failed in breakpoint handler. Error: 0x{:X}",
        GetLastError());
  }
}

void Debugger::handle_single_step(const DEBUG_EVENT &debug_event)
{
  DWORD thread_id = debug_event.dwThreadId;
  HANDLE hThread = this->thread_handles[thread_id];

  auto it = this->single_step_tids.find(thread_id);
  if (it == this->single_step_tids.end())
  {
    spdlog::warn("Single step event for unknown thread ID: {}", thread_id);
    return;
  }

  // Get Context
  CONTEXT context = {};
  context.ContextFlags = CONTEXT_FULL;
  if (!GetThreadContext(hThread, &context))
  {
    spdlog::error(
        "GetThreadContext failed in single step handler. Error: 0x{:X}",
        GetLastError());
    return;
  }
  // Reset the trap flag
  context.EFlags &= ~(1 << 8); // Clear TF
  if (!SetThreadContext(hThread, &context))
  {
    spdlog::error(
        "SetThreadContext failed in single step handler. Error: 0x{:X}",
        GetLastError());
    return;
  }

  // Write the INT 3 back to the original address
  LPVOID breakpoint_address = it->second;
  SIZE_T bytes_written;
  BYTE int3 = 0xCC;

  DWORD oldProtect;
  VirtualProtectEx(this->process_handle, breakpoint_address, sizeof(BYTE),
                   PAGE_EXECUTE_READWRITE, &oldProtect);

  if (!WriteProcessMemory(this->process_handle, breakpoint_address, &int3,
                          sizeof(BYTE), &bytes_written) ||
      bytes_written != sizeof(BYTE))
  {
    spdlog::error("Failed to re-set breakpoint at address: {}",
                  breakpoint_address);
    if (oldProtect != 0)
      VirtualProtectEx(this->process_handle, breakpoint_address, sizeof(BYTE),
                       oldProtect, &oldProtect);
    return;
  }
  if (oldProtect != 0)
    VirtualProtectEx(this->process_handle, breakpoint_address, sizeof(BYTE),
                     oldProtect, &oldProtect);
  flush_instruction_caches();

  // remove from single step tracking
  this->single_step_tids.erase(thread_id);
}

void Debugger::handle_access_violation(const DEBUG_EVENT &debug_event)
{
  PVOID exception_addr =
      debug_event.u.Exception.ExceptionRecord.ExceptionAddress;

  auto it = this->breakpoints.find(exception_addr);
  if (it == this->breakpoints.end())
  {
    spdlog::warn("Access violation hit at unknown address: {}", exception_addr);
  }
  else
  {
    Breakpoint &bp = it->second;
    bp.hit_count++;

    std::stringstream func_offset;
    func_offset << bp.function_name << "+0x" << std::hex << bp.function_offset;
    std::string func_offset_str = func_offset.str();

    spdlog::warn("Access violation at breakpoint {}!{} (0x{:X})",
                 bp.module_name, func_offset_str, bp.offset);
  }

  save_coverage_data();

  remove_all_breakpoints();
  create_minidump(debug_event);

  this->stop();
}

DWORD Debugger::handle_exception_debug_event(const DEBUG_EVENT &debug_event)
{
  const EXCEPTION_DEBUG_INFO &exception_info = debug_event.u.Exception;
  DWORD exception_code = exception_info.ExceptionRecord.ExceptionCode;

  switch (exception_code)
  {
  case EXCEPTION_BREAKPOINT:
    if (!this->hit_initial_breakpoint)
    {
      this->hit_initial_breakpoint = TRUE;
      spdlog::info("Initial breakpoint hit.");
      if (this->on_initial_breakpoint_cb)
      {
        this->on_initial_breakpoint_cb();
        spdlog::info("`on_initial_breakpoint_cb` function executed.");
      }
      return DBG_CONTINUE;
    }
    handle_breakpoint_exception(debug_event);
    break;
  case EXCEPTION_SINGLE_STEP:
    handle_single_step(debug_event);
    break;
  case EXCEPTION_ACCESS_VIOLATION:
    handle_access_violation(debug_event);
    return DBG_EXCEPTION_NOT_HANDLED;
  default:
    if (exception_info.dwFirstChance)
    {
      // First-chance: pass to the target's own handlers (SEH, CRT, VEH).
      // Common examples: C++ exceptions (0xE06D7363), guard-page faults.
      // The process will continue normally if its handler deals with it.
      spdlog::info("First-chance exception 0x{:X} at {} - passing to target",
                   exception_code,
                   exception_info.ExceptionRecord.ExceptionAddress);
    }
    else
    {
      // Second-chance: the target has no handler; it is about to crash.
      // Save coverage before the process terminates.
      spdlog::error("Second-chance exception 0x{:X} at {} - process will terminate",
                    exception_code,
                    exception_info.ExceptionRecord.ExceptionAddress);
      save_coverage_data();
    }
    return DBG_EXCEPTION_NOT_HANDLED;
  }

  return DBG_CONTINUE;
}

DWORD Debugger::handle_load_dll_event(const DEBUG_EVENT &debug_event)
{
  LOAD_DLL_DEBUG_INFO load_info = debug_event.u.LoadDll;
  LPVOID base_addr = load_info.lpBaseOfDll;
  register_module(base_addr);
  enable_breakpoints(base_addr);
  return DBG_CONTINUE;
}

void Debugger::handle_unload_dll_event(const DEBUG_EVENT &debug_event)
{
  UNLOAD_DLL_DEBUG_INFO unload_info = debug_event.u.UnloadDll;
  LPVOID base_addr = unload_info.lpBaseOfDll;
  unregister_module(base_addr);
}

void Debugger::handle_create_process_event(const DEBUG_EVENT &debug_event)
{
  CREATE_PROCESS_DEBUG_INFO create_info = debug_event.u.CreateProcessInfo;

  // It's good practice to close the file handle for the main executable image.
  // The system will do it for us when the process terminates, but being
  // explicit is better.
  if (create_info.hFile != NULL)
  {
    CloseHandle(create_info.hFile);
  }

  this->process_handle = create_info.hProcess;
  HANDLE thread_handle = create_info.hThread;
  DWORD thread_id = debug_event.dwThreadId;

  this->thread_handles[thread_id] = thread_handle;
  spdlog::info("Process created. Image base address: {}",
               create_info.lpBaseOfImage);

  register_module(create_info.lpBaseOfImage);
  enable_breakpoints(create_info.lpBaseOfImage);
}

void Debugger::run()
{
  if (!this->pid_)
  {
    spdlog::error("No process attached.");
    return;
  }

  spdlog::info("Debugger running on process {}", this->pid_);
  this->last_coverage_flush_ = std::chrono::steady_clock::now();

  DEBUG_EVENT debug_event;
  while (true)
  {
    // Check the stop flag every iteration — safe because we use a timeout
    if (this->stop_requested)
    {
      spdlog::info("Stopping debugger loop");
      break;
    }

    // Periodic coverage flush every 5 seconds (like Mesos)
    auto now = std::chrono::steady_clock::now();
    if (now - this->last_coverage_flush_ >= std::chrono::seconds(5))
    {
      if (!this->coverage_data.empty())
      {
        save_coverage_data();
        spdlog::info("Periodic coverage flush ({} unique entries)",
                     this->coverage_data.size());
      }
      this->last_coverage_flush_ = now;
    }

    // Use a short timeout so the loop can check stop_requested and flush
    // coverage even when the target is idle. Matches the Mesos pattern of
    // WaitForDebugEvent with a timeout + ERROR_SEM_TIMEOUT handling.
    if (!WaitForDebugEvent(&debug_event, 100))
    {
      DWORD err = GetLastError();
      if (err == ERROR_SEM_TIMEOUT)
      {
        // No debug event within the timeout — just loop back
        continue;
      }
      spdlog::error("WaitForDebugEvent failed. Error code: {}", err);
      break;
    }

    DWORD continue_status = DBG_CONTINUE;
    DWORD event_thread_id = debug_event.dwThreadId;

    switch (debug_event.dwDebugEventCode)
    {
    case EXCEPTION_DEBUG_EVENT:
      continue_status = handle_exception_debug_event(debug_event);
      break;
    case CREATE_THREAD_DEBUG_EVENT:
    {
      CREATE_THREAD_DEBUG_INFO thread_info = debug_event.u.CreateThread;
      this->thread_handles[event_thread_id] = thread_info.hThread;
      spdlog::info("Thread created. Thread ID: {}", event_thread_id);
      break;
    }
    case CREATE_PROCESS_DEBUG_EVENT:
      handle_create_process_event(debug_event);
      break;
    case EXIT_THREAD_DEBUG_EVENT:
      this->thread_handles.erase(event_thread_id);
      spdlog::info("Thread exited. Thread ID: {}", event_thread_id);
      break;
    case EXIT_PROCESS_DEBUG_EVENT:
      spdlog::info("Process exited. Leaving debugger loop.");
      return;
    case LOAD_DLL_DEBUG_EVENT:
      continue_status = handle_load_dll_event(debug_event);
      break;
    case UNLOAD_DLL_DEBUG_EVENT:
      handle_unload_dll_event(debug_event);
      break;
    case RIP_EVENT:
      spdlog::info("RIP event received.");
      break;
    case OUTPUT_DEBUG_STRING_EVENT:
      break;
    default:
      spdlog::warn("Unknown debug event code: {}",
                   debug_event.dwDebugEventCode);
      break;
    }

    if (!ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId,
                            continue_status))
    {
      spdlog::error("ContinueDebugEvent failed. Error code: {}",
                    GetLastError());
      break;
    }
  }
}
