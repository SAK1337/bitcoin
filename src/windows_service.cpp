// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#ifdef WIN32

#include <windows_service.h>

#include <util/signalinterrupt.h>
#include <util/strencodings.h>
#include <tinyformat.h>

#include <windows.h>

#include <atomic>
#include <cassert>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace windows_service {

// Global state for service control handler
static SERVICE_STATUS g_service_status{};
static SERVICE_STATUS_HANDLE g_service_status_handle{nullptr};
static util::SignalInterrupt* g_shutdown_signal{nullptr};
static std::string g_service_name;
static std::function<bool(int, char**)> g_node_main;
static std::atomic<bool> g_service_running{false};

// Forward declarations
static void WINAPI ServiceMain(DWORD argc, LPWSTR* argv);
static DWORD WINAPI ServiceCtrlHandler(DWORD ctrl_code, DWORD event_type, LPVOID event_data, LPVOID context);
static void ReportServiceStatus(DWORD current_state, DWORD exit_code, DWORD wait_hint);

std::string GetDisplayName(const std::string& service_name)
{
    if (service_name == DEFAULT_SERVICE_NAME) {
        return DEFAULT_DISPLAY_NAME;
    }
    return std::string(DEFAULT_DISPLAY_NAME) + " - " + service_name;
}

void LogToEventLog(const std::string& service_name, const std::string& message, bool is_error)
{
    HANDLE event_source = RegisterEventSourceA(nullptr, service_name.c_str());
    if (event_source == nullptr) {
        return;
    }

    const char* strings[1] = {message.c_str()};
    WORD event_type = is_error ? EVENTLOG_ERROR_TYPE : EVENTLOG_INFORMATION_TYPE;

    ReportEventA(event_source,
                 event_type,
                 0,              // category
                 0,              // event ID
                 nullptr,        // user SID
                 1,              // number of strings
                 0,              // data size
                 strings,
                 nullptr);       // data

    DeregisterEventSource(event_source);
}

bool InstallService(const std::string& service_name, const std::vector<std::string>& args)
{
    // Get the full path to this executable
    wchar_t module_path[MAX_PATH];
    if (GetModuleFileNameW(nullptr, module_path, MAX_PATH) == 0) {
        tfm::format(std::cerr, "Error: Failed to get executable path: %lu\n", GetLastError());
        return false;
    }

    // Open Service Control Manager
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (scm == nullptr) {
        DWORD error = GetLastError();
        if (error == ERROR_ACCESS_DENIED) {
            tfm::format(std::cerr, "Error: Administrator privileges required. Run this command from an elevated command prompt.\n");
        } else {
            tfm::format(std::cerr, "Error: Failed to open Service Control Manager: %lu\n", error);
        }
        return false;
    }

    // Convert service name to wide string
    std::wstring wide_service_name(service_name.begin(), service_name.end());
    std::string display_name = GetDisplayName(service_name);
    std::wstring wide_display_name(display_name.begin(), display_name.end());

    // Create the service
    SC_HANDLE service = CreateServiceW(
        scm,
        wide_service_name.c_str(),
        wide_display_name.c_str(),
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START,  // Manual start
        SERVICE_ERROR_NORMAL,
        module_path,
        nullptr,  // no load ordering group
        nullptr,  // no tag identifier
        nullptr,  // no dependencies
        nullptr,  // LocalSystem account
        nullptr   // no password
    );

    if (service == nullptr) {
        DWORD error = GetLastError();
        CloseServiceHandle(scm);
        if (error == ERROR_SERVICE_EXISTS) {
            tfm::format(std::cerr, "Error: Service '%s' already exists.\n", service_name);
        } else if (error == ERROR_ACCESS_DENIED) {
            tfm::format(std::cerr, "Error: Administrator privileges required. Run this command from an elevated command prompt.\n");
        } else {
            tfm::format(std::cerr, "Error: Failed to create service: %lu\n", error);
        }
        return false;
    }

    // Set the service description
    std::wstring wide_description(SERVICE_DESCRIPTION, SERVICE_DESCRIPTION + strlen(SERVICE_DESCRIPTION));
    SERVICE_DESCRIPTIONW desc{const_cast<LPWSTR>(wide_description.c_str())};
    ChangeServiceConfig2W(service, SERVICE_CONFIG_DESCRIPTION, &desc);

    // Configure preshutdown timeout
    SERVICE_PRESHUTDOWN_INFO preshutdown_info{PRESHUTDOWN_TIMEOUT_MS};
    ChangeServiceConfig2W(service, SERVICE_CONFIG_PRESHUTDOWN_INFO, &preshutdown_info);

    // Store command-line arguments in registry for service startup
    if (!args.empty()) {
        std::string reg_path = "SYSTEM\\CurrentControlSet\\Services\\" + service_name + "\\Parameters";
        HKEY hkey;
        DWORD disposition;
        LONG result = RegCreateKeyExA(
            HKEY_LOCAL_MACHINE,
            reg_path.c_str(),
            0,
            nullptr,
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            nullptr,
            &hkey,
            &disposition
        );

        if (result == ERROR_SUCCESS) {
            // Store arguments as a multi-string value
            std::string args_str;
            for (const auto& arg : args) {
                args_str += arg;
                args_str += '\0';
            }
            args_str += '\0';  // Double null terminator

            RegSetValueExA(
                hkey,
                "Arguments",
                0,
                REG_MULTI_SZ,
                reinterpret_cast<const BYTE*>(args_str.c_str()),
                static_cast<DWORD>(args_str.size())
            );
            RegCloseKey(hkey);
        }
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scm);

    tfm::format(std::cout, "Service '%s' installed successfully.\n", service_name);
    tfm::format(std::cout, "Start the service with: sc start %s\n", service_name);
    tfm::format(std::cout, "Or use services.msc to manage the service.\n");

    LogToEventLog(service_name, "Service installed", false);
    return true;
}

bool UninstallService(const std::string& service_name)
{
    // Open Service Control Manager
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (scm == nullptr) {
        DWORD error = GetLastError();
        if (error == ERROR_ACCESS_DENIED) {
            tfm::format(std::cerr, "Error: Administrator privileges required. Run this command from an elevated command prompt.\n");
        } else {
            tfm::format(std::cerr, "Error: Failed to open Service Control Manager: %lu\n", error);
        }
        return false;
    }

    // Convert service name to wide string
    std::wstring wide_service_name(service_name.begin(), service_name.end());

    // Open the service
    SC_HANDLE service = OpenServiceW(scm, wide_service_name.c_str(), SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
    if (service == nullptr) {
        DWORD error = GetLastError();
        CloseServiceHandle(scm);
        if (error == ERROR_SERVICE_DOES_NOT_EXIST) {
            tfm::format(std::cerr, "Error: Service '%s' does not exist.\n", service_name);
        } else if (error == ERROR_ACCESS_DENIED) {
            tfm::format(std::cerr, "Error: Administrator privileges required. Run this command from an elevated command prompt.\n");
        } else {
            tfm::format(std::cerr, "Error: Failed to open service: %lu\n", error);
        }
        return false;
    }

    // Stop the service if it's running
    SERVICE_STATUS status;
    if (QueryServiceStatus(service, &status) && status.dwCurrentState != SERVICE_STOPPED) {
        tfm::format(std::cout, "Stopping service '%s'...\n", service_name);
        if (!ControlService(service, SERVICE_CONTROL_STOP, &status)) {
            DWORD error = GetLastError();
            if (error != ERROR_SERVICE_NOT_ACTIVE) {
                tfm::format(std::cerr, "Warning: Failed to stop service: %lu\n", error);
            }
        }

        // Wait for service to stop (up to 30 seconds)
        int wait_count = 0;
        while (status.dwCurrentState != SERVICE_STOPPED && wait_count < 30) {
            Sleep(1000);
            if (!QueryServiceStatus(service, &status)) break;
            wait_count++;
        }

        if (status.dwCurrentState != SERVICE_STOPPED) {
            tfm::format(std::cerr, "Warning: Service did not stop in time.\n");
        }
    }

    // Delete the service
    if (!DeleteService(service)) {
        DWORD error = GetLastError();
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        tfm::format(std::cerr, "Error: Failed to delete service: %lu\n", error);
        return false;
    }

    // Clean up registry parameters
    std::string reg_path = "SYSTEM\\CurrentControlSet\\Services\\" + service_name + "\\Parameters";
    RegDeleteKeyA(HKEY_LOCAL_MACHINE, reg_path.c_str());

    CloseServiceHandle(service);
    CloseServiceHandle(scm);

    tfm::format(std::cout, "Service '%s' uninstalled successfully.\n", service_name);
    return true;
}

static void ReportServiceStatus(DWORD current_state, DWORD exit_code, DWORD wait_hint)
{
    static DWORD checkpoint = 1;

    g_service_status.dwCurrentState = current_state;
    g_service_status.dwWin32ExitCode = exit_code;
    g_service_status.dwWaitHint = wait_hint;

    if (current_state == SERVICE_START_PENDING) {
        g_service_status.dwControlsAccepted = 0;
    } else {
        g_service_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_PRESHUTDOWN;
    }

    if (current_state == SERVICE_RUNNING || current_state == SERVICE_STOPPED) {
        g_service_status.dwCheckPoint = 0;
    } else {
        g_service_status.dwCheckPoint = checkpoint++;
    }

    SetServiceStatus(g_service_status_handle, &g_service_status);
}

static DWORD WINAPI ServiceCtrlHandler(DWORD ctrl_code, DWORD /*event_type*/, LPVOID /*event_data*/, LPVOID /*context*/)
{
    switch (ctrl_code) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
    case SERVICE_CONTROL_PRESHUTDOWN:
        ReportServiceStatus(SERVICE_STOP_PENDING, NO_ERROR, PRESHUTDOWN_TIMEOUT_MS);
        LogToEventLog(g_service_name, "Service stop requested", false);

        // Trigger shutdown through the existing mechanism
        if (g_shutdown_signal) {
            (*g_shutdown_signal)();
        }
        return NO_ERROR;

    case SERVICE_CONTROL_INTERROGATE:
        return NO_ERROR;

    default:
        return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

static void WINAPI ServiceMain(DWORD /*argc*/, LPWSTR* /*argv*/)
{
    // Convert service name to wide string for registration
    std::wstring wide_service_name(g_service_name.begin(), g_service_name.end());

    // Register the service control handler
    g_service_status_handle = RegisterServiceCtrlHandlerExW(
        wide_service_name.c_str(),
        ServiceCtrlHandler,
        nullptr
    );

    if (g_service_status_handle == nullptr) {
        LogToEventLog(g_service_name, "Failed to register service control handler", true);
        return;
    }

    // Initialize service status
    g_service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_service_status.dwServiceSpecificExitCode = 0;

    // Report initial status
    ReportServiceStatus(SERVICE_START_PENDING, NO_ERROR, 30000);

    // Load arguments from registry
    std::vector<std::string> args;
    args.push_back("bitcoind");  // argv[0]

    std::string reg_path = "SYSTEM\\CurrentControlSet\\Services\\" + g_service_name + "\\Parameters";
    HKEY hkey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, reg_path.c_str(), 0, KEY_READ, &hkey) == ERROR_SUCCESS) {
        DWORD type;
        DWORD size = 0;
        if (RegQueryValueExA(hkey, "Arguments", nullptr, &type, nullptr, &size) == ERROR_SUCCESS && type == REG_MULTI_SZ && size > 0) {
            std::vector<char> buffer(size);
            if (RegQueryValueExA(hkey, "Arguments", nullptr, &type, reinterpret_cast<BYTE*>(buffer.data()), &size) == ERROR_SUCCESS) {
                // Parse multi-string value
                const char* p = buffer.data();
                while (*p) {
                    args.push_back(p);
                    p += strlen(p) + 1;
                }
            }
        }
        RegCloseKey(hkey);
    }

    // Convert to argc/argv format
    std::vector<char*> argv_ptrs;
    for (auto& arg : args) {
        argv_ptrs.push_back(arg.data());
    }
    argv_ptrs.push_back(nullptr);

    int argc = static_cast<int>(args.size());
    char** argv = argv_ptrs.data();

    // Log service start
    LogToEventLog(g_service_name, "Service starting", false);

    g_service_running = true;

    // Report running status
    ReportServiceStatus(SERVICE_RUNNING, NO_ERROR, 0);

    // Run the node
    bool success = false;
    try {
        success = g_node_main(argc, argv);
    } catch (...) {
        LogToEventLog(g_service_name, "Service crashed with exception", true);
    }

    g_service_running = false;

    // Log service stop
    if (success) {
        LogToEventLog(g_service_name, "Service stopped normally", false);
    } else {
        LogToEventLog(g_service_name, "Service stopped with error", true);
    }

    // Report stopped status
    ReportServiceStatus(SERVICE_STOPPED, success ? NO_ERROR : ERROR_SERVICE_SPECIFIC_ERROR, 0);
}

bool RunAsService(const std::string& service_name,
                  std::function<bool(int, char**)> node_main,
                  util::SignalInterrupt* shutdown_signal)
{
    // Store globals for use in callbacks
    g_service_name = service_name;
    g_node_main = std::move(node_main);
    g_shutdown_signal = shutdown_signal;

    // Convert service name to wide string
    std::wstring wide_service_name(service_name.begin(), service_name.end());

    // Build service table
    SERVICE_TABLE_ENTRYW service_table[] = {
        {const_cast<LPWSTR>(wide_service_name.c_str()), ServiceMain},
        {nullptr, nullptr}
    };

    // This call blocks until the service stops, or returns FALSE immediately
    // if we're not running as a service
    if (!StartServiceCtrlDispatcherW(service_table)) {
        DWORD error = GetLastError();
        if (error == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            // Not running as a service - this is expected when running from console
            return false;
        }
        // Some other error
        tfm::format(std::cerr, "Error: Failed to start service control dispatcher: %lu\n", error);
        return false;
    }

    return true;
}

bool IsRunningAsService()
{
    // A simple heuristic: services don't have a console window
    return GetConsoleWindow() == nullptr;
}

} // namespace windows_service

#endif // WIN32
