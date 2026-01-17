// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WINDOWS_SERVICE_H
#define BITCOIN_WINDOWS_SERVICE_H

#ifdef WIN32

#include <functional>
#include <string>
#include <vector>

namespace node {
struct NodeContext;
}

namespace util {
class SignalInterrupt;
}

namespace windows_service {

//! Default service name
static constexpr const char* DEFAULT_SERVICE_NAME = "BitcoinCore";

//! Default service display name
static constexpr const char* DEFAULT_DISPLAY_NAME = "Bitcoin Core";

//! Service description
static constexpr const char* SERVICE_DESCRIPTION = "Bitcoin Core peer-to-peer network daemon";

//! Preshutdown timeout in milliseconds (3 minutes)
static constexpr unsigned int PRESHUTDOWN_TIMEOUT_MS = 180000;

/**
 * Install bitcoind as a Windows service.
 * @param[in] service_name The service name to use (internal identifier)
 * @param[in] args Additional command-line arguments to store for service startup
 * @return true if installation succeeded, false otherwise
 */
bool InstallService(const std::string& service_name, const std::vector<std::string>& args);

/**
 * Uninstall the Windows service.
 * @param[in] service_name The service name to uninstall
 * @return true if uninstallation succeeded, false otherwise
 */
bool UninstallService(const std::string& service_name);

/**
 * Attempt to run as a Windows service.
 * This function tries to connect to the Service Control Manager. If running
 * as a service, it will not return until the service stops. If not running
 * as a service (started from console), it returns false immediately.
 *
 * @param[in] service_name The service name
 * @param[in] node_main Function to run the node (called from ServiceMain)
 * @param[in] shutdown_signal Pointer to the shutdown signal object
 * @return true if ran as service successfully, false if not running as service
 */
bool RunAsService(const std::string& service_name,
                  std::function<bool(int, char**)> node_main,
                  util::SignalInterrupt* shutdown_signal);

/**
 * Check if we're likely running as a Windows service.
 * This is a heuristic check based on having no console.
 * @return true if likely running as a service
 */
bool IsRunningAsService();

/**
 * Log a message to the Windows Event Log.
 * @param[in] service_name The event source name
 * @param[in] message The message to log
 * @param[in] is_error true for error level, false for informational
 */
void LogToEventLog(const std::string& service_name, const std::string& message, bool is_error = false);

/**
 * Generate the display name for a service.
 * @param[in] service_name The internal service name
 * @return Display name (e.g., "Bitcoin Core" or "Bitcoin Core - CustomName")
 */
std::string GetDisplayName(const std::string& service_name);

} // namespace windows_service

#endif // WIN32

#endif // BITCOIN_WINDOWS_SERVICE_H
