#ifndef DARLINGSERVER_FSEVENTS_DEVICE_HPP
#define DARLINGSERVER_FSEVENTS_DEVICE_HPP

#include <cstdint>
#include <string>
#include <vector>

namespace DarlingServer::FSEvents {
// A host directory and its name in the calling process's virtual root.
struct Root { std::string host; std::string guest; };
// Descriptors are real Unix sockets: dup, SCM_RIGHTS, fork, exec and final-close
// lifetime use Linux's open-file descriptions rather than a guest FD-number map.
int openDevice(const std::vector<Root>& roots, int flags);
int cloneDevice(int device, const std::vector<int8_t>& actions, unsigned depth);
int filterDevices(int stream, const std::vector<uint32_t>& devices);
int setCompact(int stream);
int setExtended(int stream);
bool isDevice(int fd);
size_t activeDevices();
}
#endif
