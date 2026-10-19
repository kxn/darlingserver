#ifndef DARLINGSERVER_FSEVENTS_JOURNAL_HPP
#define DARLINGSERVER_FSEVENTS_JOURNAL_HPP
#include <darlingserver/fsevents-device.hpp>
#include <functional>
#include <memory>

namespace DarlingServer::FSEvents {
struct JournalEvent { uint64_t id; uint32_t flags; std::string path; };
// send returns 1 on delivery, 0 on socket backpressure, -1 after final close.
using JournalSender = std::function<int(const JournalEvent&)>;
class Journal {
public:
    Journal(std::string stateFile, std::vector<Root> initialRoots, size_t capacity=8192);
    ~Journal();
    Journal(const Journal&)=delete;
    Journal& operator=(const Journal&)=delete;
    int current(uint64_t& value);
    int subscribe(std::vector<Root> roots,uint64_t since,uint32_t flags,
                  JournalSender sender,uint64_t& subscription,std::function<bool()> alive={});
    int barrier(uint64_t subscription,uint64_t& ticket);
    void unsubscribe(uint64_t subscription);
private:
    struct State;
    std::unique_ptr<State> state;
};
constexpr uint32_t JournalBarrierFlag=0x80000000u;
}
#endif
