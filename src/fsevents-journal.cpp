// One observed-event namespace for the Darling server. Inotify observations,
// explicit loss notifications and their IDs are serialized together. The ID
// high-water mark is durable; the bounded replay ring is deliberately volatile.
#include <darlingserver/fsevents-journal.hpp>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/vfs.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <dirent.h>
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <deque>
#include <filesystem>
#include <mutex>
#include <stdexcept>
#include <system_error>
#include <thread>
#include <unordered_map>

namespace DarlingServer::FSEvents {
namespace {
namespace fs=std::filesystem;
constexpr uint32_t Scan=1,UserDropped=2,KernelDropped=4,HistoryDone=0x10;
constexpr uint32_t Created=0x100,Removed=0x200,Renamed=0x800,Modified=0x1000;
constexpr uint32_t Metadata=0x400|0x4000|0x8000,File=0x10000,Directory=0x20000,Symlink=0x40000;
constexpr uint32_t Mask=IN_CREATE|IN_DELETE|IN_MODIFY|IN_ATTRIB|IN_MOVED_FROM|IN_MOVED_TO|
    IN_DELETE_SELF|IN_MOVE_SELF|IN_UNMOUNT;
constexpr uint64_t Magic=UINT64_C(0x3144495346455344);
bool beneath(const std::string& path,const std::string& root) {
    return path==root || (path.size()>root.size() && path.compare(0,root.size(),root)==0 &&
                          (root=="/" || path[root.size()]=='/'));
}
std::string parent(const std::string& path) {
    auto position=path.rfind('/');return position==0?"/":path.substr(0,position);
}
bool pseudo(const std::string& path) {
    struct statfs value{};
    if (statfs(path.c_str(),&value)<0) return false;
    switch (value.f_type) {
        case 0x9fa0:case 0x62656572:case 0x1cd1:case 0x27e0eb:case 0x63677270:
        case 0x42494e4d:case 0x6e736673:case 0x74726163:case 0x73636673:case 0x64626720:
        case 0xde5e81e4:case 0x19800202:return true;
        default:return false;
    }
}
}
struct Journal::State {
    struct Watch {std::string path;dev_t dev;ino_t ino;};
    struct Coverage {uint64_t start;bool complete;};
    struct Move {std::string path;std::chrono::steady_clock::time_point when;};
    struct Subscription {
        std::vector<Root> roots;
        JournalSender sender;
        std::function<bool()> alive;
        std::deque<JournalEvent> queue;
        uint32_t flags=0;
        uint64_t ticket=0;
        uint64_t droppedThrough=0;
        bool historical=false;
    };
    std::string file;
    int notify=-1,lockFD=-1,error=0;
    size_t capacity;
    uint64_t current=0,persisted=0,nextSubscriber=0;
    std::mutex mutex;
    std::atomic<bool> stopped{false};
    std::thread worker;
    std::unordered_map<int,Watch> watches;
    std::unordered_map<std::string,Coverage> coverage;
    std::unordered_map<uint32_t,Move> moves;
    std::unordered_map<uint64_t,Subscription> subscribers;
    std::deque<JournalEvent> ring;
    bool repairNeeded=false;

    State(std::string stateFile,size_t limit):file(std::move(stateFile)),capacity(limit) {
        if (capacity<8 || capacity>1048576) throw std::invalid_argument("journal capacity");
        file=fs::absolute(file).lexically_normal().string();
        file=(fs::canonical(fs::path(file).parent_path())/fs::path(file).filename()).string();
        lockFD=open((file+".lock").c_str(),O_RDWR|O_CREAT|O_CLOEXEC|O_NOFOLLOW,0600);
        if(lockFD<0)throw std::system_error(errno,std::generic_category(),"FSEvents state lock");
        if(flock(lockFD,LOCK_EX|LOCK_NB)<0){int saved=errno;close(lockFD);lockFD=-1;throw std::system_error(saved,std::generic_category(),"FSEvents state already in use");}
        try {
        struct Record {uint64_t magic,id,inverse;} record{};
        int fd=open(file.c_str(),O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
        if (fd>=0) {
            struct stat st{};ssize_t n=read(fd,&record,sizeof record);int saved=errno;
            bool valid=fstat(fd,&st)==0 && S_ISREG(st.st_mode) && st.st_size==sizeof record;
            close(fd);errno=saved;
            if (!valid || n!=sizeof record || record.magic!=Magic || record.inverse!=~record.id || record.id>=UINT64_MAX-1)
                throw std::system_error(EIO,std::generic_category(),"invalid FSEvents ID state");
            current=persisted=record.id;
        } else if (errno!=ENOENT) throw std::system_error(errno,std::generic_category(),"FSEvents ID state");
        notify=inotify_init1(IN_NONBLOCK|IN_CLOEXEC);
        if (notify<0) throw std::system_error(errno,std::generic_category(),"inotify_init1");
        } catch(...) {close(lockFD);lockFD=-1;throw;}
    }
    ~State() {stopped=true;if(worker.joinable())worker.join();if(notify>=0)close(notify);if(lockFD>=0)close(lockFD);}
    bool internal(const std::string& path) const {return path==file || path==file+".pending" || path==file+".lock";}
    void save() {
        if (error || current==persisted) return;
        struct Record {uint64_t magic,id,inverse;} record{Magic,current,~current};
        auto temporary=file+".pending";
        int fd=open(temporary.c_str(),O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC|O_NOFOLLOW,0600);
        if (fd<0) {error=errno;return;}
        ssize_t written=write(fd,&record,sizeof record);int status=written==sizeof record?fsync(fd):-1;
        int saved=errno;close(fd);
        if (written!=sizeof record || status<0 || rename(temporary.c_str(),file.c_str())<0) {
            error=status<0?(saved?saved:EIO):errno;return;
        }
        int directory=open(parent(file).c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC);
        if (directory<0) {error=errno;return;}
        status=fsync(directory);saved=errno;close(directory);
        if (status<0) {error=saved;return;}
        persisted=current;
    }
    static std::string mapped(const JournalEvent& event,const Subscription& sub) {
        const Root* match=nullptr;
        for (auto& root:sub.roots)
            if (beneath(event.path,root.host) && (!match || root.host.size()>match->host.size())) match=&root;
        bool ancestor=false;
        if(!match && (event.flags&(Directory|Scan)))
            for(auto& root:sub.roots)if(beneath(root.host,event.path)){match=&root;ancestor=true;break;}
        if (!match) return {};
        std::string path=ancestor?match->host:event.path;
        if (!(sub.flags&0x10) && !(event.flags&Directory) && path!=match->host && !(event.flags&Scan))path=parent(path);
        auto suffix=path.substr(match->host.size());
        return suffix.empty()?match->guest:(match->guest=="/"?"":match->guest)+suffix;
    }
    void queue(Subscription& sub,JournalEvent event) {
        if(event.id && event.flags!=HistoryDone&&event.flags!=JournalBarrierFlag&&event.id<=sub.droppedThrough)return;
        if (sub.queue.size()>=2048) {
            bool boundary=false;
            uint64_t barrier=0;
            for (auto& item:sub.queue) if (item.flags==HistoryDone)boundary=true;
            for (auto& item:sub.queue) if (item.flags==JournalBarrierFlag)barrier=std::max(barrier,item.id);
            sub.queue.clear();
            sub.droppedThrough=current;
            for(auto& root:sub.roots)sub.queue.push_back({current,Scan|UserDropped,root.guest});
            if(boundary)sub.queue.push_back({current,HistoryDone,sub.roots.front().guest});
            if(barrier)sub.queue.push_back({barrier,JournalBarrierFlag,{}});
        }
        if(event.id && event.flags!=HistoryDone&&event.flags!=JournalBarrierFlag&&event.id<=sub.droppedThrough)return;
        sub.queue.push_back(std::move(event));
    }
    static JournalEvent delivery(const JournalEvent& event,const Subscription& sub,std::string guest) {
        uint32_t flags=(sub.flags&0x10)?event.flags:(event.flags&0xff);
        uint64_t id=event.id;
        for(auto& root:sub.roots)if((event.flags&(Directory|Scan))&&beneath(root.host,event.path)&&root.host!=event.path)flags|=Scan;
        if((sub.flags&4)&&(event.flags&(Renamed|Removed)))
            for(auto& root:sub.roots)if(beneath(root.host,event.path)){flags|=Scan|0x20;id=0;break;}
        return {id,flags,std::move(guest)};
    }
    void publish(std::string path,uint32_t flags) {
        if (error || internal(path)) return;
        if (current>=UINT64_MAX-1) {error=EOVERFLOW;return;}
        JournalEvent event{++current,flags,std::move(path)};
        ring.push_back(event);if(ring.size()>capacity)ring.pop_front();
        for (auto& [id,sub]:subscribers) {
            auto guest=event.path.empty()?sub.roots.front().guest:mapped(event,sub);
            if (guest.empty())continue;
            queue(sub,delivery(event,sub,std::move(guest)));
        }
    }
    void flush() {
        save();if(error)return;
        for(auto it=subscribers.begin();it!=subscribers.end();) {
            auto& sub=it->second;bool dead=false;
            if(sub.alive&&!sub.alive()){it=subscribers.erase(it);continue;}
            while(!sub.queue.empty()) {
                int sent=sub.sender(sub.queue.front());
                if(sent<0){dead=true;break;}
                if(!sent)break;
                if(sub.queue.front().flags==HistoryDone)sub.historical=false;
                sub.queue.pop_front();
            }
            if(dead)it=subscribers.erase(it);else ++it;
        }
    }
    // Reuse an existing inode's name when a bind alias reaches a watched root.
    // Recursive coverage of mixed nested aliases is conservatively rejected.
    int tree(std::string path,std::string& canonical) {
        std::vector<std::string> pending{path};bool first=true;
        canonical=path;
        while(!pending.empty()) {
            auto item=std::move(pending.back());pending.pop_back();
            struct stat st{};
            if(lstat(item.c_str(),&st)<0){if(errno==ENOENT&&!first)continue;return -errno;}
            if(!S_ISDIR(st.st_mode)){if(first)return -ENOTDIR;continue;}
            if(pseudo(item)){if(first)return -ENOTSUP;continue;}
            if(watches.size()>=131072)return -ENOSPC;
            int wd=inotify_add_watch(notify,item.c_str(),Mask|IN_ONLYDIR|IN_DONT_FOLLOW);
            if(wd<0)return -errno;
            auto known=watches.find(wd);
            if(known!=watches.end() && known->second.path!=item) {
                if(first) {canonical=known->second.path;pending.push_back(canonical);continue;}
                return -EXDEV;
            }
            watches[wd]={item,st.st_dev,st.st_ino};first=false;
            DIR* directory=opendir(item.c_str());if(!directory)return -errno;
            int failure=0;
            for(;;){
                errno=0;auto* entry=readdir(directory);
                if(!entry){failure=errno;break;}
                if(!strcmp(entry->d_name,".")||!strcmp(entry->d_name,".."))continue;
                if(entry->d_type!=DT_DIR && entry->d_type!=DT_UNKNOWN)continue;
                pending.push_back(item+"/"+entry->d_name);
            }
            closedir(directory);if(failure)return -failure;
        }
        return 0;
    }
    uint64_t covered(const std::string& path) {
        uint64_t earliest=UINT64_MAX;
        for(auto& [root,value]:coverage)if(value.complete&&beneath(path,root))earliest=std::min(earliest,value.start);
        return earliest;
    }
    int cover(Root& root) {
        char* resolved=realpath(root.host.c_str(),nullptr);
        if(!resolved)return -errno;
        root.host=resolved;free(resolved);
        struct stat info{};
        if(stat(root.host.c_str(),&info)<0)return -errno;
        for(auto& [wd,watch]:watches)
            if(watch.dev==info.st_dev&&watch.ino==info.st_ino){root.host=watch.path;break;}
        if(covered(root.host)!=UINT64_MAX)return 0;
        std::string canonical;int result=tree(root.host,canonical);
        root.host=canonical;
        if(covered(root.host)!=UINT64_MAX)return 0;
        // This is a real coverage-loss boundary, not a fabricated mutation or
        // a clock-derived cache token. Its flag always requires a fresh scan.
        publish(root.host,Scan|UserDropped);
        coverage[root.host]={current,result==0};
        return result;
    }
    void invalidateCoverage(const std::string& path) {
        for(auto& [root,value]:coverage)if(beneath(root,path)||beneath(path,root))value.complete=false;
    }
    void forget(const std::string& path) {
        for(auto it=watches.begin();it!=watches.end();) {
            if(beneath(it->second.path,path)){inotify_rm_watch(notify,it->first);it=watches.erase(it);}else ++it;
        }
        // A known deletion/move out does not invalidate coverage of the other
        // directories under its parent. Only a watch rooted in the removed
        // subtree loses its own coverage.
        for(auto& [root,value]:coverage)if(beneath(root,path))value.complete=false;
    }
    void relocate(const std::string& from,const std::string& to) {
        for(auto& [wd,watch]:watches)if(beneath(watch.path,from))watch.path=to+watch.path.substr(from.size());
        // Subscriptions retain their requested path scope. A moved-out root
        // gets a loss event; it must not silently follow an unrelated pathname.
        for(auto& [root,value]:coverage)if(beneath(root,from))value.complete=false;
    }
    void event(const inotify_event& ev) {
        if(ev.mask&IN_Q_OVERFLOW){
            publish({},Scan|KernelDropped);
            for(auto& [root,value]:coverage)value.complete=false;
            repairNeeded=true;
            return;
        }
        auto found=watches.find(ev.wd);if(found==watches.end())return;
        auto watch=found->second;
        if(ev.mask&IN_IGNORED){watches.erase(found);return;}
        if(ev.mask&IN_UNMOUNT){publish(watch.path,Scan|KernelDropped);invalidateCoverage(watch.path);forget(watch.path);return;}
        if(!ev.len){
            if(ev.mask&IN_DELETE_SELF){publish(watch.path,Removed|Directory);forget(watch.path);}
            else if(ev.mask&IN_MOVE_SELF){
                struct stat st{};
                if(lstat(watch.path.c_str(),&st)<0||st.st_dev!=watch.dev||st.st_ino!=watch.ino){publish(watch.path,Renamed|Directory|Scan|UserDropped);forget(watch.path);}
            }
            else if(ev.mask&IN_ATTRIB)publish(watch.path,Metadata|Directory);
            return;
        }
        auto path=watch.path+"/"+ev.name;if(internal(path))return;
        uint32_t flags=(ev.mask&IN_ISDIR)?Directory:0;
        struct stat st{};
        if(!(ev.mask&IN_ISDIR)&&lstat(path.c_str(),&st)==0)flags|=S_ISLNK(st.st_mode)?Symlink:File;
        if(ev.mask&IN_CREATE)flags|=Created;
        if(ev.mask&IN_DELETE)flags|=Removed;
        if(ev.mask&IN_MODIFY)flags|=Modified;
        if(ev.mask&IN_ATTRIB)flags|=Metadata;
        if(ev.mask&(IN_MOVED_FROM|IN_MOVED_TO))flags|=Renamed;
        publish(path,flags);
        if((ev.mask&IN_ISDIR)&&(ev.mask&IN_MOVED_FROM))moves[ev.cookie]={path,std::chrono::steady_clock::now()};
        if((ev.mask&IN_ISDIR)&&(ev.mask&IN_MOVED_TO)) {
            auto pending=moves.find(ev.cookie);
            if(pending!=moves.end()){relocate(pending->second.path,path);moves.erase(pending);}
            else {publish(path,Scan|UserDropped);std::string canonical;int result=tree(path,canonical);if(result<0){invalidateCoverage(path);publish(path,Scan|UserDropped);}}
        } else if((ev.mask&IN_ISDIR)&&(ev.mask&IN_CREATE)) {
            publish(path,Scan|UserDropped);std::string canonical;
            if(tree(path,canonical)<0){invalidateCoverage(path);publish(path,Scan|UserDropped);}
        } else if((ev.mask&IN_ISDIR)&&(ev.mask&IN_DELETE))forget(path);
    }
    void drain() {
        // Called both from the polling thread and from server RPC fibers.
        // Their guarded stacks cannot hold a 64 KiB automatic read buffer.
        std::vector<uint8_t> buffer(65536);
        for(unsigned batch=0;batch<4096;batch++) {
            auto count=read(notify,buffer.data(),buffer.size());
            if(count<0){if(errno==EINTR)continue;if(errno!=EAGAIN)error=errno;break;}
            if(!count)break;
            for(size_t offset=0;offset<size_t(count);){
                auto* item=reinterpret_cast<const inotify_event*>(buffer.data()+offset);
                if(size_t(count)-offset<sizeof(*item)||item->len>size_t(count)-offset-sizeof(*item)){error=EIO;break;}
                event(*item);offset+=sizeof(*item)+item->len;
            }
        }
        auto now=std::chrono::steady_clock::now();
        for(auto it=moves.begin();it!=moves.end();) {
            if(now-it->second.when>std::chrono::milliseconds(100)){auto path=it->second.path;publish(path,Scan|UserDropped);forget(path);it=moves.erase(it);}else ++it;
        }
        if(repairNeeded){
            repairNeeded=false;
            std::vector<std::string> roots;for(auto& [root,value]:coverage)roots.push_back(root);
            for(auto& root:roots){std::string canonical;int result=tree(root,canonical);coverage[root]={current,result==0};}
        }
    }
};

Journal::Journal(std::string file,std::vector<Root> roots,size_t capacity):state(new State(std::move(file),capacity)) {
    if(roots.empty())throw std::invalid_argument("empty FSEvents coverage");
    for(auto& root:roots) {
        int result=state->cover(root);
        if(result<0 && state->watches.empty())throw std::system_error(-result,std::generic_category(),"FSEvents initial coverage");
    }
    state->drain();state->save();
    if(state->error)throw std::system_error(state->error,std::generic_category(),"FSEvents state publication");
    auto* shared=state.get();
    state->worker=std::thread([shared]{
        while(!shared->stopped) {
            pollfd fd{shared->notify,POLLIN,0};int result=poll(&fd,1,20);
            if(result<0&&errno==EINTR)continue;
            std::lock_guard lock(shared->mutex);shared->drain();shared->flush();
        }
    });
}
Journal::~Journal()=default;
int Journal::current(uint64_t& value) {
    std::lock_guard lock(state->mutex);state->drain();state->flush();
    if(state->error)return -state->error;value=state->current;return 0;
}
int Journal::subscribe(std::vector<Root> roots,uint64_t since,uint32_t flags,JournalSender sender,uint64_t& handle,std::function<bool()> alive) {
    if(roots.empty()||roots.size()>256||!sender)return -EINVAL;
    // IgnoreSelf/MarkSelf need originating PID information unavailable from inotify.
    if(flags&~uint32_t(1|2|4|0x10|0x40))return -ENOTSUP;
    std::lock_guard lock(state->mutex);
    state->drain();
    for(auto& root:roots){if(root.guest.empty()||root.guest[0]!='/')return -EINVAL;int result=state->cover(root);if(result<0)return result;}
    state->drain();state->save();if(state->error)return -state->error;
    State::Subscription sub;sub.roots=std::move(roots);sub.sender=std::move(sender);sub.flags=flags;sub.alive=std::move(alive);
    if(since!=UINT64_MAX) {
        sub.historical=true;
        bool lost=since>state->current || (!state->ring.empty()&&since<state->ring.front().id-1);
        for(auto& root:sub.roots)if(state->covered(root.host)>since)lost=true;
        if(lost)for(auto& root:sub.roots)sub.queue.push_back({state->current,Scan|UserDropped,root.guest});
        else for(auto& event:state->ring)if(event.id>since) {
            auto guest=event.path.empty()?sub.roots.front().guest:State::mapped(event,sub);
            if(!guest.empty())state->queue(sub,State::delivery(event,sub,std::move(guest)));
        }
        state->queue(sub,{state->current,HistoryDone,sub.roots.front().guest});
    }
    handle=++state->nextSubscriber;state->subscribers.emplace(handle,std::move(sub));state->flush();return 0;
}
int Journal::barrier(uint64_t handle,uint64_t& ticket) {
    std::lock_guard lock(state->mutex);state->drain();
    auto it=state->subscribers.find(handle);if(it==state->subscribers.end())return -ENOENT;
    ticket=++it->second.ticket;state->queue(it->second,{ticket,JournalBarrierFlag,{}});state->flush();
    return state->error?-state->error:0;
}
void Journal::unsubscribe(uint64_t handle) {std::lock_guard lock(state->mutex);state->subscribers.erase(handle);}
}
