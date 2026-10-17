/* SPDX-License-Identifier: GPL-3.0-or-later
 * Binary graph layout was cross-checked against the BSD-licensed SandBlaster
 * format research (vendor/sandblaster_26). Pattern instruction encodings are
 * checked against the pinned original Intel compiler's serializer.
 */
#include <darlingserver/sandbox-policy.hpp>
#include <algorithm>
#include <limits>
#include <unordered_map>
#include <unordered_set>

namespace DarlingServer::Sandbox {
namespace {
constexpr std::string_view operations[] = {
#include "sandbox-operation-names.inc"
};
uint16_t u16(const uint8_t* p) { return uint16_t(p[0]) | (uint16_t(p[1]) << 8); }
bool stringFilter(uint8_t filter) {
    switch (filter) {
        case 1: case 5: case 6: case 7: case 10: case 17: case 18: case 28: case 38: case 50: return true;
        default: return false;
    }
}
}
std::string_view Policy::operationName(size_t index) {
    return index < std::size(operations) ? operations[index] : std::string_view{};
}

bool Policy::parsePattern(const uint8_t* bytes, size_t length, Pattern& result, std::string& error) {
    if (!length || length > 65535) { error = "invalid pattern length"; return false; }
    struct Pending { size_t pc, next, fallback; PatternInstruction value; };
    std::vector<Pending> pending;
    std::unordered_map<size_t,size_t> index;
    size_t pc = 0;
    while (pc < length) {
        Pending p{}; p.pc = pc;
        uint8_t op = bytes[pc++];
        auto require = [&](size_t count) { return count <= length - pc; };
        if (op == 0x0a) {
            p.value.kind = PatternInstruction::Kind::Accept;
            p.next = p.fallback = SIZE_MAX;
        } else {
            if ((op >= 0x40 && op < 0x80) || op == 4) {
                size_t count;
                if (op == 4) { if (!require(1)) { error="truncated long sequence"; return false; } count=65+bytes[pc++]; }
                else count=(op & 0x3f)+1;
                if (!require(count)) { error="truncated pattern sequence"; return false; }
                p.value.kind = PatternInstruction::Kind::Sequence;
                p.value.bytes.assign(bytes+pc,bytes+pc+count); pc+=count;
            } else if (op == 0) p.value.kind = PatternInstruction::Kind::End;
            else if (op == 0x0b) {
                if (!require(1)) { error="truncated range count"; return false; }
                uint8_t count=bytes[pc++];size_t ranges=(count & 0x7f)+1;
                if (!require(ranges*2)) { error="truncated pattern ranges"; return false; }
                p.value.kind = (count & 0x80) ? PatternInstruction::Kind::RepeatRange : PatternInstruction::Kind::Range;
                p.value.bytes.assign(bytes+pc,bytes+pc+ranges*2); pc+=ranges*2;
                for(size_t i=0;i<ranges*2;i+=2) if(p.value.bytes[i]>p.value.bytes[i+1]) { error="invalid pattern range"; return false; }
            } else if (op == 2 || op == 3) {
                if (!require(1)) { error="truncated seek byte"; return false; }
                p.value.kind=op==2?PatternInstruction::Kind::Seek:PatternInstruction::Kind::SeekRetry;p.value.bytes.push_back(bytes[pc++]);
            } else { error="unsupported pattern opcode "+std::to_string(op); return false; }
            if (p.value.kind==PatternInstruction::Kind::RepeatRange) {
                p.next=pc;p.fallback=SIZE_MAX;
                if(pc>=length) {error="missing repeat continuation";return false;}
                index[p.pc]=pending.size();pending.push_back(std::move(p));continue;
            }
            if (!require(1)) { error="missing pattern conditional"; return false; }
            uint8_t branch=bytes[pc++];size_t distance=0;
            if (branch==0x0f) p.fallback=SIZE_MAX;
            else if (branch>=0x80) distance=(branch & 0x7f)+1;
            else if (branch==8) {
                if (!require(2)) { error="truncated long branch"; return false; }
                distance=129+u16(bytes+pc);pc+=2;
            } else { error="invalid pattern conditional"; return false; }
            p.next=pc;
            if (distance) {
                if (distance >= length-pc) { error="pattern branch out of bounds"; return false; }
                p.fallback=pc+distance;
            }
            if (pc>=length) { error="missing pattern continuation"; return false; }
        }
        index[p.pc]=pending.size();pending.push_back(std::move(p));
    }
    for (auto& p: pending) {
        auto resolve=[&](size_t target,size_t& into) {
            if(target==SIZE_MAX) {into=SIZE_MAX;return true;}
            auto i=index.find(target);if(i==index.end())return false;into=i->second;return true;
        };
        if(!resolve(p.next,p.value.next)||!resolve(p.fallback,p.value.fallback)) { error="pattern branch enters instruction data";return false; }
        result.instructions.push_back(std::move(p.value));
    }
    return !result.instructions.empty();
}

std::shared_ptr<const Policy> Policy::parse(std::vector<uint8_t> bytes, std::string& error) {
    error.clear();
    if(bytes.size()<16||bytes.size()>1024*1024) {error="invalid policy length";return {};}
    auto b=bytes.data();
    if(u16(b)!=0||b[4]!=std::size(operations)||b[5]||b[6]||b[7]||u16(b+8)||u16(b+10)||u16(b+12)||u16(b+14)) {
        error="unsupported policy header; expected the pinned Intel standalone graph";return {};
    }
    size_t count=u16(b+2), table=16, nodes=(16+std::size(operations)*2+7)&~size_t(7), data=nodes+count*8;
    if(!count||data>bytes.size()) {error="truncated policy node table";return {};}
    auto policy=std::shared_ptr<Policy>(new Policy);policy->_bytes=std::move(bytes);b=policy->_bytes.data();
    for(size_t i=0;i<std::size(operations);i++) {
        uint16_t entry=u16(b+table+i*2);if(entry>=count) {error="operation node out of bounds";return {};}
        policy->_operations.push_back(entry);
    }
    std::unordered_map<uint16_t,std::shared_ptr<const Pattern>> patterns;
    size_t patternBudget=1024*1024;
    for(size_t i=0;i<count;i++) {
        auto raw=b+nodes+i*8;Node n{raw[0],raw[1],u16(raw+2),u16(raw+4),u16(raw+6),{}};
        if(n.type==1) {
            if((n.filter!=0 && n.filter!=1 && n.filter!=5)||n.argument||n.match||n.unmatch) {error="unsupported terminal action/modifier";return {};}
        } else if(n.type==0) {
            if(n.match>=count||n.unmatch>=count) {error="filter edge out of bounds";return {};}
            if(stringFilter(n.filter)) {
                size_t start=data+size_t(n.argument)*8;
                if(start>policy->_bytes.size()||policy->_bytes.size()-start<2) {error="pattern reference out of bounds";return {};}
                size_t size=u16(b+start);start+=2;
                if(size>policy->_bytes.size()-start) {error="pattern data out of bounds";return {};}
                auto found=patterns.find(n.argument);
                if(found!=patterns.end())n.pattern=found->second;
                else {
                    if(size>patternBudget) {error="policy pattern complexity limit";return {};}
                    patternBudget-=size;auto pattern=std::make_shared<Pattern>();
                    if(!parsePattern(b+start,size,*pattern,error)){error="pattern "+std::to_string(n.argument)+": "+error;return {};}
                    n.pattern=pattern;patterns.emplace(n.argument,std::move(pattern));
                }
            } else if(n.filter!=14&&n.filter!=15&&n.filter!=26&&n.filter!=29&&n.filter!=43) {
                error="unsupported filter "+std::to_string(n.filter);return {};
            }
        } else {error="unknown policy node type";return {};}
        policy->_nodes.push_back(std::move(n));
    }
    // Reject cycles without trusting recursion depth from an uploaded graph.
    std::vector<uint8_t> color(count);
    for(size_t start=0;start<count;start++) {
        if(color[start])continue;
        std::vector<std::pair<size_t,bool>> stack{{start,false}};
        while(!stack.empty()) {
            auto [index,leaving]=stack.back();stack.pop_back();
            if(leaving) {color[index]=2;continue;}
            if(color[index]==1) {error="cyclic decision graph";return {};}
            if(color[index]==2)continue;
            color[index]=1;stack.emplace_back(index,true);
            auto& n=policy->_nodes[index];if(!n.type) {stack.emplace_back(n.unmatch,false);stack.emplace_back(n.match,false);}
        }
    }
    // A conservative, context-independent proof. A reachable deny rejects
    // this supported attachment class even if its predicate seems unlikely.
    policy->_alwaysAllow=true;
    std::vector<uint8_t> seen(count);
    std::vector<size_t> pending(policy->_operations.begin(),policy->_operations.end());
    while(!pending.empty()) {
        size_t index=pending.back();pending.pop_back();
        if(seen[index])continue;
        seen[index]=1;const auto& n=policy->_nodes[index];
        if(n.type==1) {if(n.filter&1) {policy->_alwaysAllow=false;break;}}
        else {pending.push_back(n.match);pending.push_back(n.unmatch);}
    }
    return policy;
}

std::optional<bool> Policy::matches(const Pattern& p, std::string_view input) {
    if(input.size()>65535)return std::nullopt;
    // A transition restores its original cursor on the alternative edge. This
    // preserves sharing/backtracking in the original serialized pattern FSA.
    struct Frame {size_t node,pos;};
    std::vector<Frame> stack{{0,0}};
    std::unordered_set<uint64_t> visited;
    size_t budget=2000000;
    auto inRange=[](const auto& ranges,uint8_t c) {
        for(size_t i=0;i<ranges.size();i+=2)if(c>=ranges[i]&&c<=ranges[i+1])return true;
        return false;
    };
    while(!stack.empty()) {
        if(!budget--)return std::nullopt;
        auto [index,pos]=stack.back();stack.pop_back();
        if(index==SIZE_MAX)continue;
        uint64_t key=(uint64_t(index)<<32)|pos;if(!visited.insert(key).second)continue;
        auto& n=p.instructions[index];
        if(n.kind==PatternInstruction::Kind::Accept)return true;
        if(n.fallback!=SIZE_MAX)stack.push_back({n.fallback,pos});
        if(n.kind==PatternInstruction::Kind::Sequence) {
            if(pos<=input.size()&&n.bytes.size()<=input.size()-pos && std::equal(n.bytes.begin(),n.bytes.end(),reinterpret_cast<const uint8_t*>(input.data()+pos)))stack.push_back({n.next,pos+n.bytes.size()});
        } else if(n.kind==PatternInstruction::Kind::End) {
            if(pos==input.size())stack.push_back({n.next,pos+1});
        } else if(n.kind==PatternInstruction::Kind::Range) {
            if(pos<=input.size()&&inRange(n.bytes,pos==input.size()?0:uint8_t(input[pos])))stack.push_back({n.next,pos+1});
        } else if(n.kind==PatternInstruction::Kind::RepeatRange) {
            size_t end=pos;while(end<input.size()&&inRange(n.bytes,uint8_t(input[end])))end++;
            for(size_t at=pos;at<=end;at++)stack.push_back({n.next,at});
        } else if(n.kind==PatternInstruction::Kind::Seek) {
            // The serializer distinguishes one-shot and retrying seeks.
            size_t at=input.find(char(n.bytes[0]),pos);if(at!=std::string_view::npos)stack.push_back({n.next,at+1});
        } else if(n.kind==PatternInstruction::Kind::SeekRetry) {
            for(size_t at=input.find(char(n.bytes[0]),pos);at!=std::string_view::npos;at=input.find(char(n.bytes[0]),at+1))stack.push_back({n.next,at+1});
        }
    }
    return false;
}

std::optional<bool> Policy::filter(const Node& n,const Context& c) {
    const std::optional<std::string>* value=nullptr;
    switch(n.filter) {
        case 1:value=&c.path;break;case 5:value=&c.posixName;break;
        case 6:value=&c.globalName;break;case 7:value=&c.localName;break;
        case 10:value=&c.controlName;break;case 17:value=&c.iokitClass;break;
        case 18:value=&c.iokitProperty;break;case 28:value=&c.preferenceDomain;break;
        case 38:value=&c.sysctlName;break;case 50:value=&c.xpcServiceName;break;
        case 14:
            switch(n.argument) {
                case 1:return c.targetSelf;case 2:return c.targetSamePgrp;
                case 3:if(c.targetSelf)return !*c.targetSelf;return std::nullopt;
                case 4:return c.targetChild;case 5:return c.targetSameSandbox;
                default:return std::nullopt;
            }
        case 15:if(c.fsctlBaseCommand)return *c.fsctlBaseCommand==n.argument;return std::nullopt;
        case 26:if(c.systemAttributes && n.argument<64)return (*c.systemAttributes & (uint64_t(1)<<n.argument))!=0;return std::nullopt;
        case 29:if(c.vnodeType)return *c.vnodeType==n.argument;return std::nullopt;
        case 43:if(c.processAttributes && n.argument<64)return (*c.processAttributes & (uint64_t(1)<<n.argument))!=0;return std::nullopt;
        default:return std::nullopt;
    }
    bool absent=(c.knownAbsentFilters & (uint64_t(1)<<n.filter))!=0;
    if(absent)return *value?std::optional<bool>{}:std::optional<bool>{false};
    if(!*value)return std::nullopt;
    if((**value).empty())return false;
    if((**value).find('\0')!=std::string::npos)return std::nullopt;
    std::string path;
    if(n.filter==1) {
        // Path predicates are serialized case-folded by this compiler. Other
        // filter strings (notably Mach names and IOKit keys) preserve case.
        path=**value;
        if(path[0]!='/')return std::nullopt;
        for(size_t at=1;at<path.size();) {
            size_t end=path.find('/',at);if(end==std::string::npos)end=path.size();
            auto part=std::string_view(path).substr(at,end-at);
            if(part.empty()||part=="."||part=="..")return std::nullopt;
            at=end+1;
        }
        for(char& ch:path)if(ch>='A'&&ch<='Z')ch+=32;
        return matches(*n.pattern,path);
    }
    return matches(*n.pattern,**value);
}

Decision Policy::evaluate(std::string_view operation,const Context& context) const {
    auto found=std::find(std::begin(operations),std::end(operations),operation);
    if(found==std::end(operations))return Decision::Unsupported;
    if(_alwaysAllow)return Decision::Allow;
    size_t index=_operations[found-std::begin(operations)];
    for(size_t steps=0;steps<_nodes.size();steps++) {
        auto& n=_nodes[index];if(n.type==1)return (n.filter&1)?Decision::Deny:Decision::Allow;
        auto matched=filter(n,context);if(!matched)return Decision::Unsupported;
        index=*matched?n.match:n.unmatch;
    }
    return Decision::Unsupported;
}
}
