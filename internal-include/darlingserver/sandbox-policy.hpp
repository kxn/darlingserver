/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace DarlingServer::Sandbox {
enum class Decision { Allow, Deny, Unsupported };
struct Context {
    std::optional<std::string> path, globalName, localName, posixName, controlName;
    std::optional<std::string> iokitClass, iokitProperty, preferenceDomain, sysctlName, xpcServiceName;
    // Missing context is unknown; a known-inapplicable filter is false. For
    // example, a global bootstrap lookup has no local or XPC-service name.
    uint64_t knownAbsentFilters = 0;
    std::optional<bool> targetSelf, targetSamePgrp, targetChild, targetSameSandbox;
    std::optional<uint32_t> vnodeType, fsctlBaseCommand;
    // A bit at the native attribute ordinal, not the ordinal itself.
    std::optional<uint64_t> processAttributes, systemAttributes;
};
// This evaluates the original compiler's decision graph. It does not attach a
// policy or claim that the filesystem/Mach operations have been confined.
class Policy {
public:
    static std::shared_ptr<const Policy> parse(std::vector<uint8_t> bytes, std::string& error);
    Decision evaluate(std::string_view operation, const Context& context) const;
    // True only when every leaf reachable from all native operation entries
    // allows. Unreachable compiler sentinel deny nodes do not restrict policy.
    bool allowsAllOperations() const { return _alwaysAllow; }
    size_t nodeCount() const { return _nodes.size(); }
    static std::string_view operationName(size_t index);
private:
    struct PatternInstruction {
        enum class Kind { Sequence, End, Range, RepeatRange, Seek, SeekRetry, Accept } kind;
        std::vector<uint8_t> bytes;
        size_t next = 0, fallback = SIZE_MAX;
    };
    struct Pattern { std::vector<PatternInstruction> instructions; };
    struct Node {
        uint8_t type = 0, filter = 0;
        uint16_t argument = 0, match = 0, unmatch = 0;
        std::shared_ptr<const Pattern> pattern;
    };
    std::vector<uint8_t> _bytes;
    std::vector<uint16_t> _operations;
    std::vector<Node> _nodes;
    bool _alwaysAllow = false;
    static bool parsePattern(const uint8_t* bytes, size_t length, Pattern& result, std::string& error);
    static std::optional<bool> matches(const Pattern& pattern, std::string_view input);
    static std::optional<bool> filter(const Node& node, const Context& context);
};
}
