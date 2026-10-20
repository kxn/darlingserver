# Headless audit-session compatibility

A server-owned AuditSession lifetime object now belongs to each Process. The
first unmanaged bootstrap process establishes a headless session from its actual
Linux UID. Children inherit the object and per-process masks; Mach-O exec keeps
both. New session creation allocates a distinct server ID, not a fixed success
value. Mach audit-token AUID and ASID are synchronized with the context.

The append-only audit_info RPC serves the paired darling-xnu getaudit_addr and
setaudit_addr implementation. Guest pointer reads/writes use checked process
memory operations. Setter authorization uses the actual caller's Linux effective
UID. Native tests run in the normal root-mapped Darling namespace.

Only headless attributes are supported: granting UI/TTY/remote attributes and
joining other sessions by a chosen ID return errors. Audit-session Mach ports,
auditon queries for other sessions and complete macOS audit semantics remain
unfinished. This is not a complete BSM implementation or a claim of graphics
access. Session identity and masks survive real fork/exec, rather than relying on
environment variables or process-local static storage.

`audit-session-lifecycle.c` is a standalone non-ARC C executable linked with
Security and libSystem. Run it with the paired source kernel/server under the
Linux integration resource-tool environment. The parent performs 261 checks;
two forked-and-execed children perform 138 each. Coverage includes real Security
SessionGetInfo, Mach TASK_AUDIT_TOKEN, 16 distinct new sessions, independent
masks, partial/zero-length copies, bad pointers, malformed terminal types and
rejected graphics attributes. Full Unity/UE compilation and signing are separate
requirements; they have not passed yet.
