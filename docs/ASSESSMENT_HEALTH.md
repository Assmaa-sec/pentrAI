# Local assessment health checks

The approved scope is diagnostic checks and intermediate activity for the existing
local source-assessment path. Preserve authorization, grants, resource limits,
finding validation, and cleanup-before-completion semantics. No schema or UI
redesign is required; use existing visible events.

Implementation steps:

1. Classify model setup, Docker, source, provider, result, deadline, and cleanup
   failures with fixed safe messages. Never publish raw exceptions or tool output.
2. Check dependencies before admission. Refresh readiness during active work;
   bound model waits by the existing job deadline and honor cancellation.
3. Send bounded, allowlisted runner stage notifications. Explain long waits
   without treating a process heartbeat as proof of analysis progress.
4. Make the API event stream observe new transactions and report unavailable
   execution or overdue cleanup, even when the worker has stopped. API checks
   never execute tools, delete containers, or invent a successful outcome.
5. Test failure paths, cancellation, healthy completion, tenant boundaries,
   event replay, and Linux-independent orchestration; document Linux-only checks.

Operational limits: warnings require a functioning API/database. Container cleanup
requires Docker and the worker/reaper to be running. When infrastructure is down,
show that cleanup is pending and preserve its retryable lease rather than falsely
claiming cleanup or completion. No finite audit can guarantee every external
failure mode has been eliminated.
