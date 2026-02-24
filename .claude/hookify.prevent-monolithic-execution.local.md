---
name: prevent-monolithic-execution
enabled: true
event: PreToolUse
conditions:
  - field: tool_name
    operator: equals
    pattern: "Edit"
  - field: prompt
    operator: regex_match
    pattern: "(complex|large|multi-step|implement|build|create|feature|refactor)"
action: warn
---

⚠️ **WARNING: Complex Task Without Planning Detected**

You're starting a potentially complex task that should use incremental planning:

**MANDATORY CHECKS:**
- [ ] Did you use TodoWrite to break down complex tasks?
- [ ] Were tasks tracked step-by-step with status updates?
- [ ] Did you mark todos as completed incrementally (not batched)?
- [ ] Was the approach incremental rather than monolithic?

**VIOLATION INDICATORS:**
- Completing large tasks without TodoWrite planning
- Batching multiple completions at once
- Attempting complex implementations without breakdown
- Missing progress tracking for multi-step work

**REQUIRED ACTIONS:**
1. Create TodoWrite plan if missing
2. Break down remaining work into trackable steps
3. Mark current progress appropriately
4. Only proceed with small, manageable increments

**Remember:** Complex tasks MUST be broken into small, trackable steps. NO monolithic approaches allowed.