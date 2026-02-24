---
name: prevent-assumption-execution
enabled: true
event: PreToolUse
conditions:
  - field: tool_name
    operator: regex_match
    pattern: "(Edit|Write)"
  - field: prompt
    operator: regex_match
    pattern: "(assume|typically|usually|should be|I think|probably)"
action: warn
---

⚠️ **WARNING: Assumption-Based Execution Detected**

Your response contains assumption language - consider clarifying requirements first:

**MANDATORY VERIFICATION:**
- [ ] Were all user requirements clearly specified?
- [ ] Did you use AskUserQuestion for any ambiguous aspects?
- [ ] Are you certain about implementation choices made?
- [ ] Did you avoid guessing user preferences or missing details?

**RED FLAGS - STOP AND ASK:**
- User said "add a feature" without specifying details
- Multiple valid implementation approaches exist
- User preferences/constraints weren't clarified
- Technical decisions made without user input
- Ambiguous words like "optimize", "improve", "fix" without specifics

**ASSUMPTION INDICATORS:**
- "I assume you want..."
- "Typically this would..."
- "I'll implement this as..."
- Making architecture choices without asking
- Proceeding with incomplete requirements

**REQUIRED ACTION:**
If ANY requirements were unclear, you MUST use AskUserQuestion to clarify before proceeding.

**Remember:** NEVER assume or guess missing requirements. STOP and ask if ANYTHING is unclear.