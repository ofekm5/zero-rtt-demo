---
name: prevent-unauthorized-documentation-creation
enabled: true
event: file
conditions:
  - field: file_path
    operator: regex_match
    pattern: \.(md|txt|rst|adoc)$
  - field: file_path
    operator: regex_match
    pattern: (docs?/|documentation/|guide|tutorial|manual|spec|api\.md|changelog|contributing|license|install|setup|getting.?started)
action: warn
---

⚠️ **WARNING: Unauthorized Documentation Creation Detected**

You are creating documentation files without explicit user request.

**REMINDER:**
Creating documentation files should only be done when user explicitly requests them.

**FORBIDDEN DOCUMENTATION FILES:**
- *.md files (except code-related files)
- *.txt documentation files
- docs/ directory files
- API documentation
- User guides or tutorials
- Installation instructions
- Contributing guidelines

**WHEN DOCUMENTATION CREATION IS ALLOWED:**
- User explicitly requests "create documentation"
- User asks for specific doc files: "make an API guide"
- User requests "write a tutorial"
- Clear instruction to create help files

**EXEMPTED FILES (OK to create):**
- Configuration files (*.json, *.yaml, *.toml)
- Code files (*.js, *.py, *.go, etc.)
- Data files needed for functionality
- Test files
- Build/deployment files

**WHAT TO DO INSTEAD:**
1. **Ask first:** Use AskUserQuestion to confirm documentation need
2. **Focus on functionality:** Complete actual work instead of docs
3. **Edit existing:** If docs exist, edit them instead of creating new
4. **Suggest later:** Offer documentation after main functionality is done

**RECOMMENDED ACTION:**
Consider if documentation creation was explicitly requested. If not, focus on functionality instead.

**Remember:** Create documentation files only when explicitly requested by user.