# Code Review Agent

## Project Overview

**What this project does:**
This is a portable, universal code review tool built with Claude Code Subagent that helps developers write better, more secure, and more performant code. It provides comprehensive code reviews using specialized Skills for quality, security, and performance analysis, supporting both Backend (Python/FastAPI) and Frontend (React/Angular) development.

**Tech Stack:**
- **Platform:** Claude Code (CLI tool)
- **Skills:** Markdown-based Skills (code-review, security-review, performance-review)
- **Subagent:** code-reviewer agent configuration
- **Languages Supported:** Python, TypeScript/JavaScript, Any (universal patterns)

**Architecture Pattern:**
Skills-based architecture with specialized review domains:
- code-review: Quality, SOLID, design patterns
- security-review: OWASP Top 10, vulnerabilities
- performance-review: Optimization, bottlenecks

## Code Review Standards

This project follows universal best practices that work across Backend and Frontend:

### Code Quality Requirements

```yaml
function_max_length: 25 lines
cyclomatic_complexity_max: 7
documentation: All Skills must have clear examples
consistency: Examples must show both BAD and GOOD code
educational_tone: Always explain WHY, not just WHAT
```

### Documentation Standards

#### Skill Documentation

All Skills must include:
- Clear overview of what it checks
- Methodology/checklist
- Multiple examples (Backend + Frontend)
- Bad code with explanation
- Good code with best practices
- Tool integration instructions
- Learning resources

Example structure:
```markdown
## Overview
- What this skill does
- Key focus areas

## Methodology
- Step-by-step approach
- What to check

## Examples
### Backend Example (Python/FastAPI)
### Frontend Example (React/Angular)

## Checklist
- Universal items
- Backend-specific items
- Frontend-specific items

## Tools Integration
## Learning Resources
```

### File Organization

```
.claude/
├── agents/
│   └── code-reviewer/
│       └── AGENT.md              # Subagent behavior definition
└── skills/
    ├── code-review/
    │   └── SKILL.md              # Quality analysis skill
    ├── security-review/
    │   └── SKILL.md              # Security analysis skill
    └── performance-review/
        └── SKILL.md              # Performance analysis skill

templates/
└── CLAUDE.template.md            # Template for other projects

docs/
├── README.md                     # Main documentation
└── USAGE.md                      # Usage guide
```

## Skill Development Guidelines

### When Adding New Examples

1. **Show Both Stacks** - If adding a backend example, also add a frontend one
2. **Explain WHY** - Don't just show bad code, explain why it's problematic
3. **Provide Context** - Link to documentation, OWASP, performance guides
4. **Be Specific** - Include file paths, line numbers in examples
5. **Stay Current** - Use modern frameworks (React 18+, Angular 16+, FastAPI 0.104+)

### Example Quality Criteria

Good examples should:
- [ ] Show realistic scenarios
- [ ] Include both BAD and GOOD code
- [ ] Explain the impact of the issue
- [ ] Provide actionable solutions
- [ ] Link to learning resources
- [ ] Use consistent formatting
- [ ] Have clear comments

### Tone and Approach

When writing Skill content:
- 🎓 **Educate** - This tool helps junior developers learn
- 🤝 **Be constructive** - No shaming, always suggest improvements
- 📚 **Provide context** - Link to official docs and resources
- ✨ **Acknowledge good practices** - Not just problems
- 🎯 **Be specific** - File paths, line numbers, concrete examples
- 💬 **Ask questions** - "Have you considered..." not "You must..."

## Testing Review Quality

### Manual Testing Checklist

When adding/updating Skills, test with:

- [ ] **Backend code sample** - Python FastAPI endpoint
- [ ] **Frontend code sample** - React component
- [ ] **Security vulnerability** - SQL injection, XSS
- [ ] **Performance issue** - N+1 query, unnecessary re-renders
- [ ] **Good code** - Should acknowledge positives
- [ ] **Mixed code** - Some good, some bad (realistic)

### Example Test Cases

```bash
# Test 1: Review Python FastAPI code
claude "Review this file" api/users.py

# Test 2: Review React component
claude "Review this component" src/components/UserList.tsx

# Test 3: Security review
claude "Check for security issues" api/auth.py

# Test 4: Performance review
claude "Find performance bottlenecks" src/pages/Dashboard.tsx

# Test 5: Full PR review
claude "Review PR #123"
```

## Portability Requirements

This tool must work on any project with minimal setup:

### Setup Process (Target: < 5 minutes)

1. Copy `.claude/` folder to target project
2. Customize `CLAUDE.md` with project standards
3. Run review command

### What Makes It Portable

- ✅ **No code dependencies** - Pure markdown Skills
- ✅ **Universal patterns** - Works for any language
- ✅ **Project adaptation** - CLAUDE.md customization
- ✅ **Self-contained** - All Skills in one folder
- ✅ **Version controlled** - `.claude/` committed to git

### CLAUDE.md Customization

Each project should customize:
- Tech stack specifics
- Coding standards
- Security requirements
- Performance SLAs
- Test coverage minimums
- Architectural patterns

## Review Checklist

### Before Committing Changes

- [ ] All Skills have Backend + Frontend examples
- [ ] Examples are realistic and current
- [ ] Tone is educational and constructive
- [ ] Formatting is consistent
- [ ] Links work and point to current docs
- [ ] CLAUDE.md reflects latest standards
- [ ] Template updated if structure changed
- [ ] README reflects new capabilities

### Before Release

- [ ] Tested on Backend project
- [ ] Tested on Frontend project
- [ ] Tested on Full-stack project
- [ ] Setup script works
- [ ] Documentation is clear
- [ ] Examples run without errors
- [ ] CLAUDE.template.md is up to date

## Resources

### Official Claude Code Documentation
- [Claude Code CLI](https://code.claude.com/)
- [Skills Documentation](https://code.claude.com/docs/en/skills.md)
- [Sub-agents](https://code.claude.com/docs/en/sub-agents.md)

### Code Quality Resources
- [SOLID Principles](https://en.wikipedia.org/wiki/SOLID)
- [Clean Code by Robert C. Martin](https://www.amazon.com/Clean-Code-Handbook-Software-Craftsmanship/dp/0132350882)
- [Refactoring Guru](https://refactoring.guru/)

### Security Resources
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [CWE Top 25](https://cwe.mitre.org/top25/)

### Performance Resources
- [Web.dev Performance](https://web.dev/performance/)
- [FastAPI Performance](https://fastapi.tiangolo.com/deployment/concepts/)
- [Angular Performance](https://angular.dev/best-practices/runtime-performance)
- [React Performance](https://react.dev/learn/render-and-commit)
- [Database Performance](https://use-the-index-luke.com/)

## Contributing Guidelines

### Adding New Skills

1. Create skill directory: `.claude/skills/new-skill/`
2. Write `SKILL.md` with examples for both stacks
3. Update `code-reviewer/AGENT.md` to include new skill
4. Test with sample code
5. Update documentation

### Improving Existing Skills

1. Add examples for underrepresented areas
2. Update outdated framework versions
3. Improve explanations
4. Add more learning resources
5. Fix broken links

## Contact

**Maintainer:** Code Review Agent Team
**Issues:** Open GitHub issue
**Questions:** Open GitHub discussion

---

**Last Updated:** 2026-01-07
**Version:** 1.0.0
**License:** MIT
