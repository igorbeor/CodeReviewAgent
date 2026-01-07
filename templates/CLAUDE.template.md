# Project Name

> **Instructions:** This is a template for CLAUDE.md. Copy this file to the root `.claude/` directory
> of your project and customize it with your project-specific standards and requirements.

## Project Overview

**What this project does:**
<!-- Brief description of the project's purpose and main functionality -->

**Tech Stack:**
<!-- List main technologies, frameworks, and libraries -->
- **Language:**
- **Framework:**
- **Database:**
- **Other:**

**Architecture Pattern:**
<!-- E.g., MVC, Clean Architecture, Microservices, etc. -->

## Code Review Standards

### Code Quality Requirements

#### General Standards

```yaml
function_max_length: 20-25 lines
cyclomatic_complexity_max: 7
test_coverage_minimum: 80%
type_hints: required  # or: recommended, optional
docstrings: required  # or: recommended, optional, none
```

#### Naming Conventions

<!-- Customize based on your language/framework -->

**Python Example:**
```python
# Functions and variables: snake_case
def calculate_total_price():
    user_name = "John"

# Classes: PascalCase
class UserRepository:
    pass

# Constants: UPPER_SNAKE_CASE
MAX_RETRY_ATTEMPTS = 3

# Private methods/variables: _leading_underscore
def _internal_method():
    pass
```

**TypeScript Example:**
```typescript
// Functions and variables: camelCase
function calculateTotalPrice(): number {
    const userName = "John";
}

// Classes and Interfaces: PascalCase
class UserRepository {}
interface IUserService {}

// Constants: UPPER_SNAKE_CASE
const MAX_RETRY_ATTEMPTS = 3;
```

#### Code Organization

```
Project structure requirements:
- [ ] One class per file (or specify your standard)
- [ ] Max file size: XXX lines
- [ ] Imports organized: stdlib, third-party, local
- [ ] Clear separation of concerns
```

### Security Requirements

#### Authentication & Authorization

<!-- Describe your auth approach -->
```markdown
- [ ] All endpoints require authentication (except: /health, /docs)
- [ ] Use JWT tokens with XXX expiration
- [ ] Role-based access control (RBAC) enforced
- [ ] MFA required for admin accounts
```

#### Data Protection

```markdown
- [ ] All passwords hashed with bcrypt/argon2
- [ ] No secrets in code (use environment variables)
- [ ] PII encrypted at rest
- [ ] HTTPS/TLS enforced
```

#### Input Validation

```markdown
- [ ] All user input validated
- [ ] Parameterized queries only (no string concatenation)
- [ ] Request size limits enforced
- [ ] File upload restrictions
```

#### Required Security Headers

```python
# Example for FastAPI
response.headers["X-Content-Type-Options"] = "nosniff"
response.headers["X-Frame-Options"] = "DENY"
response.headers["Strict-Transport-Security"] = "max-age=31536000"
response.headers["Content-Security-Policy"] = "default-src 'self'"
```

#### Compliance Requirements

<!-- Check all that apply -->
```markdown
- [ ] GDPR compliant
- [ ] PCI DSS (if handling payments)
- [ ] HIPAA (if handling health data)
- [ ] SOC 2
- [ ] Other: ___________
```

### Performance Requirements

#### API Performance SLAs

```yaml
p50_response_time: "< 100ms"
p95_response_time: "< 200ms"
p99_response_time: "< 500ms"
max_response_time: "2000ms"
```

#### Database Requirements

```markdown
- [ ] All queries must use indexes
- [ ] No SELECT * queries
- [ ] Pagination required for lists (max XXX items)
- [ ] Connection pooling configured
- [ ] Slow query logging enabled (> XXXms)
```

#### Caching Strategy

```markdown
Cache what:
- [ ] Static data (TTL: ___ minutes)
- [ ] User sessions (TTL: ___ minutes)
- [ ] API responses (TTL: ___ minutes)
- [ ] Database queries (TTL: ___ minutes)

Invalidation strategy:
<!-- Describe when/how cache is invalidated -->
```

#### Resource Limits

```yaml
max_request_body_size: "10MB"
max_concurrent_requests: 1000
max_database_connections: 50
max_memory_per_request: "500MB"
```

### Testing Requirements

#### Test Coverage

```yaml
minimum_coverage: 80%
critical_path_coverage: 100%
```

#### Required Test Types

```markdown
- [ ] Unit tests (for all business logic)
- [ ] Integration tests (for API endpoints)
- [ ] E2E tests (for critical user flows)
- [ ] Performance tests (for key endpoints)
- [ ] Security tests (for auth/permissions)
```

#### Test Standards

```python
# Example test structure
def test_user_registration_success():
    """Test that valid user data creates account."""
    # Arrange
    user_data = {"email": "test@example.com", "password": "SecurePass123!"}

    # Act
    response = client.post("/register", json=user_data)

    # Assert
    assert response.status_code == 201
    assert "id" in response.json()
```

### Documentation Requirements

#### Code Documentation

```markdown
- [ ] All public functions/methods have docstrings
- [ ] Complex algorithms explained with comments
- [ ] README.md updated for API changes
- [ ] CHANGELOG.md maintained
```

#### API Documentation

```markdown
- [ ] OpenAPI/Swagger spec
- [ ] Request/response examples
- [ ] Error codes documented
- [ ] Authentication docs
```

### Git Workflow

#### Branch Naming

```
feature/SHORT-DESCRIPTION
bugfix/SHORT-DESCRIPTION
hotfix/SHORT-DESCRIPTION
refactor/SHORT-DESCRIPTION
```

#### Commit Messages

```
type(scope): brief description

- feat: new feature
- fix: bug fix
- refactor: code refactoring
- docs: documentation
- test: tests
- perf: performance improvement
- security: security fix

Example: feat(auth): add MFA support
```

#### Pull Request Requirements

```markdown
- [ ] All tests pass
- [ ] Code coverage maintained/improved
- [ ] No linter warnings
- [ ] Documentation updated
- [ ] CHANGELOG updated
- [ ] Reviewed by at least 1 person (or X people)
```

## Design Patterns & Architecture

### Preferred Patterns

<!-- List patterns commonly used in your project -->

```markdown
**Dependency Injection:** Yes/No
**Repository Pattern:** Yes/No
**Service Layer:** Yes/No
**Factory Pattern:** When to use
**Observer Pattern:** When to use
```

### Architecture Decisions

<!-- Document key architectural choices -->

```markdown
**API Design:** RESTful / GraphQL / gRPC
**State Management:** [Describe approach]
**Error Handling:** [Describe strategy]
**Logging:** [Structured logging, log levels, etc.]
```

### Example Structure

<!-- Show ideal code organization -->

```
project/
├── api/               # API endpoints
│   ├── dependencies/  # FastAPI dependencies
│   ├── routes/        # Route handlers
│   └── schemas/       # Pydantic models
├── core/              # Core business logic
│   ├── services/      # Business services
│   ├── repositories/  # Data access
│   └── models/        # Domain models
├── infrastructure/    # External integrations
│   ├── database/      # DB config
│   ├── cache/         # Cache config
│   └── external/      # External APIs
└── tests/             # Tests mirroring src structure
```

## Linting & Formatting

### Tools Configuration

<!-- Specify linters and formatters -->

**Python Example:**
```yaml
Linters:
  - pylint
  - mypy (strict mode)
  - bandit (security)

Formatters:
  - black (line length: 100)
  - isort (import sorting)

Pre-commit hooks: Yes
```

**TypeScript Example:**
```yaml
Linters:
  - ESLint (airbnb config)
  - TypeScript strict mode

Formatters:
  - Prettier (single quotes, 2 spaces)

Pre-commit hooks: Yes
```

### Auto-Fix on Save

```markdown
Editor should auto-fix:
- [ ] Import sorting
- [ ] Code formatting
- [ ] Remove unused imports
- [ ] Organize imports
```

## Project-Specific Rules

<!-- Add any custom rules specific to your project -->

### Do's ✅

```markdown
1. Always use type hints (Python) / TypeScript
2. Use Pydantic for data validation
3. Handle errors explicitly (no bare except)
4. Log important operations with context
5. Write self-documenting code
```

### Don'ts ❌

```markdown
1. Never commit secrets or API keys
2. Don't use `SELECT *` in queries
3. Don't bypass authentication checks
4. Don't use `eval()` or `exec()`
5. Don't ignore linter warnings
```

### Special Considerations

```markdown
**Backward Compatibility:**
<!-- How to handle breaking changes -->

**Feature Flags:**
<!-- If/how feature flags are used -->

**Deprecation Policy:**
<!-- How to deprecate features -->

**Migration Strategy:**
<!-- How to handle DB/API migrations -->
```

## Third-Party Dependencies

### Approved Libraries

<!-- List approved libraries for common tasks -->

```markdown
**HTTP Client:** httpx, requests
**Validation:** pydantic
**Testing:** pytest
**Async:** asyncio
**ORM:** SQLAlchemy
**Caching:** redis, memcached
```

### Forbidden Libraries

<!-- List libraries that should not be used -->

```markdown
- [Library name]: Reason why it's forbidden
```

### Adding New Dependencies

```markdown
Process for adding new dependency:
1. Check for security vulnerabilities
2. Verify license compatibility
3. Consider bundle size / performance
4. Get approval from: [team lead / architecture review]
```

## Review Checklist

### Code Reviewer Should Check

```markdown
- [ ] Code follows project standards
- [ ] Tests cover new functionality
- [ ] No security vulnerabilities
- [ ] No performance regressions
- [ ] Documentation is updated
- [ ] Error handling is appropriate
- [ ] Logging is adequate
- [ ] No hardcoded values
- [ ] Database queries are optimized
- [ ] API contracts not broken
```

### Before Requesting Review

```markdown
As a developer, I have:
- [ ] Run all tests locally
- [ ] Run linters and fixed warnings
- [ ] Updated documentation
- [ ] Added/updated tests
- [ ] Tested manually
- [ ] Checked for console errors
- [ ] Reviewed my own code first
```

## Resources

### Internal Documentation

```markdown
- Architecture Docs: [Link]
- API Documentation: [Link]
- Deployment Guide: [Link]
- Troubleshooting: [Link]
```

### External Resources

```markdown
- [Framework Documentation](URL)
- [Company Style Guide](URL)
- [Security Best Practices](URL)
```

## Contact & Support

```markdown
**Tech Lead:** [Name]
**Security Contact:** [Name/Email]
**Architecture Questions:** [Channel/Person]
```

---

**Last Updated:** [Date]
**Version:** [Version number of this standards document]
