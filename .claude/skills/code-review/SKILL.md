---
name: code-review
description: Performs comprehensive code quality analysis, checks adherence to best practices, SOLID principles, and design patterns. Use when reviewing pull requests, analyzing code changes, or when feedback on code quality is needed.
allowed-tools: Read, Grep, Glob, Bash
---

# Code Review Skill

## Overview

This Skill provides comprehensive code reviews focusing on:

- **Code Quality** - readability, maintainability, simplicity
- **SOLID Principles** - Single Responsibility, Open/Closed, Liskov Substitution, Interface Segregation, Dependency Inversion
- **Design Patterns** - proper application of design patterns
- **Code Smells** - detection of anti-patterns and problematic code
- **Test Coverage** - verification of test presence and quality
- **Documentation** - comments, docstrings, README

## Review Methodology

### 1. First Pass: Understanding Context

Before analyzing code:

1. **Read CLAUDE.md** - understand project standards and rules
2. **Determine change type** - new feature, bug fix, refactoring, tests
3. **Assess scope** - how many files, what's the size of changes
4. **Understand purpose** - what problem does the code solve

### 2. Code Quality Analysis

For each file, check:

#### Readability
- Variable, function, and class names are descriptive and clear
- Functions are short (up to 20-25 lines)
- Cyclomatic complexity is low (up to 5-7)
- No deep nesting (maximum 3-4 levels)
- Code is self-documenting

#### DRY (Don't Repeat Yourself)
- No code duplication
- Common logic extracted into functions/classes
- Constants and magic numbers extracted into variables

#### SOLID Principles
- **Single Responsibility** - each class/function has one responsibility
- **Open/Closed** - code is open for extension, closed for modification
- **Liskov Substitution** - subclasses can replace parent classes
- **Interface Segregation** - interfaces are client-specific
- **Dependency Inversion** - depend on abstractions, not concrete implementations

#### Error Handling
- All errors are handled appropriately
- Specific exceptions are used
- Graceful degradation exists
- Errors are logged but don't contain sensitive information

### 3. Architecture and Design Patterns

Check for:

- **Correct pattern application** - is the appropriate pattern used
- **Dependency Injection** - dependencies are passed from outside
- **Separation of Concerns** - logic is separated into layers (presentation, business, data)
- **Modularity** - code is split into logical modules
- **Coupling/Cohesion** - low coupling, high cohesion

### 4. Testing

Evaluate:

- **Test presence** - are there unit/integration tests
- **Coverage** - are critical paths covered
- **Test quality** - tests verify correct behavior
- **Test Isolation** - tests are independent of each other
- **Edge Cases** - boundary cases are tested

### 5. Documentation

Check:

- **Comments** - complex logic is explained
- **Docstrings** - functions/classes have descriptions
- **README** - updated when API/architecture changes
- **Changelog** - significant changes are documented

## Output Format

Structure your review as follows:

```markdown
## 📋 Summary

**Change Type:** [Feature/Bug Fix/Refactor/Tests/Docs]
**Files Changed:** [number]
**Overall Rating:** ⭐⭐⭐⭐☆ (4/5)

---

## 🚨 Critical Issues (Must Fix)

> Issues that MUST be fixed before merge

### 1. [Issue Title]

**File:** `path/to/file.py:45`
**Description:** Detailed description of the issue
**Why It Matters:** Explanation of why this is critical
**Solution:**
```python
# Example fix
```

---

## ⚠️ Warnings (Should Fix)

> Issues that should be fixed, but don't block merge

### 1. [Warning Title]

**File:** `path/to/file.py:78`
**Description:** Issue description
**Recommendation:** How to improve

---

## 💡 Suggestions (Nice to Have)

> Ideas for improvement, optional

- Suggestion 1
- Suggestion 2

---

## ✅ What's Good

> Positive aspects of the code

- Good practice 1
- Good practice 2

---

## ❓ Questions for Discussion

> Points that need clarification

1. Question 1
2. Question 2

---

## 📚 Learning Resources

> For junior developers - links to resources for improvement

- [Resource 1](url)
- [Resource 2](url)
```

## Analysis Examples

### Example 1: Function Analysis

**Bad Code:**
```python
def process(data, type, flag):
    result = []
    if type == 1:
        for item in data:
            if flag:
                result.append(item * 2)
            else:
                result.append(item)
    elif type == 2:
        for item in data:
            if flag:
                result.append(item + 10)
            else:
                result.append(item)
    return result
```

**Issues:**
1. Unclear parameter names (`type`, `flag`)
2. Magic numbers (1, 2, 10)
3. Logic duplication
4. Violates Single Responsibility

**Recommended Fix:**
```python
from enum import Enum
from typing import List

class TransformationType(Enum):
    MULTIPLY = "multiply"
    ADD = "add"

def transform_data(
    data: List[int],
    transformation: TransformationType,
    apply_transformation: bool
) -> List[int]:
    """
    Transform data according to specified type.

    Args:
        data: List of numbers to process
        transformation: Type of transformation
        apply_transformation: Whether to apply transformation

    Returns:
        List of transformed data
    """
    if not apply_transformation:
        return data.copy()

    transformers = {
        TransformationType.MULTIPLY: lambda x: x * 2,
        TransformationType.ADD: lambda x: x + 10
    }

    transformer = transformers.get(transformation)
    if transformer is None:
        raise ValueError(f"Unknown transformation: {transformation}")

    return [transformer(item) for item in data]
```

### Example 2: Class Analysis

**Bad Code:**
```python
class UserManager:
    def __init__(self, db_connection):
        self.db = db_connection

    def create_user(self, email, password):
        # Validation
        if '@' not in email:
            return False

        # Hash password
        import hashlib
        hashed = hashlib.md5(password.encode()).hexdigest()

        # Save to DB
        self.db.execute(f"INSERT INTO users (email, password) VALUES ('{email}', '{hashed}')")

        # Send email
        import smtplib
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.send_email(email, "Welcome!")

        return True
```

**Issues:**
1. ❌ **Violates SRP** - class does too much (validation, hashing, DB, email)
2. ❌ **SQL Injection** - dangerous SQL concatenation
3. ❌ **Weak hashing** - MD5 is insecure for passwords
4. ❌ **Hardcoded config** - SMTP settings in code
5. ❌ **No error handling** - what if DB or email fail?
6. ❌ **No type hints** - unclear parameter types

**Recommended Fix:**
```python
from typing import Protocol
from dataclasses import dataclass
import bcrypt

# Define Protocols (Interfaces)
class UserRepository(Protocol):
    """Interface for user data persistence."""
    def save(self, user: 'User') -> None: ...

class EmailService(Protocol):
    """Interface for email operations."""
    def send_welcome_email(self, email: str) -> None: ...

class PasswordHasher(Protocol):
    """Interface for password hashing."""
    def hash(self, password: str) -> str: ...

# Value Objects
@dataclass
class Email:
    """Email value object with built-in validation."""
    value: str

    def __post_init__(self):
        if '@' not in self.value or '.' not in self.value:
            raise ValueError(f"Invalid email: {self.value}")

@dataclass
class User:
    """User entity."""
    email: Email
    password_hash: str

# Concrete Implementations
class BcryptPasswordHasher:
    """Bcrypt implementation of password hashing."""

    def hash(self, password: str) -> str:
        return bcrypt.hashpw(
            password.encode('utf-8'),
            bcrypt.gensalt()
        ).decode('utf-8')

class PostgresUserRepository:
    """PostgreSQL implementation of user repository."""

    def __init__(self, db_connection):
        self.db = db_connection

    def save(self, user: User) -> None:
        # Use parameterized query (prevents SQL injection)
        self.db.execute(
            "INSERT INTO users (email, password_hash) VALUES (%s, %s)",
            (user.email.value, user.password_hash)
        )

class SMTPEmailService:
    """SMTP implementation of email service."""

    def __init__(self, smtp_host: str, smtp_port: int):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port

    def send_welcome_email(self, email: str) -> None:
        import smtplib
        server = smtplib.SMTP(self.smtp_host, self.smtp_port)
        server.send_email(email, "Welcome!")

# Application Service (Single Responsibility)
class UserRegistrationService:
    """
    Service for handling user registration.

    Follows Dependency Inversion - depends on abstractions (Protocols),
    not concrete implementations.
    """

    def __init__(
        self,
        user_repository: UserRepository,
        password_hasher: PasswordHasher,
        email_service: EmailService
    ):
        self.user_repository = user_repository
        self.password_hasher = password_hasher
        self.email_service = email_service

    def register_user(self, email: str, password: str) -> User:
        """
        Register a new user.

        Args:
            email: User's email address
            password: User's password (will be hashed)

        Returns:
            Created user object

        Raises:
            ValueError: If email is invalid
            RegistrationError: If registration fails
        """
        try:
            # Validate email
            user_email = Email(email)

            # Hash password
            password_hash = self.password_hasher.hash(password)

            # Create user
            user = User(email=user_email, password_hash=password_hash)

            # Persist user
            self.user_repository.save(user)

            # Send welcome email
            self.email_service.send_welcome_email(email)

            return user

        except ValueError as e:
            raise e
        except Exception as e:
            raise RegistrationError(f"Failed to register user: {e}") from e

# Usage Example (Dependency Injection)
def create_user_registration_service(db_connection, smtp_config):
    """Factory function demonstrating dependency injection."""
    user_repository = PostgresUserRepository(db_connection)
    password_hasher = BcryptPasswordHasher()
    email_service = SMTPEmailService(
        smtp_host=smtp_config['host'],
        smtp_port=smtp_config['port']
    )

    return UserRegistrationService(
        user_repository=user_repository,
        password_hasher=password_hasher,
        email_service=email_service
    )

class RegistrationError(Exception):
    """Custom exception for registration failures."""
    pass
```

## Review Checklist

Use this checklist for each file:

- [ ] **Names** - variables, functions, classes have descriptive names
- [ ] **Function length** - up to 20-25 lines
- [ ] **Complexity** - cyclomatic complexity < 7
- [ ] **DRY** - no code duplication
- [ ] **SOLID** - principles are followed
- [ ] **Error handling** - errors are handled correctly
- [ ] **Type hints** - types are specified (for Python/TypeScript)
- [ ] **Docstrings** - public functions/classes are documented
- [ ] **Tests** - tests exist for new functionality
- [ ] **Security** - no obvious vulnerabilities
- [ ] **Performance** - no obvious performance issues
- [ ] **Dependencies** - new dependencies are justified

## Project Adaptation

Always check **CLAUDE.md** for project-specific rules:

- Coding standards (style guide, naming conventions)
- Project architectural patterns
- Required checks (minimum test coverage, linting rules)
- Special requirements (accessibility, i18n, etc.)

## Tone and Approach

When writing reviews:

- 🎓 **Educate** - explain WHY something is a problem
- 🤝 **Be constructive** - propose solutions, don't just criticize
- 📚 **Provide context** - links to documentation, articles
- ✨ **Acknowledge positives** - what was done well
- 🎯 **Be specific** - point to files and lines
- 💬 **Ask questions** - instead of categorical statements

Remember: the goal of review is to **help the developer grow**, not just find mistakes!
