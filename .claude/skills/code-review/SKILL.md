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

### Example 3: React Component Analysis

**Bad Code:**
```typescript
// UserList.tsx
import { useEffect, useState } from 'react';

function UserList() {
  const [users, setUsers] = useState([]);
  const [filter, setFilter] = useState('');

  useEffect(() => {
    fetch('https://api.example.com/users')
      .then(res => res.json())
      .then(data => setUsers(data));
  }, []);

  const filteredUsers = users.filter(u =>
    u.name.toLowerCase().includes(filter.toLowerCase())
  );

  return (
    <div>
      <input value={filter} onChange={(e) => setFilter(e.target.value)} />
      {filteredUsers.map((user, index) => (
        <div key={index} onClick={() => alert(user.name)}>
          {user.name}
        </div>
      ))}
    </div>
  );
}
```

**Issues:**
1. ❌ **No error handling** - fetch can fail
2. ❌ **No loading state** - poor UX
3. ❌ **Key using index** - can cause bugs when list changes
4. ❌ **Inline event handlers** - re-created on every render
5. ❌ **No TypeScript types** - no type safety
6. ❌ **No accessibility** - input lacks label, divs not semantic
7. ❌ **Filtering on every render** - performance issue

**Recommended Fix:**
```typescript
// types.ts
export interface User {
  id: string;
  name: string;
  email: string;
}

// UserList.tsx
import { useEffect, useState, useMemo, useCallback } from 'react';
import type { User } from './types';

interface UserListProps {
  apiUrl?: string;
}

export function UserList({ apiUrl = 'https://api.example.com/users' }: UserListProps) {
  const [users, setUsers] = useState<User[]>([]);
  const [filter, setFilter] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    const fetchUsers = async () => {
      try {
        setLoading(true);
        setError(null);

        const response = await fetch(apiUrl);

        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();

        if (!cancelled) {
          setUsers(data);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Failed to load users');
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    };

    fetchUsers();

    // Cleanup function prevents state update after unmount
    return () => {
      cancelled = true;
    };
  }, [apiUrl]);

  // Memoized derived state
  const filteredUsers = useMemo(() => {
    const lowerFilter = filter.toLowerCase();
    return users.filter(user =>
      user.name.toLowerCase().includes(lowerFilter)
    );
  }, [users, filter]);

  // Memoized callback
  const handleUserClick = useCallback((user: User) => {
    alert(user.name);
  }, []);

  const handleFilterChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    setFilter(e.target.value);
  }, []);

  if (loading) {
    return <div role="status" aria-live="polite">Loading users...</div>;
  }

  if (error) {
    return (
      <div role="alert" aria-live="assertive">
        <strong>Error:</strong> {error}
      </div>
    );
  }

  return (
    <div>
      <label htmlFor="user-filter">
        Filter users:
        <input
          id="user-filter"
          type="text"
          value={filter}
          onChange={handleFilterChange}
          aria-label="Filter users by name"
        />
      </label>

      {filteredUsers.length === 0 ? (
        <p>No users found</p>
      ) : (
        <ul role="list">
          {filteredUsers.map((user) => (
            <li key={user.id}>
              <button
                onClick={() => handleUserClick(user)}
                aria-label={`Select ${user.name}`}
              >
                {user.name}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
```

### Example 4: Angular Component Analysis

**Bad Code:**
```typescript
// user-profile.component.ts
import { Component } from '@angular/core';
import { ActivatedRoute } from '@angular/router';

@Component({
  selector: 'app-user-profile',
  template: `
    <div>
      <h1>{{ user.name }}</h1>
      <p>{{ user.email }}</p>
      <button (click)="updateUser()">Update</button>
    </div>
  `
})
export class UserProfileComponent {
  user: any;

  constructor(private route: ActivatedRoute) {
    this.loadUser();
  }

  loadUser() {
    const id = this.route.snapshot.params['id'];
    fetch('/api/user/' + id)
      .then(res => res.json())
      .then(data => this.user = data);
  }

  updateUser() {
    fetch('/api/user/' + this.user.id, {
      method: 'PUT',
      body: JSON.stringify(this.user)
    });
  }
}
```

**Issues:**
1. ❌ **No error handling** - fetch can fail silently
2. ❌ **Using `any` type** - no type safety
3. ❌ **No loading/error states** - poor UX
4. ❌ **Not using HttpClient** - should use Angular's HTTP service
5. ❌ **No unsubscribe** - potential memory leak
6. ❌ **No dependency injection** - fetch instead of service
7. ❌ **Template in component** - should be separate file

**Recommended Fix:**
```typescript
// models/user.model.ts
export interface User {
  id: string;
  name: string;
  email: string;
}

// services/user.service.ts
import { Injectable } from '@angular/core';
import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Observable, throwError } from 'rxjs';
import { catchError, retry } from 'rxjs/operators';
import { User } from '../models/user.model';

@Injectable({
  providedIn: 'root'
})
export class UserService {
  private apiUrl = '/api/user';

  constructor(private http: HttpClient) {}

  getUser(id: string): Observable<User> {
    return this.http.get<User>(`${this.apiUrl}/${id}`).pipe(
      retry(2), // Retry failed requests
      catchError(this.handleError)
    );
  }

  updateUser(user: User): Observable<User> {
    return this.http.put<User>(`${this.apiUrl}/${user.id}`, user).pipe(
      catchError(this.handleError)
    );
  }

  private handleError(error: HttpErrorResponse): Observable<never> {
    let errorMessage = 'An error occurred';

    if (error.error instanceof ErrorEvent) {
      // Client-side error
      errorMessage = error.error.message;
    } else {
      // Server-side error
      errorMessage = `Error Code: ${error.status}\nMessage: ${error.message}`;
    }

    console.error(errorMessage);
    return throwError(() => new Error(errorMessage));
  }
}

// user-profile.component.ts
import { Component, OnInit, OnDestroy } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { Subject } from 'rxjs';
import { takeUntil, finalize } from 'rxjs/operators';
import { User } from '../../models/user.model';
import { UserService } from '../../services/user.service';

@Component({
  selector: 'app-user-profile',
  templateUrl: './user-profile.component.html',
  styleUrls: ['./user-profile.component.scss']
})
export class UserProfileComponent implements OnInit, OnDestroy {
  user: User | null = null;
  loading = false;
  updating = false;
  error: string | null = null;

  private destroy$ = new Subject<void>();

  constructor(
    private route: ActivatedRoute,
    private userService: UserService
  ) {}

  ngOnInit(): void {
    this.loadUser();
  }

  ngOnDestroy(): void {
    // Clean up subscriptions
    this.destroy$.next();
    this.destroy$.complete();
  }

  loadUser(): void {
    const userId = this.route.snapshot.params['id'];

    if (!userId) {
      this.error = 'User ID is missing';
      return;
    }

    this.loading = true;
    this.error = null;

    this.userService.getUser(userId).pipe(
      takeUntil(this.destroy$),
      finalize(() => this.loading = false)
    ).subscribe({
      next: (user) => {
        this.user = user;
      },
      error: (err) => {
        this.error = err.message || 'Failed to load user';
      }
    });
  }

  updateUser(): void {
    if (!this.user) return;

    this.updating = true;
    this.error = null;

    this.userService.updateUser(this.user).pipe(
      takeUntil(this.destroy$),
      finalize(() => this.updating = false)
    ).subscribe({
      next: (updatedUser) => {
        this.user = updatedUser;
      },
      error: (err) => {
        this.error = err.message || 'Failed to update user';
      }
    });
  }
}
```

```html
<!-- user-profile.component.html -->
<div class="user-profile">
  <!-- Loading state -->
  <div *ngIf="loading" role="status" aria-live="polite">
    Loading user profile...
  </div>

  <!-- Error state -->
  <div *ngIf="error && !loading" role="alert" aria-live="assertive" class="error">
    <strong>Error:</strong> {{ error }}
  </div>

  <!-- Content -->
  <div *ngIf="user && !loading">
    <h1>{{ user.name }}</h1>
    <p>{{ user.email }}</p>

    <button
      (click)="updateUser()"
      [disabled]="updating"
      [attr.aria-busy]="updating"
    >
      {{ updating ? 'Updating...' : 'Update' }}
    </button>
  </div>
</div>
```

```scss
// user-profile.component.scss
.user-profile {
  padding: 1rem;

  .error {
    color: red;
    padding: 0.5rem;
    border: 1px solid red;
    border-radius: 4px;
  }
}
```

## Review Checklist

### Universal Checklist (Backend + Frontend)

Use this checklist for all code:

- [ ] **Names** - variables, functions, classes have descriptive names
- [ ] **Function/method length** - up to 20-25 lines (excluding docstrings/templates)
- [ ] **Complexity** - cyclomatic complexity < 7
- [ ] **DRY** - no code duplication
- [ ] **Error handling** - errors are handled correctly with proper types
- [ ] **Documentation** - public APIs/functions are documented
- [ ] **Tests** - tests exist for new functionality
- [ ] **Security** - no obvious vulnerabilities
- [ ] **Performance** - no obvious performance issues
- [ ] **Dependencies** - new dependencies are justified and secure
- [ ] **Code organization** - logical file/folder structure
- [ ] **Consistency** - follows project conventions

### Backend-Specific Checklist

- [ ] **Type hints** - all functions have Python type hints
- [ ] **SOLID principles** - Single Responsibility, Dependency Inversion, etc.
- [ ] **Database queries** - optimized, no N+1 problems
- [ ] **API design** - RESTful conventions, proper HTTP methods
- [ ] **Authentication** - proper JWT/session handling
- [ ] **Authorization** - permission checks on sensitive operations
- [ ] **Input validation** - Pydantic models for all inputs
- [ ] **SQL injection** - parameterized queries only
- [ ] **Connection pooling** - database connections properly managed
- [ ] **Async/await** - proper use for I/O operations
- [ ] **Logging** - structured logging without sensitive data
- [ ] **Environment config** - no hardcoded secrets

### Frontend-Specific Checklist

- [ ] **TypeScript** - proper types, no `any` without justification
- [ ] **Component size** - components are focused and small (< 200 lines)
- [ ] **Props/Input validation** - TypeScript interfaces defined
- [ ] **Hooks rules** - hooks called at top level, not conditionally (React)
- [ ] **Keys in lists** - unique, stable keys (not array index)
- [ ] **Accessibility** - ARIA labels, semantic HTML, keyboard navigation
- [ ] **Loading states** - loading indicators for async operations
- [ ] **Error states** - error messages displayed to users
- [ ] **Memoization** - expensive calculations memoized
- [ ] **Event handlers** - callbacks optimized to prevent re-renders
- [ ] **Unsubscribe/cleanup** - subscriptions/effects properly cleaned up
- [ ] **CSS/Styles** - styles properly scoped (modules/component styles)
- [ ] **Responsive** - works on mobile and desktop
- [ ] **Bundle size** - lazy loading for large components
- [ ] **State management** - appropriate (local vs global store)
- [ ] **Dependency injection** - services injected, not instantiated (Angular)
- [ ] **RxJS** - proper use of operators and unsubscribe (Angular)

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
