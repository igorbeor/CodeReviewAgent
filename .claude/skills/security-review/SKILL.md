---
name: security-review
description: Performs comprehensive security analysis to identify vulnerabilities, insecure patterns, and compliance issues. Use when reviewing security-sensitive code, checking for vulnerabilities, or analyzing authentication/authorization logic.
allowed-tools: Read, Grep, Glob, Bash
---

# Security Review Skill

## Overview

This Skill performs deep security analysis focusing on:

- **OWASP Top 10** - Common web application vulnerabilities
- **Authentication & Authorization** - Secure identity and access management
- **Data Protection** - Encryption, secure storage, PII handling
- **Input Validation** - Injection prevention and sanitization
- **Dependencies** - Known CVEs and vulnerable packages
- **Secrets Management** - Prevention of credential leaks
- **Secure Communication** - TLS, certificates, secure protocols

## Security Analysis Framework

### 1. OWASP Top 10 Checklist (2024)

#### A01: Broken Access Control
**What to check:**
- Authorization checks on all sensitive operations
- Users cannot access resources they shouldn't
- Vertical and horizontal privilege escalation prevention
- Forced browsing prevention
- CORS configuration is secure

**Flask Example:**
```python
# BAD - No authorization check
@app.route('/api/user/<user_id>')
def get_user(user_id):
    return User.query.get(user_id).to_dict()

# GOOD - Verify user can access this resource
@app.route('/api/user/<user_id>')
@login_required
def get_user(user_id):
    if current_user.id != user_id and not current_user.is_admin:
        abort(403)
    return User.query.get(user_id).to_dict()
```

**FastAPI Example:**
```python
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

app = FastAPI()
security = HTTPBearer()

# BAD - No authorization check
@app.get("/api/user/{user_id}")
async def get_user(user_id: int):
    user = await User.get(user_id)
    return user.dict()

# GOOD - Verify user can access this resource
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> User:
    token = credentials.credentials
    user = await verify_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials"
        )
    return user

@app.get("/api/user/{user_id}")
async def get_user(
    user_id: int,
    current_user: User = Depends(get_current_user)
):
    # Check authorization
    if current_user.id != user_id and not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this user"
        )

    user = await User.get(user_id)
    return user.dict()
```

#### A02: Cryptographic Failures
**What to check:**
- Sensitive data encrypted at rest and in transit
- Strong encryption algorithms (AES-256, RSA-2048+)
- No hardcoded encryption keys
- Proper key management
- Secure random number generation

**Common vulnerabilities:**
```python
# BAD - Weak hashing
import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()

# BAD - Hardcoded secret key
SECRET_KEY = "my-secret-key-123"

# GOOD - Strong hashing with salt
import bcrypt
password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# GOOD - Environment-based secrets
import os
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    raise ValueError("SECRET_KEY environment variable not set")
```

**FastAPI JWT Example:**
```python
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

# GOOD - Proper password hashing and JWT
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

SECRET_KEY = os.getenv("SECRET_KEY")  # From environment
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

class TokenData(BaseModel):
    email: str

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(security)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception

    user = await get_user_by_email(email=token_data.email)
    if user is None:
        raise credentials_exception
    return user
```

#### A03: Injection
**What to check:**
- SQL injection prevention (parameterized queries)
- NoSQL injection prevention
- Command injection prevention
- LDAP injection prevention
- XPath injection prevention

**Flask Example:**
```python
# BAD - SQL Injection
query = f"SELECT * FROM users WHERE email = '{email}'"
db.execute(query)

# BAD - Command Injection
os.system(f"ping {user_input}")

# GOOD - Parameterized query
query = "SELECT * FROM users WHERE email = %s"
db.execute(query, (email,))

# GOOD - Validate and sanitize input
import shlex
safe_input = shlex.quote(user_input)
subprocess.run(['ping', safe_input])
```

**FastAPI with SQLAlchemy Example:**
```python
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, EmailStr, validator

class UserQuery(BaseModel):
    email: EmailStr  # Automatic email validation
    name: str | None = None

    @validator('name')
    def validate_name(cls, v):
        if v and not v.replace(' ', '').isalnum():
            raise ValueError('Name must be alphanumeric')
        return v

# BAD - SQL Injection
@app.get("/users/search")
async def search_users_bad(email: str, db: AsyncSession = Depends(get_db)):
    query = text(f"SELECT * FROM users WHERE email = '{email}'")  # DANGEROUS!
    result = await db.execute(query)
    return result.fetchall()

# GOOD - Parameterized query with SQLAlchemy
@app.get("/users/search")
async def search_users_good(
    query: UserQuery,
    db: AsyncSession = Depends(get_db)
):
    # Using SQLAlchemy ORM (safe)
    stmt = select(User).where(User.email == query.email)
    result = await db.execute(stmt)
    return result.scalars().all()

# GOOD - Parameterized query with text()
@app.get("/users/search/raw")
async def search_users_raw(
    email: EmailStr,
    db: AsyncSession = Depends(get_db)
):
    # Using parameterized text query (safe)
    stmt = text("SELECT * FROM users WHERE email = :email")
    result = await db.execute(stmt, {"email": email})
    return result.fetchall()

# GOOD - Command execution with validation
from enum import Enum

class AllowedCommands(str, Enum):
    ping = "ping"
    traceroute = "traceroute"

@app.post("/network/diagnose")
async def diagnose_network(
    command: AllowedCommands,
    host: str
):
    # Validate host is not an IP address (prevent internal network access)
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host):
        raise HTTPException(400, "IP addresses not allowed")

    # Whitelist of allowed hosts
    allowed_hosts = ["google.com", "cloudflare.com"]
    if host not in allowed_hosts:
        raise HTTPException(400, "Host not in whitelist")

    # Safe execution
    result = subprocess.run(
        [command.value, "-c", "4", host],
        capture_output=True,
        timeout=10,
        text=True
    )
    return {"output": result.stdout}
```

#### A04: Insecure Design
**What to check:**
- Threat modeling performed
- Security requirements defined
- Secure by default configurations
- Rate limiting on sensitive operations
- Account lockout after failed attempts

**FastAPI Rate Limiting Example:**
```python
from fastapi import FastAPI, Request, HTTPException
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)
app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# GOOD - Rate limiting on sensitive endpoints
@app.post("/login")
@limiter.limit("5/minute")
async def login(
    request: Request,
    credentials: LoginCredentials,
    db: AsyncSession = Depends(get_db)
):
    user = await db.execute(
        select(User).where(User.email == credentials.email)
    )
    user = user.scalar_one_or_none()

    if not user:
        raise HTTPException(401, "Invalid credentials")

    # Check account lockout
    if user.failed_attempts >= 5:
        lockout_time = timedelta(minutes=15)
        if datetime.utcnow() - user.last_failed_attempt < lockout_time:
            raise HTTPException(
                status_code=429,
                detail=f"Account locked. Try again in {lockout_time.seconds // 60} minutes"
            )
        else:
            user.failed_attempts = 0

    # Verify password
    if not verify_password(credentials.password, user.password_hash):
        user.failed_attempts += 1
        user.last_failed_attempt = datetime.utcnow()
        await db.commit()
        raise HTTPException(401, "Invalid credentials")

    # Success - reset failed attempts
    user.failed_attempts = 0
    await db.commit()

    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}
```

#### A05: Security Misconfiguration
**What to check:**
- Default credentials changed
- Debug mode disabled in production
- Unnecessary features disabled
- Security headers configured
- Error messages don't leak information

**FastAPI Security Configuration:**
```python
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
import logging

# BAD - Insecure configuration
app = FastAPI(debug=True)  # Debug in production!

# GOOD - Secure configuration
app = FastAPI(
    title="Secure API",
    debug=False,  # Disable debug in production
    docs_url=None if os.getenv("ENV") == "production" else "/docs",  # Hide docs in prod
    redoc_url=None if os.getenv("ENV") == "production" else "/redoc"
)

# GOOD - Trusted host middleware
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["example.com", "*.example.com"]
)

# GOOD - CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://example.com"],  # Specific origins, not "*"
    allow_credentials=True,
    allow_methods=["GET", "POST"],  # Specific methods
    allow_headers=["Authorization", "Content-Type"],  # Specific headers
)

# GOOD - Security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response

# GOOD - Error handling without information leakage
logger = logging.getLogger(__name__)

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    # Log detailed error internally
    logger.error(f"Unhandled exception: {exc}", exc_info=True, extra={
        "path": request.url.path,
        "method": request.method,
        "client": request.client.host
    })

    # Return generic error to client
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"}
    )

# GOOD - Specific error handlers
from fastapi.exceptions import RequestValidationError

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # Don't expose internal validation details in production
    if os.getenv("ENV") == "production":
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"detail": "Invalid request data"}
        )
    else:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"detail": exc.errors()}
        )
```

#### A06: Vulnerable and Outdated Components
**What to check:**
- All dependencies are up to date
- No known CVEs in dependencies
- Unused dependencies removed
- Dependency sources are trusted
- Software Bill of Materials (SBOM) maintained

**How to check:**
```bash
# Python
pip list --outdated
pip-audit  # Check for known vulnerabilities
safety check

# Node.js
npm audit
npm outdated

# General
# Use Dependabot / Renovate
# Check https://nvd.nist.gov/
```

**FastAPI Dependency Management:**
```python
# requirements.txt with version pinning
fastapi==0.104.1  # Pinned version
uvicorn[standard]==0.24.0
sqlalchemy==2.0.23
pydantic==2.5.0
python-jose[cryptography]==3.3.0
passlib[bcrypt]==1.7.4

# Use pip-audit in CI/CD
# pip-audit --requirement requirements.txt
```

#### A07: Identification and Authentication Failures
**What to check:**
- Strong password policy enforced
- Multi-factor authentication available
- Session management is secure
- Credential recovery is secure
- No default/weak credentials

**FastAPI MFA Example:**
```python
import pyotp
from pydantic import BaseModel

class MFASetup(BaseModel):
    user_id: int

class MFAVerify(BaseModel):
    user_id: int
    token: str

# GOOD - MFA implementation
@app.post("/auth/mfa/setup")
async def setup_mfa(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    # Generate secret for TOTP
    secret = pyotp.random_base32()

    # Save secret to user
    current_user.mfa_secret = secret
    await db.commit()

    # Generate QR code URI
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(
        name=current_user.email,
        issuer_name="YourApp"
    )

    return {
        "secret": secret,
        "qr_uri": uri
    }

@app.post("/auth/mfa/verify")
async def verify_mfa(
    verify: MFAVerify,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if not current_user.mfa_secret:
        raise HTTPException(400, "MFA not configured")

    totp = pyotp.TOTP(current_user.mfa_secret)

    if not totp.verify(verify.token, valid_window=1):
        raise HTTPException(401, "Invalid MFA token")

    current_user.mfa_enabled = True
    await db.commit()

    return {"message": "MFA enabled successfully"}

# GOOD - Password validation
from pydantic import validator
import re

class UserRegistration(BaseModel):
    email: EmailStr
    password: str

    @validator('password')
    def validate_password(cls, v):
        if len(v) < 12:
            raise ValueError("Password must be at least 12 characters")
        if not re.search(r'[A-Z]', v):
            raise ValueError("Password must contain uppercase letter")
        if not re.search(r'[a-z]', v):
            raise ValueError("Password must contain lowercase letter")
        if not re.search(r'\d', v):
            raise ValueError("Password must contain digit")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError("Password must contain special character")
        return v

@app.post("/auth/register")
async def register(
    user_data: UserRegistration,
    db: AsyncSession = Depends(get_db)
):
    # Check if user exists
    existing = await db.execute(
        select(User).where(User.email == user_data.email)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(400, "Email already registered")

    # Hash password
    password_hash = get_password_hash(user_data.password)

    # Create user
    user = User(email=user_data.email, password_hash=password_hash)
    db.add(user)
    await db.commit()

    return {"message": "User registered successfully"}
```

#### A08: Software and Data Integrity Failures
**What to check:**
- Digital signatures verified
- CI/CD pipeline is secure
- Dependencies integrity checked
- No unsigned code/artifacts
- Deserialization is safe

**Common vulnerabilities:**
```python
# BAD - Unsafe deserialization
import pickle
data = pickle.loads(untrusted_data)  # Can execute arbitrary code!

# GOOD - Safe deserialization with Pydantic
from pydantic import BaseModel

class UserData(BaseModel):
    name: str
    email: EmailStr
    age: int

# FastAPI automatically uses Pydantic for safe deserialization
@app.post("/users")
async def create_user(user: UserData):  # Safe!
    return user

# GOOD - Verify package integrity
# Use poetry.lock or Pipfile.lock
# Verify checksums/signatures
```

#### A09: Security Logging and Monitoring Failures
**What to check:**
- Security events are logged
- Logs don't contain sensitive data
- Failed login attempts logged
- Alerting configured for suspicious activity
- Logs are tamper-proof

**FastAPI Logging Example:**
```python
import logging
from functools import wraps
from fastapi import Request

# Configure secure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("security.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# GOOD - Security event logging middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    # Log request
    logger.info("Request received", extra={
        "method": request.method,
        "path": request.url.path,
        "client_ip": request.client.host,
        "user_agent": request.headers.get("user-agent")
    })

    try:
        response = await call_next(request)

        # Log response
        logger.info("Request completed", extra={
            "method": request.method,
            "path": request.url.path,
            "status_code": response.status_code
        })

        return response

    except Exception as e:
        # Log error (without sensitive data)
        logger.error("Request failed", extra={
            "method": request.method,
            "path": request.url.path,
            "error_type": type(e).__name__
        }, exc_info=True)
        raise

# GOOD - Audit log for sensitive operations
async def audit_log(
    action: str,
    user: User,
    resource: str,
    success: bool,
    details: dict = None
):
    logger.info("Audit event", extra={
        "action": action,
        "user_id": user.id,
        "user_email": user.email,
        "resource": resource,
        "success": success,
        "details": details or {},
        "timestamp": datetime.utcnow().isoformat()
    })

@app.delete("/users/{user_id}")
async def delete_user(
    user_id: int,
    current_user: User = Depends(get_admin_user),
    db: AsyncSession = Depends(get_db)
):
    user = await db.get(User, user_id)
    if not user:
        await audit_log("delete_user", current_user, f"user:{user_id}", False)
        raise HTTPException(404, "User not found")

    await db.delete(user)
    await db.commit()

    await audit_log("delete_user", current_user, f"user:{user_id}", True)
    return {"message": "User deleted"}
```

#### A10: Server-Side Request Forgery (SSRF)
**What to check:**
- URL validation on user-provided URLs
- Whitelist of allowed domains
- No requests to internal/private IPs
- DNS rebinding protection

**FastAPI SSRF Prevention:**
```python
import ipaddress
import socket
from urllib.parse import urlparse
import httpx
from pydantic import BaseModel, HttpUrl, validator

ALLOWED_SCHEMES = ['http', 'https']
ALLOWED_DOMAINS = ['api.example.com', 'cdn.example.com']

class URLFetchRequest(BaseModel):
    url: HttpUrl

    @validator('url')
    def validate_url(cls, v):
        parsed = urlparse(str(v))

        # Check scheme
        if parsed.scheme not in ALLOWED_SCHEMES:
            raise ValueError(f"Scheme {parsed.scheme} not allowed")

        # Check domain whitelist
        if parsed.hostname not in ALLOWED_DOMAINS:
            raise ValueError(f"Domain {parsed.hostname} not allowed")

        try:
            # Resolve hostname and check for private IPs
            ip = socket.gethostbyname(parsed.hostname)
            ip_obj = ipaddress.ip_address(ip)

            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
                raise ValueError("Cannot access private IP addresses")

        except socket.gaierror:
            raise ValueError("Invalid hostname")

        return v

# BAD - SSRF vulnerability
@app.get("/fetch")
async def fetch_url_bad(url: str):
    async with httpx.AsyncClient() as client:
        response = await client.get(url)  # Can access internal services!
        return response.text

# GOOD - URL validation
@app.post("/fetch")
async def fetch_url_good(request: URLFetchRequest):
    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            response = await client.get(str(request.url))
            return {"content": response.text[:1000]}  # Limit response size
        except httpx.RequestError as e:
            raise HTTPException(500, f"Request failed: {str(e)}")
```

### 2. Additional Security Checks

#### Cross-Site Scripting (XSS)
**FastAPI automatically escapes output in templates, but be careful with:**
```python
from fastapi.responses import HTMLResponse

# BAD - Manual HTML construction
@app.get("/search", response_class=HTMLResponse)
async def search(q: str):
    return f"<h1>Results for: {q}</h1>"  # XSS!

# GOOD - Use templating engine
from fastapi.templating import Jinja2Templates

templates = Jinja2Templates(directory="templates")

@app.get("/search", response_class=HTMLResponse)
async def search(request: Request, q: str):
    return templates.TemplateResponse(
        "search.html",
        {"request": request, "query": q}  # Auto-escaped
    )
```

#### Cross-Site Request Forgery (CSRF)
**FastAPI CSRF protection:**
```python
from fastapi_csrf_protect import CsrfProtect
from pydantic import BaseModel

class CsrfSettings(BaseModel):
    secret_key: str = os.getenv("CSRF_SECRET_KEY")

@CsrfProtect.load_config
def get_csrf_config():
    return CsrfSettings()

app = FastAPI()

@app.post("/important-action")
async def important_action(
    csrf_protect: CsrfProtect = Depends()
):
    await csrf_protect.validate_csrf(request)
    # Process action
    return {"message": "Action completed"}
```

### 3. Secrets Detection

**Scan for:**
- API keys
- Database passwords
- Private keys
- OAuth tokens
- AWS/Cloud credentials
- JWT secrets

**Patterns to search:**
```bash
# Use Grep to find potential secrets
grep -r "password.*=.*['\"]" .
grep -r "api_key.*=.*['\"]" .
grep -r "secret.*=.*['\"]" .
grep -r "AKIA[0-9A-Z]{16}" .  # AWS access keys
grep -r "-----BEGIN.*PRIVATE KEY-----" .
```

**FastAPI Secrets Management:**
```python
from pydantic_settings import BaseSettings

# GOOD - Environment-based configuration
class Settings(BaseSettings):
    database_url: str
    secret_key: str
    api_key: str
    smtp_password: str

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()

# Use in app
@app.on_event("startup")
async def startup():
    # Never log secrets!
    logger.info("Starting app", extra={
        "database": settings.database_url.split('@')[1]  # Log host only, not credentials
    })
```

## Output Format

Structure security review as:

```markdown
## 🔒 Security Review Summary

**Risk Level:** [Critical/High/Medium/Low]
**Vulnerabilities Found:** [number]
**Files Reviewed:** [number]

---

## 🚨 Critical Vulnerabilities (Fix Immediately)

### 1. SQL Injection in User Query

**Severity:** Critical (CVSS 9.8)
**File:** `api/users.py:45`
**OWASP:** A03:2021 - Injection

**Description:**
User input is directly concatenated into SQL query without sanitization.

**Exploit Scenario:**
```
GET /api/users?email=' OR '1'='1
Returns all users in database
```

**Impact:**
- Data breach
- Unauthorized access
- Data manipulation

**Fix:**
```python
# Replace
query = f"SELECT * FROM users WHERE email = '{email}'"

# With
query = "SELECT * FROM users WHERE email = %s"
db.execute(query, (email,))
```

**References:**
- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [CWE-89](https://cwe.mitre.org/data/definitions/89.html)

---

## ⚠️ High Risk Issues

[Similar format...]

---

## 💡 Security Recommendations

- Enable dependency scanning (Dependabot/Snyk)
- Implement rate limiting
- Add security headers
- Set up WAF

---

## ✅ Security Strengths

- HTTPS enforced
- Password hashing with bcrypt
- CSRF protection enabled

---

## 📋 Compliance Check

- [ ] GDPR - Personal data handling
- [ ] PCI DSS - Payment card data
- [ ] HIPAA - Healthcare data
- [ ] SOC 2 - Security controls
```

## Tools Integration

**Use Bash tool to run security scanners:**

```bash
# Static analysis
bandit -r . -f json  # Python
semgrep --config=auto .  # Multi-language

# Dependency check
pip-audit  # Python
npm audit  # Node.js

# Secrets detection
trufflehog git file://.
gitleaks detect

# SAST
sonarqube scanner
```

## Project-Specific Security Rules

Always check **CLAUDE.md** for:
- Security compliance requirements
- Industry-specific regulations
- Custom security policies
- Approved cryptographic libraries
- Security testing requirements

## Learning Resources

For junior developers, include:
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [FastAPI Security](https://fastapi.tiangolo.com/tutorial/security/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [Security Headers](https://securityheaders.com/)

Remember: **Security is not a feature, it's a requirement!**
