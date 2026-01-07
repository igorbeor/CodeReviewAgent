---
name: performance-review
description: Analyzes code for performance issues, optimization opportunities, and resource efficiency. Use when optimizing code, identifying bottlenecks, analyzing algorithms, or reviewing database queries.
allowed-tools: Read, Grep, Glob, Bash
---

# Performance Review Skill

## Overview

This Skill performs comprehensive performance analysis focusing on:

- **Algorithmic Complexity** - Big O analysis, algorithm selection
- **Database Performance** - Query optimization, N+1 problems, indexing
- **Resource Management** - Memory leaks, connection pooling, file handles
- **Caching** - Cache strategies, invalidation, hit rates
- **Concurrency** - Async/await patterns, thread safety, parallelism
- **Network** - API calls, payload size, compression

## Performance Analysis Framework

### 1. Algorithmic Complexity

#### What to Check

**Time Complexity:**
- Nested loops (O(n²))
- Recursive functions (exponential complexity)
- Sorting algorithms
- Search algorithms
- Data structure operations

**Space Complexity:**
- Unnecessary data copies
- Large intermediate results
- Memory-inefficient data structures

#### Common Issues

```python
# BAD - O(n²) nested loop
def find_duplicates(items):
    duplicates = []
    for i in range(len(items)):
        for j in range(i + 1, len(items)):
            if items[i] == items[j]:
                duplicates.append(items[i])
    return duplicates

# GOOD - O(n) using set
def find_duplicates(items):
    seen = set()
    duplicates = set()
    for item in items:
        if item in seen:
            duplicates.add(item)
        seen.add(item)
    return list(duplicates)

# BAD - O(n) list membership check in loop = O(n²)
def filter_items(items, blacklist):
    return [item for item in items if item not in blacklist]  # O(n²)!

# GOOD - O(n) with set lookup
def filter_items(items, blacklist):
    blacklist_set = set(blacklist)  # O(1) lookup
    return [item for item in items if item not in blacklist_set]  # O(n)

# BAD - Unnecessary list creation in loop
result = []
for i in range(1000000):
    result = result + [i]  # Creates new list each time! O(n²)

# GOOD - List append
result = []
for i in range(1000000):
    result.append(i)  # O(1) amortized

# BETTER - List comprehension
result = [i for i in range(1000000)]  # More efficient

# BEST - Direct range to list
result = list(range(1000000))  # Optimized C implementation
```

### 2. Database Performance

#### N+1 Query Problem

```python
# BAD - N+1 queries
@app.get("/posts")
async def get_posts(db: AsyncSession = Depends(get_db)):
    posts = await db.execute(select(Post))
    posts = posts.scalars().all()

    result = []
    for post in posts:
        # N additional queries!
        author = await db.execute(
            select(User).where(User.id == post.author_id)
        )
        author = author.scalar_one()

        result.append({
            "title": post.title,
            "author": author.name
        })

    return result

# GOOD - Eager loading with join
@app.get("/posts")
async def get_posts(db: AsyncSession = Depends(get_db)):
    stmt = (
        select(Post)
        .join(User, Post.author_id == User.id)
        .options(selectinload(Post.author))  # Eager load
    )
    posts = await db.execute(stmt)
    posts = posts.scalars().all()

    return [
        {
            "title": post.title,
            "author": post.author.name
        }
        for post in posts
    ]

# ALTERNATIVE - Single query with join
@app.get("/posts")
async def get_posts(db: AsyncSession = Depends(get_db)):
    stmt = select(Post.title, User.name).join(User, Post.author_id == User.id)
    result = await db.execute(stmt)
    return [
        {"title": title, "author": name}
        for title, name in result.all()
    ]
```

#### Query Optimization

```python
# BAD - SELECT *
stmt = select(User)  # Fetches all columns

# GOOD - Select only needed columns
stmt = select(User.id, User.name, User.email)

# BAD - No pagination
@app.get("/users")
async def get_users(db: AsyncSession = Depends(get_db)):
    users = await db.execute(select(User))
    return users.scalars().all()  # Could be millions of records!

# GOOD - Pagination
from pydantic import BaseModel

class PaginationParams(BaseModel):
    skip: int = 0
    limit: int = 100

@app.get("/users")
async def get_users(
    pagination: PaginationParams = Depends(),
    db: AsyncSession = Depends(get_db)
):
    stmt = select(User).offset(pagination.skip).limit(pagination.limit)
    users = await db.execute(stmt)
    return users.scalars().all()

# BAD - Count without index
stmt = select(func.count()).select_from(User).where(User.email.like('%@example.com'))

# GOOD - Ensure index on email column
# CREATE INDEX idx_user_email ON users(email);
stmt = select(func.count()).select_from(User).where(User.email.like('%@example.com'))

# BAD - Filtering in Python
users = await db.execute(select(User))
users = users.scalars().all()
active_users = [u for u in users if u.is_active]  # Bad!

# GOOD - Filtering in database
stmt = select(User).where(User.is_active == True)
active_users = await db.execute(stmt)
active_users = active_users.scalars().all()
```

#### Database Connection Pooling

```python
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

# BAD - No connection pooling
engine = create_async_engine("postgresql+asyncpg://...")

# GOOD - Connection pooling configured
engine = create_async_engine(
    "postgresql+asyncpg://user:pass@localhost/db",
    pool_size=20,          # Number of connections to maintain
    max_overflow=10,       # Additional connections when pool is full
    pool_timeout=30,       # Timeout waiting for connection
    pool_recycle=3600,     # Recycle connections after 1 hour
    pool_pre_ping=True,    # Verify connections before using
    echo_pool=False        # Disable pool logging in production
)

# Use session maker
async_session = sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False
)
```

### 3. Caching Strategies

#### Response Caching

```python
from fastapi_cache import FastAPICache
from fastapi_cache.backends.redis import RedisBackend
from fastapi_cache.decorator import cache
from redis import asyncio as aioredis

# Initialize cache on startup
@app.on_event("startup")
async def startup():
    redis = aioredis.from_url("redis://localhost")
    FastAPICache.init(RedisBackend(redis), prefix="fastapi-cache")

# BAD - No caching for expensive operation
@app.get("/stats")
async def get_stats(db: AsyncSession = Depends(get_db)):
    # Expensive aggregation query
    total_users = await db.scalar(select(func.count(User.id)))
    total_posts = await db.scalar(select(func.count(Post.id)))
    # ... more expensive queries
    return {"users": total_users, "posts": total_posts}

# GOOD - Cache expensive results
@app.get("/stats")
@cache(expire=300)  # Cache for 5 minutes
async def get_stats(db: AsyncSession = Depends(get_db)):
    total_users = await db.scalar(select(func.count(User.id)))
    total_posts = await db.scalar(select(func.count(Post.id)))
    return {"users": total_users, "posts": total_posts}

# GOOD - Manual caching with invalidation
from functools import lru_cache

@lru_cache(maxsize=128)
def get_expensive_computation(param: int) -> dict:
    # Expensive computation
    result = complex_calculation(param)
    return result

# GOOD - Redis caching with custom key
import json
from redis import asyncio as aioredis

redis = aioredis.from_url("redis://localhost")

async def get_user_with_cache(user_id: int, db: AsyncSession):
    cache_key = f"user:{user_id}"

    # Try cache first
    cached = await redis.get(cache_key)
    if cached:
        return json.loads(cached)

    # Fetch from database
    user = await db.get(User, user_id)
    if user:
        # Store in cache
        await redis.setex(
            cache_key,
            3600,  # 1 hour TTL
            json.dumps(user.dict())
        )

    return user
```

### 4. Async/Await Patterns

#### Concurrency Optimization

```python
import asyncio
import httpx

# BAD - Sequential API calls
@app.get("/aggregate-data")
async def aggregate_data():
    async with httpx.AsyncClient() as client:
        user_data = await client.get("https://api.example.com/users/1")
        posts_data = await client.get("https://api.example.com/posts/1")
        comments_data = await client.get("https://api.example.com/comments/1")

    return {
        "user": user_data.json(),
        "posts": posts_data.json(),
        "comments": comments_data.json()
    }
    # Total time: ~300ms (3 sequential 100ms calls)

# GOOD - Concurrent API calls
@app.get("/aggregate-data")
async def aggregate_data():
    async with httpx.AsyncClient() as client:
        user_task = client.get("https://api.example.com/users/1")
        posts_task = client.get("https://api.example.com/posts/1")
        comments_task = client.get("https://api.example.com/comments/1")

        # Execute concurrently
        user_data, posts_data, comments_data = await asyncio.gather(
            user_task,
            posts_task,
            comments_task
        )

    return {
        "user": user_data.json(),
        "posts": posts_data.json(),
        "comments": comments_data.json()
    }
    # Total time: ~100ms (3 concurrent 100ms calls)

# BAD - Blocking I/O in async function
import time

@app.get("/blocking")
async def blocking_operation():
    time.sleep(5)  # Blocks the entire event loop!
    return {"done": True}

# GOOD - Use async sleep
@app.get("/non-blocking")
async def non_blocking_operation():
    await asyncio.sleep(5)  # Doesn't block event loop
    return {"done": True}

# GOOD - CPU-intensive task in thread pool
from concurrent.futures import ProcessPoolExecutor
import numpy as np

executor = ProcessPoolExecutor(max_workers=4)

def cpu_intensive_task(data):
    # Heavy computation
    result = np.fft.fft(data)
    return result.tolist()

@app.post("/process")
async def process_data(data: list[float]):
    # Run in separate process to avoid blocking
    result = await asyncio.get_event_loop().run_in_executor(
        executor,
        cpu_intensive_task,
        data
    )
    return {"result": result}
```

#### Background Tasks

```python
from fastapi import BackgroundTasks

# BAD - Blocking email send
@app.post("/register")
async def register_user(email: str, db: AsyncSession = Depends(get_db)):
    user = User(email=email)
    db.add(user)
    await db.commit()

    # Blocks response
    await send_welcome_email(email)  # Takes 2-3 seconds

    return {"message": "User registered"}

# GOOD - Background task
async def send_welcome_email_task(email: str):
    # Email sending logic
    await asyncio.sleep(2)  # Simulating email send
    print(f"Email sent to {email}")

@app.post("/register")
async def register_user(
    email: str,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    user = User(email=email)
    db.add(user)
    await db.commit()

    # Schedule in background
    background_tasks.add_task(send_welcome_email_task, email)

    # Return immediately
    return {"message": "User registered"}
```

### 5. Memory Optimization

```python
# BAD - Loading entire file into memory
@app.post("/upload")
async def upload_file(file: UploadFile):
    content = await file.read()  # Loads entire file into RAM!
    process_content(content)
    return {"size": len(content)}

# GOOD - Streaming file processing
@app.post("/upload")
async def upload_file(file: UploadFile):
    total_size = 0
    chunk_size = 1024 * 1024  # 1MB chunks

    while chunk := await file.read(chunk_size):
        process_chunk(chunk)  # Process incrementally
        total_size += len(chunk)

    return {"size": total_size}

# BAD - Storing large results in memory
@app.get("/export")
async def export_data(db: AsyncSession = Depends(get_db)):
    # Loads millions of records into memory
    users = await db.execute(select(User))
    users = users.scalars().all()

    return [user.dict() for user in users]  # Huge response!

# GOOD - Streaming response
from fastapi.responses import StreamingResponse
import io

@app.get("/export")
async def export_data(db: AsyncSession = Depends(get_db)):
    async def generate():
        stmt = select(User).execution_options(yield_per=1000)
        stream = await db.stream(stmt)

        async for user in stream.scalars():
            yield f"{user.id},{user.name},{user.email}\n"

    return StreamingResponse(
        generate(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=users.csv"}
    )
```

### 6. JSON Serialization

```python
from pydantic import BaseModel
import orjson

# BAD - Slow JSON serialization
import json

@app.get("/data")
async def get_data():
    large_data = get_large_dataset()
    return json.dumps(large_data)  # Slow!

# GOOD - Fast JSON with orjson
from fastapi.responses import ORJSONResponse

app = FastAPI(default_response_class=ORJSONResponse)

@app.get("/data")
async def get_data():
    large_data = get_large_dataset()
    return large_data  # Automatically uses orjson (2-3x faster)

# GOOD - Pydantic model caching
class User(BaseModel):
    id: int
    name: str
    email: str

    class Config:
        # Enable model caching for repeated serialization
        orm_mode = True
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
```

### 7. Request/Response Optimization

```python
# BAD - No compression
app = FastAPI()

# GOOD - Enable compression
from fastapi.middleware.gzip import GZipMiddleware

app = FastAPI()
app.add_middleware(GZipMiddleware, minimum_size=1000)  # Compress responses > 1KB

# BAD - Large request bodies without limit
@app.post("/upload")
async def upload(data: bytes):
    return {"size": len(data)}

# GOOD - Limit request body size
from fastapi import Request
from fastapi.exceptions import HTTPException

MAX_REQUEST_SIZE = 10 * 1024 * 1024  # 10MB

@app.middleware("http")
async def limit_request_size(request: Request, call_next):
    content_length = request.headers.get("content-length")

    if content_length and int(content_length) > MAX_REQUEST_SIZE:
        raise HTTPException(413, "Request too large")

    return await call_next(request)
```

### 8. Startup Optimization

```python
# BAD - Expensive operations on every request
@app.get("/predict")
async def predict(data: list[float]):
    model = load_ml_model()  # Loads model on every request!
    result = model.predict(data)
    return {"prediction": result}

# GOOD - Load resources on startup
ml_model = None

@app.on_event("startup")
async def load_resources():
    global ml_model
    ml_model = load_ml_model()  # Load once on startup

@app.get("/predict")
async def predict(data: list[float]):
    result = ml_model.predict(data)
    return {"prediction": result}

# GOOD - Lazy loading with caching
from functools import lru_cache

@lru_cache(maxsize=1)
def get_ml_model():
    return load_ml_model()

@app.get("/predict")
async def predict(data: list[float]):
    model = get_ml_model()  # Cached after first call
    result = model.predict(data)
    return {"prediction": result}
```

## Performance Metrics to Track

### Application Metrics

```python
from prometheus_client import Counter, Histogram, generate_latest
from fastapi import Response

# Request counter
request_count = Counter(
    'http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status']
)

# Response time histogram
request_duration = Histogram(
    'http_request_duration_seconds',
    'HTTP request duration',
    ['method', 'endpoint']
)

# Database query counter
db_query_count = Counter(
    'db_queries_total',
    'Total database queries',
    ['operation']
)

@app.middleware("http")
async def track_metrics(request: Request, call_next):
    import time

    start_time = time.time()

    response = await call_next(request)

    duration = time.time() - start_time

    request_count.labels(
        method=request.method,
        endpoint=request.url.path,
        status=response.status_code
    ).inc()

    request_duration.labels(
        method=request.method,
        endpoint=request.url.path
    ).observe(duration)

    return response

@app.get("/metrics")
async def metrics():
    return Response(content=generate_latest(), media_type="text/plain")
```

## Output Format

```markdown
## ⚡ Performance Review Summary

**Overall Performance:** [Excellent/Good/Poor]
**Critical Issues:** [number]
**Optimization Opportunities:** [number]

---

## 🔴 Critical Performance Issues

### 1. N+1 Query Problem in Posts Endpoint

**Severity:** Critical
**File:** `api/posts.py:23`
**Impact:** 100x slower with 100 posts

**Issue:**
```python
# Current: 1 query + N queries = 101 queries
for post in posts:
    author = await db.get(User, post.author_id)
```

**Measured Performance:**
- 100 posts: 2.5 seconds
- Database queries: 101

**Fix:**
```python
# Use eager loading: 1-2 queries total
stmt = select(Post).options(selectinload(Post.author))
```

**Expected Improvement:**
- Response time: 2.5s → 50ms (50x faster)
- Database queries: 101 → 2 (50x fewer)

---

## ⚠️ Performance Warnings

### 1. Sequential API Calls

**File:** `api/aggregate.py:15`
**Impact:** 3x slower than necessary

**Issue:** Three API calls are made sequentially
**Fix:** Use `asyncio.gather()` for concurrent execution
**Expected Improvement:** 300ms → 100ms (3x faster)

---

## 💡 Optimization Suggestions

- Add Redis caching for `/stats` endpoint (called frequently)
- Enable GZip compression for responses > 1KB
- Implement pagination for `/users` endpoint
- Add database index on `users.email`

---

## 📊 Performance Benchmarks

| Endpoint | Current | Target | Status |
|----------|---------|--------|--------|
| GET /posts | 250ms | <100ms | ⚠️ Needs optimization |
| GET /users | 50ms | <100ms | ✅ Good |
| POST /login | 150ms | <200ms | ✅ Good |

---

## ✅ Performance Strengths

- Async/await properly used
- Connection pooling configured
- Background tasks for emails
- Streaming for large exports
```

## Frontend-Specific Performance

### Bundle Size Optimization

```typescript
// BAD - Importing entire library
import _ from 'lodash';  // 70KB!
import moment from 'moment';  // 67KB!

const result = _.debounce(fn, 300);
const date = moment().format('YYYY-MM-DD');

// GOOD - Import only what you need
import debounce from 'lodash/debounce';  // 2KB
import { format } from 'date-fns';  // 12KB

const result = debounce(fn, 300);
const date = format(new Date(), 'yyyy-MM-dd');

// GOOD - Tree-shaking friendly imports
import { debounce } from 'lodash-es';  // Only includes what's used
```

### Code Splitting & Lazy Loading

**React:**
```typescript
// BAD - Import all components upfront
import HeavyChart from './HeavyChart';
import HeavyTable from './HeavyTable';
import HeavyEditor from './HeavyEditor';

// Bundle size: 500KB

// GOOD - Lazy load components
const HeavyChart = lazy(() => import('./HeavyChart'));
const HeavyTable = lazy(() => import('./HeavyTable'));
const HeavyEditor = lazy(() => import('./HeavyEditor'));

function App() {
  return (
    <Suspense fallback={<LoadingSpinner />}>
      <Routes>
        <Route path="/chart" element={<HeavyChart />} />
        <Route path="/table" element={<HeavyTable />} />
        <Route path="/editor" element={<HeavyEditor />} />
      </Routes>
    </Suspense>
  );
}

// Initial bundle: 100KB, chunks loaded on demand
```

**Angular:**
```typescript
// BAD - Eager loading
const routes: Routes = [
  { path: 'admin', component: AdminComponent },
  { path: 'reports', component: ReportsComponent }
];

// GOOD - Lazy loading modules
const routes: Routes = [
  {
    path: 'admin',
    loadChildren: () => import('./admin/admin.module').then(m => m.AdminModule)
  },
  {
    path: 'reports',
    loadChildren: () => import('./reports/reports.module').then(m => m.ReportsModule)
  }
];
```

### Image Optimization

```typescript
// BAD - Large unoptimized images
<img src="/images/hero.jpg" alt="Hero" />  // 5MB JPEG!

// GOOD - Responsive images with modern formats
<picture>
  <source srcSet="/images/hero.webp" type="image/webp" />
  <source srcSet="/images/hero.jpg" type="image/jpeg" />
  <img
    src="/images/hero.jpg"
    srcSet="/images/hero-320w.jpg 320w,
            /images/hero-640w.jpg 640w,
            /images/hero-1280w.jpg 1280w"
    sizes="(max-width: 320px) 280px,
           (max-width: 640px) 600px,
           1200px"
    alt="Hero"
    loading="lazy"
    width="1200"
    height="600"
  />
</picture>

// GOOD - Next.js Image component (auto-optimization)
import Image from 'next/image';

<Image
  src="/images/hero.jpg"
  alt="Hero"
  width={1200}
  height={600}
  priority  // For above-fold images
/>
```

### Prevent Unnecessary Re-renders

**React:**
```typescript
// BAD - Component re-renders on every parent render
function UserList({ users }: Props) {
  return (
    <ul>
      {users.map(user => (
        <UserItem key={user.id} user={user} />
      ))}
    </ul>
  );
}

function UserItem({ user }: {user: User}) {
  console.log('Rendering:', user.name);  // Logs on every parent update!
  return <li>{user.name}</li>;
}

// GOOD - Memoize component
const UserItem = memo(function UserItem({ user }: {user: User}) {
  console.log('Rendering:', user.name);  // Only logs when user changes
  return <li>{user.name}</li>;
});

// GOOD - Memoize expensive calculations
function ProductList({ products }: Props) {
  // BAD - Recalculates on every render
  const total = products.reduce((sum, p) => sum + p.price, 0);

  // GOOD - Only recalculates when products change
  const total = useMemo(
    () => products.reduce((sum, p) => sum + p.price, 0),
    [products]
  );

  return <div>Total: ${total}</div>;
}
```

**Angular:**
```typescript
// BAD - Default change detection (checks everything)
@Component({
  selector: 'app-user-list',
  template: `
    <div *ngFor="let user of users">
      {{ user.name }}
    </div>
  `
})
export class UserListComponent {
  @Input() users: User[];
}

// GOOD - OnPush change detection
@Component({
  selector: 'app-user-list',
  template: `
    <div *ngFor="let user of users; trackBy: trackByUserId">
      {{ user.name }}
    </div>
  `,
  changeDetection: ChangeDetectionStrategy.OnPush
})
export class UserListComponent {
  @Input() users: User[];

  trackByUserId(index: number, user: User): string {
    return user.id;
  }
}
```

### Virtual Scrolling / Windowing

```typescript
// BAD - Rendering 10,000 items in DOM
function LargeList({ items }: { items: Item[] }) {
  return (
    <div style={{ height: '600px', overflow: 'auto' }}>
      {items.map(item => (
        <div key={item.id} style={{ height: '50px' }}>
          {item.name}
        </div>
      ))}
    </div>
  );
}
// DOM nodes: 10,000!  Performance: 💀

// GOOD - Virtual scrolling (react-window)
import { FixedSizeList } from 'react-window';

function LargeList({ items }: { items: Item[] }) {
  return (
    <FixedSizeList
      height={600}
      itemCount={items.length}
      itemSize={50}
      width="100%"
    >
      {({ index, style }) => (
        <div style={style}>
          {items[index].name}
        </div>
      )}
    </FixedSizeList>
  );
}
// DOM nodes: ~20  Performance: ⚡
```

### Web Vitals Optimization

**Largest Contentful Paint (LCP) - Target: < 2.5s**
```typescript
// BAD - Large image blocks LCP
<img src="/hero.jpg" width="1200" height="600" />  // 3MB, loads in 4s

// GOOD - Optimize critical images
<img
  src="/hero-optimized.webp"  // 200KB, loads in 0.5s
  width="1200"
  height="600"
  fetchpriority="high"  // Prioritize loading
  decoding="async"
/>

// GOOD - Preload critical resources
<link rel="preload" as="image" href="/hero-optimized.webp" />
```

**First Input Delay (FID) - Target: < 100ms**
```typescript
// BAD - Long task blocks main thread
function processData(data: large) {
  // 500ms synchronous processing
  return data.map(item => heavyComputation(item));
}

// GOOD - Break into chunks
async function processData(data: large) {
  const results = [];
  for (let i = 0; i < data.length; i++) {
    results.push(heavyComputation(data[i]));

    // Yield to browser every 50 items
    if (i % 50 === 0) {
      await new Promise(resolve => setTimeout(resolve, 0));
    }
  }
  return results;
}

// BETTER - Use Web Workers
const worker = new Worker('processor.worker.js');
worker.postMessage(data);
worker.onmessage = (e) => {
  const results = e.data;
};
```

**Cumulative Layout Shift (CLS) - Target: < 0.1**
```typescript
// BAD - Images without dimensions cause layout shift
<img src="/avatar.jpg" />  // CLS: 0.25

// GOOD - Always specify dimensions
<img src="/avatar.jpg" width="100" height="100" />  // CLS: 0

// GOOD - Reserve space with aspect ratio
<div style={{ aspectRatio: '16/9' }}>
  <img src="/video-thumbnail.jpg" style={{ width: '100%', height: 'auto' }} />
</div>
```

### Memory Leaks

**React:**
```typescript
// BAD - Event listener not cleaned up
function Component() {
  useEffect(() => {
    const handleResize = () => console.log('resized');
    window.addEventListener('resize', handleResize);
    // Missing cleanup!
  }, []);

  return <div>Content</div>;
}

// GOOD - Cleanup event listeners
function Component() {
  useEffect(() => {
    const handleResize = () => console.log('resized');
    window.addEventListener('resize', handleResize);

    return () => {
      window.removeEventListener('resize', handleResize);
    };
  }, []);

  return <div>Content</div>;
}

// BAD - Timer not cleared
function Component() {
  useEffect(() => {
    const timer = setInterval(() => fetchData(), 5000);
    // Missing cleanup!
  }, []);
}

// GOOD - Clear timers
function Component() {
  useEffect(() => {
    const timer = setInterval(() => fetchData(), 5000);

    return () => {
      clearInterval(timer);
    };
  }, []);
}
```

### Debouncing & Throttling

```typescript
// BAD - Handler fires on every keystroke
function SearchInput() {
  const [query, setQuery] = useState('');

  const handleChange = (e: ChangeEvent<HTMLInputElement>) => {
    setQuery(e.target.value);
    fetchResults(e.target.value);  // API call on every keystroke!
  };

  return <input onChange={handleChange} />;
}

// GOOD - Debounced search
import { useDebouncedCallback } from 'use-debounce';

function SearchInput() {
  const [query, setQuery] = useState('');

  const debouncedSearch = useDebouncedCallback(
    (value: string) => {
      fetchResults(value);
    },
    500  // Wait 500ms after last keystroke
  );

  const handleChange = (e: ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value;
    setQuery(value);
    debouncedSearch(value);
  };

  return <input value={query} onChange={handleChange} />;
}
```

### CSS Performance

```css
/* BAD - Expensive selectors */
* {  /* Matches everything! */
  box-sizing: border-box;
}

div > div > div > .class {  /* Deep nesting */
  color: red;
}

[data-attribute*="value"] {  /* Complex attribute selector */
  margin: 0;
}

/* GOOD - Efficient selectors */
.container {
  box-sizing: border-box;
}

.specific-class {  /* Direct class selector */
  color: red;
}

/* BAD - Triggering layout/reflow */
.animated {
  animation: move 1s;
}

@keyframes move {
  from { top: 0; }  /* Triggers layout! */
  to { top: 100px; }
}

/* GOOD - Use transform (GPU accelerated) */
.animated {
  animation: move 1s;
}

@keyframes move {
  from { transform: translateY(0); }  /* Composite only */
  to { transform: translateY(100px); }
}
```

## Tools for Performance Analysis

**Backend Tools:**

```bash
# Python profiling
python -m cProfile -o profile.stats app.py
python -m pstats profile.stats

# Memory profiling
pip install memory-profiler
python -m memory_profiler script.py

# Database query analysis
EXPLAIN ANALYZE SELECT ...

# Load testing
pip install locust
locust -f locustfile.py

# API benchmarking
wrk -t12 -c400 -d30s http://localhost:8000/api/endpoint
```

**Frontend Tools:**

```bash
# Bundle analysis
npm install --save-dev webpack-bundle-analyzer
npx webpack-bundle-analyzer dist/stats.json

# Lighthouse CI
npm install -g @lhci/cli
lhci autorun

# Web Vitals measurement
npm install web-vitals

# Performance testing
npm install -g lighthouse
lighthouse https://example.com --view

# Bundle size check
npm install --save-dev size-limit
npx size-limit
```

**Browser DevTools:**
- **Performance tab** - Record and analyze runtime performance
- **Coverage tab** - Find unused CSS/JS
- **Network tab** - Check asset sizes and load times
- **Lighthouse** - Automated performance audits

## Project-Specific Performance Requirements

Always check **CLAUDE.md** for:
- Performance SLAs (e.g., P95 < 200ms)
- Throughput requirements (requests/second)
- Resource limits (memory, CPU)
- Database query limits
- Cache invalidation strategies

## Learning Resources

- [FastAPI Performance Tips](https://fastapi.tiangolo.com/deployment/concepts/)
- [SQLAlchemy Performance](https://docs.sqlalchemy.org/en/20/faq/performance.html)
- [Python Performance Tips](https://wiki.python.org/moin/PythonSpeed/PerformanceTips)
- [Database Indexing](https://use-the-index-luke.com/)

Remember: **Premature optimization is the root of all evil, but measured optimization is essential!**
