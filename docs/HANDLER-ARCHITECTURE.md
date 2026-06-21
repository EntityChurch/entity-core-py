# Handler Architecture

This document describes the Python handler architecture after the V6 revision, bringing it to parity with Go/Rust implementations.

## Overview

The handler system provides capability-gated request dispatch with:
- **Handler-to-handler dispatch** via `ctx.execute()`
- **Handler protocols** for self-describing handlers
- **Capability scoping** to limit handler permissions
- **Two-tier storage** with tree handler as the only direct storage accessor

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                         Peer                                     │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                   Handler Registry                       │    │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐     │    │
│  │  │ system/tree  │ │  system/*    │ │     *        │     │    │
│  │  │  (tree)      │ │  (system)    │ │  (storage)   │     │    │
│  │  │  priority:110│ │  priority:100│ │  priority:0  │     │    │
│  │  └──────────────┘ └──────────────┘ └──────────────┘     │    │
│  └─────────────────────────────────────────────────────────┘    │
│                              │                                   │
│                              ▼                                   │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                  HandlerContext                          │    │
│  │  • execute(uri, operation, params) → ExecuteResult       │    │
│  │  • capability (effective, after max_scope intersection)  │    │
│  │  • bounds, chain_id (for tracing)                        │    │
│  │  • emit_pathway (deprecated, except for tree handler)    │    │
│  └─────────────────────────────────────────────────────────┘    │
│                              │                                   │
│                              ▼                                   │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    EmitPathway                           │    │
│  │  ┌─────────────────┐  ┌─────────────────┐               │    │
│  │  │  ContentStore   │  │   EntityTree    │               │    │
│  │  │  (Hash → Entity)│  │  (URI → Hash)   │               │    │
│  │  └─────────────────┘  └─────────────────┘               │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

## Handler Types

### 1. Tree Handler (Privileged)

The tree handler (`system/tree`) is the **only handler** with direct storage access. All other handlers use `ctx.execute()` to access storage.

```python
# Tree handler has direct emit_pathway access (no deprecation warnings)
async def tree_handler(path, operation, params, ctx):
    # Direct access to storage (privileged)
    entity = ctx.emit_pathway.content_store.get(hash)
    ctx.emit_pathway.entity_tree.set(uri, hash)
```

### 2. Regular Handlers

Regular handlers use `ctx.execute()` for storage operations:

```python
async def my_handler(path, operation, params, ctx):
    # Read via tree handler
    result = await ctx.execute("system/tree", "get", {"path": "data/foo"})
    if result.ok:
        entity = result.result

    # Write via tree handler
    result = await ctx.execute("system/tree", "put", {
        "path": "data/bar",
        "entity": {"type": "my/type", "data": {...}}
    })
```

### 3. Handler Objects with Protocols

Handlers can be objects implementing protocols for self-description:

```python
class MyHandler:
    @property
    def name(self) -> str:
        """NamedHandler protocol - auto-detected by builder."""
        return "my-handler"

    def register_types(self, registry: TypeRegistry) -> None:
        """TypeProvider protocol - called at startup."""
        registry.register(my_custom_type)

    def manifest(self) -> Entity:
        """ManifestProvider protocol - emitted to system/handlers/{name}."""
        return Entity(
            type="system/handler",
            data={
                "name": self.name,
                "pattern": "myapp/*",
                "operations": {
                    "process": {"description": "Process data"},
                },
            },
        )

    async def __call__(self, path, operation, params, ctx):
        """Handler implementation."""
        return {"status": 200, "result": {...}}
```

## Capability Scoping

### Handler max_scope

Handlers can have a `max_scope` that restricts their effective capability:

```python
from entity_core.capability.grant import Grant

# Handler can only read from data/* paths
restricted_grants = [
    Grant(
        handlers=["*"],
        resources=["data/*"],
        operations=["read", "get"],
    )
]

peer = (PeerBuilder()
    .with_keypair(keypair)
    .with_handler("reader/*", read_handler, max_scope=restricted_grants)
    .build())
```

When a request arrives:
1. Request capability is validated at dispatch
2. If handler has `max_scope`, effective capability = intersection(request_cap, max_scope)
3. Handler receives the restricted effective capability in `ctx.capability`

### Two-Level Capability Model

Per V4 spec, capabilities use two-level checking:

1. **Handler scope**: Does capability grant operation on this handler?
   - Checked at dispatch time via `handlers` field

2. **Path scope**: Does capability grant operation on this path?
   - Checked by handler via `resources` field

```python
# In handler, check path-level permission
from entity_core.capability.checking import check_path_permission

if not check_path_permission(ctx.capability, "get", path, ctx.local_peer_id):
    return {"status": 403, "result": {"error": "Forbidden"}}
```

## ExecuteResult

Handler-to-handler calls return `ExecuteResult`:

```python
@dataclass
class ExecuteResult:
    status: int                      # HTTP-style status code
    result: dict[str, Any] | None    # Success data
    error: str | None                # Error message

    @property
    def ok(self) -> bool:
        """True for 2xx status codes."""
        return 200 <= self.status < 300

    def raise_for_status(self) -> None:
        """Raise RuntimeError if not ok."""
```

Usage:

```python
result = await ctx.execute("system/tree", "get", {"path": "data/foo"})

# Option 1: Check ok
if result.ok:
    process(result.result)
else:
    log_error(result.error)

# Option 2: Raise on error
result.raise_for_status()
process(result.result)
```

## Building New Handlers

### Simple Function Handler

```python
async def echo_handler(path, operation, params, ctx):
    """Simple echo handler."""
    if operation == "echo":
        return {"status": 200, "result": {"echo": params}}
    return {"status": 400, "result": {"error": f"Unknown operation: {operation}"}}

peer = (PeerBuilder()
    .with_keypair(keypair)
    .with_handler("echo/*", echo_handler, name="echo")
    .build())
```

### Handler Class with Protocols

```python
from entity_core.handlers.protocols import NamedHandler, ManifestProvider
from entity_core.protocol.entity import Entity

class CounterHandler:
    """Stateful counter handler."""

    def __init__(self):
        self._counters: dict[str, int] = {}

    @property
    def name(self) -> str:
        return "counter"

    def manifest(self) -> Entity:
        return Entity(
            type="system/handler",
            data={
                "name": "counter",
                "pattern": "counter/*",
                "description": "In-memory counter service",
                "operations": {
                    "get": {"description": "Get counter value"},
                    "increment": {"description": "Increment counter"},
                    "reset": {"description": "Reset counter to zero"},
                },
            },
        )

    async def __call__(self, path, operation, params, ctx):
        counter_name = path.split("/")[-1]

        if operation == "get":
            value = self._counters.get(counter_name, 0)
            return {"status": 200, "result": {"value": value}}

        elif operation == "increment":
            self._counters[counter_name] = self._counters.get(counter_name, 0) + 1
            return {"status": 200, "result": {"value": self._counters[counter_name]}}

        elif operation == "reset":
            self._counters[counter_name] = 0
            return {"status": 200, "result": {"value": 0}}

        return {"status": 400, "result": {"error": f"Unknown operation: {operation}"}}

# Register - name and manifest auto-detected
peer = (PeerBuilder()
    .with_keypair(keypair)
    .with_handler("counter/*", CounterHandler(), priority=50)
    .build())
```

### Handler that Delegates to Tree

```python
class CachingHandler:
    """Handler that caches entities with TTL."""

    @property
    def name(self) -> str:
        return "cache"

    async def __call__(self, path, operation, params, ctx):
        if operation == "get":
            cache_key = params.get("key")

            # Check cache first (stored in tree)
            result = await ctx.execute("system/tree", "get", {
                "path": f"cache/{cache_key}"
            })

            if result.ok:
                cached = result.result.get("data", {})
                if not self._is_expired(cached):
                    return {"status": 200, "result": cached.get("value")}

            # Cache miss - return 404
            return {"status": 404, "result": {"error": "Cache miss"}}

        elif operation == "set":
            cache_key = params.get("key")
            value = params.get("value")
            ttl = params.get("ttl", 3600)

            # Store in tree
            result = await ctx.execute("system/tree", "put", {
                "path": f"cache/{cache_key}",
                "entity": {
                    "type": "cache/entry",
                    "data": {
                        "value": value,
                        "expires_at": int(time.time() * 1000) + ttl * 1000,
                    },
                },
            })

            return {"status": 200, "result": {"cached": True}}
```

## Migration Guide

### From Direct Storage Access

Before (deprecated):
```python
async def old_handler(path, operation, params, ctx):
    # Direct storage access - triggers deprecation warning
    entity = ctx.get_at(path)
    ctx.emit(path, new_entity)
```

After:
```python
async def new_handler(path, operation, params, ctx):
    # Via tree handler - capability-gated
    result = await ctx.execute("system/tree", "get", {"path": path})
    if result.ok:
        entity = result.result

    await ctx.execute("system/tree", "put", {
        "path": path,
        "entity": new_entity.to_dict(),
    })
```

### From Extension Direct Registration

Before (deprecated):
```python
class MyExtension(Extension):
    def initialize(self, ctx: ExtensionContext):
        ctx.handlers.register("my/*", self._handler)  # Deprecated
```

After:
```python
# Register via builder instead
peer = (PeerBuilder()
    .with_keypair(keypair)
    .with_handler("my/*", my_handler, name="my")
    .with_extension(MyExtension())
    .build())
```

## Package Structure

```
packages/
├── entity-core/           # Minimal core protocol
│   └── src/entity_core/
│       ├── handlers/
│       │   ├── __init__.py
│       │   ├── context.py      # HandlerContext, ExecuteResult
│       │   ├── registry.py     # HandlerRegistry, RegisteredHandler
│       │   ├── protocols.py    # NamedHandler, TypeProvider, ManifestProvider
│       │   └── bootstrap.py    # Bootstrap handler (required)
│       └── ...
│
├── entity-handlers/       # Standard handlers (optional)
│   └── src/entity_handlers/
│       ├── tree.py        # Tree handler (privileged)
│       ├── system.py      # System introspection
│       ├── storage.py     # Fallback CRUD (uses ctx.execute)
│       └── manifest.py    # Manifest utilities
│
└── entity-cli/            # CLI application
    └── src/entity_cli/
        └── ...
```

## Best Practices

1. **Use `ctx.execute()` for storage** - Don't access emit_pathway directly
2. **Implement protocols** - Use NamedHandler, ManifestProvider for discoverability
3. **Check path permissions** - Call `check_path_permission()` for path-level access
4. **Use max_scope** - Restrict handler permissions to minimum required
5. **Return proper status codes** - Use HTTP-style codes (200, 400, 403, 404, 500)
6. **Handle errors gracefully** - Check `result.ok` before accessing `result.result`
