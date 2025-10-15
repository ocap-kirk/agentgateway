# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Agentgateway is an open source data plane for agentic AI connectivity, written in Rust. It provides security, observability, and governance for agent-to-agent (A2A) and agent-to-tool (MCP) communication. The project supports dynamic configuration via both local file-based config and XDS (control plane).

## Build Commands

**Build the UI:**
```bash
cd ui
npm install
npm run build
cd ..
```

**Build the binary:**
```bash
export CARGO_NET_GIT_FETCH_WITH_CLI=true
make build
```

**Run the binary:**
```bash
./target/release/agentgateway
```

The UI will be available at `http://localhost:15000/ui`.

## Development Commands

**Linting:**
```bash
make lint                  # Check formatting and run clippy
make fix-lint             # Auto-fix lint issues
```

**Testing:**
```bash
make test                 # Run all tests
cargo test <test_name>    # Run a specific test
```

**Code generation:**
```bash
make gen                  # Generate APIs, schemas, and auto-fix lint
make generate-schema      # Generate schema only
make generate-apis        # Generate XDS APIs only
```

**Configuration validation:**
```bash
make validate             # Validate all example configs
cargo run -- -f <config.yaml> --validate-only  # Validate a specific config
```

**UI Development:**
```bash
cd ui
npm run dev              # Start Next.js dev server (runs on port 3000)
npm run lint             # Lint UI code
```

## Architecture

### Workspace Structure

Agentgateway is a Cargo workspace with multiple crates:

- **`crates/agentgateway`**: Main gateway implementation with HTTP/MCP/A2A proxying logic
- **`crates/agentgateway-app`**: Binary entry point
- **`crates/core`**: Core networking and utilities shared across all crates
- **`crates/xds`**: XDS protocol implementation for control plane communication
- **`crates/hbone`**: HBONE (HTTP-Based Overlay Network Encapsulation) transport
- **`crates/a2a-sdk`**: Rust types for the A2A (Agent2Agent) protocol
- **`crates/mock-server`**: Testing utilities
- **`crates/xtask`**: Development automation tasks
- **`ui/`**: Next.js-based web UI

### Configuration Architecture

Agentgateway has three configuration layers:

1. **Static Configuration**: Set once at startup via environment variables or YAML/JSON. Contains global settings like ports, logging, etc.

2. **Local Configuration**: File-based (YAML/JSON) with hot-reload via file watch. Defines backends, routes, policies, etc. Maps to an internal representation (IR).

3. **XDS Configuration**: Remote control plane using xDS protocol with custom types (not Envoy types). Also maps to the same IR as local config. See `crates/agentgateway/proto/resource.proto` for the protobuf definitions.

**Key principle**: XDS resources maintain 1:1 cardinality with user-facing concepts (one route → one Route resource, one pod → one Workload) rather than bundling children into parents. This avoids expensive fanout when updating configuration.

### CEL Expression Language

CEL (Common Expression Language) is used extensively throughout the codebase for:

- Authorization policies
- Logging/tracing field extraction
- HTTP header/body transformations
- Rate limiting selectors

**Key architecture detail**: CEL evaluation uses a `ContextBuilder` that dynamically determines which request data to retain based on whether any expression references it. This is critical for expensive fields like `request.body`.

Available variables are auto-generated into `schema/cel.json` and documented in `schema/README.md`. Custom functions include `json()`, `with()`, `flatten()`, `base64Encode()`, `regexReplace()`, and others.

### Main Source Organization

Inside `crates/agentgateway/src/`:

- **`proxy/`**: Core proxying logic and request handling
- **`mcp/`**: Model Context Protocol implementation
- **`a2a/`**: Agent2Agent protocol implementation
- **`llm/`**: LLM provider integrations and request/response handling
- **`http/`**: HTTP request routing and transformation
- **`cel/`**: CEL expression evaluation and context building
- **`config.rs`**: Configuration parsing and validation
- **`state_manager.rs`**: Dynamic configuration state management
- **`store/`**: Resource storage and lookup
- **`transport/`**: Connection management and protocol handling
- **`telemetry/`**: Metrics, tracing, and logging
- **`management/`**: Admin API handlers
- **`control/`**: XDS client and certificate management
- **`client/`**: Upstream connection pooling and DNS

### Request Processing Flow

1. Request arrives at a listener (defined in config)
2. Routing matches request to a backend/target
3. Policies are applied (authentication, authorization, rate limiting, etc.)
4. For MCP/A2A: protocol-specific handling and transformation
5. Request proxied to upstream backend
6. Response transformed (if needed) and returned
7. Throughout: CEL expressions evaluated for telemetry, policy decisions, etc.

### External Authorization (ext_authz)

Agentgateway implements the Envoy external authorization protocol (`envoy.service.auth.v3.Authorization`). The implementation is in `crates/agentgateway/src/http/ext_authz.rs`.

**How it works**:
1. When `extAuthz` policy is configured, agentgateway makes a gRPC call to the external service before proxying the request
2. The `CheckRequest` includes:
   - Source/destination peer info (IP, port, TLS identity)
   - Full HTTP request details (method, path, headers, protocol)
   - Optionally: request body (configured via `includeRequestBody`)
   - Context extensions (custom key-value pairs from config)
3. External service responds with allow/deny decision
4. On allow: request continues, optional headers can be added/removed
5. On deny: returns 403 or custom status code

**Configuration options**:
- `host`: Target service address (e.g., `localhost:8042`)
- `includeRequestBody`: Send request body to auth service
  - `maxRequestBytes`: Max body size (default 8192)
  - `packAsBytes`: Send as binary (`raw_body`) vs UTF-8 string (`body`)
  - `allowPartialMessage`: Send partial body if size exceeded
- `timeout`: Request timeout (default 200ms)
- `context`: Custom key-value pairs sent in `context_extensions`
- `failOpen`/`statusOnError`: Failure handling behavior

**Proto definition**: `crates/agentgateway/proto/ext_authz.proto`

**Testing**: Use `grpcurl` with the proto file to test external auth services:
```bash
cd crates/agentgateway
grpcurl -plaintext -proto proto/ext_authz.proto -import-path proto \
  -d '{"attributes":{...}}' localhost:8042 \
  envoy.service.auth.v3.Authorization/Check
```

## Testing

Tests are co-located with source code. The codebase uses:

- Standard Rust unit tests (`#[test]`)
- Integration tests in `tests/` directories
- Snapshot testing with `insta` crate (see `crates/agentgateway/src/llm/tests/`)
- Test fixtures in JSON files for request/response validation
- Mock servers via `crates/mock-server`

To update snapshots after intentional changes:
```bash
cargo insta review
```

## Common Patterns

**Adding a new CEL variable**: Modify the context builder in `crates/agentgateway/src/cel/` and regenerate the schema with `make generate-schema`.

**Adding a new policy type**: Define types in `crates/agentgateway/src/types/`, implement evaluation in `crates/agentgateway/src/proxy/`, and add corresponding XDS proto in `crates/agentgateway/proto/`.

**Supporting a new protocol**: Add handlers in a new module (like `mcp/` or `a2a/`), integrate with routing in `proxy/`, and update configuration types in `config.rs`.


## Build Profiles

The workspace defines custom build profiles:

- `quick-release`: Optimized but with faster incremental builds (16 codegen units, no LTO)
- `release`: Full optimization (1 codegen unit, LTO enabled)
- `bench`: Based on quick-release with debug symbols

## Dependencies

Key dependencies to be aware of:

- `tokio`: Async runtime
- `hyper`: HTTP implementation
- `axum`: HTTP routing for admin APIs
- `tonic`: gRPC/protobuf for XDS
- `rustls`: TLS implementation (using ring)
- `rmcp`: MCP protocol implementation
- `cel`: CEL expression evaluation
- `schemars`: JSON schema generation
- `async-openai`: OpenAI API client

## UI Development

The UI is a Next.js 15 application using:

- React 19
- TailwindCSS 4
- Radix UI components
- `@a2a-js/sdk` and `@modelcontextprotocol/sdk` for protocol support

The UI must run on port 3000 when developing alongside agentgateway.
