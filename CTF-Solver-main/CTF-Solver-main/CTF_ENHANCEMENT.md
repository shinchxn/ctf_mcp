# Roadmap for Enhancing MCP Kali Server for Complex CTF Solving

## 🎯 Current System Limitations

### 1. Lack of State Management
- **Issue**: API calls execute independently without preserving prior execution context.
- **Impact**: Multi-step exploits and interactive shell sessions fail.
- **Example**: In Pwnable challenges, the workflow (binary analysis → exploit authoring → execution) is fragmented.

### 2. Missing Binary Analysis Tools
- **Issue**: Server provides web vulnerability scanning but lacks binary reversing / pwnable tooling.
- **Missing Tools**:
  - `pwntools` - Python exploit framework
  - `gdb` + `gef`/`pwndbg` - Debuggers
  - `radare2`/`ghidra` - Reverse engineering frameworks

---

## 🛠️ Proposed Solutions & Enhancements

### 1. Workspace & Session Management System

- Implement `/api/session/create` to allocate dedicated working directories (`/tmp/mcp_sessions/<session_id>`).
- Implement `/api/session/<session_id>/context` to save state variables, binary headers, offsets, and gadget locations.
- Support file upload (`/api/file/upload`) and download (`/api/file/download`) for binary analysis.

### 2. Interactive Shell Management (`pexpect` integration)

- Support interactive process sessions (`/api/interactive/start`, `/api/interactive/send`, `/api/interactive/read`).
- Allow bidirectional shell interaction for `nc`, `gdb`, or interactive Python exploits.

### 3. Dedicated Tool Endpoints for CTF Categories

#### A. Pwnable & Binary Exploitation
- `checksec_binary`: Extract binary protections (RELRO, Stack Canary, NX, PIE).
- `find_rop_gadgets`: Search ROP gadgets using `ROPgadget` / `ropper`.
- `analyze_with_radare2`: Run disassembly and symbol analysis with `radare2`.
- `run_pwntools_exploit`: Execute Python pwntools scripts inside session workspace.

#### B. Cryptography & Hash Cracking
- `factordb_query`: Query FactorDB API for RSA modulus factorization.
- `rsa_attack`: Run automated RSA attacks via `RsaCtfTool`.
- `hashcat_crack` / `john_crack`: Cracking hashes with standard wordlists (`rockyou.txt`).

#### C. Forensics & Steganography
- `volatility_analyze`: Memory analysis using Volatility 3 plugins.
- `steghide_extract`: Extract steganographic payloads from images.
- `binwalk_analyze`: Firmware & binary file carving.

---

## 🏗️ Architecture Design

```
+------------------+         HTTP/JSON         +-------------------+
|    MCP Client    | <=======================> |  MCP Kali Server  |
| (Claude / Gemini)|         Port 5000         |   (kali_server)   |
+------------------+                           +-------------------+
                                                         |
                                                +-----------------+
                                                | Session Manager |
                                                +-----------------+
                                                         |
                                                +-----------------+
                                                | Linux Subprocess|
                                                |  & Tools (Kali) |
                                                +-----------------+
```
