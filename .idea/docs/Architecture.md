# WebAnalyzer Architecture

## Overview
WebAnalyzer is a comprehensive, open-source web vulnerability and reconnaissance tool. It represents an integrated suite of modules designed to perform deep, passive, and active testing of web applications. The tool follows a highly modular architecture, robust session management, and safe execution practices.

## Directory Structure
```
WebAnalyzer/
├── main.py                     # Entry point and orchestrator
├── modules/                    # Feature-specific scanning modules
│   ├── advanced_content_scanner.py
│   ├── api_security_scanner.py
│   ├── cloudflare_bypass.py
│   ├── contact_spy.py
│   ├── domain_dns.py
│   ├── domain_info.py
│   ├── geo_analysis.py
│   ├── nmap_zero_day.py
│   ├── security_analysis.py
│   ├── seo_analysis.py
│   ├── subdomain_takeover.py
│   ├── subfinder_tool.py
│   └── web_technologies.py
├── utils/                      # Core utilities and execution wrappers
│   ├── module_wrapper.py       # Safe execution, delays, rotation orchestration
│   ├── session_manager.py      # HTTP sessions, user agents, proxy cycling
│   └── utils.py                # Logging, serialization, UI components
└── logs/                       # JSON reports and output data
```

## Core Components

### 1. The Orchestrator (`main.py`)
The orchestrator is an interactive Command-Line Interface (CLI) built using the `Rich` and `Prompt_Toolkit` libraries.
- **Role:** Handles user input, parses target domains, presents menus for module selection, and delegates execution using asyncio routines.
- **Workflow:** Initializes the environment, fetches the selected modules, calls `execute_modules_safely` from `module_wrapper.py`, and finally serializes findings to JSON.
- **Design Pattern:** Acts as a Facade to hide the underlying complexity of the scanning mechanisms from the user.

### 2. Module Wrapper (`utils/module_wrapper.py`)
Responsible for executing modules gracefully to avoid bans and ensure stability.
- **Role:** Manages inter-module delays based on the "weight" of the module (light, medium, heavy scans).
- **Session Rotation:** Triggers session IP/User-Agent rotation through the session manager before executing a new module.
- **Error Handling:** Implements fail-safes. If a module crashes, it catches the exception, logs it, and continues with the next module without aborting the entire scan.

### 3. Session Management (`utils/session_manager.py`)
An advanced wrapper around Python `requests` and `aiohttp` to evade bot detection limits.
- **HTTP/S Configurations:** Handles SSL context ignoring verifications if required.
- **Anti-Bot Features:** Randomizes User-Agents per session, supports proxy cycling, implements exponential backoff on HTTP 429 Rate Limits, and configures realistic HTTP headers (`Sec-Fetch-Mode`, `Upgrade-Insecure-Requests`, etc.).
- **Retries:** Configures the urllib3 Retries adapter for 500, 502, 503, and 504 status codes.

### 4. Modules Array
All logic relating to security checks, OSINT, and performance is decoupled from the core loop and resides completely in the `modules/` folder. Every module adopts its approach (synchronous vs. asynchronous, using ThreadPoolExecutors where necessary) and is treated as a black-box function by the orchestrator.

## Architectural Characteristics
- **Async & Threaded Mixed Concurrency:** Core execution is asynchronous (`asyncio`), but individual modules utilize either internal `ThreadPoolExecutor` (e.g., `domain_dns.py`, `subdomain_takeover.py`) or pure async HTTP streams (e.g., `api_security_scanner.py`) to maximize efficiency and scan speed.
- **State Isolation:** The modules do not share a global state directly. Each module receives the domain input, runs its analysis autonomously, and returns a dictionary or dataclass which is subsequently serialized.
- **Graceful Degradation:** Features that rely on external tools (e.g., `nmap_zero_day.py` uses system `nmap`, playwright integration) handle absence gracefully, usually falling back to native methods or logging a warning to the user.
