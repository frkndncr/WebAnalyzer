# Writing a module

A WebAnalyzer module is one function. Register it and it shows up in the API,
the dashboard and the scan presets - no other file changes.

## The 20-line version

Create `modules/plugins/my_check.py`:

```python
from modules.registry import module


@module(
    "Robots.txt",                       # unique name, shown everywhere
    description="Fetches robots.txt",   # shown in the dashboard
    group="recon",                      # recon | security | offensive
    weight="light",                     # light | medium | heavy
)
def robots(domain):
    import requests
    r = requests.get(f"https://{domain}/robots.txt", timeout=8, allow_redirects=False)
    return {"found": r.status_code == 200, "status": r.status_code}
```

Start the API (or run the tests) and `Robots.txt` is in `GET /api/modules`, in
the dashboard's module picker and in the "Full" preset. That is the whole
contract: **a function that takes a domain and returns JSON-serialisable data.**

A working, tested example ships in the repo:
[`modules/plugins/security_txt.py`](../modules/plugins/security_txt.py).

## Options

| Option | Default | Meaning |
|---|---|---|
| `description` | `""` | One line for the module picker. |
| `group` | `"recon"` | `recon`, `security` or `offensive`. Used for grouping and icons. |
| `weight` | `"medium"` | `light`, `medium` or `heavy`: how hard it hits the target. |
| `active` | `False` | Set `True` if it sends **intrusive** traffic (see below). |
| `needs_results` | `False` | Signature becomes `fn(domain, results)`; `results` maps module names to what the others produced so far. |
| `runs_in_loop` | `False` | Call it on the event loop instead of a worker thread (for code that must run there). |
| `order` | `100` | Position in listings; lower comes first. |

Functions may be `async def`. Blocking functions run in a worker thread, so
they cannot stall the API. If your module raises, only its own result becomes
`{"error": "..."}` and the rest of the scan continues.

## Passive vs active - please get this right

On the public demo, **active** modules only run for domains whose owner has
verified them with a DNS TXT record; passive modules are open to everyone.
Mark a module `active=True` if it does any of the following to a target:

- port or service scanning,
- sending payloads (injection, fuzzing, brute force),
- probing many hosts or paths derived from the target,
- anything a site owner could reasonably call an attack.

A module that just reads public data, or makes one or two ordinary requests, is
passive. When unsure, mark it active - it only costs verification on the demo;
self-hosted instances are never restricted.

## Safety rules for modules that make requests

- Always set a **timeout**.
- Do **not** follow redirects blindly (`allow_redirects=False`, or only follow to
  the same site): a target must not be able to redirect your request to an
  internal address.
- Cap the size of what you read.
- Never put secrets in the returned data.

## Where plugins are loaded from

1. every `*.py` file (not starting with `_`) in `modules/plugins/`;
2. every directory listed in the `WEBANALYZER_PLUGIN_DIRS` environment variable
   (separated by `:` on Linux/macOS, `;` on Windows) - handy for private modules
   you do not want in the repository.

A plugin that fails to import is logged and skipped; it can never stop the
platform from starting. A plugin cannot replace a built-in module: registering
an existing name is an error.

## Test it

Keep the network out of your tests: let the function take its fetcher as an
optional argument, as `security_txt.py` does, and pass a fake in the test.

```python
# modules/plugins/robots.py
@module("Robots.txt", description="Fetches robots.txt", group="recon", weight="light")
def robots(domain, get=None):
    if get is None:
        import requests
        get = lambda url: requests.get(url, timeout=8, allow_redirects=False)
    r = get(f"https://{domain}/robots.txt")
    return {"found": r.status_code == 200, "status": r.status_code}
```

```python
# tests/test_robots.py
from modules.plugins.robots import robots

class Response:
    status_code = 200

def test_found():
    assert robots("example.org", get=lambda url: Response())["found"] is True
```

Run everything with:

```bash
pytest
```

## Pull request checklist

- [ ] One file in `modules/plugins/`, with a clear `description`.
- [ ] Timeouts, no blind redirects, bounded reads.
- [ ] `active=True` if it is intrusive.
- [ ] Tests that do not touch the network.
- [ ] `pytest` and `flake8 . --select=E9,F63,F7,F82` pass.
