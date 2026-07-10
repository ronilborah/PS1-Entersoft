"""
parser.py — Person B owns this file.

Reads the context JSON that comes from the Mapper agent (upstream).
Mapper passes things like js_files and endpoints it already discovered.
We use those instead of rediscovering them ourselves.

If no context is passed (standalone mode), returns empty lists
so the rest of the code still works without crashing.
"""


def parse_context(context: dict) -> dict:
    """
    Extract useful surface data from upstream agent context.

    Mapper typically sends something like:
    {
        "js_files": ["https://target.com/main.js", "/admin.js"],
        "endpoints": ["/api/login", "/api/users"],
        "urls": ["https://target.com/page1"]
    }

    We pull out whatever we can find and return a clean dict.
    """
    if not context:
        return {"js_files": [], "endpoints": [], "urls": []}

    # Mapper might nest its output under a "response" key
    data = context.get("response", context)

    js_files  = data.get("js_files",  [])
    endpoints = data.get("endpoints", [])
    urls      = data.get("urls",      [])
    routes    = data.get("routes",    [])  # some mappers call it routes

    # Merge routes into endpoints (same idea, different key)
    all_endpoints = list(set(endpoints + routes))

    return {
        "js_files":  js_files,
        "endpoints": all_endpoints,
        "urls":      urls,
    }
