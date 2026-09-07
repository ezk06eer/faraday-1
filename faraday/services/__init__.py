"""
Services layer — extracted from faraday/server/api/base.py and utils.

Deterministic composition over inheritance (E2-A4).
Import-safe: sorting import deferred to avoid flask_classful dep in tests.
"""
# Lazy re-exports to keep import without flask_classful
try:
    from faraday.services.pagination import PaginationService  # noqa: F401
except ImportError:
    pass
try:
    from faraday.services.sorting import SortingService  # noqa: F401
except ImportError:
    pass
try:
    from faraday.services.filtering import FilteringService  # noqa: F401
except ImportError:
    pass
