"""LDAP control helpers and OID notes.

Only Simple Paged Results (RFC 2696 / AD OID 1.2.840.113556.1.4.319) is
required for the MVP. Other OIDs are documented as notes with explicit
support status so the spike matrix can reference them.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# OID notes: (oid, name, support status)
PAGED_RESULTS_OID = "1.2.840.113556.1.4.319"
LDAP_SERVER_SHOW_DELETED_OID = "1.2.840.113556.1.4.417"
LDAP_SERVER_DIRSYNC_OID = "1.2.840.113556.1.4.841"
LDAP_SERVER_SD_FLAGS_OID = "1.2.840.113556.1.4.801"
LDAP_SERVER_RANGE_OPTION_OID = "1.2.840.113556.1.4.802"
LDAP_SERVER_VERIFY_NAME_OID = "1.2.840.113556.1.4.1338"

OID_NOTES: tuple[tuple[str, str, str], ...] = (
    (PAGED_RESULTS_OID, "Simple Paged Results", "required"),
    (LDAP_SERVER_SHOW_DELETED_OID, "Show Deleted Objects", "not-required"),
    (LDAP_SERVER_DIRSYNC_OID, "DirSync", "not-required"),
    (LDAP_SERVER_SD_FLAGS_OID, "SD Flags (security descriptor)", "forbidden-mvp"),
    (LDAP_SERVER_RANGE_OPTION_OID, "Range Retrieval", "best-effort"),
    (LDAP_SERVER_VERIFY_NAME_OID, "Verify Name", "not-required"),
)

DEFAULT_PAGE_SIZE = 500
MAX_PAGE_SIZE = 1000


@dataclass(frozen=True)
class PagedCookie:
    """Opaque paging cursor.

    Attributes:
        cookie: Server-returned cookie bytes (empty means start/finished).
        page_size: Requested page size.
        finished: Whether the server signalled completion.
    """

    cookie: bytes = b""
    page_size: int = DEFAULT_PAGE_SIZE
    finished: bool = False

    def __post_init__(self) -> None:
        if not 1 <= self.page_size <= MAX_PAGE_SIZE:
            raise ValueError("page_size must be 1..1000")


@dataclass
class PagedSearchState:
    """Client-side paging iteration state.

    Attributes:
        cookie: Current cookie exchanged with the server.
        pages_returned: Number of pages consumed so far.
        entries_seen: Total entries returned across pages.
        seen_dns: Lower-cased DNs observed (duplicate detection).
    """

    cookie: PagedCookie = field(default_factory=PagedCookie)
    pages_returned: int = 0
    entries_seen: int = 0
    seen_dns: set[str] = field(default_factory=set)

    def advance(self, next_cookie: bytes, page_entries: list[str]) -> None:
        """Advance state after one page.

        Args:
            next_cookie: Cookie returned by the server for this page.
            page_entries: DNs in the current page.

        Raises:
            ValueError: If a duplicate DN is observed across pages.
        """
        for dn in page_entries:
            lowered = dn.lower()
            if lowered in self.seen_dns:
                raise ValueError(f"duplicate DN across pages: {dn}")
            self.seen_dns.add(lowered)
        self.entries_seen += len(page_entries)
        self.pages_returned += 1
        finished = len(next_cookie) == 0
        self.cookie = PagedCookie(cookie=next_cookie, page_size=self.cookie.page_size, finished=finished)

    @property
    def is_finished(self) -> bool:
        """Return True when the server cookie is empty after a page."""
        return self.cookie.finished


def initial_cookie(page_size: int = DEFAULT_PAGE_SIZE) -> PagedCookie:
    """Create the initial paging cookie.

    Args:
        page_size: Requested page size.

    Returns:
        Initial :class:`PagedCookie`.
    """
    return PagedCookie(cookie=b"", page_size=page_size, finished=False)
