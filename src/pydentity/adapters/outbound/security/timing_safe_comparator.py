from __future__ import annotations

import hmac

from pydentity.domain.ports.timing_safe_comparator import TimingSafeComparatorPort


class HMACTimingSafeComparator(TimingSafeComparatorPort):
    def equals(self, a: bytes, b: bytes) -> bool:
        return hmac.compare_digest(a, b)
