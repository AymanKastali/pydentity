from abc import ABC, abstractmethod


class TokenHasher(ABC):
    @abstractmethod
    def hash(self, raw_token: str) -> str: ...
