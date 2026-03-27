from abc import ABC, abstractmethod


class TokenGenerator(ABC):
    @abstractmethod
    def generate(self) -> str: ...
