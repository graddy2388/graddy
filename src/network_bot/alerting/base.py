from abc import ABC, abstractmethod
from typing import List

from ..checks.base import CheckResult


class BaseAlerter(ABC):
    def __init__(self, config: dict):
        self.config = config

    @abstractmethod
    def send(self, results: List[CheckResult], run_timestamp: str) -> None:
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        pass
