from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum


class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    title: str
    severity: Severity
    description: str
    recommendation: str = ""
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CheckResult:
    check_name: str
    target: str
    passed: bool
    findings: List[Finding] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class BaseCheck(ABC):
    def __init__(self, config: dict):
        self.config = config

    @abstractmethod
    def run(self, target: dict) -> CheckResult:
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        pass
