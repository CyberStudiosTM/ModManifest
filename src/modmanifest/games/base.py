"""Game module interface."""

from __future__ import annotations

from abc import ABC, abstractmethod

from modmanifest.context import ScanContext


class GameModule(ABC):
    """A game-specific recognizer and validator. Modules never share validation logic."""

    name: str
    label: str

    @abstractmethod
    def recognize(self, ctx: ScanContext) -> bool:
        """Return True if the source contains structures this module understands."""

    @abstractmethod
    def validate(self, ctx: ScanContext) -> None:
        """Record recognized files, package information and findings on ``ctx.report``."""
