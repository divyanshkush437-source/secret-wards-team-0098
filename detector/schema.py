"""Offsets are Python character offsets in the ORIGINAL string; end is exclusive.
Results contain sensitive data. Never log, serialize to reports, or print them.
"""
from __future__ import annotations
from dataclasses import dataclass, field

@dataclass(frozen=True, repr=False)
class EntitySpan:
    start: int
    end: int
    entity_type: str
    text: str
    normalized: str
    action: str
    confidence: float

    def __repr__(self):
        return f'EntitySpan(start={self.start}, end={self.end}, type={self.entity_type})'

@dataclass(repr=False)
class DetectionResult:
    spans: list[EntitySpan] = field(default_factory=list)
    patient_names: list[str] = field(default_factory=list)
    relative_names: list[str] = field(default_factory=list)
    phones: list[str] = field(default_factory=list)
    ids: dict[str, list[str]] = field(default_factory=dict)
    dates: list[str] = field(default_factory=list)
    dob: str | None = None
    age: int | None = None
    gender: str | None = None
    locations: list[str] = field(default_factory=list)
    pincodes: list[str] = field(default_factory=list)

    def __repr__(self):
        return f'DetectionResult(span_count={len(self.spans)})'
