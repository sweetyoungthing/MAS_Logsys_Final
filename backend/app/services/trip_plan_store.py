"""Persistent storage for generated trip plans."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

from ..models.schemas import TripPlan


class TripPlanStore:
    """Store trip plans on disk so result pages can be refreshed safely."""

    def __init__(self, storage_dir: Path | None = None):
        """Initialize the store and ensure the backing directory exists."""
        base_dir = Path(__file__).resolve().parent.parent.parent
        self.storage_dir = storage_dir or (base_dir / "data" / "trip_plans")
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def create(self, trip_plan: TripPlan) -> str:
        """Persist a newly generated trip plan and return its identifier."""
        plan_id = uuid.uuid4().hex
        self._write(plan_id, trip_plan)
        return plan_id

    def update(self, plan_id: str, trip_plan: TripPlan) -> None:
        """Overwrite an existing trip plan."""
        self._write(plan_id, trip_plan)

    def get(self, plan_id: str) -> TripPlan:
        """Load a stored trip plan by identifier."""
        path = self._path_for(plan_id)
        if not path.exists():
            raise FileNotFoundError(f"Trip plan not found: {plan_id}")
        with path.open("r", encoding="utf-8") as file:
            data = json.load(file)
        return TripPlan(**data)

    def _write(self, plan_id: str, trip_plan: TripPlan) -> None:
        """Write a trip plan to disk."""
        path = self._path_for(plan_id)
        with path.open("w", encoding="utf-8") as file:
            json.dump(trip_plan.model_dump(), file, ensure_ascii=False, indent=2)

    def _path_for(self, plan_id: str) -> Path:
        """Resolve a trip plan identifier to a JSON file path."""
        return self.storage_dir / f"{plan_id}.json"


_trip_plan_store = TripPlanStore()


def get_trip_plan_store() -> TripPlanStore:
    """Return the shared trip plan store instance."""
    return _trip_plan_store
