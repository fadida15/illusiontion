from __future__ import annotations

import os
from typing import Protocol

from .schemas import DecisionRecord


class DecisionStore(Protocol):
    def save(self, record: DecisionRecord) -> str: ...


class InMemoryDecisionStore:
    def __init__(self) -> None:
        self.records: dict[str, DecisionRecord] = {}

    def save(self, record: DecisionRecord) -> str:
        self.records[record.claim_id] = record
        return record.claim_id


class FirestoreDecisionStore:
    """Optional durable store used in Cloud Run / hackathon deployment."""

    def __init__(self, collection: str = "illusiontion_decisions") -> None:
        from google.cloud import firestore

        project = os.getenv("GOOGLE_CLOUD_PROJECT")
        self.client = firestore.Client(project=project)
        self.collection = self.client.collection(collection)

    def save(self, record: DecisionRecord) -> str:
        self.collection.document(record.claim_id).set(record.model_dump(mode="json"))
        return record.claim_id
