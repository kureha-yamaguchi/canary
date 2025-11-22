from pydantic import BaseModel, Field
from uuid import uuid4
from datetime import datetime


class ExploitationStep(BaseModel):
    technique_id: str


class VulnerabilityLog(ExploitationStep):
    id: str = Field(default_factory=uuid4)
    created_at: datetime = Field(default_factory=datetime.now)
    vulnerability_type: str
    session_id: str
    attacker_id: str


class ModelCreate(BaseModel):
    scenario_description: str
    vulnerability_type: str
    exploitation_steps: list[ExploitationStep]
