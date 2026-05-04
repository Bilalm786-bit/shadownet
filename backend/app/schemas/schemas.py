"""
ShadowNet — Pydantic Schemas
Request/Response models for all API endpoints.
"""

from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


# ─── Enums ──────────────────────────────────────────────
class TargetTypeEnum(str, Enum):
    email = "email"
    username = "username"
    domain = "domain"
    ip = "ip"
    phone = "phone"
    person = "person"
    organization = "organization"
    url = "url"
    file = "file"


class CaseStatusEnum(str, Enum):
    active = "active"
    archived = "archived"
    closed = "closed"


class SeverityEnum(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


# ─── Auth Schemas ───────────────────────────────────────
class UserRegister(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=100)
    password: str = Field(min_length=8, max_length=128)
    full_name: Optional[str] = None


class UserLogin(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class UserResponse(BaseModel):
    id: str
    email: str
    username: str
    full_name: Optional[str]
    role: str
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


# ─── Case Schemas ───────────────────────────────────────
class CaseCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: Optional[str] = None
    priority: int = Field(default=0, ge=0, le=2)
    tags: List[str] = []


class CaseUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    status: Optional[CaseStatusEnum] = None
    priority: Optional[int] = None
    tags: Optional[List[str]] = None


class CaseResponse(BaseModel):
    id: str
    name: str
    description: Optional[str]
    status: str
    priority: int
    tags: List[str]
    owner_id: str
    created_at: datetime
    updated_at: Optional[datetime]
    target_count: int = 0

    model_config = {"from_attributes": True}


# ─── Target Schemas ─────────────────────────────────────
class TargetCreate(BaseModel):
    target_type: TargetTypeEnum
    value: str = Field(min_length=1, max_length=500)
    label: Optional[str] = None
    extra_data: Dict[str, Any] = {}


class TargetResponse(BaseModel):
    id: str
    case_id: str
    target_type: str
    value: str
    label: Optional[str]
    extra_data: Dict[str, Any] = {}
    created_at: datetime

    model_config = {"from_attributes": True}


# ─── Scan Schemas ───────────────────────────────────────
class ScanRequest(BaseModel):
    target_id: str
    modules: List[str] = ["all"]  # e.g. ["identity.username", "network.dns"]
    options: Dict[str, Any] = {}


class ScanResultResponse(BaseModel):
    id: str
    target_id: str
    module: str
    status: str
    severity: str
    summary: Optional[str]
    data: Dict[str, Any]
    error_message: Optional[str]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_at: datetime

    model_config = {"from_attributes": True}


# ─── OSINT Module Output ───────────────────────────────
class EntityFound(BaseModel):
    """A single entity discovered by an OSINT module."""
    entity_type: str  # person, email, domain, ip, username, etc.
    value: str
    source: str  # module that found it
    confidence: float = Field(ge=0.0, le=1.0, default=0.8)
    metadata: Dict[str, Any] = {}
    relationships: List[Dict[str, str]] = []  # [{"type": "USES", "target": "..."}]


class ScanOutput(BaseModel):
    """Standardized output from any OSINT module."""
    module: str
    target: str
    success: bool
    entities: List[EntityFound] = []
    raw_data: Dict[str, Any] = {}
    summary: str = ""
    severity: SeverityEnum = SeverityEnum.info
    error: Optional[str] = None


# ─── Alert Schemas ──────────────────────────────────────
class AlertResponse(BaseModel):
    id: str
    case_id: Optional[str]
    title: str
    message: Optional[str]
    severity: str
    source_module: Optional[str]
    is_read: bool
    created_at: datetime

    model_config = {"from_attributes": True}


# ─── Graph Schemas ──────────────────────────────────────
class GraphNode(BaseModel):
    id: str
    label: str
    entity_type: str
    properties: Dict[str, Any] = {}


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    relationship: str
    properties: Dict[str, Any] = {}


class GraphResponse(BaseModel):
    nodes: List[GraphNode] = []
    edges: List[GraphEdge] = []
