"""
Database Schemas for Finanalyzer

Each Pydantic model corresponds to a MongoDB collection.
Collection name is the lowercase of the class name.
"""
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime

class User(BaseModel):
    email: str = Field(..., description="User email (unique)")
    name: Optional[str] = Field(None, description="Display name")
    plan: str = Field("free", description="Subscription plan: free|paid")
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

class Magiclinktoken(BaseModel):
    email: str
    token: str
    expires_at: datetime
    used: bool = False
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

class File(BaseModel):
    user_id: str
    filename: str
    content_type: str = "application/pdf"
    size_bytes: int
    storage_path: str
    encrypted: bool = True
    upload_date: datetime
    status: str = Field("processing", description="processing|complete|error")
    last_queried: Optional[datetime] = None
    doc_type: Optional[str] = None
    fiscal_year: Optional[str] = None
    analysis: Optional[Dict[str, Any]] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

class Chatmessage(BaseModel):
    user_id: str
    file_id: str
    role: str = Field(..., description="user|assistant|system")
    content: str
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

class Rateln(BaseModel):
    user_id: str
    window_start: datetime
    count: int = 0
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
