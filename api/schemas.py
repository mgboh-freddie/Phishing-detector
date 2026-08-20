"""Request and response models."""

from typing import Optional

from pydantic import BaseModel, Field, model_validator

MAX_HTML_BYTES = 5 * 1024 * 1024


class ScanRequest(BaseModel):
    url: Optional[str] = Field(default=None, max_length=2048)
    html: Optional[str] = None
    threshold: Optional[float] = Field(default=None, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def require_one_input(self):
        if not self.url and not self.html:
            raise ValueError("Provide either 'url' or 'html'.")
        return self


class ErrorBody(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    error: ErrorBody


class ScanResponse(BaseModel):
    id: str
    target: str
    source: str
    score: float
    verdict: str
    threshold: float
    features: dict
    warnings: list
    tls_verified: Optional[bool] = None
    model_version: str
    elapsed_ms: int
    created_at: str


class ScanListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    scans: list
