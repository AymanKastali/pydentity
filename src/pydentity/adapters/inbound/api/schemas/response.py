from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class ErrorDetail(BaseModel):
    model_config = ConfigDict(frozen=True)

    code: str
    message: str


class ErrorResponse(BaseModel):
    model_config = ConfigDict(frozen=True)

    error: ErrorDetail


class ApiResponse[T](BaseModel):
    model_config = ConfigDict(frozen=True)

    data: T
