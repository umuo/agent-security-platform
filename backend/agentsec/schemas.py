from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginIn(StrictModel):
    username: str = Field(min_length=1, max_length=80, pattern=r"^[a-zA-Z0-9_.@-]+$")
    password: str = Field(min_length=1, max_length=256)


class TargetIn(StrictModel):
    name: str = Field(min_length=1, max_length=120)
    kind: Literal["fixture", "openai", "http-agent", "langchain4j"]
    config: dict = Field(default_factory=dict)
    secret: str = Field(default="", max_length=4096)
    parent_target_id: str | None = Field(default=None, max_length=36)


class CaseIn(StrictModel):
    name: str = Field(min_length=1, max_length=160)
    category: str = Field(min_length=1, max_length=64)
    surface: Literal["user_message", "rag_document", "tool_response", "memory", "tool_description"]
    user_task: str = Field(min_length=1, max_length=12000)
    payload: str = Field(default="", max_length=24000)
    oracle: Literal["forbidden_tool", "canary_leak", "unauthorized_read", "clean_task"]
    forbidden_tool: str = Field(default="send_report", max_length=80)
    attack: bool = True


class Budget(StrictModel):
    timeout_seconds: int = Field(default=60, ge=5, le=300)
    max_turns: int = Field(default=8, ge=1, le=24)
    max_tool_calls: int = Field(default=12, ge=1, le=48)
    max_tokens: int = Field(default=4096, ge=64, le=16384)
    max_total_tokens: int = Field(default=30000, ge=64, le=500000)
    max_job_tokens: int = Field(default=120000, ge=64, le=2000000)
    max_job_turns: int = Field(default=500, ge=1, le=12000)
    max_job_tool_calls: int = Field(default=1000, ge=1, le=24000)
    max_job_seconds: int = Field(default=1800, ge=1, le=86400)


class EvaluationIn(StrictModel):
    name: str = Field(default="安全回归评测", min_length=1, max_length=160)
    target_id: str = Field(min_length=1, max_length=36)
    case_ids: list[str] = Field(min_length=1, max_length=100)
    repeats: int = Field(default=1, ge=1, le=5)
    budget: Budget = Field(default_factory=Budget)

    @field_validator("case_ids")
    @classmethod
    def unique_cases(cls, value):
        if len(set(value)) != len(value):
            raise ValueError("case_ids 不能重复")
        return value


class FindingUpdate(StrictModel):
    status: Literal[
        "OPEN", "CONFIRMED", "FIX_PROPOSED", "RETESTING", "VERIFIED", "CLOSED", "ACCEPTED_RISK"
    ]
    note: str = Field(default="", max_length=4000)
    retest_attempt_id: str | None = Field(default=None, max_length=36)


class UserIn(LoginIn):
    role: Literal["admin", "operator", "viewer"] = "operator"


class UserUpdate(StrictModel):
    role: Literal["admin", "operator", "viewer"] | None = None
    disabled: bool | None = None
    new_password: str | None = Field(default=None, min_length=12, max_length=256)


class PasswordChange(StrictModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=12, max_length=256)
