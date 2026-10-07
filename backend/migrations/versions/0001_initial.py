"""Initial immutable migration; future schema changes require a new revision."""

import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # 迁移使用冻结的列声明，不导入后续可变 ORM metadata。
    op.create_table(
        "users",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("username", sa.String(80), nullable=False, unique=True),
        sa.Column("password_hash", sa.Text, nullable=False),
        sa.Column("role", sa.String(20), nullable=False),
        sa.Column("disabled", sa.Boolean, nullable=False),
    )
    op.create_table(
        "sessions",
        sa.Column("token_hash", sa.String(64), primary_key=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("csrf_hash", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.Float, nullable=False),
    )
    op.create_index("ix_sessions_expires_at", "sessions", ["expires_at"])
    op.create_table(
        "login_throttles",
        sa.Column("key", sa.String(64), primary_key=True),
        sa.Column("failures", sa.Integer, nullable=False),
        sa.Column("until", sa.Float, nullable=False),
    )
    op.create_table(
        "targets",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("asset_id", sa.String(36), nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("config", sa.JSON, nullable=False),
        sa.Column("secret", sa.Text, nullable=False),
        sa.Column("revision", sa.String(64), nullable=False),
        sa.Column("archived", sa.Boolean, nullable=False),
        sa.Column("created_at", sa.Float, nullable=False),
    )
    op.create_index("ix_targets_asset_id", "targets", ["asset_id"])
    op.create_table(
        "cases",
        sa.Column("id", sa.String(80), primary_key=True),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("category", sa.String(64), nullable=False),
        sa.Column("surface", sa.String(64), nullable=False),
        sa.Column("spec", sa.JSON, nullable=False),
        sa.Column("revision", sa.String(64), nullable=False),
        sa.Column("builtin", sa.Boolean, nullable=False),
        sa.Column("enabled", sa.Boolean, nullable=False),
    )
    op.create_index("ix_cases_category", "cases", ["category"])
    op.create_table(
        "evaluations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("target_id", sa.String(36), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("target_snapshot", sa.JSON, nullable=False),
        sa.Column("created_by", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("idempotency_key", sa.String(120), nullable=True),
        sa.Column("request_digest", sa.String(64), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("cancel_requested", sa.Boolean, nullable=False),
        sa.Column("lease_token", sa.String(64), nullable=True),
        sa.Column("lease_until", sa.Float, nullable=True),
        sa.Column("created_at", sa.Float, nullable=False),
        sa.Column("finished_at", sa.Float, nullable=True),
        sa.Column("budget", sa.JSON, nullable=False),
        sa.Column("error_code", sa.String(64), nullable=True),
        sa.UniqueConstraint("created_by", "idempotency_key"),
    )
    for field in ["status", "created_at"]:
        op.create_index("ix_evaluations_" + field, "evaluations", [field])
    op.create_table(
        "attempts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("evaluation_id", sa.String(36), sa.ForeignKey("evaluations.id"), nullable=False),
        sa.Column("case_id", sa.String(80), nullable=False),
        sa.Column("case_snapshot", sa.JSON, nullable=False),
        sa.Column("repeat", sa.Integer, nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("result", sa.JSON, nullable=True),
        sa.Column("started_at", sa.Float, nullable=True),
        sa.Column("finished_at", sa.Float, nullable=True),
        sa.UniqueConstraint("evaluation_id", "case_id", "repeat"),
    )
    op.create_index("ix_attempts_evaluation_id", "attempts", ["evaluation_id"])
    op.create_table(
        "findings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "attempt_id", sa.String(36), sa.ForeignKey("attempts.id"), nullable=False, unique=True
        ),
        sa.Column("target_id", sa.String(36), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("note", sa.Text, nullable=False),
        sa.Column("created_at", sa.Float, nullable=False),
    )
    op.create_table(
        "management_audit",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("actor_id", sa.String(36), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("object_id", sa.String(120), nullable=False),
        sa.Column("created_at", sa.Float, nullable=False),
        sa.Column("details", sa.JSON, nullable=False),
    )
    op.create_index("ix_management_audit_created_at", "management_audit", ["created_at"])


def downgrade():
    for table in [
        "management_audit",
        "findings",
        "attempts",
        "evaluations",
        "cases",
        "targets",
        "login_throttles",
        "sessions",
        "users",
    ]:
        op.drop_table(table)
