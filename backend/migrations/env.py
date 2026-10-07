from agentsec.config import Settings
from agentsec.db import Database
from agentsec.models import Base
from alembic import context

settings = context.config.attributes.get("settings") or Settings.load().validate()
db = Database(settings)
with db.engine.connect() as connection:
    context.configure(connection=connection, target_metadata=Base.metadata, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()
db.engine.dispose()
