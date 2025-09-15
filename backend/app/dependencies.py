from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:pass@localhost/zapmanejo")
engine = create_engine(DATABASE_URL, connect_args={"ssl": {"sslcert": None, "sslkey": None, "sslrootcert": None, "sslmode": "require"}})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def get_current_tenant(user: dict = Depends(get_current_user)):
    return user.tenant_id
