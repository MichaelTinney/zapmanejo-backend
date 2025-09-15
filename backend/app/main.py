from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.security import HTTPBearer
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from .dependencies import get_db
from .crud import create_tenant, create_user
from .schemas import TenantCreate, UserCreate, UserLogin, Token, AnimalCreate
from .auth import authenticate_user, create_access_token, get_current_user
from .models import Base
from sqlalchemy import text
from pathlib import Path
from datetime import timedelta

app = FastAPI(title="ZapManejo API", version="1.0.0")

# Security Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Update to specific domains in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Create tables
Base.metadata.create_all(bind=engine)

@app.on_event("startup")
async def startup():
    try:
        db = next(get_db())
        db.execute(text("SELECT 1"))
    except Exception as e:
        raise RuntimeError(f"Database connection failed: {e}")

@app.get("/health")
@limiter.limit("5/minute")
async def health_check():
    return {"status": "healthy", "db_connected": True}

@app.post("/tenants", response_model=dict)
async def create_new_tenant(tenant: TenantCreate, db=Depends(get_db)):
    existing = db.execute(text("SELECT 1 FROM tenants WHERE subdomain = :sub"), {"sub": tenant.subdomain}).fetchone()
    if existing:
        raise HTTPException(status_code=400, detail="Subdomain taken")
    new_tenant = create_tenant(db, tenant.name, tenant.subdomain)
    return {"id": new_tenant.id, "subdomain": new_tenant.subdomain}

@app.post("/login", response_model=Token)
async def login_for_access_token(form_data: UserLogin, db=Depends(get_db)):
    user = authenticate_user(db, form_data.email, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    access_token_expires = timedelta(minutes=15)
    access_token = create_access_token(
        data={"sub": user.email, "tenant_id": str(user.tenant_id)}, expires_delta=access_token_expires
    )
    return {"access_token": access_token}

@app.post("/herd/upload")
@limiter.limit("10/hour")
async def upload_herd(file: UploadFile = File(...), current_tenant=Depends(get_current_tenant), db=Depends(get_db)):
    if not file.filename.endswith(('.csv', '.xlsx')):
        raise HTTPException(status_code=400, detail="Only CSV/XLSX allowed")
    contents = await file.read()
    return {"filename": file.filename, "tenant_id": current_tenant}

@app.get("/herd")
async def get_herd(current_tenant=Depends(get_current_tenant), db=Depends(get_db)):
    animals = get_animals_by_tenant(db, current_tenant)
    return {"animals": [a.__dict__ for a in animals]}

# Serve static dashboard from public/
@app.get("/{path:path}", include_in_schema=False)
async def serve_static(path: str, request: Request):
    static_file = Path("public") / path
    if static_file.exists():
        return FileResponse(static_file)
    return FileResponse("public/dashboard.html")  # Default to dashboard if not found

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
