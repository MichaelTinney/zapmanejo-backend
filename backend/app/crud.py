from sqlalchemy.orm import Session
from sqlalchemy.exc import NoResultFound
from .models import User, Tenant, Animal
from .schemas import UserCreate
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()

def create_user(db: Session, user: UserCreate):
    hashed_password = pwd_context.hash(user.password)
    db_user = User(email=user.email, hashed_password=hashed_password, tenant_id=user.tenant_id)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def create_tenant(db: Session, name: str, subdomain: str):
    db_tenant = Tenant(name=name, subdomain=subdomain)
    db.add(db_tenant)
    db.commit()
    db.refresh(db_tenant)
    return db_tenant

def get_animals_by_tenant(db: Session, tenant_id: UUID):
    return db.query(Animal).filter(Animal.tenant_id == tenant_id).all()
