import logging
import secrets
from fastapi import FastAPI, Depends, HTTPException, Header, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import DateTime, create_engine, Column, Integer, String, ForeignKey, Table
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
from sqlalchemy.exc import IntegrityError
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import jwt
from jwt import PyJWKClient
from functools import lru_cache
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Database setup
SQLALCHEMY_DATABASE_URL = "sqlite:///./auth_store.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# Association tables
user_organizations = Table('user_organizations', Base.metadata,
    Column('user_id', String, ForeignKey('users.id', ondelete="CASCADE"), primary_key=True),
    Column('org_id', String, ForeignKey('organizations.id', ondelete="CASCADE"), primary_key=True)
)

user_roles = Table('user_roles', Base.metadata,
    Column('user_id', String, ForeignKey('users.id', ondelete="CASCADE"), primary_key=True),
    Column('role_id', Integer, ForeignKey('roles.id', ondelete="CASCADE"), primary_key=True)
)

class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, index=True)
    name = Column(String, nullable=True)
    organizations = relationship("Organization", secondary=user_organizations, back_populates="users")
    roles = relationship("Role", secondary=user_roles, back_populates="users")

class Organization(Base):
    __tablename__ = "organizations"

    id = Column(String, primary_key=True, index=True)
    name = Column(String)
    users = relationship("User", secondary=user_organizations, back_populates="organizations")
    api_keys = relationship("APIKey", back_populates="organization")

class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True)
    users = relationship("User", secondary=user_roles, back_populates="roles")

class APIKey(Base):
    __tablename__ = "api_keys"

    id = Column(String, primary_key=True, index=True)
    key = Column(String, unique=True, index=True)
    org_id = Column(String, ForeignKey('organizations.id'))
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used = Column(DateTime, nullable=True)

    organization = relationship("Organization", back_populates="api_keys")

# Create tables
Base.metadata.create_all(bind=engine)

app = FastAPI()

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5500"],  # Update this with your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Auth0 configuration
AUTH0_DOMAIN = 'dev-mazc2h57lknel3yr.uk.auth0.com'
API_AUDIENCE = 'sspm'
ALGORITHMS = ["RS256"]

# JWT validation
token_auth_scheme = HTTPBearer()

# Database dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@lru_cache()
def get_jwks_client():
    return PyJWKClient(f"https://{AUTH0_DOMAIN}/.well-known/jwks.json")

def get_token_claims(token: str) -> Dict[str, Any]:
    try:
        jwks_client = get_jwks_client()
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=ALGORITHMS,
            audience=API_AUDIENCE,
            issuer=f"https://{AUTH0_DOMAIN}/",
            options={
                "verify_exp": True,
                "verify_iat": True,
                "leeway": 120  # 2 minutes leeway
            }
        )
        return claims
    except jwt.PyJWTError as e:
        logger.error(f"Token validation error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid authentication credentials: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )

def get_roles(token_claims: Dict[str, Any]) -> List[str]:
    return token_claims.get('https://watchhousesspm.com/roles', [])

def require_roles(roles: List[str]):
    def decorator(func):
        async def wrapper(request: Request, token: str = Depends(token_auth_scheme)):
            token_claims = get_token_claims(token.credentials)
            user_roles = get_roles(token_claims)
            if not any(role in user_roles for role in roles):
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
            return await func(token_claims)
        return wrapper
    return decorator


def get_or_create_user(db: Session, user_info: dict):
    user_id = user_info['sub']
    user = db.query(User).filter(User.id == user_id).first()
    
    if not user:
        user = User(
            id=user_id,
            name=user_info.get('name', '')
        )
        db.add(user)
    else:
        user.name = user_info.get('name', user.name)
    
    # Update or create organization
    org_id = user_info.get('https://watchhousesspm.com/org_id')
    org_name = user_info.get('https://watchhousesspm.com/org_name')
    if org_id and org_name:
        org = db.query(Organization).filter(Organization.id == org_id).first()
        if not org:
            org = Organization(id=org_id, name=org_name)
            db.add(org)
        if org not in user.organizations:
            user.organizations.append(org)
    
    # Update roles
    roles = user_info.get('https://watchhousesspm.com/roles', [])
    current_roles = set(role.name for role in user.roles)
    for role_name in roles:
        if role_name not in current_roles:
            role = db.query(Role).filter(Role.name == role_name).first()
            if not role:
                role = Role(name=role_name)
                db.add(role)
            user.roles.append(role)
    
    db.commit()
    db.refresh(user)
    return user

def generate_api_key(db: Session, org_id: str) -> str:
    api_key = secrets.token_urlsafe(32)  # Generate a secure random string
    db_api_key = APIKey(id=secrets.token_urlsafe(16), key=api_key, org_id=org_id)
    db.add(db_api_key)
    db.commit()
    db.refresh(db_api_key)
    return api_key

async def get_api_key(api_key: str = Header(..., alias="X-API-Key"), db: Session = Depends(get_db)):
    db_api_key = db.query(APIKey).filter(APIKey.key == api_key).first()
    if not db_api_key:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    
    db_api_key.last_used = datetime.utcnow()
    db.commit()
    
    return db_api_key.organization

@app.get("/", status_code=status.HTTP_200_OK)
async def root():
    return {"message": "Hello World"}

@app.get("/protected", status_code=status.HTTP_200_OK)
@require_roles(["User"])
async def protected_route(token_claims: Dict[str, Any]):
    return {
        "message": "This is a protected route",
        "user": token_claims.get('email') or token_claims.get('https://watchhousesspm.com/user_name')
    }

@app.get("/admin", status_code=status.HTTP_200_OK)
@require_roles(["Admin"])
async def admin_route(token_claims: Dict[str, Any]):
    return {
        "message": "This is an admin route",
        "user": token_claims.get('email') or token_claims.get('https://watchhousesspm.com/user_name')
    }

@app.get("/user_info", status_code=status.HTTP_200_OK)
async def user_info(token: HTTPAuthorizationCredentials = Depends(token_auth_scheme), db: Session = Depends(get_db)):
    try:
        token_claims = get_token_claims(token.credentials)
        user = get_or_create_user(db, token_claims)
        return {
            "user_id": user.id,
            "name": user.name,
            "org_id": user.organizations[0].id if user.organizations else None,
            "org_name": user.organizations[0].name if user.organizations else None,
            "roles": [role.name for role in user.roles]
        }
    except Exception as e:
        logger.error(f"Error in user_info endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

# API KEYS

@app.post("/api-keys", status_code=status.HTTP_201_CREATED)
@require_roles(["Admin"])
async def create_api_key(org_id: str, db: Session = Depends(get_db), token: HTTPAuthorizationCredentials = Depends(token_auth_scheme)):
    token_claims = get_token_claims(token.credentials)
    user_org_id = token_claims.get('https://watchhousesspm.com/org_id')
    
    if user_org_id != org_id:
        raise HTTPException(status_code=403, detail="You can only create API keys for your own organization")
    
    api_key = generate_api_key(db, org_id)
    return {"api_key": api_key}

@app.get("/api-keys", status_code=status.HTTP_200_OK)
@require_roles(["Admin"])
async def list_api_keys(db: Session = Depends(get_db), token: HTTPAuthorizationCredentials = Depends(token_auth_scheme)):
    token_claims = get_token_claims(token.credentials)
    org_id = token_claims.get('https://watchhousesspm.com/org_id')
    
    api_keys = db.query(APIKey).filter(APIKey.org_id == org_id).all()
    return {"api_keys": [{"id": key.id, "created_at": key.created_at, "last_used": key.last_used} for key in api_keys]}

@app.delete("/api-keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
@require_roles(["Admin"])
async def delete_api_key(key_id: str, db: Session = Depends(get_db), token: HTTPAuthorizationCredentials = Depends(token_auth_scheme)):
    token_claims = get_token_claims(token.credentials)
    org_id = token_claims.get('https://watchhousesspm.com/org_id')
    
    api_key = db.query(APIKey).filter(APIKey.id == key_id, APIKey.org_id == org_id).first()
    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")
    
    db.delete(api_key)
    db.commit()
    return

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)