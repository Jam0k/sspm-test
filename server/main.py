import logging
import secrets
import time
from fastapi import FastAPI, Depends, HTTPException, Header, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import DateTime, create_engine, Column, Integer, String, ForeignKey, Table
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
from sqlalchemy.exc import IntegrityError
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
import jwt
from jwt import PyJWKClient
from functools import lru_cache
from datetime import datetime
from cachetools import TTLCache

# Configure logging
logging.basicConfig(level=logging.DEBUG)
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
    devices = relationship("Device", back_populates="organization")  # Add this line

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

# New Device model
class Device(Base):
    __tablename__ = "devices"

    id = Column(String, primary_key=True, index=True)
    org_id = Column(String, ForeignKey('organizations.id'))
    uuid = Column(String, unique=True, index=True)
    internal_ip = Column(String)
    last_seen = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    organization = relationship("Organization", back_populates="devices")  # Update this line

# Update the DeviceRegister model
class DeviceRegister(BaseModel):
    uuid: str
    internal_ip: str

class DeviceRegister(BaseModel):
    uuid: str
    internal_ip: Optional[str]
    session_id: str

class DeviceHeartbeat(BaseModel):
    uuid: str

class DeviceUpdateIP(BaseModel):
    uuid: str
    internal_ip: Optional[str] = Field(None)

# Create tables
Base.metadata.create_all(bind=engine)

app = FastAPI()

# CORS configuration with multiple origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # This allows all origins
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

# Create a cache with a 1-hour TTL
jwks_client_cache = TTLCache(maxsize=1, ttl=3600)

@lru_cache()
def get_jwks_client():
    if 'client' not in jwks_client_cache:
        jwks_client_cache['client'] = PyJWKClient(f"https://{AUTH0_DOMAIN}/.well-known/jwks.json")
    return jwks_client_cache['client']

def get_token_claims(token: str) -> Dict[str, Any]:
    try:
        start_time = time.time()
        jwks_client = get_jwks_client()
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        logger.debug(f"Signing key retrieved in {time.time() - start_time:.2f} seconds")

        decode_start = time.time()
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
        logger.debug(f"Token decoded in {time.time() - decode_start:.2f} seconds")
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
        async def wrapper(request: Request, token: HTTPAuthorizationCredentials = Depends(token_auth_scheme), db: Session = Depends(get_db)):
            token_claims = get_token_claims(token.credentials)
            user = refresh_user_data(db, token_claims)
            user_roles = set(role.name for role in user.roles)
            
            # Implement role hierarchy
            if 'Admin' in user_roles:
                user_roles.add('User')  # Admin inherits User permissions
            
            if not set(roles).intersection(user_roles):
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
            return await func(token_claims, db)
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

async def get_org_from_api_key(api_key: str = Header(..., alias="X-API-Key"), db: Session = Depends(get_db)):
    db_api_key = db.query(APIKey).filter(APIKey.key == api_key).first()
    if not db_api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API Key")
    
    db_api_key.last_used = datetime.utcnow()
    db.commit()
    
    organization = db.query(Organization).filter(Organization.id == db_api_key.org_id).first()
    if not organization:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organization not found")
    
    return organization

def refresh_user_data(db: Session, user_info: dict):
    start_time = time.time()
    user_id = user_info['sub']
    logger.debug(f"Refreshing data for user {user_id}")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        user = User(id=user_id)
        db.add(user)
        logger.debug(f"Created new user {user_id}")

    user.name = user_info.get('name', '')

    # Update or create organization
    org_time = time.time()
    org_id = user_info.get('https://watchhousesspm.com/org_id')
    org_name = user_info.get('https://watchhousesspm.com/org_name')
    if org_id and org_name:
        org = db.query(Organization).filter(Organization.id == org_id).first()
        if not org:
            org = Organization(id=org_id, name=org_name)
            db.add(org)
            logger.debug(f"Created new organization {org_id}")
        elif org.name != org_name:
            org.name = org_name
            logger.debug(f"Updated organization name for {org_id}")
        
        if org not in user.organizations:
            user.organizations = [org]
            logger.debug(f"Associated user {user_id} with organization {org_id}")
    elif user.organizations:
        user.organizations = []
        logger.debug(f"Removed organization association for user {user_id}")
    logger.debug(f"Organization update took {time.time() - org_time:.2f} seconds")

    # Update roles
    roles_time = time.time()
    new_roles = set(user_info.get('https://watchhousesspm.com/roles', []))
    current_roles = set(role.name for role in user.roles)
    
    roles_to_remove = current_roles - new_roles
    roles_to_add = new_roles - current_roles

    for role_name in roles_to_remove:
        role = next((role for role in user.roles if role.name == role_name), None)
        if role:
            user.roles.remove(role)
            logger.debug(f"Removed role {role_name} from user {user_id}")
    
    for role_name in roles_to_add:
        role = db.query(Role).filter(Role.name == role_name).first()
        if not role:
            role = Role(name=role_name)
            db.add(role)
            logger.debug(f"Created new role {role_name}")
        user.roles.append(role)
        logger.debug(f"Added role {role_name} to user {user_id}")

    logger.debug(f"Roles update took {time.time() - roles_time:.2f} seconds")

    commit_time = time.time()
    db.commit()
    db.refresh(user)
    logger.debug(f"Database commit and refresh took {time.time() - commit_time:.2f} seconds")

    logger.debug(f"Total refresh_user_data time: {time.time() - start_time:.2f} seconds")
    return user

def refresh_user_data(db: Session, user_info: dict):
    start_time = time.time()
    user_id = user_info['sub']
    logger.debug(f"Refreshing data for user {user_id}")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        user = User(id=user_id)
        db.add(user)
        logger.debug(f"Created new user {user_id}")

    user.name = user_info.get('name', '')

    # Update or create organization
    org_time = time.time()
    org_id = user_info.get('https://watchhousesspm.com/org_id')
    org_name = user_info.get('https://watchhousesspm.com/org_name')
    if org_id and org_name:
        org = db.query(Organization).filter(Organization.id == org_id).first()
        if not org:
            org = Organization(id=org_id, name=org_name)
            db.add(org)
            logger.debug(f"Created new organization {org_id}")
        elif org.name != org_name:
            org.name = org_name
            logger.debug(f"Updated organization name for {org_id}")
        
        if org not in user.organizations:
            user.organizations = [org]
            logger.debug(f"Associated user {user_id} with organization {org_id}")
    elif user.organizations:
        user.organizations = []
        logger.debug(f"Removed organization association for user {user_id}")
    logger.debug(f"Organization update took {time.time() - org_time:.2f} seconds")

    # Update roles
    roles_time = time.time()
    new_roles = set(user_info.get('https://watchhousesspm.com/roles', []))
    current_roles = set(role.name for role in user.roles)
    
    for role in user.roles[:]:
        if role.name not in new_roles:
            user.roles.remove(role)
            logger.debug(f"Removed role {role.name} from user {user_id}")
    
    for role_name in new_roles:
        if role_name not in current_roles:
            role = db.query(Role).filter(Role.name == role_name).first()
            if not role:
                role = Role(name=role_name)
                db.add(role)
                logger.debug(f"Created new role {role_name}")
            user.roles.append(role)
            logger.debug(f"Added role {role_name} to user {user_id}")
    logger.debug(f"Roles update took {time.time() - roles_time:.2f} seconds")

    commit_time = time.time()
    db.commit()
    db.refresh(user)
    logger.debug(f"Database commit and refresh took {time.time() - commit_time:.2f} seconds")

    logger.debug(f"Total refresh_user_data time: {time.time() - start_time:.2f} seconds")
    return user

@app.get("/", status_code=status.HTTP_200_OK)
@require_roles(["User"])
async def root(token_claims: Dict[str, Any], db: Session = Depends(get_db)):
    return {"message": "Hello World"}

@app.get("/protected", status_code=status.HTTP_200_OK)
@require_roles(["User"])
async def protected_route(token_claims: Dict[str, Any], db: Session = Depends(get_db)):
    user = refresh_user_data(db, token_claims)
    return {
        "message": "This is a protected route",
        "user": user.name
    }

@app.get("/admin", status_code=status.HTTP_200_OK)
@require_roles(["Admin"])
async def admin_route(token_claims: Dict[str, Any], db: Session = Depends(get_db)):
    user = refresh_user_data(db, token_claims)
    return {
        "message": "This is an admin route",
        "user": user.name
    }

@app.get("/user_info", status_code=status.HTTP_200_OK)
@require_roles(["User"])
async def user_info(token_claims: Dict[str, Any], db: Session = Depends(get_db)):
    user = refresh_user_data(db, token_claims)
    logger.info(f"User info requested for user {user.id}")
    logger.info(f"User roles: {[role.name for role in user.roles]}")
    response_data = {
        "user_id": user.id,
        "name": user.name,
        "org_id": user.organizations[0].id if user.organizations else None,
        "org_name": user.organizations[0].name if user.organizations else None,
        "roles": [role.name for role in user.roles]
    }
    logger.info(f"Sending user info response: {response_data}")
    return response_data

@app.post("/api-keys", status_code=status.HTTP_201_CREATED)
@require_roles(["Admin"])
async def create_api_key(token_claims: Dict[str, Any], db: Session = Depends(get_db)):
    user_org_id = token_claims.get('https://watchhousesspm.com/org_id')
    
    if not user_org_id:
        raise HTTPException(status_code=400, detail="User does not belong to an organization")
    
    api_key = generate_api_key(db, user_org_id)
    return {"api_key": api_key}

@app.get("/api-keys", status_code=status.HTTP_200_OK)
@require_roles(["Admin"])
async def list_api_keys(token_claims: Dict[str, Any], db: Session = Depends(get_db)):
    org_id = token_claims.get('https://watchhousesspm.com/org_id')
    
    if not org_id:
        raise HTTPException(status_code=400, detail="User does not belong to an organization")
    
    api_keys = db.query(APIKey).filter(APIKey.org_id == org_id).all()
    return {"api_keys": [{"id": key.id, "key": key.key, "created_at": key.created_at, "last_used": key.last_used} for key in api_keys]}

@app.delete("/api-keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
@require_roles(["Admin"])
async def delete_api_key(key_id: str, token_claims: Dict[str, Any], db: Session = Depends(get_db)):
    org_id = token_claims.get('https://watchhousesspm.com/org_id')
    
    if not org_id:
        raise HTTPException(status_code=400, detail="User does not belong to an organization")
    
    api_key = db.query(APIKey).filter(APIKey.id == key_id, APIKey.org_id == org_id).first()
    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")
    
    db.delete(api_key)
    db.commit()
    return

@app.get("/api/org-data", status_code=status.HTTP_200_OK)
@require_roles(["User"])
async def get_org_data(token_claims: Dict[str, Any], db: Session = Depends(get_db)):
    org_id = token_claims.get('https://watchhousesspm.com/org_id')
    if not org_id:
        raise HTTPException(status_code=400, detail="User does not belong to an organization")
    
    org = db.query(Organization).filter(Organization.id == org_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    return {
        "org_id": org.id,
        "org_name": org.name,
        "user_count": len(org.users),
        "api_key_count": len(org.api_keys)
    }

@app.post("/register-device", status_code=status.HTTP_200_OK)
async def register_device(
    device: DeviceRegister,
    organization: Organization = Depends(get_org_from_api_key),
    db: Session = Depends(get_db)
):
    existing_device = db.query(Device).filter(Device.uuid == device.uuid, Device.org_id == organization.id).first()
    
    if existing_device:
        existing_device.internal_ip = device.internal_ip
        existing_device.last_seen = datetime.utcnow()
        message = "Device updated successfully"
    else:
        new_device = Device(
            id=secrets.token_urlsafe(16),
            org_id=organization.id,
            uuid=device.uuid,
            internal_ip=device.internal_ip
        )
        db.add(new_device)
        message = "Device registered successfully"
    
    db.commit()
    return {"message": message}

@app.get("/devices", status_code=status.HTTP_200_OK)
@require_roles(["User"])
async def list_devices(token_claims: Dict[str, Any], db: Session = Depends(get_db)):
    org_id = token_claims.get('https://watchhousesspm.com/org_id')
    
    if not org_id:
        raise HTTPException(status_code=400, detail="User does not belong to an organization")
    
    devices = db.query(Device).filter(Device.org_id == org_id).all()
    return {
        "devices": [
            {
                "id": device.id,
                "uuid": device.uuid,
                "internal_ip": device.internal_ip,
                "last_seen": device.last_seen
            } for device in devices
        ]
    }

@app.post("/update-device", status_code=status.HTTP_200_OK)
async def update_device(
    device: DeviceRegister,
    organization: Organization = Depends(get_org_from_api_key),
    db: Session = Depends(get_db)
):
    existing_device = db.query(Device).filter(Device.uuid == device.uuid, Device.org_id == organization.id).first()
    
    if not existing_device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    existing_device.internal_ip = device.internal_ip
    existing_device.last_heartbeat = datetime.utcnow()
    existing_device.session_id = device.session_id
    
    db.commit()
    return {"message": "Device updated successfully"}

@app.post("/heartbeat", status_code=status.HTTP_200_OK)
async def heartbeat(
    device: DeviceHeartbeat,
    organization: Organization = Depends(get_org_from_api_key),
    db: Session = Depends(get_db)
):
    db_device = db.query(Device).filter(Device.uuid == device.uuid, Device.org_id == organization.id).first()
    if db_device:
        db_device.last_heartbeat = datetime.utcnow()
        db.commit()
        return {"message": "Heartbeat received"}
    else:
        raise HTTPException(status_code=404, detail="Device not found")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)