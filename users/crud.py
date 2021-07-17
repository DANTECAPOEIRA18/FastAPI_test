from . import models
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy.orm import Session
from jose import JWTError, jwt
from . import schemas
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import exc
from . import denpendencies

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def authenticate_user(db: Session, username: str, password: str):
    try:
        user = db.query(models.User).filter(models.User.username == username).first()
        db.close()
        if not user:
            return False
        if not verify_password(password, user.password):
            return False
        return user
    except exc.SQLAlchemyError:
        return False


def get_user(db: Session, user_id: int):
    try:
        user = db.query(models.User).filter(models.User.identification == user_id).first()
        db.close()
        return user
    except exc.SQLAlchemyError:
        return None


def get_user_by_email(db: Session, username: str):
    try:
        user = db.query(models.User).filter(models.User.username == username).first()
        db.close()
        return user
    except exc.SQLAlchemyError:
        return None


def get_users(db: Session, skip: int = 0, limit: int = 100):
    try:
        list_users = db.query(models.User).offset(skip).limit(limit).all()
        db.close()
        return list_users
    except exc.SQLAlchemyError:
        return None


def create_user(db: Session, user: schemas.UserCreate):
    try:
        query = "INSERT INTO users (identification, username, password, is_superuser, created_date) " \
                "VALUES (:identification, :username, :password_user, :superuser, :date)"
        db_user = db.execute(query,
                             {'password_user': get_password_hash(user.password),
                              'identification': user.identification,
                              'username': user.username,
                              'superuser': user.is_superuser,
                              'date': datetime.now()})
        db.commit()
        db.close()
        return db_user
    except exc.SQLAlchemyError:
        return None


def delete_user(db: Session, user_id: int):
    try:
        query = "DELETE FROM users WHERE identification = :identification"
        db_user = db.execute(query, {'identification': user_id})
        db.commit()
        db.close()
        return db_user
    except exc.SQLAlchemyError:
        return None


def update_user(db: Session, user: schemas.UserUpdate, user_id: int):
    try:
        query = "UPDATE users SET is_superuser = :superuser, username = :username, " \
                "password = :password_user, identification = :identification WHERE identification = :identification"
        db_user = db.execute(query,
                             {'password_user': get_password_hash(user.password),
                              'identification': user_id,
                              'username': user.username,
                              'superuser': user.is_superuser})
        db.commit()
        db.close()
        return db_user
    except exc.SQLAlchemyError:
        return None
