from fastapi import Depends, APIRouter, HTTPException, status
from datetime import timedelta
from fastapi.responses import JSONResponse
from . import schemas
from . import crud
from . import denpendencies
from typing import List
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from sqlalchemy import exc

router = APIRouter(
    prefix="",
)

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


async def get_current_user(db: denpendencies.Session = Depends(denpendencies.get_db),
                           token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = schemas.TokenData(username=username)
    except JWTError:
        raise credentials_exception
    try:
        user = crud.get_user_by_email(db, token_data.username)
        if user is None:
            raise credentials_exception
        return user
    except exc.SQLAlchemyError:
        return None


async def get_current_active_user(current_user: schemas.User = Depends(get_current_user)):
    return current_user


async def get_current_role_user(current_user: schemas.User = Depends(get_current_user)):
    if not current_user.is_superuser:
        raise HTTPException(status_code=400, detail="! USUARIO NO PERMITIDO PARA ESTA OPERACION !")
    return current_user


@router.post("/token", response_model=schemas.Token)
async def login_for_access_token(db: denpendencies.Session = Depends(denpendencies.get_db),
                                 form_data: OAuth2PasswordRequestForm = Depends()):
    user = crud.authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = crud.create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@router.get('/all_users', response_model=List[schemas.User])
def read_all_users(skip: int = 0, limit: int = 100, db: denpendencies.Session = Depends(denpendencies.get_db),
                   current_user: schemas.User = Depends(get_current_active_user)):
    users = crud.get_users(db, skip=skip, limit=limit)
    return users


@router.get("/get_id/{user_id}", response_model=schemas.User)
def read_user(user_id: int, db: denpendencies.Session = Depends(denpendencies.get_db),
              current_user: schemas.User = Depends(get_current_role_user)):
    db_user = crud.get_user(db, user_id=user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user


@router.post("/create_user", response_model=schemas.UserCreate)
async def create_user(user: schemas.UserCreate, db: denpendencies.Session = Depends(denpendencies.get_db),
                      current_user: schemas.User = Depends(get_current_role_user)):
    db_user = crud.create_user(db=db, user=user)
    if db_user is None:
        raise HTTPException(status_code=404, detail="Error creating User")
    return JSONResponse({'status': 'User created'})


@router.patch('/update_user/{user_id}', response_model=schemas.UserUpdate)
def update_user(user_id: int, user: schemas.UserUpdate, db: denpendencies.Session = Depends(denpendencies.get_db),
                current_user: schemas.User = Depends(get_current_role_user)):
    db_user = crud.update_user(db=db, user=user, user_id=user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="Error updating User")
    return JSONResponse({'status': 'User updated'})


@router.put("/delete_user/{user_id}", response_model=schemas.UserDelete)
def delete_user(user_id: int, db: denpendencies.Session = Depends(denpendencies.get_db),
                current_user: schemas.User = Depends(get_current_role_user)):
    db_user = crud.delete_user(db, user_id=user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="Error deleting User")
    return JSONResponse({'status': 'User deleted'})
