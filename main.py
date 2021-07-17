from fastapi import FastAPI, Depends
from users import main, models, schemas, crud, denpendencies
from users.database import engine

models.Base.metadata.create_all(bind=engine)

app = FastAPI()

app.include_router(main.router)
