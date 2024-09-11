from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from mongoengine import connect

from myapp import auth

app = FastAPI()

origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

connect("assignment", host="mongodb://localhost:27017/")

app.include_router(auth.router)

@app.get("/")
def root():
    return("use this   http://127.0.0.1:8000/docs")