import os
import django

from myapp.auth import router

os.environ.setdefault("DJANGO_SETTINGS_MODULE","assignment.settings")

django.setup()
from fastapi import FastAPI






app=FastAPI()
app.include_router(router)

@app.get("/")
def root():
    return {"Hello  USe this link for swagger":"http://127.0.0.1:8000/docs"}







