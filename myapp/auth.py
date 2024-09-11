from datetime import datetime, timedelta
from enum import Enum
from typing import List
from fastapi import APIRouter, Depends, HTTPException, Form
from pydantic import BaseModel
import jwt


from .dependencies import admin_required, get_current_user, ALGORITHM, SECRET_KEY
from .models import User, Project

router = APIRouter()

class RoleEnum(str, Enum):
    user = "user"
    admin = "admin"

class UserIn(BaseModel):
    username: str
    password: str
    role: RoleEnum

class UserOut(BaseModel):
    username: str
    role: str

class ProjectIn(BaseModel):
    name: str
    description: str

class ProjectOut(BaseModel):
    id: str
    name: str
    description: str

@router.post("/register")
async def create_user(user: UserIn):
    if user.role not in RoleEnum.__members__.values():
        raise HTTPException(status_code=400, detail="Invalid role. Please choose 'user' or 'admin'.")

    existing_user = User.objects(username=user.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")

    user_obj = User(**user.dict())
    user_obj.set_password(user.password)  # Hash the password
    user_obj.save()
    return {"message": "User created successfully"}

@router.post("/login")
async def login_user(username: str = Form(...), password: str = Form(...), role: RoleEnum = Form(...)):
    user_obj = User.objects(username=username).first()
    if not user_obj or not user_obj.check_password(password) or user_obj.role != role:
        raise HTTPException(status_code=401, detail="Invalid username, password, or role")

    # Encode the JWT
    payload = {
        "user_id": str(user_obj.id),
        "role": user_obj.role,
        "exp": datetime.utcnow() + timedelta(hours=1)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token}


@router.post("/projects")
async def create_project(project: ProjectIn, user: User = Depends(admin_required)):
    project_obj = Project(name=project.name, description=project.description, created_by=user)
    project_obj.save()
    return {"message": "Project created successfully"}

@router.delete("/projects/{project_id}")
async def delete_project(project_id: str, user: User = Depends(admin_required)):
    project_obj = Project.objects(id=project_id).first()
    if not project_obj:
        raise HTTPException(status_code=404, detail="Project not found")
    project_obj.delete()
    return {"message": "Project deleted successfully"}

@router.put("/projects/{project_id}")
async def update_project(project_id: str, project: ProjectIn, user: User = Depends(admin_required)):
    project_obj = Project.objects(id=project_id).first()
    if not project_obj:
        raise HTTPException(status_code=404, detail="Project not found")
    project_obj.name = project.name
    project_obj.description = project.description
    project_obj.save()
    return {"message": "Project updated successfully"}

@router.get("/projects/all", response_model=List[ProjectOut])
async def get_all_projects(user: User = Depends(admin_required)):
    projects = Project.objects.all()
    return [
        {"id": str(project.id), "name": project.name, "description": project.description}
        for project in projects
    ]
