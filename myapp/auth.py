from datetime import datetime, timedelta
from enum import Enum
from typing import List, Optional
from bson import ObjectId
from fastapi import APIRouter, Depends, HTTPException
from mongoengine import DoesNotExist, NotUniqueError, Q
from pydantic import BaseModel
import jwt

from .dependencies import admin_required, get_current_user, ALGORITHM, SECRET_KEY, user_or_admin_required
from .models import User, Project

router = APIRouter()

class RoleEnum(str, Enum):
    user = "user"
    admin = "admin"

class UserIn(BaseModel):
    username: str
    password: str
    role: Optional[RoleEnum] = None

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

    class Config:
        from_attributes = True



class LogIn(BaseModel):
    username: str
    password: str

class MessageOut(BaseModel):
    message: str

class TokenResponse(BaseModel):
    access_token: str

# Register a new user
@router.post("/register", response_model=MessageOut)
async def create_user(user: UserIn):
    # Check if the username already exists
    existing_user = User.objects(username=user.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")

    # Create the user object with the provided role or default to "user"
    user_obj = User(username=user.username, role=user.role or "user")
    user_obj.set_password(user.password)  # Hash the password
    user_obj.save()

    return {"message": "User created successfully"}

# User login
@router.post("/login", response_model=TokenResponse)
async def login_user(login: LogIn):
    user_obj = User.objects(username=login.username).first()
    if not user_obj or not user_obj.check_password(login.password):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    # Encode the JWT
    payload = {
        "user_id": str(user_obj.id),
        "role": user_obj.role,
        "exp": datetime.utcnow() + timedelta(hours=1)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": token}

# Create a new project (Admin only)
from mongoengine.errors import NotUniqueError

@router.post("/projects", response_model=MessageOut)
async def create_project(project: ProjectIn, user: User = Depends(admin_required)):
    # Check if a project with the same name already exists
    existing_project = Project.objects(name=project.name).first()
    if existing_project:
        raise HTTPException(status_code=400, detail="A project with this name already exists")

    try:
        # Create the new project
        project_obj = Project(name=project.name, description=project.description, created_by=user)
        project_obj.save()
    except NotUniqueError:
        raise HTTPException(status_code=400, detail="A project with this name already exists")

    return {"message": "Project created successfully"}


# Delete a project (Admin only)
@router.delete("/projects/{project_id}", response_model=MessageOut)
async def delete_project(project_id: str, user: User = Depends(admin_required)):
    project_obj = Project.objects(id=project_id).first()
    if not project_obj:
        raise HTTPException(status_code=404, detail="Project not found")
    project_obj.delete()
    return {"message": "Project deleted successfully"}

# Update a project (Admin only)
@router.put("/projects/{project_id}", response_model=MessageOut)
async def update_project(project_id: str, project: ProjectIn, user: User = Depends(admin_required)):
    project_obj = Project.objects(id=project_id).first()
    if not project_obj:
        raise HTTPException(status_code=404, detail="Project not found")

    # Check if the new project name already exists (excluding the current project)
    if project.name:
        existing_project = Project.objects(Q(name=project.name) & Q(id__ne=project_id)).first()
        if existing_project:
            raise HTTPException(status_code=400, detail="A project with this name already exists")


    # Update only the fields provided in the request
    update_fields = {}
    if project.name:
        update_fields['name'] = project.name
    if project.description:
        update_fields['description'] = project.description

    try:
        # Update the project
        Project.objects(id=project_id).update(**update_fields)
    except NotUniqueError:
        raise HTTPException(status_code=400, detail="A project with this name already exists")

    return {"message": "Project updated successfully"}

# Get all projects (User or Admin access)

@router.get("/projects/all", response_model=List[ProjectOut])
async def get_all_projects(user: User = Depends(user_or_admin_required)):
    projects = Project.objects.all()
    return [
        {"id": str(project.id), "name": project.name, "description": project.description}
        for project in projects
    ]


@router.get("/project/{project_id}", response_model=ProjectOut)
async def get_project_by_id(project_id: str):
    # Check if the provided project_id is a valid ObjectId
    if not ObjectId.is_valid(project_id):
        raise HTTPException(status_code=400, detail="Invalid project ID format")

    try:
        # Fetch project using the valid ObjectId
        project_obj = Project.objects.get(id=project_id)
    except DoesNotExist:
        # Return 404 if the project is not found
        raise HTTPException(status_code=404, detail="Project not found")

    # Return the project in the expected format
    return ProjectOut(id=str(project_obj.id), name=project_obj.name, description=project_obj.description)
