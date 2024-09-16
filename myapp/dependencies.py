import jwt
from fastapi import HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from myapp.models import User

SECRET_KEY = 'your_secret_key'
ALGORITHM = 'HS256'

# Define the HTTPBearer security scheme
security = HTTPBearer()
def decode_jwt(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_current_user(authorization: HTTPAuthorizationCredentials = Depends(security)) -> User:
    token = authorization.credentials
    payload = decode_jwt(token)
    user_id = payload.get("user_id")
    user_obj = User.objects(id=user_id).first()
    if not user_obj:
        raise HTTPException(status_code=401, detail="User not found")
    return user_obj

def admin_required(user: User = Depends(get_current_user)):
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admins can perform this action")
    return user

def user_or_admin_required(user: User = Depends(get_current_user)):
    if user.role not in ['admin', 'user']:
        raise HTTPException(status_code=403, detail="User or Admin access required")
    return user