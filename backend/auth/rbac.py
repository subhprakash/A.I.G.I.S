from fastapi import Depends, HTTPException
from backend.auth.dependencies import get_current_user


def require_role(role):

    def role_checker(user=Depends(get_current_user)):

        if not user.role or user.role.name != role:
            raise HTTPException(403)

        return user

    return role_checker