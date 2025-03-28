from flask import current_app, Response

def set_refresh_token_cookie(response: Response, refresh_token: str):
    max_age = current_app.config.get("JWT_REFRESH_TOKEN_EXPIRES", 60 * 60 * 24 * 7)
    secure = current_app.config.get("COOKIE_SECURE", False)
    response.set_cookie(
        "refresh_token",
        refresh_token,
        httponly=True,
        secure=secure,         
        samesite="Lax",   
        path="/auth/refresh",
        max_age=max_age
    )
    return response

def clear_refresh_token_cookie(response: Response):
    secure = current_app.config.get("COOKIE_SECURE", False)

    response.set_cookie(
        "refresh_token",
        "",
        httponly=True,
        secure=secure,
        samesite="Lax",
        path="/auth/refresh",
        max_age=0
    )
    return response