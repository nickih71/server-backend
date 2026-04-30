def parse_token(token: str) -> str:
    """
    Very simple parser: you’re currently using tokens like
    f"{username}-{timestamp}". For logging, we just return the username part.
    """
    # "username-1714440000" -> "username"
    return token.split("-")[0]
