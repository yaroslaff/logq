def dhms(seconds: int) -> str:
    parts = []
    days, seconds = divmod(seconds, 86400)
    if days:
        parts.append(f"{days}d ")
    hours, seconds = divmod(seconds, 3600)
    if hours:
        parts.append(f"{hours}h ")
    minutes, seconds = divmod(seconds, 60)
    if minutes:
        parts.append(f"{minutes}m ")
    if seconds or not parts:
        parts.append(f"{seconds}s")
    return "".join(parts)
