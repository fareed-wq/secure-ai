from datetime import datetime, time, timedelta
import zoneinfo
from typing import Optional

def get_next_run_at(frequency: str, time_of_day: time, timezone_str: str, 
                    day_of_week: Optional[int] = None, 
                    day_of_month: Optional[int] = None, 
                    now_utc: Optional[datetime] = None) -> datetime:
    """
    Calculate the next occurrence of a schedule based on local timezone and time_of_day.
    Returns a timezone-aware UTC datetime.
    """
    if now_utc is None:
        now_utc = datetime.now(zoneinfo.ZoneInfo("UTC"))
        
    try:
        tz = zoneinfo.ZoneInfo(timezone_str)
    except zoneinfo.ZoneInfoNotFoundError:
        raise ValueError(f"Invalid timezone: {timezone_str}")

    now_local = now_utc.astimezone(tz)
    
    # Start checking from today in local time
    candidate = now_local.replace(hour=time_of_day.hour, minute=time_of_day.minute, second=time_of_day.second, microsecond=0)
    
    if frequency == 'daily':
        if candidate <= now_local:
            candidate += timedelta(days=1)
            
    elif frequency == 'weekly':
        if day_of_week is None:
            raise ValueError("day_of_week is required for weekly frequency")
        # Candidate might be today, but is it the right day of the week?
        while candidate.weekday() != day_of_week or candidate <= now_local:
            candidate += timedelta(days=1)
            
    elif frequency == 'monthly':
        if day_of_month is None or not (1 <= day_of_month <= 28):
            raise ValueError("day_of_month must be between 1 and 28 for monthly frequency")
        
        while candidate.day != day_of_month or candidate <= now_local:
            candidate += timedelta(days=1)
            
    else:
        raise ValueError(f"Unsupported frequency: {frequency}")

    # Convert back to UTC for storage
    return candidate.astimezone(zoneinfo.ZoneInfo("UTC"))

def is_valid_timezone(tz_str: str) -> bool:
    try:
        zoneinfo.ZoneInfo(tz_str)
        return True
    except Exception:
        return False
