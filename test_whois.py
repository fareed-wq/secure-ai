import whois
import datetime

domain = "expired.badssl.com"
try:
    w = whois.whois(domain)
    print(w)
    
    c_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
    if c_date:
        age_days = (datetime.datetime.now() - c_date.replace(tzinfo=None)).days
        print(f"Age: {age_days // 365} Years Old")
except Exception as e:
    print(f"Error: {e}")
