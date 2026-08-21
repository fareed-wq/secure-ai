import requests
from api.scanner.modules.auth_session_security import AuthenticationSessionSecurityModule
from requests.sessions import Session

session = Session()
mod = AuthenticationSessionSecurityModule()

for i in range(10):
    resp = requests.get('https://google.com')
    forms = mod.extract_forms(resp.text)
    
    triggered_forms = []
    
    for form in forms:
        inputs = mod.extract_inputs(form)
        method_match = mod.METHOD_PATTERN.search(form)
        method = method_match.group(1).upper() if method_match else "GET"
        
        is_password_form = any('type="password"' in i.lower() or "type='password'" in i.lower() for i in inputs)
        
        is_state_changing = method in ['POST', 'PUT', 'DELETE'] or is_password_form or mod.is_auth_related(form)
        
        if is_state_changing:
            has_csrf = False
            for inp in inputs:
                inp_lower = inp.lower()
                if 'type="hidden"' in inp_lower or "type='hidden'" in inp_lower:
                    if any(csrf_kw in inp_lower for csrf_kw in mod.CSRF_KEYWORDS):
                        has_csrf = True
                        break
            if not has_csrf:
                triggered_forms.append(form)
                
    if triggered_forms:
        print(f"Run {i}: CSRF triggered by {len(triggered_forms)} forms")
        print("First form:")
        print(triggered_forms[0])
        break
    else:
        print(f"Run {i}: No CSRF found")
