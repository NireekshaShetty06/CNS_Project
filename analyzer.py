"""Explainable URL screening and verified TLS inspection. No page content is fetched."""
import ipaddress
import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

VERSION = '1.0.0'

def validate_url(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 4096:
        raise ValueError('Enter a URL containing at most 4096 characters.')
    value = value.strip()
    if any(c.isspace() or ord(c) < 32 for c in value) or '\\' in value:
        raise ValueError('URLs cannot contain whitespace, control characters or backslashes.')
    if '://' not in value:
        value = 'https://' + value
    try:
        p = urlsplit(value)
        if p.scheme.lower() not in ('http', 'https') or not p.hostname:
            raise ValueError()
        host = p.hostname.encode('idna').decode('ascii').lower()
        port = p.port
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if len(host) > 253 or '.' not in host or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in host.split('.')):
                raise ValueError()
        if port and port not in (80, 443):
            raise ValueError('Only standard web ports 80 and 443 are supported.')
    except (ValueError, UnicodeError) as e:
        raise ValueError(str(e) if 'Only standard' in str(e) else 'Enter a valid HTTP or HTTPS URL with a public hostname.')
    return p, host, urlunsplit((p.scheme.lower(), p.netloc, p.path, p.query, ''))

def public_addresses(host, port):
    addresses = list(dict.fromkeys(x[4][0] for x in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)))
    if not addresses or any(not ipaddress.ip_address(a).is_global for a in addresses):
        raise ValueError('Private, local and reserved network destinations cannot be scanned.')
    return addresses

def inspect_certificate(host, addresses, port=443):
    result = {'status': 'unavailable', 'verified': False, 'hostname_match': None, 'chain_verified': None}
    context = ssl.create_default_context()
    try:
        # Connect to the already validated address to prevent DNS rebinding.
        with socket.create_connection((addresses[0], port), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=host) as conn:
                cert = conn.getpeercert()
                end = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert['notAfter']), timezone.utc)
                result.update(status='verified', verified=True, hostname_match=True, chain_verified=True,
                    issuer=', '.join(f'{k}={v}' for group in cert.get('issuer', ()) for k, v in group),
                    subject=', '.join(f'{k}={v}' for group in cert.get('subject', ()) for k, v in group),
                    valid_from=cert.get('notBefore'), valid_until=cert.get('notAfter'),
                    days_remaining=(end-datetime.now(timezone.utc)).days,
                    san=[v for k,v in cert.get('subjectAltName', ()) if k == 'DNS'], protocol=conn.version())
    except ssl.SSLCertVerificationError as e:
        result.update(status='verification_failed', error=e.verify_message, verification_code=e.verify_code,
                      chain_verified=False, hostname_match=False if e.verify_code == 62 else None)
    except (OSError, ssl.SSLError) as e:
        result['error'] = str(e)
    return result

def analyze(value):
    p, host, normalized = validate_url(value)
    indicators = []
    def add(code, label, points, detail):
        indicators.append(dict(code=code, label=label, points=points, detail=detail))
    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        pass
    features = dict(url_length=len(normalized), hostname_length=len(host), subdomain_depth=max(0,len(host.split('.'))-2) if not is_ip else 0,
                    hyphens=host.count('-'), uses_ip=is_ip, https=p.scheme == 'https', punycode='xn--' in host,
                    has_credentials=p.username is not None, percent_escapes=len(re.findall(r'%[0-9a-fA-F]{2}', normalized)))
    if not features['https']: add('http', 'Unencrypted HTTP', 25, 'The submitted URL does not request HTTPS.')
    if is_ip: add('ip', 'IP address used as hostname', 25, 'A numeric address makes the website identity harder to establish.')
    if features['has_credentials']: add('userinfo', 'Misleading URL credentials', 30, 'Text before @ is user information, not the destination hostname.')
    if len(normalized)>100: add('length', 'Unusually long URL', 10 if len(normalized)<200 else 15, f'{len(normalized)} characters can obscure the destination.')
    if len(host)>60: add('host_length', 'Long hostname', 10, 'The hostname exceeds 60 characters.')
    if features['subdomain_depth']>=3: add('subdomains', 'Deep hostname structure', 15, 'Many hostname labels can conceal the controlling domain; depth is approximate, not public-suffix aware.')
    if features['hyphens']>=3: add('hyphens', 'Repeated hostname hyphens', 10, 'Three or more hyphens appear in the hostname.')
    if features['punycode']: add('idn', 'Internationalized hostname', 10, 'Punycode can represent legitimate names or visually deceptive characters.')
    if features['percent_escapes']>=3: add('encoding', 'Heavy URL encoding', 10, 'Repeated percent escapes can conceal readable URL text.')
    terms = sorted(set(re.findall(r'(?i)(?:login|verify|secure|account|password|wallet|update)', host)))
    if terms: add('terms', 'Identity-related hostname terms', 10, 'Hostname contains: '+', '.join(terms)+'. These terms alone do not establish phishing.')
    cert = {'status':'not_applicable', 'verified':False, 'hostname_match':None, 'chain_verified':None}
    resolution_error = None
    try:
        addresses = public_addresses(host, p.port or (443 if features['https'] else 80))
    except ValueError:
        raise
    except OSError as e:
        addresses=[]
        resolution_error=str(e)
    if features['https']:
        cert = inspect_certificate(host, addresses, p.port or 443) if addresses else {'status':'unavailable','verified':False,'hostname_match':None,'chain_verified':None,'error':resolution_error}
        if cert['status']=='verification_failed': add('tls_invalid', 'TLS verification failed', 40, cert['error'])
        elif cert['status']=='unavailable': add('tls_unknown', 'Certificate inspection unavailable', 10, 'A network or TLS failure prevented verification. This is uncertainty, not proof of phishing.')
        elif cert.get('days_remaining',100)<14: add('expiry', 'Certificate expires soon', 5, 'The verified certificate expires within 14 days; renewal may be automatic.')
    score=min(100,sum(i['points'] for i in indicators))
    incomplete=not addresses or (features['https'] and cert['status']=='unavailable')
    category='high_risk' if score>=60 else 'suspicious' if score>=25 or incomplete else 'likely_legitimate'
    return dict(url=normalized, hostname=host, score=score, category=category, incomplete=incomplete, features=features, certificate=cert,
                indicators=indicators, resolution_error=resolution_error, analyzed_at=datetime.now(timezone.utc).isoformat(), version=VERSION,
                disclaimer='Screening aid only. A low score or valid HTTPS certificate does not guarantee safety. The score is not a probability.')
