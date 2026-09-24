import math, re
from collections import Counter
from urllib.parse import urlsplit
import pandas as pd

FEATURES = [
    "URLLength","DomainLength","IsDomainIP","NoOfSubDomain","LetterRatioInURL",
    "NoOfDegitsInURL","DegitRatioInURL","NoOfEqualsInURL","NoOfQMarkInURL",
    "NoOfAmpersandInURL","NoOfOtherSpecialCharsInURL","SpacialCharRatioInURL",
    "IsHTTPS","PathLength","QueryLength","PathDepth","HyphenCount","DotCount",
    "AtCount","PercentCount","Entropy","SuspiciousTokenCount"
]
SUSPICIOUS = {"login","signin","verify","verification","account","update","secure","password","billing","support","confirm","wallet","bank"}

def normalize_url(url: str) -> str:
    url=(url or '').strip()
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', url):
        url='http://'+url
    return url

def entropy(s):
    if not s: return 0.0
    n=len(s); c=Counter(s)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

def extract_url_features(url: str) -> dict:
    u=normalize_url(url)
    p=urlsplit(u)
    host=(p.hostname or '').lower()
    raw=u
    no_scheme=re.sub(r'^[a-zA-Z][a-zA-Z0-9+.-]*://','',raw)
    letters=sum(ch.isalpha() for ch in raw)
    digits=sum(ch.isdigit() for ch in raw)
    special=sum(not ch.isalnum() for ch in raw)
    labels=[x for x in host.split('.') if x]
    sub=max(0,len(labels)-2)
    ipv4=bool(re.fullmatch(r'(?:\d{1,3}\.){3}\d{1,3}',host))
    ipv6=':' in host and bool(host)
    tokens=[x for x in re.split(r'[^a-z0-9]+',raw.lower()) if x]
    return {
        "URLLength":len(raw), "DomainLength":len(host), "IsDomainIP":int(ipv4 or ipv6),
        "NoOfSubDomain":sub, "LetterRatioInURL":letters/max(1,len(raw)),
        "NoOfDegitsInURL":digits, "DegitRatioInURL":digits/max(1,len(raw)),
        "NoOfEqualsInURL":raw.count('='), "NoOfQMarkInURL":raw.count('?'),
        "NoOfAmpersandInURL":raw.count('&'), "NoOfOtherSpecialCharsInURL":special,
        "SpacialCharRatioInURL":special/max(1,len(raw)), "IsHTTPS":int(p.scheme.lower()=='https'),
        "PathLength":len(p.path or ''), "QueryLength":len(p.query or ''),
        "PathDepth":len([x for x in (p.path or '').split('/') if x]),
        "HyphenCount":raw.count('-'), "DotCount":no_scheme.count('.'), "AtCount":raw.count('@'),
        "PercentCount":raw.count('%'), "Entropy":entropy(raw),
        "SuspiciousTokenCount":sum(t in SUSPICIOUS for t in tokens)
    }

def frame(url: str):
    return pd.DataFrame([extract_url_features(url)], columns=FEATURES)
