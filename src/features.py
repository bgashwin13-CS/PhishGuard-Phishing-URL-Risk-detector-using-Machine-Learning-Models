import math, re
from collections import Counter
from urllib.parse import urlsplit
import pandas as pd

FEATURES=["URLLength","DomainLength","IsDomainIP","NoOfSubDomain","LetterRatioInURL","NoOfDegitsInURL","DegitRatioInURL","NoOfEqualsInURL","NoOfQMarkInURL","NoOfAmpersandInURL","NoOfOtherSpecialCharsInURL","SpacialCharRatioInURL","IsHTTPS","PathLength","QueryLength","PathDepth","HyphenCount","DotCount","AtCount","PercentCount","Entropy","SuspiciousTokenCount"]
SUSPICIOUS={"login","signin","verify","verification","account","update","secure","password","billing","support","confirm","wallet","bank","kyc","otp","payment","unlock","recover","credential"}
SHORTENERS={"bit.ly","tinyurl.com","t.co","rb.gy","cutt.ly","is.gd","tiny.cc"}
BRANDS={"google","microsoft","apple","amazon","paypal","netflix","facebook","instagram","whatsapp","sbi","hdfc","icici","axisbank","paytm","phonepe","irctc","aadhaar"}

def normalize_url(url):
    url=(url or "").strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://",url): url="http://"+url
    return url

def entropy(s):
    if not s:return 0.0
    n=len(s);c=Counter(s)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

def extract_url_features(url):
    u=normalize_url(url);p=urlsplit(u);host=(p.hostname or "").lower();raw=u
    no_scheme=re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://","",raw)
    letters=sum(ch.isalpha() for ch in raw);digits=sum(ch.isdigit() for ch in raw);special=sum(not ch.isalnum() for ch in raw)
    labels=[x for x in host.split(".") if x];sub=max(0,len(labels)-2)
    ipv4=bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}",host));ipv6=":" in host and bool(host)
    tokens=[x for x in re.split(r"[^a-z0-9]+",raw.lower()) if x]
    return {"URLLength":len(raw),"DomainLength":len(host),"IsDomainIP":int(ipv4 or ipv6),"NoOfSubDomain":sub,"LetterRatioInURL":letters/max(1,len(raw)),"NoOfDegitsInURL":digits,"DegitRatioInURL":digits/max(1,len(raw)),"NoOfEqualsInURL":raw.count("="),"NoOfQMarkInURL":raw.count("?"),"NoOfAmpersandInURL":raw.count("&"),"NoOfOtherSpecialCharsInURL":special,"SpacialCharRatioInURL":special/max(1,len(raw)),"IsHTTPS":int(p.scheme.lower()=="https"),"PathLength":len(p.path or ""),"QueryLength":len(p.query or ""),"PathDepth":len([x for x in (p.path or "").split("/") if x]),"HyphenCount":raw.count("-"),"DotCount":no_scheme.count("."),"AtCount":raw.count("@"),"PercentCount":raw.count("%"),"Entropy":entropy(raw),"SuspiciousTokenCount":sum(t in SUSPICIOUS for t in tokens)}

def explain_url(url):
    u=normalize_url(url);p=urlsplit(u);host=(p.hostname or "").lower();f=extract_url_features(url);reasons=[]
    def add(name,status,detail): reasons.append({"name":name,"status":status,"detail":detail})
    add("HTTPS","good" if f["IsHTTPS"] else "warn","HTTPS scheme present." if f["IsHTTPS"] else "URL does not use HTTPS.")
    add("Domain format","bad" if f["IsDomainIP"] else "good","Uses an IP address instead of a normal domain." if f["IsDomainIP"] else "Normal domain-name format.")
    add("Subdomains","warn" if f["NoOfSubDomain"]>=3 else "good",f'{f["NoOfSubDomain"]} subdomain level(s) detected.')
    add("URL length","warn" if f["URLLength"]>=100 else "good",f'{f["URLLength"]} characters.')
    add("Suspicious words","bad" if f["SuspiciousTokenCount"]>=2 else ("warn" if f["SuspiciousTokenCount"] else "good"),f'{f["SuspiciousTokenCount"]} suspicious token(s) detected.')
    add("@ symbol","bad" if f["AtCount"] else "good",f'{f["AtCount"]} @ symbol(s).')
    add("URL shortener","warn" if host in SHORTENERS else "good","Known shortening service." if host in SHORTENERS else "No common shortener detected.")
    brand_hits=[b for b in BRANDS if b in host]
    add("Brand-like domain","warn" if brand_hits and not any(host==b+".com" or host.endswith("."+b+".com") for b in brand_hits) else "good",("Brand terms detected: "+", ".join(brand_hits)) if brand_hits else "No common brand keyword detected in hostname.")
    return reasons

def frame(url): return pd.DataFrame([extract_url_features(url)],columns=FEATURES)
