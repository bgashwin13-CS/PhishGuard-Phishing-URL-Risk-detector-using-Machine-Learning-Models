import math,re
from collections import Counter
from urllib.parse import urlsplit
import pandas as pd
FEATURES=["URLLength","DomainLength","IsDomainIP","NoOfSubDomain","LetterRatioInURL","NoOfDegitsInURL","DegitRatioInURL","NoOfEqualsInURL","NoOfQMarkInURL","NoOfAmpersandInURL","NoOfOtherSpecialCharsInURL","SpacialCharRatioInURL","IsHTTPS","PathLength","QueryLength","PathDepth","HyphenCount","DotCount","AtCount","PercentCount","Entropy","SuspiciousTokenCount"]
SUSPICIOUS={"login","signin","verify","verification","account","update","secure","password","billing","support","confirm","wallet","bank","kyc","otp","payment","unlock","recover","credential"}
def normalize_url(url):
 url=(url or "").strip()
 if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://",url):url="http://"+url
 return url
def entropy(s):
 if not s:return 0.0
 n=len(s);c=Counter(s);return -sum((v/n)*math.log2(v/n) for v in c.values())
def extract_url_features(url):
 u=normalize_url(url);p=urlsplit(u);host=(p.hostname or "").lower();raw=u;nos=re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://","",raw)
 letters=sum(c.isalpha() for c in raw);digits=sum(c.isdigit() for c in raw);special=sum(not c.isalnum() for c in raw);labels=[x for x in host.split(".") if x];tokens=[x for x in re.split(r"[^a-z0-9]+",raw.lower()) if x]
 return {"URLLength":len(raw),"DomainLength":len(host),"IsDomainIP":int(bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}",host)) or (":" in host and bool(host))),"NoOfSubDomain":max(0,len(labels)-2),"LetterRatioInURL":letters/max(1,len(raw)),"NoOfDegitsInURL":digits,"DegitRatioInURL":digits/max(1,len(raw)),"NoOfEqualsInURL":raw.count("="),"NoOfQMarkInURL":raw.count("?"),"NoOfAmpersandInURL":raw.count("&"),"NoOfOtherSpecialCharsInURL":special,"SpacialCharRatioInURL":special/max(1,len(raw)),"IsHTTPS":int(p.scheme.lower()=="https"),"PathLength":len(p.path or ""),"QueryLength":len(p.query or ""),"PathDepth":len([x for x in (p.path or "").split("/") if x]),"HyphenCount":raw.count("-"),"DotCount":nos.count("."),"AtCount":raw.count("@"),"PercentCount":raw.count("%"),"Entropy":entropy(raw),"SuspiciousTokenCount":sum(t in SUSPICIOUS for t in tokens)}
def url_text(url):return normalize_url(url).lower()
def explain_url(url):
 f=extract_url_features(url);checks=[]
 def add(n,s,d):checks.append({"name":n,"status":s,"detail":d})
 add("HTTPS","good" if f["IsHTTPS"] else "warn","HTTPS scheme present." if f["IsHTTPS"] else "No HTTPS scheme.")
 add("Domain format","bad" if f["IsDomainIP"] else "good","IP-address host detected." if f["IsDomainIP"] else "Normal domain-name host.")
 add("Subdomains","warn" if f["NoOfSubDomain"]>=3 else "good",f'{f["NoOfSubDomain"]} subdomain level(s).')
 add("URL length","warn" if f["URLLength"]>=120 else "good",f'{f["URLLength"]} characters.')
 add("Suspicious terms","bad" if f["SuspiciousTokenCount"]>=3 else ("warn" if f["SuspiciousTokenCount"] else "good"),f'{f["SuspiciousTokenCount"]} suspicious token(s).')
 add("@ symbol","bad" if f["AtCount"] else "good",f'{f["AtCount"]} @ symbol(s).')
 return checks
def frame(url):return pd.DataFrame([extract_url_features(url)],columns=FEATURES)
