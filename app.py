import json,os,time,joblib
from urllib.parse import urlsplit
from flask import Flask,render_template,request,jsonify
from scipy.sparse import csr_matrix,hstack
from src.features import frame,extract_url_features,normalize_url,explain_url,url_text
BASE=os.path.dirname(os.path.abspath(__file__));app=Flask(__name__);CACHE=None
def paths_ready():return all(os.path.exists(os.path.join(BASE,"models",x)) for x in ("random_forest.joblib","xgboost.joblib","url_vectorizer.joblib","url_scaler.joblib"))
def load_models():
 global CACHE
 if CACHE is None:CACHE=tuple(joblib.load(os.path.join(BASE,"models",x)) for x in ("random_forest.joblib","xgboost.joblib","url_vectorizer.joblib","url_scaler.joblib"))
 return CACHE
def band(s):
 if s<35:return "LIKELY LEGITIMATE","low","Low model-estimated phishing risk."
 if s<70:return "SUSPICIOUS","medium","Mixed phishing-like patterns detected. Verify the domain before continuing."
 return "LIKELY PHISHING","high","High model-estimated phishing risk. Avoid entering credentials or payment information."
def valid_url(url):
 try:
  p=urlsplit(normalize_url(url));return p.scheme in ("http","https") and bool(p.hostname) and "." in p.hostname
 except:return False
def read_metrics():
 p=os.path.join(BASE,"reports","metrics.json")
 if not os.path.exists(p):return None
 with open(p) as f:return json.load(f)
@app.get("/")
def home():return render_template("index.html",ready=paths_ready(),metrics=read_metrics())
@app.get("/api/metrics")
def api_metrics():return jsonify(read_metrics() or {})
@app.post("/api/analyze")
def analyze():
 if not paths_ready():return jsonify({"error":"New hybrid model artifacts are missing. Run: python -m src.train"}),503
 data=request.get_json(silent=True) or {};url=(data.get("url") or "").strip()
 if not url:return jsonify({"error":"Paste a URL to analyze."}),400
 if len(url)>4096 or not valid_url(url):return jsonify({"error":"Enter a valid website URL such as https://example.com/page"}),400
 rf,xgb,v,scaler=load_models();num=scaler.transform(frame(url));text=v.transform([url_text(url)]);X=hstack([text,csr_matrix(num)]).tocsr();start=time.perf_counter()
 t=time.perf_counter();pr=float(rf.predict_proba(X)[0,1]);rms=(time.perf_counter()-t)*1000;t=time.perf_counter();px=float(xgb.predict_proba(X)[0,1]);xms=(time.perf_counter()-t)*1000
 score=round(((pr+px)/2)*100);label,level,msg=band(score)
 return jsonify({"normalized_url":normalize_url(url),"score":score,"label":label,"level":level,"message":msg,"random_forest_probability":round(pr*100,2),"xgboost_probability":round(px*100,2),"combined_probability":round((pr+px)*50,2),"rf_ms":round(rms,3),"xgb_ms":round(xms,3),"total_ms":round((time.perf_counter()-start)*1000,3),"features":extract_url_features(url),"signals":explain_url(url),"notice":"Hybrid character TF-IDF + structural URL features. No domain whitelist is used."})
if __name__=="__main__":
 if paths_ready():load_models()
 app.run(host="127.0.0.1",port=5000,debug=False)
