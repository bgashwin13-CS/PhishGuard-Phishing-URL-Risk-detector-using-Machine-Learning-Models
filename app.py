import json, os, time
from flask import Flask, render_template, request, jsonify
import joblib
from src.features import frame, extract_url_features, normalize_url, explain_url
BASE=os.path.dirname(os.path.abspath(__file__));app=Flask(__name__);_MODEL_CACHE=None
def paths_ready(): return all(os.path.exists(os.path.join(BASE,"models",x)) for x in ("random_forest.joblib","xgboost.joblib"))
def load_models():
 global _MODEL_CACHE
 if _MODEL_CACHE is None:_MODEL_CACHE=(joblib.load(os.path.join(BASE,"models","random_forest.joblib")),joblib.load(os.path.join(BASE,"models","xgboost.joblib")))
 return _MODEL_CACHE
def band(score):
 if score<35:return "LIKELY LEGITIMATE","low","The models found relatively few phishing-like URL patterns."
 if score<70:return "SUSPICIOUS","medium","The URL contains patterns that deserve additional verification."
 return "LIKELY PHISHING","high","The models estimate a high phishing risk. Avoid entering credentials or payment details."
def read_metrics():
 p=os.path.join(BASE,"reports","metrics.json")
 if not os.path.exists(p):return None
 with open(p,encoding="utf-8") as f:return json.load(f)
@app.get("/")
def home():return render_template("index.html",ready=paths_ready(),metrics=read_metrics())
@app.get("/api/metrics")
def metrics():return jsonify(read_metrics() or {})
@app.post("/api/analyze")
def analyze():
 if not paths_ready():return jsonify({"error":"Trained model files are missing. Run the training script first."}),503
 data=request.get_json(silent=True) or {};url=(data.get("url") or "").strip()
 if not url:return jsonify({"error":"Paste a URL to analyze."}),400
 if len(url)>4096:return jsonify({"error":"URL is too long."}),400
 try:X=frame(url)
 except Exception:return jsonify({"error":"The URL could not be parsed."}),400
 rf,xgb=load_models();start=time.perf_counter()
 t=time.perf_counter();pr=float(rf.predict_proba(X)[0,1]);rf_ms=(time.perf_counter()-t)*1000
 t=time.perf_counter();px=float(xgb.predict_proba(X)[0,1]);xgb_ms=(time.perf_counter()-t)*1000
 combined=(pr+px)/2;score=int(round(combined*100));label,level,message=band(score)
 return jsonify({"input_url":url,"normalized_url":normalize_url(url),"score":score,"label":label,"level":level,"message":message,"random_forest_probability":round(pr*100,2),"xgboost_probability":round(px*100,2),"combined_probability":round(combined*100,2),"rf_ms":round(rf_ms,3),"xgb_ms":round(xgb_ms,3),"total_ms":round((time.perf_counter()-start)*1000,3),"features":extract_url_features(url),"signals":explain_url(url),"notice":"URL-only research prototype; the destination page is not opened."})
if __name__=="__main__":
 if paths_ready():load_models()
 app.run(host="127.0.0.1",port=5000,debug=False)
