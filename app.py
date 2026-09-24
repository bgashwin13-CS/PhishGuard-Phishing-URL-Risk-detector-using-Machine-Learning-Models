import json, os, time
from flask import Flask, render_template, request, jsonify
import joblib
from src.features import frame, extract_url_features, normalize_url

BASE=os.path.dirname(os.path.abspath(__file__))
app=Flask(__name__)
_MODEL_CACHE=None

def paths_ready():
    return all(os.path.exists(os.path.join(BASE,'models',x)) for x in ('random_forest.joblib','xgboost.joblib'))

def load_models():
    global _MODEL_CACHE
    if _MODEL_CACHE is None:
        _MODEL_CACHE=(joblib.load(os.path.join(BASE,'models','random_forest.joblib')),
                      joblib.load(os.path.join(BASE,'models','xgboost.joblib')))
    return _MODEL_CACHE

def band(score):
    if score < 35:
        return 'LIKELY LEGITIMATE','low','Low model-estimated phishing risk. Still verify unfamiliar links before opening them.'
    if score < 70:
        return 'SUSPICIOUS','medium','The URL has suspicious characteristics. Verify the sender and destination before opening it.'
    return 'LIKELY PHISHING','high','High model-estimated phishing risk. Avoid opening the link unless it is independently verified.'

def read_metrics():
    mp=os.path.join(BASE,'reports','metrics.json')
    if not os.path.exists(mp): return None
    with open(mp,encoding='utf-8') as f: return json.load(f)

@app.route('/')
def home():
    return render_template('index.html', ready=paths_ready(), metrics=read_metrics())

@app.get('/api/metrics')
def metrics():
    data=read_metrics()
    return jsonify(data or {})

@app.post('/api/analyze')
def analyze():
    if not paths_ready():
        return jsonify({'error':'Trained model files are missing. Train the models first.'}),503
    payload=request.get_json(silent=True) or {}
    url=(payload.get('url') or '').strip()
    if not url: return jsonify({'error':'Enter a URL to analyze.'}),400
    if len(url)>4096: return jsonify({'error':'URL is too long.'}),400

    X=frame(url)
    rf,xgb=load_models()
    t=time.perf_counter(); pr=float(rf.predict_proba(X)[0,1]); rf_ms=(time.perf_counter()-t)*1000
    t=time.perf_counter(); px=float(xgb.predict_proba(X)[0,1]); xgb_ms=(time.perf_counter()-t)*1000

    combined=(pr+px)/2.0
    score=int(round(combined*100))
    label,level,message=band(score)
    return jsonify({
        'input_url':url,
        'normalized_url':normalize_url(url),
        'score':score,
        'label':label,
        'level':level,
        'message':message,
        'random_forest_probability':round(pr*100,2),
        'xgboost_probability':round(px*100,2),
        'combined_probability':round(combined*100,2),
        'rf_ms':round(rf_ms,3),
        'xgb_ms':round(xgb_ms,3),
        'features':extract_url_features(url),
        'notice':'This is a URL-only machine-learning prediction. The destination webpage is not opened.'
    })

if __name__=='__main__':
    if paths_ready(): load_models()
    app.run(host='127.0.0.1',port=5000,debug=False)
