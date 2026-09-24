import json, os, time
from flask import Flask, render_template, request, jsonify
import joblib
from src.features import frame, extract_url_features, normalize_url

BASE=os.path.dirname(os.path.abspath(__file__))
app=Flask(__name__)

def paths_ready():
    return all(os.path.exists(os.path.join(BASE,'models',x)) for x in ('random_forest.joblib','xgboost.joblib'))

def load_models():
    return (joblib.load(os.path.join(BASE,'models','random_forest.joblib')),
            joblib.load(os.path.join(BASE,'models','xgboost.joblib')))

def band(score):
    if score < 35: return 'LOW RISK', 'low', 'Relatively low model-estimated phishing probability.'
    if score < 70: return 'SUSPICIOUS', 'medium', 'Use caution and independently verify the destination.'
    return 'HIGH RISK', 'high', 'High model-estimated phishing probability. Avoid opening unless independently verified.'

@app.route('/')
def home():
    metrics=None
    mp=os.path.join(BASE,'reports','metrics.json')
    if os.path.exists(mp):
        with open(mp,encoding='utf-8') as f: metrics=json.load(f)
    return render_template('index.html', ready=paths_ready(), metrics=metrics)

@app.post('/api/analyze')
def analyze():
    if not paths_ready(): return jsonify({'error':'Models are not trained. Run train_windows.bat first.'}),503
    payload=request.get_json(silent=True) or {}
    url=(payload.get('url') or '').strip()
    if not url: return jsonify({'error':'Enter a URL.'}),400
    if len(url)>4096: return jsonify({'error':'URL is too long.'}),400
    X=frame(url); rf,xgb=load_models()
    t=time.perf_counter(); pr=float(rf.predict_proba(X)[0,1]); rf_ms=(time.perf_counter()-t)*1000
    t=time.perf_counter(); px=float(xgb.predict_proba(X)[0,1]); xgb_ms=(time.perf_counter()-t)*1000
    combined=(pr+px)/2.0; score=int(round(combined*100)); label,level,message=band(score)
    return jsonify({'input_url':url,'normalized_url':normalize_url(url),'score':score,'label':label,'level':level,
                    'message':message,'random_forest_probability':round(pr*100,2),'xgboost_probability':round(px*100,2),
                    'rf_ms':round(rf_ms,3),'xgb_ms':round(xgb_ms,3),'features':extract_url_features(url),
                    'notice':'Research prototype. The URL string is analysed locally; the destination webpage is not opened.'})

if __name__=='__main__':
    app.run(host='127.0.0.1',port=5000,debug=False)
