import json,os,time,warnings,joblib,pandas as pd
from scipy.sparse import csr_matrix,hstack
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score,precision_score,recall_score,f1_score,roc_auc_score,confusion_matrix
from xgboost import XGBClassifier
from src.features import FEATURES,extract_url_features,url_text
warnings.filterwarnings("ignore")
BASE=os.path.dirname(os.path.dirname(os.path.abspath(__file__)));DATA=os.path.join(BASE,"data","PhiUSIIL_Phishing_URL_Dataset.csv");MODELS=os.path.join(BASE,"models");REPORTS=os.path.join(BASE,"reports");os.makedirs(MODELS,exist_ok=True);os.makedirs(REPORTS,exist_ok=True)
def get_data():
 raw=pd.read_csv(DATA,low_memory=False);uc=[c for c in raw if c.strip().lower() in ("url","website","link")];lc=[c for c in raw if c.strip().lower() in ("label","class","status","target","result")]
 if not uc or not lc:raise RuntimeError("Dataset must contain URL and label columns.")
 urls=raw[uc[0]].fillna("").astype(str);orig=pd.to_numeric(raw[lc[0]],errors="coerce").fillna(1).astype(int);y=(orig==0).astype(int)
 print(f"Loaded {len(urls):,} URLs. Extracting one shared train/serve feature pipeline...")
 Xnum=pd.DataFrame([extract_url_features(u) for u in urls],columns=FEATURES)
 return urls,Xnum,y
def metrics(model,X,y):
 p=model.predict(X);q=model.predict_proba(X)[:,1];return {"accuracy":float(accuracy_score(y,p)),"precision":float(precision_score(y,p,zero_division=0)),"recall":float(recall_score(y,p,zero_division=0)),"f1":float(f1_score(y,p,zero_division=0)),"roc_auc":float(roc_auc_score(y,q)),"confusion_matrix":confusion_matrix(y,p).tolist()}
def main():
 urls,Xnum,y=get_data();idx_train,idx_test=train_test_split(range(len(y)),test_size=.2,random_state=42,stratify=y)
 tr=list(idx_train);te=list(idx_test);v=TfidfVectorizer(analyzer="char",ngram_range=(3,5),min_df=2,max_features=30000,sublinear_tf=True);Xt=v.fit_transform([url_text(urls.iloc[i]) for i in tr]);Xe=v.transform([url_text(urls.iloc[i]) for i in te])
 scaler=StandardScaler();Ntr=scaler.fit_transform(Xnum.iloc[tr]);Nte=scaler.transform(Xnum.iloc[te]);A=hstack([Xt,csr_matrix(Ntr)]).tocsr();B=hstack([Xe,csr_matrix(Nte)]).tocsr();yt=y.iloc[tr];ye=y.iloc[te]
 models={"Random Forest":RandomForestClassifier(n_estimators=350,random_state=42,n_jobs=-1,class_weight="balanced_subsample",max_features="sqrt"),"XGBoost":XGBClassifier(n_estimators=400,max_depth=7,learning_rate=.07,subsample=.9,colsample_bytree=.9,objective="binary:logistic",eval_metric="logloss",random_state=42,n_jobs=-1)}
 out={}
 for name,m in models.items():
  print("Training",name);m.fit(A,yt);out[name]=metrics(m,B,ye);joblib.dump(m,os.path.join(MODELS,"random_forest.joblib" if name=="Random Forest" else "xgboost.joblib"));print(name,out[name])
 joblib.dump(v,os.path.join(MODELS,"url_vectorizer.joblib"));joblib.dump(scaler,os.path.join(MODELS,"url_scaler.joblib"))
 with open(os.path.join(MODELS,"metadata.json"),"w") as f:json.dump({"features":FEATURES,"text_features":"character TF-IDF 3-5 grams","positive_class":"phishing","pipeline":"same URL extractor used for training and serving"},f,indent=2)
 with open(os.path.join(REPORTS,"metrics.json"),"w") as f:json.dump(out,f,indent=2)
 print("Training complete. Now run: python app.py")
if __name__=="__main__":main()
