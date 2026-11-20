from contextlib import contextmanager
import csv
import io
import json
import sqlite3
import threading
from pathlib import Path
from flask import Flask, jsonify, request, send_from_directory
from analyzer import analyze

BASE=Path(__file__).parent
app=Flask(__name__, static_folder='static')
app.config['MAX_CONTENT_LENGTH']=1024*1024
SCAN_LOCK=threading.BoundedSemaphore(4)
DB=BASE/'data'/'history.sqlite3'

@contextmanager
def database():
    DB.parent.mkdir(exist_ok=True)
    conn=sqlite3.connect(DB)
    conn.execute('CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY, result TEXT NOT NULL)')
    try:
        with conn:
            yield conn
    finally:
        conn.close()

@app.get('/')
def home(): return send_from_directory(app.static_folder,'index.html')

@app.post('/api/analyze')
def scan():
    if not SCAN_LOCK.acquire(blocking=False): return jsonify(error='Scanner busy. Please retry shortly.'),429
    try:
        payload=request.get_json(silent=True) or {}
        if not isinstance(payload, dict): raise ValueError('Send a JSON object containing a URL.')
        result=analyze(payload.get('url'))
        with database() as db:
            cur=db.execute('INSERT INTO scans(result) VALUES (?)',(json.dumps(result),))
            result['id']=cur.lastrowid
        return jsonify(result)
    except ValueError as e: return jsonify(error=str(e)),400
    finally: SCAN_LOCK.release()

@app.get('/api/history')
def history():
    with database() as db:
        rows=db.execute('SELECT id,result FROM scans ORDER BY id DESC LIMIT 100').fetchall()
    return jsonify([dict(json.loads(r),id=i) for i,r in rows])

@app.delete('/api/history')
def clear():
    with database() as db: db.execute('DELETE FROM scans')
    return jsonify(ok=True)

@app.post('/api/evaluate')
def evaluate():
    file=request.files.get('file')
    if not file: return jsonify(error='Upload a CSV with label and prediction columns.'),400
    try:
        rows=list(csv.DictReader(io.StringIO(file.read().decode('utf-8-sig'))))
        if not rows or len(rows)>10000: raise ValueError('Provide 1 to 10,000 labeled rows.')
        tp=tn=fp=fn=0
        for r in rows:
            actual=r['label'].strip().lower(); pred=r['prediction'].strip().lower()
            if actual not in ('legitimate','phishing') or pred not in ('likely_legitimate','suspicious','high_risk'): raise ValueError('Invalid label or prediction. Use the supplied sample format.')
            positive=pred!='likely_legitimate'
            tp+=actual=='phishing' and positive; fn+=actual=='phishing' and not positive
            fp+=actual=='legitimate' and positive; tn+=actual=='legitimate' and not positive
        precision=tp/(tp+fp) if tp+fp else 0
        recall=tp/(tp+fn) if tp+fn else 0
        return jsonify(rows=len(rows),tp=tp,tn=tn,fp=fp,fn=fn,precision=precision,recall=recall,f1=2*precision*recall/(precision+recall) if precision+recall else 0,accuracy=(tp+tn)/len(rows))
    except (ValueError,KeyError,UnicodeError,csv.Error) as e: return jsonify(error=str(e)),400

@app.after_request
def security_headers(response):
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['Referrer-Policy']='no-referrer'
    response.headers['Content-Security-Policy']="default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    return response

@app.errorhandler(413)
def large(e): return jsonify(error='Upload must be smaller than 1 MB.'),413

if __name__=='__main__': app.run(host='127.0.0.1',port=8000,debug=False)
