"""ShieldWatch: educational Apache/Nginx access-log analyzer."""
from __future__ import annotations

import os
import re
import sqlite3
from collections import Counter, defaultdict
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

BASE = Path(__file__).resolve().parent
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_ROWS = 10_000
LOG_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<date>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<url>\S+) [^\"]+" '
    r'(?P<status>\d{3}) (?P<size>\d+|-)'
    r'(?: "[^"]*" "(?P<agent>[^"]*)")?'
)
SUSPICIOUS = ("/.env", "/.git/", "/wp-login.php", "/phpmyadmin", "/etc/passwd", "/server-status", "/config.php")

@contextmanager
def connect(path: str):
    db = sqlite3.connect(path, check_same_thread=False)
    db.row_factory = sqlite3.Row
    try:
        yield db
        db.commit()
    finally:
        db.close()

def parse_line(line: str) -> dict | None:
    """Parse common/combined access logs; return None for invalid or unsupported lines."""
    m = LOG_RE.match(line.strip())
    if not m:
        return None
    data = m.groupdict()
    try:
        ts = datetime.strptime(data["date"], "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)
        status = int(data["status"])
        if status < 100 or status >= 600:
            return None
        url = data["url"]
        parsed = urlsplit(url)
        path = parsed.path[:500] or "/"
    except (ValueError, OverflowError):
        return None
    return {"ip":data["ip"][:45], "time":ts.isoformat(timespec="seconds"), "method":data["method"],
            "path":path, "status":status, "size":int(data["size"]) if data["size"]!="-" else 0,
            "agent":(data["agent"] or "")[:180]}

def sample_events() -> list[dict]:
    base = datetime.now(timezone.utc).replace(minute=0,second=0,microsecond=0)
    normals = ["/", "/catalog", "/about", "/api/products", "/contacts", "/assets/main.css", "/api/orders", "/favicon.ico", "/pricing"]
    ip_pool = ["192.0.2.17", "192.0.2.24", "198.51.100.8", "203.0.113.15", "192.0.2.48"]
    events = []
    def add(ip, dt, path, status=200, method="GET", size=1732):
        events.append({"ip":ip,"time":dt.isoformat(timespec="seconds"),"method":method,"path":path,
                       "status":status,"size":size,"agent":"Mozilla/5.0 (Demo browser)"})
    for i in range(132):
        h = (i*7)%24
        dt = base - timedelta(hours=h,minutes=(i*11)%60,seconds=(i*7)%55)
        add(ip_pool[i%len(ip_pool)],dt,normals[(i*3)%len(normals)],200 if i%10 else 304)
    for i in range(9):
        add("198.51.100.42",base-timedelta(hours=2,minutes=8)+timedelta(seconds=25*i),"/api/login",401, "POST",132)
    for i,p in enumerate(["/.env", "/.git/config", "/wp-login.php", "/phpmyadmin/", "/config.php", "/server-status"]):
        add("203.0.113.99",base-timedelta(hours=1,minutes=14)+timedelta(seconds=27*i),p,404, "GET",120)
    for i in range(13):
        add("203.0.113.99",base-timedelta(hours=1,minutes=10)+timedelta(seconds=18*i),f"/old-admin-{i}",404, "GET",114)
    for i in range(62):
        add("198.51.100.77",base-timedelta(hours=3,minutes=4)+timedelta(seconds=i*3),"/api/products",200, "GET",4100)
    events.sort(key=lambda x:x["time"],reverse=True)
    return events

def init_db(path: str):
    Path(path).parent.mkdir(parents=True,exist_ok=True)
    with connect(path) as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS logs (
          id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL, time TEXT NOT NULL,
          method TEXT NOT NULL, path TEXT NOT NULL, status INTEGER NOT NULL,
          size INTEGER NOT NULL, agent TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS logs_time ON logs(time);
        CREATE INDEX IF NOT EXISTS logs_ip ON logs(ip);
        CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        """)
        if db.execute("SELECT COUNT(*) FROM logs").fetchone()[0] == 0:
            insert_rows(db,sample_events())
            db.execute("INSERT OR REPLACE INTO meta(key,value) VALUES ('source','Демонстрационные данные')")

def insert_rows(db, events: list[dict]):
    db.executemany("INSERT INTO logs (ip,time,method,path,status,size,agent) VALUES (:ip,:time,:method,:path,:status,:size,:agent)",events)

def window_peak(events: list[dict], minutes: int) -> int:
    """Maximum requests within a sliding time window (timestamps sorted ascending)."""
    ts = sorted(datetime.fromisoformat(e["time"]) for e in events)
    j = 0; best = 0
    for i,t in enumerate(ts):
        while t-ts[j] > timedelta(minutes=minutes):
            j += 1
        best = max(best,i-j+1)
    return best

def detect(events: list[dict]) -> list[dict]:
    by_ip = defaultdict(list)
    for e in events:
        by_ip[e["ip"]].append(e)
    findings = []
    def report(ip,severity,title,description,count,recommendation,rule):
        findings.append({"id":f"{rule}:{ip}","ip":ip,"severity":severity,"title":title,
                         "description":description,"count":count,"recommendation":recommendation,"rule":rule})
    for ip, rows in by_ip.items():
        bad_auth = [e for e in rows if e["status"] in (401,403)]
        if len(bad_auth)>=5 and window_peak(bad_auth,10)>=5:
            report(ip,"high","Много неудачных попыток входа",f"5 или более ответов 401/403 за 10 минут с адреса {ip}.",len(bad_auth),
                   "Проверьте учётные записи, включите ограничение попыток входа и MFA.","auth")
        probes = [e for e in rows if any(s in e["path"].lower() for s in SUSPICIOUS)]
        if probes:
            report(ip,"high","Обращения к чувствительным путям",f"Запросы к файлам конфигурации или типовым административным адресам с {ip}.",len(probes),
                   "Проверьте журналы приложения и убедитесь, что секретные файлы не доступны из веба.","probe")
        notfound = [e for e in rows if e["status"]==404]
        if len(notfound)>=8 and len({e["path"] for e in notfound})>=6:
            report(ip,"medium","Возможное сканирование URL",f"Много ответов 404 по разным путям с адреса {ip}.",len(notfound),
                   "Проверьте пользовательский агент и примените WAF или rate limiting при подтверждении.","scan")
        if len(rows)>=50 and window_peak(rows,5)>=50:
            report(ip,"medium","Всплеск запросов",f"Не менее 50 запросов за 5 минут от {ip}.",window_peak(rows,5),
                   "Сравните с обычной нагрузкой; при необходимости настройте лимиты.","burst")
    return sorted(findings,key=lambda f: (0 if f["severity"]=="high" else 1,-f["count"],f["ip"]))

def attach_risk(events: list[dict], findings: list[dict]):
    auth_ips={x["ip"] for x in findings if x["rule"]=="auth"}
    scan_ips={x["ip"] for x in findings if x["rule"]=="scan"}
    burst_ips={x["ip"] for x in findings if x["rule"]=="burst"}
    for e in events:
        if any(s in e["path"].lower() for s in SUSPICIOUS) or e["ip"] in auth_ips and e["status"] in (401,403):
            e["severity"]="high"
        elif e["ip"] in scan_ips and e["status"]==404 or e["ip"] in burst_ips:
            e["severity"]="medium"
        else:
            e["severity"]="normal"
    return events

def make_overview(events, source):
    findings=detect(events)
    annotated=attach_risk(events,findings)
    flagged=[e for e in annotated if e["severity"]!="normal"]
    ips=Counter(e["ip"] for e in events)
    status_counts=Counter(str(e["status"]//100)+"xx" for e in events)
    buckets=defaultdict(lambda:{"requests":0,"alerts":0})
    for e in events:
        dt=datetime.fromisoformat(e["time"])
        key=dt.strftime("%Y-%m-%dT%H:00:00+00:00")
        buckets[key]["requests"]+=1
        buckets[key]["alerts"]+=e["severity"]!="normal"
    timeline=[{"label":datetime.fromisoformat(k).strftime("%d.%m %H:00"),**v} for k,v in sorted(buckets.items())]
    # Keep the latest 15 buckets for a readable compact chart; sort with actual timestamps.
    timeline=timeline[-15:]
    ip_rows=[]
    for ip,count in ips.most_common(6):
        bad=sum(e["severity"]!="normal" for e in annotated if e["ip"]==ip)
        ip_rows.append({"ip":ip,"requests":count,"alerts":bad})
    return {"source":source,"total":len(events),"unique_ips":len(ips),"flagged":len(flagged),
            "findings_count":len(findings),"high_count":sum(f["severity"]=="high" for f in findings),
            "findings":findings,"timeline":timeline,"top_ips":ip_rows,
            "status_counts":dict(status_counts),"events":annotated[:100]}

def create_app(db_path: str | None = None) -> FastAPI:
    path = db_path or os.getenv("SHIELDWATCH_DB",str(BASE / "shieldwatch.db"))
    init_db(path)
    app = FastAPI(title="ShieldWatch Log Analyzer API",version="1.0.0",
                  description="Educational offline heuristic log analyzer, not a production IDS.")
    app.mount("/static",StaticFiles(directory=BASE/"static"),name="static")

    def dataset():
        with connect(path) as db:
            rows=[dict(r) for r in db.execute("SELECT ip,time,method,path,status,size,agent FROM logs ORDER BY time DESC,id DESC")]
            source=db.execute("SELECT value FROM meta WHERE key='source'").fetchone()
        return rows,source[0] if source else "Не указан"

    @app.get("/",include_in_schema=False)
    def index():
        return FileResponse(BASE/"static"/"index.html")

    @app.get("/api/overview")
    def overview():
        rows,source=dataset()
        return make_overview(rows,source)

    @app.post("/api/upload")
    async def upload(file: UploadFile = File(...)):
        filename=file.filename or ""
        if not filename.lower().endswith((".log",".txt")):
            raise HTTPException(400,"Загрузите файл .log или .txt")
        raw=await file.read(MAX_FILE_BYTES+1)
        if len(raw)>MAX_FILE_BYTES:
            raise HTTPException(413,"Размер файла превышает 2 МБ")
        lines=raw.decode("utf-8-sig",errors="replace").splitlines()
        if len(lines)>MAX_ROWS:
            raise HTTPException(413,"Не более 10 000 строк за одну загрузку")
        parsed=[row for line in lines if (row:=parse_line(line))]
        if not parsed:
            raise HTTPException(422,"Не найдены записи в формате Apache/Nginx access log")
        with connect(path) as db:
            db.execute("DELETE FROM logs")
            insert_rows(db,parsed)
            db.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('source',?)",(f"Загружен файл: {Path(filename).name[:100]}",))
        return {"imported":len(parsed),"skipped":len(lines)-len(parsed),"source":Path(filename).name[:100]}

    @app.post("/api/reset")
    def reset_demo():
        with connect(path) as db:
            db.execute("DELETE FROM logs")
            events=sample_events()
            insert_rows(db,events)
            db.execute("INSERT OR REPLACE INTO meta(key,value) VALUES ('source','Демонстрационные данные')")
        return {"imported":len(events)}

    return app

app=create_app()
