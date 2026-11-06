from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
from app import create_app, parse_line, detect

LINE = '198.51.100.42 - - [05/Nov/2026:11:03:15 +0000] "GET /.env HTTP/1.1" 404 124 "-" "DemoTest"'

def test_parser():
    event=parse_line(LINE)
    assert event is not None
    assert event['ip']=='198.51.100.42'
    assert event['path']=='/.env'
    assert event['status']==404
    assert parse_line('invalid line') is None

def test_detection_auth():
    base=datetime(2026,11,5,tzinfo=timezone.utc)
    rows=[dict(ip='198.51.100.42',time=(base+timedelta(seconds=i*30)).isoformat(),status=401,path='/login',method='POST',size=0,agent='') for i in range(6)]
    assert any(f['rule']=='auth' for f in detect(rows))

def test_demo_overview(tmp_path):
    with TestClient(create_app(str(tmp_path/'test.db'))) as client:
        r=client.get('/api/overview')
        assert r.status_code==200
        data=r.json()
        assert data['total']>=200
        assert data['unique_ips']>=5
        assert any(f['rule']=='probe' for f in data['findings'])

def test_upload_and_reset(tmp_path):
    with TestClient(create_app(str(tmp_path/'test.db'))) as client:
        r=client.post('/api/upload',files={'file':('web.log',LINE+'\nnot log\n','text/plain')})
        assert r.status_code==200
        assert r.json()['imported']==1
        assert client.get('/api/overview').json()['total']==1
        assert client.post('/api/reset').json()['imported']>=200
        assert client.post('/api/upload',files={'file':('test.csv',LINE,'text/plain')}).status_code==400
        assert client.post('/api/upload',files={'file':('bad.log','nonsense','text/plain')}).status_code==422
