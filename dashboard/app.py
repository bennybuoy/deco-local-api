"""Local Deco console. Reads never invoke writes; all mutations require CSRF + confirmation."""
import base64, copy, hashlib, json, os, secrets, socket, sys, threading, time, urllib.request
from pathlib import Path
from urllib.parse import urlsplit
from flask import Flask, jsonify, request, session, send_from_directory
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT.parent))
sys.path.append('/home/ben/.local/share/uv/tools/deco-local/lib/python3.11/site-packages')
from deco_client import DecoClient
from deco_local import tmp, web
CREDS=json.loads((ROOT/'credentials.json').read_text())
app=Flask(__name__,static_folder='static')
keyfile=ROOT/'session.key'
if not keyfile.exists():
 fd=os.open(keyfile,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'w') as f:f.write(secrets.token_hex(32))
app.secret_key=keyfile.read_text()
app.config.update(MAX_CONTENT_LENGTH=64*1024*1024,SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Strict',SESSION_COOKIE_SECURE=True)
LOCK=threading.RLock(); CACHE={}; STAGED={}; client=None
HOST=CREDS['host']
ALLOWED={'127.0.0.1:8790','localhost:8790','atrium-agents.zonkey-interval.ts.net:10443'}

def scrub(o):
 if isinstance(o,dict):return {k:('[hidden]' if any(s in k.lower() for s in ('password','secret','token','psk','group_key')) else scrub(v)) for k,v in o.items()}
 if isinstance(o,list):return [scrub(v) for v in o]
 return o

def decode(v):
 try:return base64.b64decode(v,validate=True).decode('utf-8')
 except Exception:return v

def encode(v):return base64.b64encode(v.encode()).decode()
def revision(o):
 # Clock ticks are observations, not editable configuration revisions.
 stable={k:v for k,v in o.items() if k not in ('time','date','dst_status')} if isinstance(o,dict) else o
 return hashlib.sha256(json.dumps(stable,sort_keys=True).encode()).hexdigest()
def login():
 global client
 client=DecoClient(HOST,scheme='https',timeout=30)
 status,raw,_,_=client.login('admin',CREDS['password'])
 data=client._open(raw)
 if status!=200 or not data.get('result',{}).get('stok'):raise RuntimeError('Deco authentication failed')
 client.stok=data['result']['stok']
 return client

def call(path,form,operation='read',params=None,extra=None):
 global client
 c=client or login(); payload={'operation':operation}
 if params is not None:payload['params']=params
 if extra:payload.update(extra)
 status,data,_=c.call('admin/'+path,form,payload)
 if operation=='read' and (status==403 or data.get('error_code') in (-40401,-40402,-40403)):
  c=login();status,data,_=c.call('admin/'+path,form,payload)
 if status!=200 or data.get('error_code')!=0:raise RuntimeError(f'{path}/{form}: HTTP {status}, device code {data.get("error_code","unreadable response")}')
 return data.get('result',{})

def cached(key,fn,ttl=90):
 with LOCK:
  prev=CACHE.get(key)
  if prev and time.time()-prev['at']<ttl:return prev
  try:
   value={'at':time.time(),'data':fn(),'stale':False}; CACHE[key]=value;return value
  except Exception as e:
   if prev:return {**prev,'stale':True,'warning':str(e)}
   raise

def overview():
 # TMP is optional; avoid login retries when the control port is closed.
 source='TMP :20001';warning=None
 try:
  with socket.create_connection((HOST,20001),timeout=2):pass
  with tmp.DecoClient(HOST,CREDS['email'],CREDS['password'],timeout=10) as c:reads=c.snapshot(['device_list','client_list'],gap=1)
  if not all(v['ok'] for v in reads.values()):raise RuntimeError('TMP returned incomplete data')
 except Exception:
  source='Local web API · deco-local fallback';warning='TMP port 20001 is unavailable. Mesh and clients are read through the local web API.'
  reads=web.snapshot(HOST,CREDS['password'],['device_list','client_list'],gap=1,probes=1)
  global client
  client=None # library authentication may replace the encrypted session
 for k,v in reads.items():
  if not v['ok']:raise RuntimeError(k+': read failed')
 nodes=reads['device_list']['result']['device_list'];clients=reads['client_list']['result']['client_list']
 for c in clients:
  c['display_name']=decode(c.get('name') or c.get('custom_name') or '') or c.get('hostname') or c.get('mac','Unknown')
 for n in nodes:
  n['display_name']=n.get('nickname') or decode(n.get('custom_nickname','')) or n.get('device_model','Deco')
  n['client_count']=sum(1 for c in clients if c.get('linked_device_info',{}).get('device_id')==n.get('device_id')) if n.get('device_id') else None
 return {'nodes':sorted(nodes,key=lambda n:n.get('role')!='master'),'clients':clients,'source':source,'warning':warning}

def wifi():
 raw=call('wireless','wlan');networks=[]
 for band in ['band2_4','band5_1','band5_2','band6','iot']:
  for kind in ['host','guest']:
   n=raw.get(band,{}).get(kind)
   if not isinstance(n,dict):continue
   networks.append({'band':band,'kind':kind,'ssid':decode(n.get('ssid','')),'enabled':n.get('enable',False),'channel':n.get('channel'),'hidden':n.get('enable_hide_ssid',False),'enable_2g':n.get('enable_2g'),'enable_5g':n.get('enable_5g'),'encryption':n.get('encryption_mode','Device managed'),'password_set':bool(n.get('password'))})
 return {'networks':networks,'revision':revision(raw),'raw':scrub(raw)}
def settings(path,form):
 raw=call(path,form);return {'values':scrub(raw),'revision':revision(raw)}

@app.before_request
def security():
 if request.host not in ALLOWED:return jsonify(error='Untrusted host'),403
 if request.method=='POST':
  origin=request.headers.get('Origin')
  if not origin or urlsplit(origin).netloc!=request.host:return jsonify(error='Same-origin request required'),403
  if not session.get('csrf') or not secrets.compare_digest(request.headers.get('X-CSRF-Token',''),session['csrf']):return jsonify(error='Invalid CSRF token; reload the page'),403

@app.after_request
def headers(r):
 r.headers['Cache-Control']='no-store'
 r.headers['X-Content-Type-Options']='nosniff';r.headers['X-Frame-Options']='DENY'
 r.headers['Referrer-Policy']='no-referrer'
 r.headers['Content-Security-Policy']="default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
 return r
@app.errorhandler(Exception)
def error(e):
 from werkzeug.exceptions import HTTPException
 return jsonify(error=str(e) if isinstance(e,(ValueError,RuntimeError,HTTPException)) else 'Device request failed; no automatic retry was attempted'),(400 if isinstance(e,ValueError) else getattr(e,'code',None) or 502)
@app.get('/')
def index():return send_from_directory(ROOT/'static','index.html')
@app.get('/api/session')
def init():
 session.setdefault('csrf',secrets.token_urlsafe(32));return jsonify(csrf=session['csrf'],host=HOST)
@app.get('/health')
def health():return jsonify(ok=True,service='deco-console')
@app.get('/api/overview')
def get_overview():return jsonify(cached('overview',overview))
@app.get('/api/wifi')
def get_wifi():return jsonify(cached('wifi',wifi))
@app.get('/api/cwmp')
def get_cwmp():return jsonify(cached('cwmp',lambda:settings('cwmp','cwmp_info')))
@app.get('/api/system')
def get_system():
 def load():
  out={}
  for name,path,form in [('time','device','timesetting'),('igmp','network','igmp_setting'),('performance','network','performance'),('flow','network','flow_control'),('wifi_network','network','wifi_network')]:
   try:out[name]={'ok':True,**settings(path,form)}
   except Exception as e:out[name]={'ok':False,'error':str(e)}
   time.sleep(.5)
  return out
 return jsonify(cached('system',load))
@app.get('/api/logs')
def get_logs():
 page=max(0,min(int(request.args.get('page',0)),1000))
 return jsonify(cached('logs'+str(page),lambda:call('log_export','feedback_log',extra={'index':page,'limit':100})))
@app.get('/api/reads')
def list_reads():return jsonify(reads=sorted(tmp.READ),note='Reads run on demand. TMP must be available.')
@app.get('/api/read/<name>')
def read(name):
 if name not in tmp.READ:raise ValueError('Unknown read')
 def load():
  with socket.create_connection((HOST,20001),timeout=2):pass
  with tmp.DecoClient(HOST,CREDS['email'],CREDS['password'],timeout=10) as c:return scrub(c.get(name))
 return jsonify(cached('tmp/'+name,load))

def audit(action,status):
 with open(ROOT/'audit.jsonl','a') as f:f.write(json.dumps({'at':time.time(),'action':action,'status':status,'actor':request.headers.get('Tailscale-User-Login','local')})+'\n')
 os.chmod(ROOT/'audit.jsonl',0o600)
def check_confirm(body):
 if body.get('confirm')!='APPLY':raise ValueError('Explicit APPLY confirmation is required')
def check_revision(body,raw):
 if body.get('revision')!=revision(raw):raise ValueError('Settings changed since loading. Refresh before applying.')
def verify(path,form,expected):
 global client
 client=None
 actual=call(path,form)
 def includes(a,b):return all(k in a and (includes(a[k],v) if isinstance(v,dict) else a[k]==v) for k,v in b.items())
 return includes(actual,expected)

@app.post('/api/action/<action>')
def action(action):
 body=request.get_json();check_confirm(body)
 with LOCK:
  try:
   result=perform(action,body);audit(action,result.get('status','completed'));CACHE.clear();return jsonify(result)
  except Exception:
   audit(action,'failed or outcome unknown');CACHE.clear();raise

def perform(action,b):
 if action=='cwmp':
  raw=call('cwmp','cwmp_info');check_revision(b,raw)
  url=b.get('ACS_URL','');parts=urlsplit(url)
  if parts.scheme not in ('http','https') or not parts.hostname or parts.username or parts.password:raise ValueError('ACS URL must be an HTTP(S) URL without embedded credentials')
  patch={'ACS_URL':url}
  for key in ('cwmp_enable','inform_enable'):
   if type(b.get(key)) is not bool:raise ValueError('Enable fields must be booleans')
   patch[key]=b[key]
  raw.update(patch);call('cwmp','cwmp_info','write',raw)
  ok=verify('cwmp','cwmp_info',patch)
  return {'status':'verified' if ok else 'unverified','message':'CWMP saved and read-back verified.' if ok else 'Device acknowledged the write, but read-back differs. Inspect settings.'}
 if action=='wifi':
  raw=call('wireless','wlan');check_revision(b,raw);band=b.get('band');kind=b.get('kind')
  if band not in raw or kind not in ('host','guest') or kind not in raw[band]:raise ValueError('Unknown network')
  if band=='iot':raise ValueError('IoT writes are not enabled: this firmware exposes an IoT read but no verified web write handler.')
  target=raw[band][kind];ssid=b.get('ssid','')
  if not 1<=len(ssid.encode())<=32:raise ValueError('SSID must be 1–32 UTF-8 bytes')
  if type(b.get('enabled')) is not bool:raise ValueError('Enabled must be boolean')
  changes={'ssid':encode(ssid),'enable':b['enabled']}
  pwd=b.get('password','')
  if pwd:
   if not (8<=len(pwd.encode())<=63 and all(32<=ord(c)<=126 for c in pwd)):raise ValueError('Wi-Fi password must be 8–63 printable ASCII characters')
   changes['password']=encode(pwd)
  if 'channel' in b and int(b['channel'])!=target.get('channel'):
   channel=int(b['channel']);allowed=range(1,14) if band=='band2_4' else [36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,144,149,153,157,161,165]
   if channel!=0 and channel not in allowed:raise ValueError('Unsupported channel')
   changes['channel']=channel
   # The stock write wrapper inspects band.radio.channel, while its read
   # representation exposes the active channel in band.host.channel.
   raw[band].setdefault('radio',{})['channel']=channel
  target.update(changes)
  if not any(raw.get(x,{}).get('host',{}).get('enable') for x in ('band2_4','band5_1')):raise ValueError('At least one main Wi-Fi band must remain enabled')
  # Pass the full current object: firmware write handlers may blank omitted keys.
  call('wireless','wlan','write',raw)
  ok=verify('wireless','wlan',{band:{kind:changes}})
  return {'status':'verified' if ok else 'unverified','message':'Wi-Fi saved and read-back verified.' if ok else 'Write acknowledged, but values did not fully match read-back. Refresh and inspect; the router may synchronize bands.'}
 if action=='time':
  raw=call('device','timesetting');check_revision(b,raw)
  patch={k:str(b.get(k,'')) for k in ('timezone','continent','tz_region')}
  if not all(patch.values()) or not patch['timezone'].lstrip('-').isdigit():raise ValueError('Timezone offset, continent and region are required')
  raw.update(patch);call('device','timesetting','write',raw);ok=verify('device','timesetting',patch)
  return {'status':'verified' if ok else 'unverified','message':'Time settings read-back '+('verified.' if ok else 'did not match.')}
 if action=='igmp':
  raw=call('network','igmp_setting');check_revision(b,raw)
  if type(b.get('enable_join_igmpv3')) is not bool:raise ValueError('IGMP setting must be boolean')
  raw['enable_join_igmpv3']=b['enable_join_igmpv3'];call('network','igmp_setting','write',raw)
  ok=verify('network','igmp_setting',raw);return {'status':'verified' if ok else 'unverified','message':'System parameter '+('verified.' if ok else 'acknowledged, read-back differs.')}
 if action=='reboot':
  nodes=call('device','device_list')['device_list'];known={n['mac'] for n in nodes};selected=b.get('macs',[])
  if not isinstance(selected,list) or not selected or any(x not in known for x in selected):raise ValueError('Choose known Deco units')
  call('device','system','reboot',{'mac_list':[{'mac':x} for x in selected]})
  return {'status':'accepted','message':'Reboot accepted. Completion is not yet verified. Wait about two minutes, then refresh the mesh.'}
 if action=='logs-prepare':
  call('log_export','feedback_log','build',{'level':6})
  return {'status':'accepted','message':'Log snapshot requested. Use Read logs to retrieve it; no settings were changed.'}
 if action=='firmware-check':
  value=call('cloud','firmware_status','check')
  return {'status':'checked','message':'Online firmware check completed. No update was installed.','data':scrub(value)}
 if action=='firmware-install':return install(b)
 raise ValueError('Unsupported action')

@app.post('/api/firmware/stage')
def stage():
 file=request.files.get('file')
 if not file or not file.filename.lower().endswith('.bin'):raise ValueError('Choose a .bin firmware image')
 data=file.read()
 if len(data)<1024:raise ValueError('Firmware image is too small')
 token=secrets.token_urlsafe(24);directory=ROOT/'uploads';directory.mkdir(mode=0o700,exist_ok=True)
 with LOCK:
  for old in directory.glob('*.bin'):
   if time.time()-old.stat().st_mtime>86400:old.unlink()
  if sum(p.stat().st_size for p in directory.glob('*.bin'))+len(data)>128*1024*1024:raise ValueError('Staging storage is full. Remove old uploads on the server.')
  path=directory/(token+'.bin');fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
  with os.fdopen(fd,'wb') as f:f.write(data)
  info={'token':token,'filename':Path(file.filename).name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'at':time.time(),'owner':session['csrf']};STAGED[token]=info
 return jsonify({k:v for k,v in info.items() if k!='owner'},message='Staged on dashboard only. No bytes sent to Deco. Device compatibility and signature are not verified.')

def install(b):
 token=b.get('token');info=STAGED.get(token)
 if not info or info['owner']!=session['csrf'] or time.time()-info['at']>1800:raise ValueError('Staged image expired; upload again')
 nodes=call('device','device_list')['device_list'];node=next((n for n in nodes if n['mac']==b.get('mac')),None)
 if not node:raise ValueError('Choose a known model')
 if node.get('oversized_firmware'):raise ValueError('This model requires direct per-unit upload; not supported here')
 # Stock firmware upload is intentionally exempt from the AES envelope. It is
 # session-authenticated multipart over HTTPS, then encrypted local_upgrade.
 c=client or login();boundary='----DecoConsole'+secrets.token_hex(16);parts=[]
 fields={'operation':'upload','hw_id':node['hw_id'],'oem_id':node['oem_id'],'device_model':node['device_model']}
 for k,v in fields.items():parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
 path=ROOT/'uploads'/(token+'.bin')
 parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="image"; filename="firmware.bin"\r\nContent-Type: application/octet-stream\r\n\r\n'.encode()+path.read_bytes()+b'\r\n')
 parts.append(f'--{boundary}--\r\n'.encode())
 headers={'Content-Type':'multipart/form-data; boundary='+boundary}
 if c.cookie:headers['Cookie']=c.cookie
 req=urllib.request.Request(f'https://{HOST}/cgi-bin/luci/;stok={c.stok}/admin/cloud?form=firmware',data=b''.join(parts),headers=headers,method='POST')
 with urllib.request.urlopen(req,timeout=180,context=c.ctx) as response:reply=c._open(response.read().decode())
 if reply.get('error_code')!=0:raise RuntimeError('Device rejected firmware upload; upgrade not started')
 result=call('cloud','firmware_status','local_upgrade');path.unlink();STAGED.pop(token,None)
 return {'status':'accepted','message':'Firmware upgrade accepted for matching hardware in the mesh. Completion is NOT verified. Do not power off; wait and refresh versions.','data':scrub(result)}
