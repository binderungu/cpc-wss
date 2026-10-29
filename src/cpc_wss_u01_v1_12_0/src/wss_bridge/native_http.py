"""Explicit ordinary Moodle loopback forms for supplied synthetic actor/targets.

No construction/import connects or reads a password. Raw HTML is private; public
receipts exclude request body, cookies and credentials. No retry is provided.
"""
from html.parser import HTMLParser
from pathlib import Path
import urllib.request,urllib.parse,urllib.error,http.cookiejar,hashlib,time,datetime,gzip,json,os
ORIGIN='http://127.0.0.1:8088'
class ProtocolStop(RuntimeError):pass
class Forms(HTMLParser):
 def __init__(self):super().__init__(convert_charrefs=True);self.forms=[];self.current=None;self.links=[];self.text=[]
 def handle_starttag(self,tag,attrs):
  a=dict(attrs)
  if tag=='form':
   if self.current is not None:raise ProtocolStop('NESTED_FORM')
   self.current={'attrs':a,'inputs':[]}
  elif tag in ('input','textarea','select','button') and self.current is not None:
   if tag!='input':a['type']=tag
   self.current['inputs'].append(a)
  elif tag=='a' and a.get('href'):self.links.append(a['href'])
 def handle_endtag(self,tag):
  if tag=='form' and self.current is not None:self.forms.append(self.current);self.current=None
 def handle_data(self,data):self.text.append(data)
def parsed(raw):
 p=Forms();p.feed(raw.decode('utf-8','strict'));return p

def same_origin(url):
 p=urllib.parse.urlsplit(url)
 if p.scheme!='http' or p.netloc!='127.0.0.1:8088' or p.username or p.password:raise ProtocolStop('HTTP_TARGET_NOT_LOOPBACK_ORIGIN')
 return url
class OriginRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,req,fp,code,msg,headers,newurl):
  same_origin(urllib.parse.urljoin(req.full_url,newurl))
  return super().redirect_request(req,fp,code,msg,headers,newurl)
def singleton_fields(form):
 names=[i['name'] for i in form['inputs'] if i.get('name')]
 if len(names)!=len(set(names)):raise ProtocolStop('DUPLICATE_FORM_FIELD')
 return form
def choose_login(raw):
 p=parsed(raw);fs=[f for f in p.forms if {'username','password','logintoken'}<={i.get('name') for i in f['inputs']}]
 if len(fs)!=1:raise ProtocolStop('LOGIN_FORM_NOT_SINGLETON')
 return singleton_fields(fs[0])
def choose_target(raw, cmid, itemid, expected_text):
 p=parsed(raw);field='textfield_'+str(itemid)
 fs=[f for f in p.forms if any(i.get('name')==field for i in f['inputs'])]
 if len(fs)!=1:raise ProtocolStop('TARGET_FORM_NOT_SINGLETON')
 f=singleton_fields(fs[0]);fields={i['name']:i.get('value','') for i in f['inputs'] if i.get('name') and i.get('type','text').lower()=='hidden'}
 if fields.get('id')!=str(cmid) or fields.get('courseid')!='2' or not fields.get('sesskey'):raise ProtocolStop('TARGET_HIDDEN_CONTEXT_OR_CSRF')
 required={'id','courseid','gopage','lastpage','startitempos','lastitempos','sesskey','_qf__mod_feedback_complete_form'}
 if set(fields)!=required or fields['gopage']!='0' or fields['_qf__mod_feedback_complete_form']!='1' or any(fields[k] not in ('','0','1') for k in ['lastpage','startitempos','lastitempos']):raise ProtocolStop('CLOSED_HIDDEN_FIELDS')
 text=[i for i in f['inputs'] if i.get('type','text').lower() in ['text','textarea'] and i.get('name')]
 if [i['name'] for i in text]!=[field] or any(i.get('type','text')!='text' for i in text):raise ProtocolStop('UNEXPECTED_QUESTION_FIELDS')
 if f['attrs'].get('method','').lower()!='post' or len([i for i in f['inputs'] if i.get('name')=='savevalues' and i.get('type')=='submit' and i.get('value')=='Submit your answers'])!=1:raise ProtocolStop('TARGET_FINALIZE_CONTROL')
 if any(i.get('name') and i['name'] not in required|{field,'savevalues','cancel'} for i in f['inputs']):raise ProtocolStop('UNKNOWN_NAMED_CONTROL')
 if ' '.join(expected_text.split()) not in ' '.join(' '.join(p.text).split()):raise ProtocolStop('TARGET_ITEM_TEXT_DRIFT')
 action=same_origin(urllib.parse.urljoin(ORIGIN+'/mod/feedback/complete.php',f['attrs'].get('action','')))
 if urllib.parse.urlsplit(action).path!='/mod/feedback/complete.php' or urllib.parse.parse_qs(urllib.parse.urlsplit(action).query) not in ({},{'id':[str(cmid)]}):raise ProtocolStop('TARGET_ACTION')
 return action,fields

def known_completion(raw,url,status,cmid,itemid):
 p=parsed(raw);text=' '.join(' '.join(p.text).split());q=urllib.parse.urlsplit(url)
 return (status==200 and urllib.parse.urlunsplit((q.scheme,q.netloc,'','',''))==ORIGIN and urllib.parse.parse_qs(q.query) in ({},{'id':[str(cmid)]}) and q.path=='/mod/feedback/complete.php' and 'Your answers have been saved. Thank you.' in text
         and not any(i.get('name','').startswith('textfield_') for f in p.forms for i in f['inputs']))
class MoodleFormClient:
 def __init__(self,private_root,*,username,userid,display_name,targets):
  self.private=Path(private_root);self.private.mkdir(mode=0o700,parents=True,exist_ok=True);self.n=0;self.authenticated=False
  if username!='cpc_wss_worked_v1' or userid!=4 or set(targets)!={'TASK','FOLLOWUP'}:raise ProtocolStop('WORKED_ACCOUNT_SCOPE')
  for kind,t in targets.items():
   if set(t)!={'cmid','itemid','item_text'} or (t['cmid'],t['itemid'])!=({'TASK':(4,3),'FOLLOWUP':(5,4)}[kind]) or not t['item_text']:raise ProtocolStop('WORKED_TARGET_SCOPE')
  self.username=username;self.userid=userid;self.display_name=display_name;self.targets=targets
  self.cookies=http.cookiejar.CookieJar();self.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(self.cookies),OriginRedirect())
 def request(self,url,fields=None,label='get'):
  same_origin(url);self.n+=1
  data=None if fields is None else urllib.parse.urlencode(fields).encode()
  req=urllib.request.Request(url,data=data,headers={'User-Agent':'CPC-bounded-worked-demonstration','Cache-Control':'no-cache'})
  start=time.monotonic_ns()
  error=None
  try:
   with self.opener.open(req,timeout=15) as response:
    raw=response.read(2*1024*1024+1);status=response.status;actual=response.url;same_origin(actual)
  except urllib.error.HTTPError as e:
   raw=e.read(2*1024*1024+1);status=e.code;actual=url;error='HTTP_ERROR'
  except Exception as e:
   raw=b'';status=0;actual=url;error=type(e).__name__
  end=time.monotonic_ns();utc=datetime.datetime.now(datetime.timezone.utc).isoformat()
  dest=self.private/(str(self.n).zfill(3)+'_'+label+'.html.gz')
  with dest.open('xb') as f:
   dest.chmod(0o600)
   with gzip.GzipFile(fileobj=f,mode='wb',mtime=0) as gz:gz.write(raw)
   f.flush();os.fsync(f.fileno())
  fd=os.open(self.private,os.O_RDONLY)
  try:os.fsync(fd)
  finally:os.close(fd)
  if error or len(raw)>2*1024*1024:
   failure={'error':error or 'HTTP_RESPONSE_LIMIT','private_retained_bytes':len(raw),'private_response':str(dest),'completion_known':False,'partial_or_empty_possible':True}
   fp=dest.with_suffix('.failure.json');fp.write_text(json.dumps(failure));fp.chmod(0o600)
   raise ProtocolStop('HTTP_FAILURE_RETAINED_NO_RETRY')
  rec={'method':'GET' if fields is None else 'POST','url':actual,'status':status,'response_sha256':hashlib.sha256(raw).hexdigest(),'private_response':str(dest),'request_start_monotonic_ns':start,'return_monotonic_ns':end,'return_UTC':utc,'response_bytes':len(raw),'password_cookie_token_exported':False}
  return raw,rec
 def login(self,password_path):
  raw,_=self.request(ORIGIN+'/login/index.php',label='login_form');f=choose_login(raw)
  fields={i['name']:i.get('value','') for i in f['inputs'] if i.get('name') and i.get('type','text')=='hidden'}
  fields.update(username=self.username,password=Path(password_path).read_text().strip())
  action=same_origin(urllib.parse.urljoin(ORIGIN+'/login/index.php',f['attrs'].get('action','')))
  if urllib.parse.urlsplit(action).path!='/login/index.php':raise ProtocolStop('LOGIN_ACTION')
  raw,rec=self.request(action,fields,label='login_result');p=parsed(raw)
  identity=any(urllib.parse.urlsplit(h).path=='/user/profile.php' and urllib.parse.parse_qs(urllib.parse.urlsplit(h).query).get('id')==[str(self.userid)] for h in p.links)
  logout=any(urllib.parse.urlsplit(h).path=='/login/logout.php' for h in p.links)
  if not identity or not logout or self.display_name not in raw.decode():raise ProtocolStop('ORDINARY_LOGIN_IDENTITY_NOT_VERIFIED')
  self.authenticated=True;return {**rec,'ordinary_username':self.username,'expected_userid':self.userid,'self_profile_link_and_logout_present':True,'admin_impersonation_used':False}
 def get_target(self,kind):
  if not self.authenticated or kind not in self.targets:raise ProtocolStop('NOT_AUTHENTICATED_OR_TARGET')
  t=self.targets[kind]
  raw,rec=self.request(ORIGIN+'/mod/feedback/complete.php?id='+str(t['cmid']),label=kind.lower()+'_form')
  action,fields=choose_target(raw,t['cmid'],t['itemid'],t['item_text'])
  return {'action':action,'fields':fields,'receipt':rec,'kind':kind}
 def submit(self,prepared,payload):
  if not self.authenticated or type(payload) is not bytes:raise ProtocolStop('SUBMISSION_SCOPE')
  try:text=payload.decode('utf8','strict')
  except UnicodeError:raise ProtocolStop('PAYLOAD_UTF8')
  if not 1<=len(text)<=255 or chr(0) in text:raise ProtocolStop('PAYLOAD_TEXTFIELD_LIMIT')
  kind=prepared['kind'];t=self.targets[kind]
  # Exact form context is rechecked before finalization; no alternate route/retry.
  if prepared['fields']['id']!=str(t['cmid']):raise ProtocolStop('PREPARED_TARGET_CONFLICT')
  fields=dict(prepared['fields']);fields.update({'textfield_'+str(t['itemid']):text,'savevalues':'Submit your answers'})
  raw,rec=self.request(prepared['action'],fields,label=kind.lower()+'_finalize')
  return {**rec,'known':known_completion(raw,rec['url'],rec['status'],t['cmid'],t['itemid']),
          'kind':kind,'payload_sha256':hashlib.sha256(payload).hexdigest(),
          'completion_rule':'Pinned Moodle entries_saved notification + no question form + exact target complete endpoint; not HTTP200 alone'}
