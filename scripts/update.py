#!/usr/bin/env python3
"""Official-source monitor. No third-party Python packages; public data only.
Not a substitute for emergency alerts. Run from repository root.
"""
import json, os, pathlib, urllib.request, urllib.parse, datetime, hashlib
ROOT=pathlib.Path(__file__).resolve().parents[1]
NOW=datetime.datetime.now(datetime.timezone.utc)
STAMP=NOW.isoformat(timespec='seconds')
HEADERS={'User-Agent':'StrategicWarningDashboard/1.0 (GitHub Action; admin: repo owner)', 'Accept':'application/geo+json, application/json'}
POINTS={'Evansville, IN':(37.9716,-87.5711),'Newburgh, IN':(37.9445,-87.4053),'Henderson, KY':(37.8362,-87.5900)}
NWS_DOCS='https://www.weather.gov/documentation/services-web-alerts'
KEV_URL='https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
TRACKS=[
 ('Immediate hazards','connected','NWS point alerts for three Tri-State locations'),
 ('Service continuity','unconnected','FAA, telecom, payment and hospital service feeds pending'),
 ('Supply chain / markets','unconnected','EIA/transport/retail checks pending'),
 ('Global security','partial','See the dated, manually reviewed foreign developments briefing'),
 ('Political / governance','unconnected','Official state/local restrictions monitoring pending'),
 ('Public preparedness intent','unconnected','Search/retail indicators require backtesting'),
 ('Overall','not_assessed','No national collapse prediction or all-clear derived'),
 ('Cyber & digital infrastructure','partial','CISA KEV exposure intelligence, not cyber incidents'),
 ('Local essential services','unconnected','Utility/water/operator APIs pending'),
 ('Cross-track correlation','partial','Duplicate NWS alert IDs merged; cross-provider correlation pending'),
]

def get_json(url):
    req=urllib.request.Request(url,headers=HEADERS)
    with urllib.request.urlopen(req,timeout=18) as res:
        if res.status!=200: raise RuntimeError(f'HTTP {res.status}')
        return json.load(res)

def normalize(alert):
    p=alert.get('properties') or {}
    return {'id':alert.get('id') or p.get('id'),'title':str(p.get('headline') or p.get('event') or 'NWS alert')[:180],
        'event':p.get('event') or 'Weather alert','severity':p.get('severity') or 'Unknown',
        'certainty':p.get('certainty') or 'Unknown','onset':p.get('onset') or p.get('effective'),
        'expires':p.get('expires') or p.get('ends'),'url':p.get('@id') or alert.get('id') or NWS_DOCS,
        'source':'National Weather Service','description':str(p.get('description') or '')[:1100], 'locations':[]}

def is_actionable(a):
    e=a['event'].lower()
    return (a['severity'] in ('Extreme','Severe') or 'warning' in e or e in ('tornado emergency','flash flood emergency'))

def send_push(token,user,alert,url):
    form=urllib.parse.urlencode({'token':token,'user':user,'title':'Verified NWS warning',
        'message':f"{alert['event']}: {', '.join(alert['locations'])}. Confirm details with NWS.",
        'priority':'1' if alert['severity'] in ('Extreme','Severe') else '0','url':url}).encode()
    req=urllib.request.Request('https://api.pushover.net/1/messages.json',data=form,method='POST')
    with urllib.request.urlopen(req,timeout=15) as res:
        response=json.load(res)
        if response.get('status') != 1: raise RuntimeError('Pushover rejected message')

def main():
    (ROOT/'site').mkdir(exist_ok=True)
    (ROOT/'state').mkdir(exist_ok=True)
    statefile=ROOT/'state'/'notified.json'
    try: state=json.loads(statefile.read_text())
    except (OSError, ValueError):state={'nws_ids':[]}
    notified=set(state.get('nws_ids',[]))
    feeds=[]; alerts_by_id={}; errors=[]
    for place,(lat,lon) in POINTS.items():
        url='https://api.weather.gov/alerts/active?point='+urllib.parse.quote(f'{lat},{lon}',safe=',')
        try:
            payload=get_json(url)
            features=payload['features']
            if not isinstance(features, list):
                raise ValueError('Unexpected NWS alert feed format')
            count=0
            for raw in features:
                a=normalize(raw)
                if not a['id']:continue
                if a['id'] not in alerts_by_id:alerts_by_id[a['id']]=a
                if place not in alerts_by_id[a['id']]['locations']:alerts_by_id[a['id']]['locations'].append(place)
                count+=1
            feeds.append({'name':f'NWS {place}','status':'ok','checked_at':STAMP,'count':count,'url':url})
        except Exception as exc:
            errors.append(f'NWS {place}: {type(exc).__name__}')
            feeds.append({'name':f'NWS {place}','status':'error','checked_at':STAMP,'url':url,'note':'Fetch failed; not an all-clear'})
    kev_count=None;kev_recent=[]
    try:
        kev=get_json(KEV_URL)
        entries=kev['vulnerabilities']
        if not isinstance(entries, list):
            raise ValueError('Unexpected KEV catalog format')
        kev_count=len(entries)
        kev_recent=[{'vendor':str(v.get('vendorProject',''))[:100],'product':str(v.get('product',''))[:100],
                     'cve':v.get('cveID',''),'added':v.get('dateAdded','')} for v in entries[-8:]]
        feeds.append({'name':'CISA Known Exploited Vulnerabilities','status':'ok','checked_at':STAMP,'count':kev_count,'url':KEV_URL})
    except Exception as exc:
        errors.append(f'CISA KEV: {type(exc).__name__}')
        feeds.append({'name':'CISA Known Exploited Vulnerabilities','status':'error','checked_at':STAMP,'url':KEV_URL,'note':'Fetch failed; not an all-clear'})
    alerts=sorted(alerts_by_id.values(),key=lambda a:(not is_actionable(a),a['event']))
    token=os.environ.get('PUSHOVER_APP_TOKEN','');user=os.environ.get('PUSHOVER_USER_KEY','')
    push_enabled=bool(token and user)
    push_sent=0
    # Retry notifications on later runs if sending fails; store IDs only on successful send.
    # Without push credentials, mark no alerts as notified, allowing later activation.
    if push_enabled:
        for a in alerts:
            if is_actionable(a) and a['id'] not in notified:
                try:
                    send_push(token,user,a,a['url'])
                    notified.add(a['id']);push_sent+=1
                except Exception as exc:errors.append('Pushover notification failed: '+type(exc).__name__)
    # Retain up to 3000 known notifications; no local personal data retained.
    statefile.write_text(json.dumps({'nws_ids':sorted(notified)[-3000:]},indent=2)+'\n')
    ok=sum(f['status']=='ok' for f in feeds)
    all_ok=ok==len(feeds)
    output={
      'schema_version':1,'checked_at':STAMP,'status':'NOT ASSESSED',
      'message':'Not a nationwide-threat assessment or official warning service. Tracks without live sources remain unassessed.',
      'coverage':{'feeds_ok':ok,'feeds_total':len(feeds),'dashboard_indicators':56,'historical_indicators_connected':0,
        'note':'These 4 source checks are not equivalent to validation of the 56 original indicators.'},
      'sources':feeds,'alerts':alerts,'high_priority_alerts':sum(is_actionable(a) for a in alerts),
      'cyber':{'kev_entries':kev_count,'latest_sample':kev_recent,'interpretation':'A KEV listing indicates known exploited vulnerability; it is not confirmation of an attack or outage.'},
      'tracks':[{'name':n,'connection':c,'detail':d} for n,c,d in TRACKS],
      'health':{'all_sources_ok':all_ok,'errors':errors,'pushover_enabled':push_enabled,'push_sent_this_run':push_sent},
      'source_references':[NWS_DOCS,KEV_URL,'https://www.cisa.gov/known-exploited-vulnerabilities-catalog']}
    (ROOT/'site'/'data.json').write_text(json.dumps(output,indent=2,ensure_ascii=False)+'\n')
    print(f'{STAMP}: {ok}/{len(feeds)} checks passed, {len(alerts)} unique active alerts, {push_sent} notifications; no nationwide posture inferred')
    if not all_ok:print('NOTICE: One or more data sources failed. Dashboard must show incomplete status.')

if __name__=='__main__':main()
