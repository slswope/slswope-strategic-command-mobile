#!/usr/bin/env python3
"""Official-source monitor. No third-party Python packages; public data only.
Not a substitute for emergency alerts. Run from repository root.
"""
import datetime
import json
import math
import os
import pathlib
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from email.utils import parsedate_to_datetime
ROOT=pathlib.Path(__file__).resolve().parents[1]
NOW=datetime.datetime.now(datetime.timezone.utc)
STAMP=NOW.isoformat(timespec='seconds')
HEADERS={'User-Agent':'StrategicWarningDashboard/1.0 (GitHub Action; admin: repo owner)', 'Accept':'application/geo+json, application/json'}
POINTS={'Evansville, IN':(37.9716,-87.5711),'Newburgh, IN':(37.9445,-87.4053),'Henderson, KY':(37.8362,-87.5900)}
NWS_DOCS='https://www.weather.gov/documentation/services-web-alerts'
KEV_URL='https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
FAA_URL = 'https://nasstatus.faa.gov/api/airport-status-information'
RIVER_URL = 'https://api.water.noaa.gov/nwps/v1/gauges/NBGI3'
FEMA_URL = 'https://www.fema.gov/api/open/v2/DisasterDeclarationsSummaries'
TRACKS=[
 ('Immediate hazards','connected','NWS point alerts and the NOAA Newburgh river forecast'),
 ('Service continuity','partial','FAA ground stops. Telecom, payments and hospitals have no automated coverage.'),
 ('Supply chain / markets','unconnected','EIA/transport/retail checks pending'),
 ('Global security','partial','See the dated, manually reviewed foreign developments briefing'),
 ('Political / governance','partial','FEMA disaster declarations for Indiana and Kentucky. Local restrictions have no automated coverage.'),
 ('Public preparedness intent','unconnected','Search/retail indicators require backtesting'),
 ('Overall','not_assessed','No national collapse prediction or all-clear derived'),
 ('Cyber & digital infrastructure','partial','CISA KEV exposure intelligence, not cyber incidents'),
 ('Local essential services','unconnected','Utility/water/operator APIs pending'),
 ('Cross-track correlation','partial','Duplicate NWS alert IDs merged; cross-provider correlation pending'),
]

def get_document(url, accept):
    headers = {**HEADERS, 'Accept': accept}
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=18) as response:
        return response.read()


def get_json(url):
    return json.loads(get_document(url, HEADERS['Accept']))


def read_station_time(value):
    stamp = datetime.datetime.fromisoformat(value)
    if stamp.tzinfo is None:
        raise ValueError('Expected timestamp with time zone')
    return stamp


def parse_ground_stops(document, now):
    root = ET.fromstring(document)
    if root.tag != 'AIRPORT_STATUS_INFORMATION':
        raise ValueError('Unexpected FAA feed format')
    updated = parsedate_to_datetime(root.findtext('Update_Time', ''))
    if updated.tzinfo is None or not now - datetime.timedelta(hours=1) <= updated <= now + datetime.timedelta(minutes=5):
        raise ValueError('FAA report timestamp is outside the freshness window')
    stops = []
    for delay in root.findall('Delay_type'):
        ground_stop_list = delay.find('Ground_Stop_List')
        if ground_stop_list is None:
            if delay.findtext('Name', '').strip().lower().startswith('ground stop'):
                raise ValueError('FAA ground-stop list missing')
            continue
        for entry in ground_stop_list:
            airport = entry.findtext('ARPT', '').strip()
            if not airport:
                raise ValueError('FAA ground-stop airport missing')
            stops.append({
                'airport': airport,
                'reason': entry.findtext('Reason', '').strip(),
                'end_time': entry.findtext('End_Time', '').strip(),
            })
    return {'updated_at': updated.isoformat(), 'stops': stops}


def checked_stage(stage):
    if type(stage) not in (int, float) or not math.isfinite(stage) or stage <= -999:
        raise ValueError('Invalid river stage')
    return stage


def stage_reading(row):
    return {'stage': checked_stage(row['primary']),
            'valid_at': read_station_time(row['validTime']).isoformat()}


def parse_river_stage(gauge, stageflow, now):
    reading = gauge['status'].get('observed') or {}
    flood = gauge['flood']
    forecast = stageflow.get('forecast') or {}
    if (gauge['lid'] != 'NBGI3' or (reading and reading['primaryUnit'] != 'ft')
            or flood['stageUnits'] != 'ft' or (forecast and forecast['primaryUnits'] != 'ft')):
        raise ValueError('Unexpected NOAA gauge or stage units')
    observation = stage_reading(reading) if reading else None
    thresholds = {name: checked_stage(flood['categories'][name]['stage'])
                  for name in ('action', 'minor', 'moderate', 'major')}
    if not thresholds['action'] < thresholds['minor'] < thresholds['moderate'] < thresholds['major']:
        raise ValueError('Unexpected NOAA flood thresholds')
    if observation:
        observed_at = read_station_time(observation['valid_at'])
        if not now - datetime.timedelta(hours=6) <= observed_at <= now + datetime.timedelta(minutes=5):
            observation = None
    issued_at = read_station_time(forecast['issuedTime']) if forecast else None
    upcoming = []
    if issued_at and now - datetime.timedelta(hours=36) <= issued_at <= now + datetime.timedelta(minutes=5):
        for row in forecast['data']:
            if read_station_time(row['validTime']) >= now:
                stage = row['primary']
                if type(stage) in (int, float) and math.isfinite(stage) and stage > -999:
                    upcoming.append(stage_reading(row))
    upcoming.sort(key=lambda row: row['valid_at'])
    peak = max(upcoming, key=lambda row: row['stage'], default=None)
    category = None
    if peak:
        category = next((name for name in reversed(thresholds)
                         if peak['stage'] >= thresholds[name]), 'below_action')
    return {
        'observation': observation, 'forecast_peak': peak,
        'forecast_issued_at': issued_at.isoformat() if issued_at else None, 'forecast_category': category,
        'thresholds': thresholds,
    }


def fema_query(now):
    since = (now.date() - datetime.timedelta(days=180)).isoformat()
    return FEMA_URL + '?' + urllib.parse.urlencode({
        '$filter': f"(state eq 'IN' or state eq 'KY') and declarationDate ge '{since}T00:00:00.000Z'",
        '$orderby': 'declarationDate desc,disasterNumber desc',
        '$top': 1000,
    })


def parse_declarations(payload):
    rows = payload['DisasterDeclarationsSummaries']
    if not isinstance(rows, list) or len(rows) >= 1000:
        raise ValueError('Invalid or incomplete OpenFEMA response')
    declarations = {}
    for row in rows:
        state, number = row['state'], row['disasterNumber']
        area = row['designatedArea']
        if state not in ('IN', 'KY') or type(number) is not int or not area:
            raise ValueError('Invalid OpenFEMA declaration')
        key = (state, number)
        if key not in declarations:
            declarations[key] = {
                'state': state, 'number': number, 'title': row['declarationTitle'],
                'date': read_station_time(row['declarationDate']).date().isoformat(),
                'type': row['declarationType'], 'areas': set(), 'local_areas': set(),
            }
        declaration = declarations[key]
        declaration['areas'].add(area)
        if (state, area.split(' (')[0]) in {('IN', 'Vanderburgh'), ('IN', 'Warrick'), ('KY', 'Henderson')}:
            declaration['local_areas'].add(area)
    ordered = sorted(declarations.values(), key=lambda row: (row['date'], row['number']), reverse=True)
    return [{'state': row['state'], 'number': row['number'], 'title': row['title'], 'date': row['date'],
             'type': row['type'], 'area_count': len(row['areas']), 'local_areas': sorted(row['local_areas'])}
            for row in ordered]


def collect_supplemental_feeds(feeds, errors):
    signals = {}
    query = fema_query(NOW)
    sources = (
        ('faa', 'FAA airport status', FAA_URL,
         lambda: parse_ground_stops(get_document(FAA_URL, 'application/xml'), NOW)),
        ('river', 'NOAA Newburgh river gauge and forecast', RIVER_URL + '/stageflow',
         lambda: parse_river_stage(get_json(RIVER_URL), get_json(RIVER_URL + '/stageflow'), NOW)),
        ('fema', 'OpenFEMA declarations for Indiana and Kentucky', query,
         lambda: parse_declarations(get_json(query))),
    )
    for key, name, url, collect in sources:
        feed = {'name': name, 'status': 'ok', 'checked_at': STAMP, 'url': url}
        try:
            signal = collect()
            if key == 'faa':
                feed.update(count=len(signal['stops']), updated_at=signal['updated_at'])
            if key == 'river':
                feed['count'] = sum(signal[field] is not None for field in ('observation', 'forecast_peak'))
                if feed['count'] != 2:
                    feed.update(status='partial' if feed['count'] else 'error',
                                note='River observation or forecast missing or stale')
                    errors.append(name + ': ' + feed['note'])
            if key == 'fema':
                feed['count'] = len(signal)
                signal = {'count': len(signal), 'declarations': signal[:12]}
            signals[key] = signal
        except (ValueError, TypeError, KeyError, AttributeError, ET.ParseError, OSError) as exc:
            errors.append(f'{name}: {type(exc).__name__}')
            feed.update(status='error', note='Feed unavailable or stale')
            signals[key] = None
        feeds.append(feed)
    return signals


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
    supplemental = collect_supplemental_feeds(feeds, errors)
    ok=sum(f['status']=='ok' for f in feeds)
    all_ok=ok==len(feeds)
    output={
      'schema_version':1,'checked_at':STAMP,'status':'NOT ASSESSED',
      'message':'Not a nationwide-threat assessment or official warning service. Tracks without live sources remain unassessed.',
      'coverage':{'feeds_ok':ok,'feeds_total':len(feeds),'dashboard_indicators':56,'historical_indicators_connected':0,
        'note':'These source checks are not equivalent to validation of the 56 original indicators.'},
      'supplemental': supplemental,
      'sources':feeds,'alerts':alerts,'high_priority_alerts':sum(is_actionable(a) for a in alerts),
      'cyber':{'kev_entries':kev_count,'latest_sample':kev_recent,'interpretation':'A KEV listing indicates known exploited vulnerability; it is not confirmation of an attack or outage.'},
      'tracks':[{'name':n,'connection':c,'detail':d} for n,c,d in TRACKS],
      'health':{'all_sources_ok':all_ok,'errors':errors,'pushover_enabled':push_enabled,'push_sent_this_run':push_sent},
      'source_references':[NWS_DOCS,KEV_URL,'https://www.cisa.gov/known-exploited-vulnerabilities-catalog']}
    (ROOT/'site'/'data.json').write_text(json.dumps(output,indent=2,ensure_ascii=False)+'\n')
    print(f'{STAMP}: {ok}/{len(feeds)} checks passed, {len(alerts)} unique active alerts, {push_sent} notifications; no nationwide posture inferred')
    if not all_ok:print('NOTICE: One or more data sources failed. Dashboard must show incomplete status.')

if __name__=='__main__':main()
