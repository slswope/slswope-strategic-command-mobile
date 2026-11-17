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
CORPS_LOCKS_URL = 'https://ndc.ops.usace.army.mil/ords/lpms/lock_status_report_json?in_river_code=OH'
WATER_URL = (
    'https://services7.arcgis.com/CpU55e5tQz42Nf6c/ArcGIS/rest/services/'
    'Boil_Advisory_Area_Public/FeatureServer/0/query?' + urllib.parse.urlencode({
        'where': "Status = 'Active'", 'outFields': 'OBJECTID,Status,IssuedDate',
        'returnGeometry': 'false', 'f': 'json',
    })
)
CLOUDFLARE_URL = 'https://www.cloudflarestatus.com/api/v2/summary.json'
STRIPE_URL = 'https://www.stripestatus.com/api/v2/summary.json'
IC3_URL = 'https://www.ic3.gov/CSA/rss'

# A requirement can use a feed, a reviewed briefing, or a direct source link.
# Source links leave a coverage gap until a monitor or review process is connected.
TRACKS = [
    ('Immediate hazards', (
        ('Tri-State NWS weather alerts', 'nws'),
        ('Newburgh river stage and forecast', 'river'),
    )),
    ('Service continuity', (
        ('FAA ground stops', 'faa'),
        ('Cloudflare internet infrastructure', 'cloudflare'),
        ('Stripe payments', 'stripe'),
        ('Local telecommunications', None, 'https://www.fcc.gov/general/disaster-information-reporting-system-dirs-0'),
        ('Local hospital service disruptions', None),
    )),
    ('Supply chain / markets', (
        ('Ohio River lock queues and delays', 'locks'),
        ('Midwest fuel prices', None, 'https://www.eia.gov/dnav/pet/pet_pri_gnd_dcus_r20_w.htm'),
        ('Global supply-chain pressure', None, 'https://www.newyorkfed.org/research/policy/gscpi'),
        ('Freight corridor closures', None, 'https://511in.org/'),
        ('Local retail inventory', None),
    )),
    ('Global security', (
        ('Reviewed foreign briefing and Taiwan–Japan watch', 'briefing'),
        ('Official military activity updates', None, 'https://www.mnd.gov.tw/En/news/plaactlist'),
        ('Maritime security advisory changes', None, 'https://www.maritime.dot.gov/msci-advisories'),
    )),
    ('Political / governance', (
        ('Indiana and Kentucky FEMA declarations', 'fema'),
        ('County travel restrictions', None, 'https://www.in.gov/dhs/travel-advisory-map/'),
        ('Local emergency and reopening orders', None),
        ('State executive actions', None),
    )),
    ('Public preparedness intent', (
        ('FEMA household survey baseline', None, 'https://www.fema.gov/sites/default/files/documents/fema_icpd_2024-national-household-survey-on-disaster-preparedness-findings_05072025.pdf'),
        ('Backtested search-interest trends', None, 'https://developers.google.com/search/apis/trends'),
        ('Backtested retail preparedness indicators', None),
    )),
    ('Cyber & digital infrastructure', (
        ('CISA known exploited vulnerabilities', 'kev'),
        ('FBI IC3 industry cyber advisories', 'ic3'),
        ('Material company incident filings', None, 'https://www.sec.gov/search-filings/edgar-application-programming-interfaces'),
        ('Confirmed operator cyber impacts', None),
    )),
    ('Local essential services', (
        ('Evansville Water and Sewer Utility boil advisories', 'water'),
        ('Southwest Indiana electricity outage maps', None, 'https://www.in.gov/iurc/energy-division/electricity-industry/utility-outages/'),
        ('Henderson Municipal Power & Light outages', None, 'https://www.hmpl.com/outage-info.html'),
        ('Henderson Water Utility boil advisories', None, 'https://www.hkywater.org/226/Boil-Water-Advisories'),
        ('Newburgh-area drinking water service territories and alerts', None),
        ('Wastewater service disruptions', None),
    )),
    ('Cross-track correlation', (
        ('Merge duplicate NWS alerts', 'nws'),
        ('Match independent events by location and time', None),
        ('Verify shared causes and changes in status', None),
    )),
]


def track_coverage(feeds, briefing_date):
    tracks = []
    for name, requirements in TRACKS:
        indicators = []
        for label, key, *links in requirements:
            matching = [feed for feed in feeds if key is not None and feed['key'] == key]
            indicator = {'label': label, 'mode': 'automatic' if key else 'pending'}
            if links:
                indicator.update(mode='link only', url=links[0])
            if key == 'briefing':
                indicator.update(mode='reviewed', reviewed_on=briefing_date, url='#foreign')
            if key and key != 'briefing':
                states = [feed['status'] for feed in matching]
                if states and all(state == 'ok' for state in states):
                    health = 'current'
                elif any(state in ('ok', 'partial') for state in states):
                    health = 'degraded'
                else:
                    health = 'unavailable'
                indicator.update(health=health, checked_at=matching[0]['checked_at'] if matching else None)
            indicators.append(indicator)
        covered = sum(item['mode'] == 'automatic' or bool(item.get('reviewed_on')) for item in indicators)
        connection = 'connected' if covered == len(indicators) else 'partial' if covered else 'unconnected'
        tracks.append({'name': name, 'connection': connection, 'covered': covered, 'required': len(indicators),
                       'indicators': indicators})
    return tracks


def briefing_review_date():
    try:
        briefing = json.loads((ROOT / 'site' / 'foreign.json').read_text())
        review = datetime.date.fromisoformat(briefing['reviewed_on'])
        return review.isoformat() if briefing['developments'] else None
    except (OSError, ValueError, TypeError, KeyError):
        return None


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


def parse_corps_locks(payload, now):
    if not isinstance(payload, list):
        raise ValueError('Unexpected Corps Locks response')
    rivers = [river for river in payload if river.get('riverName') == 'OHIO RIVER']
    if len(rivers) != 1:
        raise ValueError('Ohio River missing from Corps Locks response')
    expected = {'75': 'Cannelton', '76': 'Newburgh', '77': 'John T. Myers'}
    records = {}
    for lock in rivers[0]['locks']:
        number = lock.get('lockNumber')
        if number not in expected:
            continue
        name = expected[number]
        if name.lower() not in lock['lockName'].lower() or name in records:
            raise ValueError('Unexpected or duplicate Ohio River lock')
        reading = datetime.datetime.strptime(lock['readingEntryDateTime'], '%m%d%y:%H%M')
        if not now.date() - datetime.timedelta(days=1) <= reading.date() <= now.date():
            continue
        values = {}
        for key, field in [('pending', 'totalPendingArrivals'), ('locking', 'totalLocking'),
                           ('average_delay', 'average24HourDelay')]:
            value = lock.get(field)
            values[key] = value if type(value) in (int, float) and math.isfinite(value) and value >= 0 else None
        if all(value is None for value in values.values()):
            continue
        records[name] = {
            'name': name, 'recorded_at': reading.strftime('%Y-%m-%d %H:%M'),
            'notes': (lock.get('notes') or '').strip(), **values,
        }
    if not records:
        raise ValueError('No recent local lock readings')
    return {'checked_at': now.isoformat(), 'locks': [records[name] for name in expected.values() if name in records]}


def collect_corps_locks():
    # The Corps legacy endpoint can include literal newlines inside operator notes.
    payload = json.loads(get_document(CORPS_LOCKS_URL, 'application/json'), strict=False)
    return parse_corps_locks(payload, NOW)


def parse_evsu_water(payload):
    if 'error' in payload or payload.get('exceededTransferLimit') or not isinstance(payload.get('features'), list):
        raise ValueError('Invalid or incomplete Evansville water query')
    notices = []
    ids = set()
    for feature in payload['features']:
        row = feature['attributes']
        if row['Status'] != 'Active':
            raise ValueError('Evansville water query included a non-active advisory')
        identifier = row['OBJECTID']
        if identifier in ids:
            continue
        ids.add(identifier)
        issued = row.get('IssuedDate')
        notices.append(datetime.datetime.fromtimestamp(issued / 1000, datetime.timezone.utc).isoformat()
                       if issued is not None else None)
    return {'active_count': len(notices), 'issued_at': sorted(notices, key=lambda value: value or '', reverse=True)}


def parse_provider_status(payload, provider_id, host):
    status = payload['status']
    page = payload['page']
    if page['id'] != provider_id or status['indicator'] not in ('none', 'minor', 'major', 'critical', 'maintenance'):
        raise ValueError('Unexpected provider status response')
    incidents = []
    for row in payload['incidents']:
        url = urllib.parse.urlsplit(row['shortlink'])
        if url.scheme != 'https' or url.hostname not in (host, 'stspg.io'):
            raise ValueError('Unexpected incident link')
        incidents.append({'title': row['name'], 'status': row['status'], 'url': row['shortlink']})
    return {'status': status['description'], 'indicator': status['indicator'], 'incidents': incidents,
            'updated_at': read_station_time(page['updated_at']).isoformat()}


def parse_ic3_advisories(document):
    root = ET.fromstring(document)
    channel = root.find('channel')
    if root.tag != 'rss' or channel is None or channel.findtext('title') != 'IC3.gov Industry Alerts':
        raise ValueError('Unexpected FBI advisory feed')
    results = []
    for item in channel.findall('item')[:5]:
        url = urllib.parse.urlsplit(item.findtext('link', ''))
        title = item.findtext('title', '').strip()
        if not title or url.scheme != 'https' or url.hostname != 'www.ic3.gov' or not url.path.startswith('/CSA/'):
            raise ValueError('Invalid FBI industry advisory')
        results.append({'title': title, 'url': url.geturl(),
                        'published_at': parsedate_to_datetime(item.findtext('pubDate', '')).isoformat()})
    return results


def local_operations(feeds, supplemental, alerts):
    local_keys = {'nws', 'river', 'water'}
    gaps = [feed['name'] for feed in feeds if feed['key'] in local_keys and feed['status'] != 'ok']
    notices = []
    if alerts:
        notices.append(f'{len(alerts)} active NWS ' + ('alert' if len(alerts) == 1 else 'alerts'))
    river = supplemental.get('river') or {}
    flood = river.get('forecast_category')
    if flood in ('action', 'minor', 'moderate', 'major'):
        notices.append('Newburgh forecast reaches ' + (flood + ' flood stage' if flood != 'action' else 'action stage'))
    water = supplemental.get('water') or {}
    count = water.get('active_count', 0)
    if count:
        notices.append(f'{count} active Evansville utility boil-advisory ' + ('area' if count == 1 else 'areas'))
    if notices:
        title = 'Active local notices'
    elif gaps:
        title = 'Local checks incomplete'
    else:
        title = 'No active notices in checked feeds'
    return {'title': title, 'notices': notices, 'gaps': gaps}


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
        ('locks', 'USACE Ohio River lock status', CORPS_LOCKS_URL, collect_corps_locks),
        ('water', 'Evansville utility boil advisories', WATER_URL, lambda: parse_evsu_water(get_json(WATER_URL))),
        ('cloudflare', 'Cloudflare status', CLOUDFLARE_URL,
         lambda: parse_provider_status(get_json(CLOUDFLARE_URL), 'yh6f0r4529hb', 'www.cloudflarestatus.com')),
        ('stripe', 'Stripe status', STRIPE_URL,
         lambda: parse_provider_status(get_json(STRIPE_URL), 'd5zv7xbys5v3', 'www.stripestatus.com')),
        ('ic3', 'FBI IC3 industry cyber advisories', IC3_URL,
         lambda: parse_ic3_advisories(get_document(IC3_URL, 'application/rss+xml'))),
    )
    for key, name, url, collect in sources:
        feed = {'key': key, 'name': name, 'status': 'ok', 'checked_at': STAMP, 'url': url}
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
            if key == 'locks':
                feed['count'] = len(signal['locks'])
                if feed['count'] != 3 or any(
                    lock[field] is None for lock in signal['locks'] for field in ('pending', 'locking', 'average_delay')
                ):
                    feed.update(status='partial', note='Some lock readings unavailable')
                    errors.append(name + ': ' + feed['note'])
            if key == 'water':
                feed['count'] = signal['active_count']
            if key in ('cloudflare', 'stripe'):
                feed.update(count=len(signal['incidents']), updated_at=signal['updated_at'])
            if key == 'ic3':
                feed['count'] = len(signal)
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
            feeds.append({'key':'nws','name':f'NWS {place}','status':'ok','checked_at':STAMP,'count':count,'url':url})
        except Exception as exc:
            errors.append(f'NWS {place}: {type(exc).__name__}')
            feeds.append({'key':'nws','name':f'NWS {place}','status':'error','checked_at':STAMP,'url':url,'note':'Fetch failed; not an all-clear'})
    kev_count=None;kev_recent=[]
    try:
        kev=get_json(KEV_URL)
        entries=kev['vulnerabilities']
        if not isinstance(entries, list):
            raise ValueError('Unexpected KEV catalog format')
        kev_count=len(entries)
        kev_recent=[{'vendor':str(v.get('vendorProject',''))[:100],'product':str(v.get('product',''))[:100],
                     'cve':v.get('cveID',''),'added':v.get('dateAdded','')} for v in entries[-8:]]
        feeds.append({'key':'kev','name':'CISA Known Exploited Vulnerabilities','status':'ok','checked_at':STAMP,'count':kev_count,'url':KEV_URL})
    except Exception as exc:
        errors.append(f'CISA KEV: {type(exc).__name__}')
        feeds.append({'key':'kev','name':'CISA Known Exploited Vulnerabilities','status':'error','checked_at':STAMP,'url':KEV_URL,'note':'Fetch failed; not an all-clear'})
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
      'tracks': track_coverage(feeds, briefing_review_date()),
      'local_operations': local_operations(feeds, supplemental, alerts),
      'health':{'all_sources_ok':all_ok,'errors':errors,'pushover_enabled':push_enabled,'push_sent_this_run':push_sent},
      'source_references':[NWS_DOCS,KEV_URL,'https://www.cisa.gov/known-exploited-vulnerabilities-catalog']}
    (ROOT/'site'/'data.json').write_text(json.dumps(output,indent=2,ensure_ascii=False)+'\n')
    print(f'{STAMP}: {ok}/{len(feeds)} checks passed, {len(alerts)} unique active alerts, {push_sent} notifications; no nationwide posture inferred')
    if not all_ok:print('NOTICE: One or more data sources failed. Dashboard must show incomplete status.')

if __name__=='__main__':main()
