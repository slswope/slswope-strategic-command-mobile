import unittest, importlib.util, pathlib
src=pathlib.Path(__file__).resolve().parents[1]/'scripts'/'update.py'
spec=importlib.util.spec_from_file_location('monitor',src)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class TestMonitor(unittest.TestCase):
    def test_warning_sends(self):
        self.assertTrue(m.is_actionable({'event':'Flash Flood Warning','severity':'Moderate'}))
        self.assertTrue(m.is_actionable({'event':'Tornado Warning','severity':'Severe'}))
    def test_watch_not_push(self):
        self.assertFalse(m.is_actionable({'event':'Flood Watch','severity':'Moderate'}))
        self.assertFalse(m.is_actionable({'event':'Special Weather Statement','severity':'Unknown'}))
    def test_normalization(self):
        a=m.normalize({'id':'abc','properties':{'event':'Winter Storm Warning','severity':'Severe'}})
        self.assertEqual(a['id'],'abc')
        self.assertEqual(a['locations'],[])
    def test_all_tracks_present(self):
        self.assertEqual(len(m.TRACKS),10)
    def test_no_false_source_status(self):
        self.assertNotIn('all clear',m.TRACKS[6][2].lower())

class TestSupplementalFeeds(unittest.TestCase):
    now = m.read_station_time('2026-11-17T20:30:00Z')

    def test_faa_empty_and_active_ground_stops(self):
        def report(events):
            return ('<AIRPORT_STATUS_INFORMATION><Update_Time>'
                    'Tue, 17 Nov 2026 20:25:00 GMT</Update_Time>'
                    + events + '</AIRPORT_STATUS_INFORMATION>')

        self.assertEqual(m.parse_ground_stops(report(''), self.now)['stops'], [])
        event = ('<Delay_type><Name>Ground Stops</Name><Ground_Stop_List><Ground_Stop>'
                 '<ARPT>ORD</ARPT><Reason>Weather</Reason><End_Time>21:15 UTC</End_Time>'
                 '</Ground_Stop></Ground_Stop_List></Delay_type>')
        stops = m.parse_ground_stops(report(event), self.now)['stops']
        self.assertEqual(stops, [{'airport': 'ORD', 'reason': 'Weather', 'end_time': '21:15 UTC'}])
        with self.assertRaises(ValueError):
            m.parse_ground_stops(report('').replace('20:25', '18:25'), self.now)

    def test_river_forecast_peak_uses_future_valid_readings(self):
        gauge = {'lid': 'NBGI3', 'status': {'observed': {
            'primary': 34, 'primaryUnit': 'ft', 'validTime': '2026-11-17T20:00:00Z'}},
            'flood': {'stageUnits': 'ft', 'categories': {
                name: {'stage': level} for name, level
                in {'action': 35, 'minor': 38, 'moderate': 48, 'major': 56}.items()}}}
        forecast = {'forecast': {'issuedTime': '2026-11-17T19:00:00Z', 'primaryUnits': 'ft',
            'data': [{'primary': 60, 'validTime': '2026-11-17T20:00:00Z'},
                     {'primary': 38.1, 'validTime': '2026-11-18T00:00:00Z'},
                     {'primary': -9999, 'validTime': '2026-11-18T06:00:00Z'}]}}
        river = m.parse_river_stage(gauge, forecast, self.now)
        self.assertEqual(river['forecast_peak']['stage'], 38.1)
        self.assertEqual(river['forecast_category'], 'minor')
        self.assertIsNone(m.parse_river_stage(gauge, {}, self.now)['forecast_peak'])

    def test_fema_deduplicates_designated_areas(self):
        row = {'state': 'IN', 'disasterNumber': 1234, 'declarationTitle': 'Flooding',
               'declarationDate': '2026-11-15T00:00:00Z', 'declarationType': 'DR'}
        county = {**row, 'designatedArea': 'Warrick (County)'}
        result = m.parse_declarations({'DisasterDeclarationsSummaries': [
            county, county, {**row, 'designatedArea': 'Gibson (County)'}]})
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['area_count'], 2)
        self.assertEqual(result[0]['local_areas'], ['Warrick (County)'])

if __name__=='__main__':unittest.main()
