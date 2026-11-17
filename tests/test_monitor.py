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
if __name__=='__main__':unittest.main()
