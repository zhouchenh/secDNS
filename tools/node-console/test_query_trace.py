import unittest
import json
import health_controller as h
class TraceTests(unittest.TestCase):
 def test_allowlist(self):
  v=dict(kind='secdns-query-exchange',correlation='a'*64,started_unix_ms=10,ended_unix_ms=20,duration_ms=10,outcome='exchange_error',secret='must-not-copy')
  self.assertNotIn('secret',h.query_trace(json.dumps(v)))
  for change in ({'correlation':'private.example'},{'duration_ms':True},{'duration_ms':10001},{'ended_unix_ms':9},{'outcome':'raw network message'}):
   self.assertIsNone(h.query_trace(json.dumps(dict(v,**change))))
  for raw in ('', '[]', 'x'*2049, '{}'):self.assertIsNone(h.query_trace(raw))
if __name__=='__main__':unittest.main()
