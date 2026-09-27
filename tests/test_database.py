from pyfileguard.core import Event
from pyfileguard.database import add_event,query_events
def test_db(tmp_path):
 p=tmp_path/"e.db"; add_event(Event("MODIFIED","a.conf",severity="HIGH"),"/x",p); add_event(Event("CREATED","a.txt"),"/x",p); assert len(query_events(severity="HIGH",db_path=p))==1
