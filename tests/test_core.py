from pathlib import Path
from pyfileguard.core import snapshot, diff

def test_create_modify_delete_rename(tmp_path: Path):
    a=tmp_path/'a.txt'; a.write_text('alpha')
    s1=snapshot(tmp_path)
    a.write_text('changed'); (tmp_path/'b.txt').write_text('beta')
    s2=snapshot(tmp_path); d=diff(s1,s2)
    assert 'a.txt' in d['modified'] and 'b.txt' in d['created']
    s_before=snapshot(tmp_path); (tmp_path/'b.txt').rename(tmp_path/'c.txt')
    d2=diff(s_before,snapshot(tmp_path)); assert d2['renamed'][0]['from']=='b.txt' and d2['renamed'][0]['to']=='c.txt'
