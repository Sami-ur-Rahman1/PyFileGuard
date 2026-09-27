import csv,json
from pathlib import Path
from .database import query_events
HEADERS=["id","timestamp","event","severity","root","path","old_path"]
def export_events(output,fmt="json",**filters):
    rows=query_events(**filters); records=[dict(zip(HEADERS,r)) for r in rows]; p=Path(output).expanduser(); p.parent.mkdir(parents=True,exist_ok=True)
    if fmt.lower()=="json": p.write_text(json.dumps(records,indent=2),encoding="utf-8")
    elif fmt.lower()=="csv":
        with p.open("w",newline="",encoding="utf-8") as f: w=csv.DictWriter(f,fieldnames=HEADERS); w.writeheader(); w.writerows(records)
    else: raise ValueError("Format must be json or csv.")
    return len(records)
