import fnmatch
RULES=[("CRITICAL",["*/etc/ssh/*","*/etc/sudoers*","*/etc/passwd","*/etc/shadow"]),("HIGH",["*.conf","*.ini","*.service","*.sh","*.ps1","*.exe","*.dll"]),("MEDIUM",["*"])]
def classify(path,kind,rules=None):
    p=path.replace("\\\\","/")
    for sev,pats in (rules or RULES):
        if any(fnmatch.fnmatch(p,x) or fnmatch.fnmatch(p.split("/")[-1],x) for x in pats): return sev
    return "MEDIUM"
