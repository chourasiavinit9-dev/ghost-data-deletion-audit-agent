"""Does the request actually authorise deletion?  (multilingual, rule based)

An optional LLM fallback (set ANTHROPIC_API_KEY) is only consulted for texts the
rules cannot decide; the default run needs no network or credentials.
"""
import re

DELETE = re.compile(
    r"(delet|eras(e|ure)|remov(e|al)|close (my|this|the) account|closed|closure|permanent|get rid|"
    r"elimin|borr(ar|e)|cierr|baja|exclu[ií]|exclus|apag|encerr|suppress|supprim|effac|cl[oô]tur|"
    r"l[öo]sch|entfern|삭제|영구|탈퇴|지워|削除|消去|退会|解約|アカウントを閉)", re.I)
NEGATED = re.compile(
    r"(not (a request|asking|requesting|want(ing)?)( for| to)?( any)? ?(deletion|delete|erase|erasure|remov\w*|clos\w*)|"
    r"(do not|don't|dont|please do not|never|without) (delete|erase|remove|close|closing|removing|deleting)|"
    r"(leave|keep) (the |my |this )?(account|profile)( active| as it is| in place)?|"
    r"without removing|no(t)? (deletion|delete)|"
    r"(information|access) request, not( a request)?( for| to)?( \w+)?|"
    r"(remove|unsubscribe|delete)[^.]{0,40}marketing[^.]{0,30}only|not asking for deletion|"
    r"still (need|want|use)|continue using|leave my (profile|account))", re.I)
OTHER = re.compile(
    r"(copy of|download|portable format|what personal information|information (you )?hold|"
    r"reset|can't access|cannot access|misspell|correct (it|my|the)|replace it|change the email|"
    r"marketing lists only|promotional|stop the|update my|out of date|invoices)", re.I)


def authorises_deletion(text, llm=None):
    """Deletion is the default reading; a request is non-deletion only when it
    asks for something else (access, correction, opt-out ...) or explicitly
    declines deletion, and no deletion ask survives once negations are removed."""
    t = text or ""
    other = bool(NEGATED.search(t) or OTHER.search(t))
    if not other:
        return True
    positive = bool(DELETE.search(NEGATED.sub(" ", t)))
    if not positive:
        return False
    return llm(t) if llm else True
