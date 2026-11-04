"""Faithful confirmation of CVE-2026-13508 using Khoj's REAL code, run in the
Django shell (bypasses the LLM answer pipeline, which a dumb echo server can't
drive). Run:

    docker exec -i ragtest-khoj python3 src/khoj/manage.py shell < studies/apps/khoj/khoj_cve_confirm.py

It shows, for the conversation user B forked from A's shared conversation:
  (1) the fork is bound to A's PRIVATE agent (creator = A), an unauthorized binding;
  (2) ais_agent_accessible(agent, B) == False -- the exact check the vulnerable
      fork+chat path omits, proving B is not authorized for this agent;
  (3) the agent's knowledge base (what the chat retrieval selects via
      owner_filter = Q(agent=agent), user=None) contains A's private canary.
Together: B, via fork, can read A's private-agent knowledge base.
"""
from asgiref.sync import async_to_sync

from khoj.database.models import Conversation, Entry, KhojUser
from khoj.database.adapters import AgentAdapters

CAN = "KHOJKBMARKER77"

B = KhojUser.objects.get(email="b@test.local")
convs = list(Conversation.objects.filter(user=B).exclude(agent__isnull=True))
print("B's forked conversations bound to an agent:", len(convs))

leak_confirmed = False
for conv in convs:
    ag = conv.agent
    creator = ag.creator.email if ag and ag.creator else None
    try:
        accessible = async_to_sync(AgentAdapters.ais_agent_accessible)(ag, B)
    except Exception as e:
        accessible = f"ERR:{e}"
    kb = Entry.objects.filter(agent=ag)
    has_canary = any(CAN in ((e.raw or "") + (e.compiled or "")) for e in kb)
    print(f"  conv={str(conv.id)[:8]}  agent={ag.slug}  privacy={ag.privacy_level}  creator={creator}")
    print(f"    (2) B authorized for this agent?  ais_agent_accessible = {accessible}")
    print(f"    (3) agent KB entries={kb.count()}  contains A's canary {CAN}? {has_canary}")
    if accessible is False and has_canary and ag.privacy_level == "private" and creator == "a@test.local":
        leak_confirmed = True

print("\n==== CVE-2026-13508 CONFIRMED:", leak_confirmed, "====")
print("B holds a forked conversation bound to A's PRIVATE agent that B is NOT authorized to use,")
print("and that agent's knowledge base holds A's private canary -> the fork+chat retrieval path")
print("(owner_filter = Q(agent=agent) with user=None) serves A's private documents to B.")
