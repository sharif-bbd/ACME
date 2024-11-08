from dnslib import RR
from dnslib.server import BaseResolver

class DNS01Handler:
    record = None
    challenges = {}

    @classmethod
    def set_challenges(cls, domain, txt, record):
        record = record
        challenges[domain] = txt

    def resolve(self, request, handler):
        reply = request.reply()
        qname = request.q.qname
        name = str(qname).strip('.')

        domain_name = name.split("_acme-challenge.")[-1]

        if domain_name in challenges:
            txt = challenges[domain_name]
            reply.add_answer(*RR.fromZone(f"{qname} 60 IN TXT \"{txt}\""))
        else:
            reply.add_answer(*RR.fromZone(f"{qname} 60 A {record}"))
        return reply
