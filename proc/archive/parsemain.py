from tahoe import Raw
import pdb, logging

class  MispRaw(Raw):
    def duplicate(self): return self.backend.find_one({"raw_type": "x-misp-event", "data.Event.id" : self.data["Event"]["id"]})


def parsemain(typtag, orgid, timezone, data):
    try: 
        orgid = 'identity--'+orgid
        if typtag == "misp-api": raw = MispRaw("x-misp-event", data, orgid, timezone)
        elif typtag == "unr-honeypot": raw = Raw("x-unr-honeypot", data, orgid, timezone)
        else:
            raw = None
            logging.warning("\nproc.archive.parsemain -- Unknown typtag : " + str(typtag))
        return raw
    except:
        logging.error("\nproc.archive.parsemain -- " + str(typtag), exc_info=True)
        pdb.set_trace()
