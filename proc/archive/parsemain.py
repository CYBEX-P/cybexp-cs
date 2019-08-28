from tahoe import Raw
import logging, pdb


def parsemain(typtag, orgid, timezone, data):
    try:
        orgid = "identity--" + orgid
        raw_sub_type = {
            "misp-api": "x-misp-event",
            "unr-honeypot": "x-unr-honeypot",
            "phishtank-api": "x-phishtank",
        }.get(typtag, None)
        if raw_sub_type:
            raw = Raw(raw_sub_type, data, orgid, timezone)
        else:
            raw = None
            logging.warning(
                "\nproc.archive.parsemain -- Unknown typtag : " + str(typtag)
            )
        return raw
    except:
        logging.error("\nproc.archive.parsemain -- " + str(typtag), exc_info=True)
