from tahoe import Raw
import logging, pdb
import subtype_parse

def parsemain(typtag, orgid, timezone, data):
    try:
        orgid = "identity--" + orgid
        raw_sub_type = {
            "misp-api": "x-misp-event",
            "unr-honeypot": "x-unr-honeypot",
            "phishtank-api": "x-phishtank",
            "openphish-file-feed": "x-openphish",
        }.get(typtag, None)
        if raw_sub_type:
            parsed_raw_data = subtype_parser(typtag, data)
            raw = Raw(raw_sub_type, parsed_raw_data, orgid, timezone)
        else:
            raw = None
            logging.warning(
                "\nproc.archive.parsemain -- Unknown typtag : " + str(typtag)
            )
        return raw
    except:
        logging.error("\nproc.archive.parsemain -- " + str(typtag), exc_info=True)


def subtype_parser(typtag, data):
    parser = getattr(subtype_parse, typtag.replace("-","_")+"_parser" )
    return parser(data)
