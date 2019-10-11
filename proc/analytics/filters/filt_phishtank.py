import os, logging, json, copy, time

from typing import Any, Dict, List, Tuple

if __name__ == "__main__":
    from demo_env import *

from tahoe import (
    get_backend,
    NoBackend,
    Attribute as TahoeAttribute,
    Object as TahoeObject,
    Event as TahoeEvent,
    Session,
    parse,
)


def coerce_types_to_tahoe(record):
    if "timestamp" in record:
        from datetime import datetime as dt

        ts = record["timestamp"]

        ts = ts[: -len("+00:00")]  # Strip UTC offset

        dt = dt.strptime(ts, "%Y-%m-%dT%H:%M:%S")

        record["timestamp"] = dt.timestamp()  # Convert to float


def translate_record_to_tahoe(record, translator: Dict[str, str]):
    """ Translate a JSON `record` to a Tahoe object based on a translator. 

    Translators have the following structure:

    {
        "Tahoe object name": "JSON document path of object value"
    }

    For example, if I wanted to set the value of "count" to record["a"]["b"]["c"]:

    {
    "a" : { "b" : { "c" : 5 } }
    }

    I would use:

    {"count": ".a.b.c"}

    """
    logging.info("Remapping Phishtank record to Tahoe structure")
    logging.info(f"Translator = {translator}")

    tahoe_record = {}

    for tahoe_param, record_path in translator.items():
        path = translator[tahoe_param].split(".")

        if len(path) == 1:
            # The param is expressed in the translator literally
            # (i.e. no '.' chars forming a path expression)
            tahoe_record[tahoe_param] = path[0]
            continue

        record_obj = record
        for field in path[1:]:
            record_obj = record_obj[field]

        tahoe_record[tahoe_param] = record_obj

    return tahoe_record


def extract_attrs_from_phishtank_record(
    record
) -> Tuple[List[TahoeAttribute], List[TahoeObject]]:
    logging.info("Extracting TahoeAttributes from the Phishtank record.")
    tahoe_attr_realname = {
        "target": "name",
        "verification_time": "verification_timestamp",
        "ip_address": "ipv4",
        "cidr_block": "cidr",
        "announcing_network": "asn",
        "country": "country_code2",
        "url": "url",
    }

    tahoe_object_realname = {
        "ip_address": ["geoip"],
        "cidr_block": ["geoip"],
        "announcing_network": ["geoip"],
        "rir": ["geoip"],
        "country": ["geoip"],
        "target": ["organization", "target"],
        "url": ["url"],
    }

    attrs_to_extract = record["data"]

    extracted_attrs = []
    extracted_objs = []

    # Unroll nested attributes, if they exist
    if attrs_to_extract["details"]:
        attrs_to_extract.update(attrs_to_extract["details"][0])

    for aname, attr in attrs_to_extract.items():
        if aname in tahoe_attr_realname:
            # May need to rename some Phishtank attrs
            # We may also need to create sub-objects from a given Phish attr
            if aname in tahoe_attr_realname:
                aname = tahoe_attr_realname[aname]
            ta = TahoeAttribute(aname, attr)
            extracted_attrs.append(ta)

            if aname in tahoe_object_realname:
                i = 0
                object_aliases = tahoe_object_realname[aname]
                for i in range(len(object_aliases)):
                    extracted_objs.append(
                        TahoeObject(
                            object_aliases[i], ta if i == 0 else object_aliases[i - 1]
                        )
                    )

    return extracted_attrs, extracted_objs


def convert_to_tahoe_and_archive(phishtank_record):
    translator = {
        "event_type": "phishtank-url",
        "data": ".data.details",
        "orgid": ".orgid",
        "timestamp": ".data.submission_time",
        "malicious": "True",
    }

    # TODO: handle translator keys that require coercion to a datatype,
    # e.g. malicious: bool and timestamp: float

    tahoe_record = translate_record_to_tahoe(phishtank_record, translator)

    coerce_types_to_tahoe(tahoe_record)

    attrs, objs = extract_attrs_from_phishtank_record(phishtank_record)

    data = [*attrs, *objs]
    logging.info(f"Data = {data}")

    TahoeEvent(
        tahoe_record["event_type"],
        data,
        tahoe_record["orgid"],
        tahoe_record["timestamp"],
    )


def archive_all_threat_data(
    sub_type="x-phishtank", filt_id="1f8169b1-2d02-4806-91ee-5299d02aa414"
):
    # TODO: Can we use a bool for filter_id?
    # TODO: Can we replace the archive database with an MQ?
    if os.getenv("_MONGO_URL"):
        backend = get_backend()

    query = {
        "itype": "raw",
        "sub_type": sub_type,
        "filters": {"$ne": filt_id},
        "_valid": {"$ne": False},
    }
    projection = {"_id": 0, "filters": 0, "_valid": 0}

    cursor = backend.find(query, projection, no_cursor_timeout=True)

    for record in cursor:
        try:
            convert_to_tahoe_and_archive(record)
        except:
            logging.error(
                "proc.analytics.filters.filt_phishtank: "
                "Phishtank Event id " + record["data"]["phish_id"],
                exc_info=True,
            )
        else:
            backend.update_one(
                {"uuid": record["uuid"]}, {"$addToSet": {"filters": filt_id}}
            )


if __name__ == "__main__":
    archive_all_threat_data()
