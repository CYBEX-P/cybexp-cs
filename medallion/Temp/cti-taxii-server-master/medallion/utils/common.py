import datetime as dt
import uuid

import pytz
import six
from six import iteritems


def generate_stix20_id(sdo_type):
    return "{sdo_type}--{uuid}".format(sdo_type=sdo_type,
                                       uuid=six.text_type(uuid.uuid4()))


def create_bundle(o):
    return dict(id=generate_stix20_id("bundle"),
                objects=o,
                spec_version="2.0",
                type="bundle")


def get(data, key):
    for ancestors, item in iterpath(data):
        if key in ancestors:
            return item


def iterpath(obj, path=None):
    """
    Generator which walks the input ``obj`` model. Each iteration yields a
    tuple containing a list of ancestors and the property value.

    Args:
        obj: A SDO or SRO object.
        path: None, used recursively to store ancestors.

    Example:
        >>> for item in iterpath(obj):
        >>>     print(item)
        (['type'], 'campaign')
        ...
        (['cybox', 'objects', '[0]', 'hashes', 'sha1'], 'cac35ec206d868b7d7cb0b55f31d9425b075082b')

    Returns:
        tuple: Containing two items: a list of ancestors and the property value.

    """
    if path is None:
        path = []

    for varname, varobj in iter(sorted(iteritems(obj))):
        path.append(varname)
        yield (path, varobj)

        if isinstance(varobj, dict):

            for item in iterpath(varobj, path):
                yield item

        elif isinstance(varobj, list):

            for item in varobj:
                index = "[{0}]".format(varobj.index(item))
                path.append(index)

                yield (path, item)

                if isinstance(item, dict):
                    for descendant in iterpath(item, path):
                        yield descendant

                path.pop()

        path.pop()


def get_timestamp():
    return dt.datetime.now(tz=pytz.UTC)


def format_datetime(dttm):
    # 1. Convert to timezone-aware
    # 2. Convert to UTC
    # 3. Format in ISO format
    # 4. Add subsecond value if non-zero
    # 5. Add "Z"

    if dttm.tzinfo is None or dttm.tzinfo.utcoffset(dttm) is None:
        # dttm is timezone-naive; assume UTC
        zoned = pytz.utc.localize(dttm)
    else:
        zoned = dttm.astimezone(pytz.utc)
    ts = zoned.strftime("%Y-%m-%dT%H:%M:%S")
    if zoned.microsecond > 0:
        ms = zoned.strftime("%f")
        ts = ts + '.' + ms.rstrip("0")
    return ts + "Z"


def convert_to_stix_datetime(timestamp_string):
    try:
        return dt.datetime.strptime(timestamp_string, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        return dt.datetime.strptime(timestamp_string, "%Y-%m-%dT%H:%M:%SZ")


def generate_status(request_time, status, succeeded, failed, pending,
                    successes_ids=None, failures=None, pendings=None):
    status = {
        "id": "%s" % uuid.uuid4(),
        "status": status,
        "request_timestamp": request_time,
        "total_count": succeeded + failed + pending,
        "success_count": succeeded,
        "failure_count": failed,
        "pending_count": pending
    }

    if successes_ids:
        status["successes"] = successes_ids
    if failures:
        status["failures"] = failures
    if pendings:
        status["pendings"] = pendings

    return status
