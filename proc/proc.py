import argparse, json, logging, threading
import archive

parser = argparse.ArgumentParser()
parser.add_argument("-c", "--config", default="config.json", help="Path of config.json file")
parser.add_argument("-a", "--archive", action="store_false", help="Set to run archive script")
parser.add_argument("-n", "--analytics", action="store_false", help="Set to run analytics script")
parser.add_argument("-r", "--report", action="store_false", help="Set to run report script")
args = parser.parse_args()

with open(args.config) as f: config = json.load(f)
archive_config = config.pop("archive", None)
analytics_config = config.pop("analytics", None)
report_config = config.pop("report", None)


