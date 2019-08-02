#!/usr/bin/env python3

if __name__ == "__main__": from common import *
else: from .common import *


class MISPFileSource(CybexSource):
    def __init__(self, api_config, input_config, filename):
        self.filename = filename
        super().__init__(api_config, input_config)
        
    def __str__(self):
        return('MISP File input, orgid = {}, typtag = {}, timezone = {}, url = {}'.format(
                self.orgid, self.typtag, self.timezone, self.url))

    def run(self):
        f = open(self.filename, "r")
        j = json.load(f)
        for event in j['response']:
            rr = self.post_event(event)
            [logging.exception(str(r.status_code) + ' ' + r.reason) for r in rr if not r.ok]
        f.close()
        os.rename(self.filename, self.filename+'.bak')


def misp_file_fetch():
    config_file = get_config_file()
    api_config = config_file["api_srv"]
    misp_file_config = config_for_source_type(config_file, "misp_file")
    
    misp_file_dir = misp_file_config['directory']
    
    misp_files = [
        os.path.join(misp_file_dir, misp_file)
        for misp_file in os.listdir(misp_file_dir)
        if misp_file.endswith("json")
    ]

    for misp_file in misp_files:
        misp_file_source = MISPFileSource(api_config, misp_server_config, misp_file)
        CybexSourceFetcher(misp_file_source).run()
        

if __name__ == "__main__":
    misp_file_fetch()
