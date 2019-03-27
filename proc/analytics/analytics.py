# proc\analytics\analytics.py
#
from queue import Queue
from filt_cowrie import filt_cowrie_2_ip
from filt_cowrie import filt_cowrie_session_file_download_2_file_url

def wait_10_mins():
    time.sleep(600)
    return True

def infinite_worker(q):
    while not q.empty():
        func = q.get()
        r = func()
        q.task_done()
##        if not r : q.put(wait_10_mins)
        q.put(func)

q = Queue()
q.put(filt_cowrie_2_ip)
##q.put(filt_cowrie_session_file_download_2_file_url)

infinite_worker(q)


