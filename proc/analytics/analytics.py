# proc\analytics\analytics.py
#
from queue import Queue
from filt_cowrie import filt_cowrie_session_file_download
from filt_cowrie import filt_cowrie_2_ip
from filt_cowrie import filt_cowrie_2_url
import time

def wait_10_mins():
    time.sleep(600)
    return True

def infinite_worker(q):
    while not q.empty():
        func = q.get()
        try:
            r = func()
            if r == None:
                time.sleep(300)
                continue

        except Exception as exception:
            print('=======================')
            print(time.time())
            print(exception)
            time.sleep(300)

        q.task_done()
        q.put(func)

        

q = Queue()
q.put(filt_cowrie_2_url)
q.put(filt_cowrie_session_file_download)
q.put(filt_cowrie_2_ip)

infinite_worker(q)


    

