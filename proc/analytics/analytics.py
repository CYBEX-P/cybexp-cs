# proc\analytics\analytics.py
#
from queue import Queue
from filt_cowrie import filt_cowrie_session_file_download
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
                print('-----------------------')
                print(time.time())
                print('Data Exhausted')
                return
        except e:
            print('=======================')
            print(time.time)
            print(e)
            time.sleep(300)
        q.task_done()
        q.put(func)

q = Queue()
q.put(filt_cowrie_session_file_download)
##q.put(filt_cowrie_session_file_download_2_file_url)

infinite_worker(q)


    

