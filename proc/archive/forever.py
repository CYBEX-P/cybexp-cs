from subprocess import Popen
import sys, time

filename = "archive.py"
while True:
    print("\nStarting " + filename)
    p = Popen("python " + filename, shell=True)
    p.wait()
    time.sleep(600)
