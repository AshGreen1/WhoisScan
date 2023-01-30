#!/usr/bin/python3
# counter taken from https://superfastpython.com/thread-safe-counter-in-python/
from threading import Lock

class ThreadSafeCounter():
    # constructor
    def __init__(self):
        # initialize counter
        self._counter = 0
        # initialize lock
        self._lock = Lock()

    # increment the counter
    def increment(self):
        with self._lock:
            self._counter += 1

    # get the counter value
    def value(self):
        with self._lock:
            return self._counter