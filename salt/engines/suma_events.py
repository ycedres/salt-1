# -*- coding: utf-8 -*-
'''
SUSE Manager Salt events engine

This engine stores all Salt events needed for SUSE Manager into the configured
PostgreSQL database.

Example config in the Salt Master

.. code-block:: yaml

    engines:
      - suma_events:
          hostname: localhost
          port: 1234
          database: example
          username: user
          password: password
'''
# Import Python libs
from __future__ import absolute_import, print_function, unicode_literals

# Import salt libs
import salt.config
import salt.utils.event

# Import python libs
import fnmatch
import logging
import Queue
import re
import threading


log = logging.getLogger(__name__)

LISTEN_EVENTS_REGEXS = [
    '^salt/auth$',
    '^minion_start$',
    '^salt/job/.*/ret/.*$',
    '^salt/beacon/.*/.*$',
]

class SumaEventsProcessor(object):
    def __init__(self):
        # if no count passed, default to number of CPUs
        if num_threads is None:
            num_threads = multiprocessing.cpu_count()
        self.num_threads = num_threads

        self._events_queue = Queue.Queue()
        self._workers = []
        self._pg = None

        # create worker threads
        for _ in range(num_threads):
            thread = threading.Thread(target=self._thread_target)
            thread.daemon = True
            thread.start()
            self._workers.append(thread)

    def _thread_target(self):
        log.debug("Thread init!!!")
        while True:
            # 1s timeout so that if the parent dies this thread will die within 1s
            try:
                try:
                    event = self._events_queue.get(timeout=1)
                    log.debug("Thread ---> Consumed event!!! {}".format(event)
                    self._events_queue.task_done()  # Mark the task as done once we get it
                except queue.Empty:
                    continue
            except AttributeError:
                # During shutdown, `queue` may not have an `Empty` atttribute. Thusly,
                # we have to catch a possible exception from our exception handler in
                # order to avoid an unclean shutdown. Le sigh.
                continue
            try:
                log.debug(
                    'SumaEventsProcessor send event to the database: {}'.format(event))
                # TODO: Send event to DB
            except Exception as err:
                log.debug(err, exc_info=True)


def start(hostname=None, port=None, database=None, username=None, password=None):
    log.debug("Starting SUSE Manager events engine")
    suma_event_regex = re.compile('|'.join('(?:%s)' % p for p in LISTEN_EVENTS_REGEXS))

    opts = salt.config.client_config('/etc/salt/master')
    sevent = salt.utils.event.get_event(
            'master',
            sock_dir=opts['sock_dir'],
            transport=opts['transport'],
            opts=opts)

    while True:
        ret = sevent.get_event(full=True)
        if ret is None:
            continue

        if suma_event_regex.match(ret['tag']):
            process_suma_event(ret)


def process_suma_event(event):
    log.debug("Processing event: {}".format(event)) 
    events_queue.put(event)
