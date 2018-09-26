# -*- coding: utf-8 -*-
'''
Module to manage transactional-updates on SUSE / openSUSE distributions

.. versionadded:: 2018.3.0

:codeauthor:    Pablo Suárez Hernández <psuarezhernandez@suse.de>

:depends:       ``transactional-updates`` https://github.com/openSUSE/transactional-update
:maturity:      new
:platform:      Linux
'''
from __future__ import absolute_import, unicode_literals, print_function

# Import Python libs
import logging
import os

# Import Salt libs
import salt.utils.path
from salt.exceptions import CommandExecutionError

# Import 3rd party libs
from salt.ext import six

# Define the module's virtual name
__virtualname__ = 'txupdate'

# pylint: disable=invalid-name
log = logging.getLogger(__name__)


def __virtual__():
    if salt.utils.path.which('transactional-update'):
        return __virtualname__
    return False, '"transactional-update" is not installed on the minion'


class _TransactionalUpdate(object):
    '''
    Transactional-update parallel caller.
    Validates the result and either raises an exception or reports an error.
    '''

    SUCCESS_EXIT_CODES = [0]
    TXUPDATE_LOCK = '/var/run/transactional-update.pid'
    TAG_RELEASED = 'txupdate/released'
    TAG_BLOCKED = 'txupdate/blocked'


    def __init__(self):
        '''
        Constructor
        '''
        self.__called = False
        self._reset()

    def _reset(self):
        '''
        Resets values of the call setup.

        :return:
        '''
        self.__cmd = ['transactional-update']
        self.__exit_code = 0
        self.__call_result = dict()
        self.__error_msg = ''
        self.__env = {'SALT_RUNNING': "1"}  # Subject to change

        # Call config
        self.__no_raise = False
        self.__systemd_scope = False

    def __call__(self, *args, **kwargs):
        '''
        :param args:
        :param kwargs:
        :return:
        '''
        # Ignore exit code for 106 (repo is not available)
        if 'systemd_scope' in kwargs:
            self.__systemd_scope = kwargs['systemd_scope']
        return self

    def __getattr__(self, item):
        '''
        Call configurator.

        :param item:
        :return:
        '''
        # Reset after the call
        if self.__called:
            self._reset()
            self.__called = False

        elif item == 'noraise':
            self.__no_raise = True
        elif item == 'call':
            return self.__call
        else:
            return self.__dict__[item]

        return self

    @property
    def exit_code(self):
        return self.__exit_code

    @exit_code.setter
    def exit_code(self, exit_code):
        self.__exit_code = int(exit_code or '0')

    @property
    def error_msg(self):
        return self.__error_msg

    @error_msg.setter
    def error_msg(self, msg):
        if self._is_error():
            self.__error_msg = msg and os.linesep.join(msg) or "Check Transactional-update's logs."

    @property
    def stdout(self):
        return self.__call_result.get('stdout', '')

    @property
    def stderr(self):
        return self.__call_result.get('stderr', '')

    @property
    def pid(self):
        return self.__call_result.get('pid', '')

    def _is_error(self):
        '''
        Is this is an error code?

        :return:
        '''
        return self.exit_code not in self.SUCCESS_EXIT_CODES

    def _check_result(self):
        '''
        Check and set the result of a transactional-update command. In case of an error,
        either raise a CommandExecutionError or extract the error.

        result
            The result of a transactional-update command called with cmd.run_all
        '''
        if not self.__call_result:
            raise CommandExecutionError('No output result from Transactional-update?')

        self.exit_code = self.__call_result['retcode']

        if self._is_error():
            _error_msg = list()
            msg = self.__call_result['stderr'] and self.__call_result['stderr'].strip() or ""
            if msg:
                _error_msg.append(msg)
            self.error_msg = _error_msg
        return True

    def __call(self, *args, **kwargs):
        '''
        Call Transactional-update.

        :param state:
        :return:
        '''
        self.__called = True
        self.__cmd.extend(args)
        kwargs['output_loglevel'] = 'trace'
        kwargs['python_shell'] = False
        kwargs['env'] = self.__env.copy()

        # Transactional-update call will stuck here waiting, if another transactional-update hangs until forever.
        # However, Transactional-update lock needs to be always respected.
        was_blocked = False
        while True:
            cmd = []
            if self.__systemd_scope:
                cmd.extend(['systemd-run', '--scope'])
            cmd.extend(self.__cmd)
            log.debug("Calling Transactional-update: " + ' '.join(cmd))
            self.__call_result = __salt__['cmd.run_all'](cmd, **kwargs)
            if self._check_result():
                break

            if os.path.exists(self.TXUPDATE_LOCK):
                try:
                    with salt.utils.files.fopen(self.TXUPDATE_LOCK) as rfh:
                        data = __salt__['ps.proc_info'](int(rfh.readline()),
                                                        attrs=['pid', 'name', 'cmdline', 'create_time'])
                        data['cmdline'] = ' '.join(data['cmdline'])
                        data['info'] = 'Blocking process created at {0}.'.format(
                            datetime.datetime.utcfromtimestamp(data['create_time']).isoformat())
                        data['success'] = True
                except Exception as err:
                    data = {'info': 'Unable to retrieve information about blocking process: {0}'.format(err.message),
                            'success': False}
            else:
                data = {'info': 'Transactional-update is locked, but no Transactional-update lock has been found.', 'success': False}

            if not data['success']:
                log.debug("Unable to collect data about blocking process.")
            else:
                log.debug("Collected data about blocking process.")

            __salt__['event.fire_master'](data, self.TAG_BLOCKED)
            log.debug("Fired a Transactional-update blocked event to the master with the data: %s", data)
            log.debug("Waiting 5 seconds for Transactional-update gets released...")
            time.sleep(5)
            if not was_blocked:
                was_blocked = True

        if was_blocked:
            __salt__['event.fire_master']({'success': not len(self.error_msg),
                                           'info': self.error_msg or 'Transactional-update has been released'},
                                          self.TAG_RELEASED)
        if self.error_msg and not self.__no_raise:
            raise CommandExecutionError('Transactional-update command failure: {0}'.format(self.error_msg))

        return self.__call_result['stdout']


__transactional_update__ = _TransactionalUpdate()


