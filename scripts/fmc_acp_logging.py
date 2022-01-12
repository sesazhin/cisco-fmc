#!/usr/bin/env python
#  -*- coding: utf-8 -*-

###############################
# ABOUT THIS SCRIPT (READ ME) #
###############################
#
# Disable or enable logging in all rules of a specified Access Control Policy (ACP)
# ----------------
# Author: Sergey Sazhin (sesazhin@cisco.com)
# Property of: Cisco Systems, Inc.
# Version: 0.1
# Release Date: 12/01/2022

# What it scripts does:
# 1. Takes Access Control Policy (ACP) name
# 2. Gets all access control rules for a specified ACP
# 3. Disables or enables logging in all* rules for a specified ACP
# *those rules that already have logging configured in a right way - skipped

import config
import json
import logging.handlers
import requests
import sys
from typing import List
from typing import Dict
import warnings

from pprint import pprint
from dataclasses import dataclass

log_formatter = logging.Formatter('%(asctime)s - line %(lineno)s - %(funcName)s - %(levelname)s: %(message)s')
log_level = config.log_level

consoleHandler = logging.StreamHandler()
consoleHandler.setLevel(log_level)
consoleHandler.setFormatter(log_formatter)
consoleHandler.set_name("console_handler")
logging.getLogger('').addHandler(consoleHandler)
global log
log = logging.getLogger(log_level)
log.setLevel(logging.INFO)

LOGFILE = config.log_path

try:
    # save logging output to file up to 20 Mbytes size,
    # keep 10 files in logging directory
    file_handler = logging.handlers.RotatingFileHandler(LOGFILE, maxBytes=(1048576 * 10),
                                                        backupCount=10,
                                                        encoding='utf-8')
    file_handler.setLevel(log_level)
    file_handler.setFormatter(log_formatter)
    file_handler.set_name("file_handler")
    logging.getLogger('').addHandler(file_handler)

except PermissionError:
    log.exception(f'Unable to create log file: {LOGFILE}.\nLogs not saved!')

warnings.filterwarnings('ignore', message='Unverified HTTPS request')


@dataclass
class AccessRule:
    acp_name: str
    acp_id: str
    rule_name: str
    rule_id: str
    access_rule_dict: Dict

    def set_access_rule_dict(self, input_dict: Dict):
        self.access_rule_dict = input_dict

    def get_acp_name(self) -> str:
        return self.acp_name

    def get_acp_id(self) -> str:
        return self.acp_id

    def get_rule_name(self) -> str:
        return self.rule_name

    def get_rule_id(self) -> str:
        return self.rule_id

    def get_access_rule_dict(self) -> Dict:
        return self.access_rule_dict


class FMC:
    def __init__(self, fmc_ip: str, fmc_username: str, fmc_password: str):
        self.fmc_ip = fmc_ip
        self.fmc_username = fmc_username
        self.fmc_password = fmc_password

        # Authentication and connection preparation for FMC starts
        self.headers = {'Content-Type': 'application/json'}
        self.auth_headers = {}
        self.auth_token = {}
        self.refresh_token = {}

        # initialize HTTPS request parameters: self.auth_headers, self.auth_token, self.refresh_token
        self.authenticate()

        self.refresh_headers = {'X-auth-refresh-token': self.auth_headers.get(
            'X-auth-refresh-token'), 'X-auth-access-token': self.auth_headers.get(
            'X-auth-access-token')}

        self.headers['X-auth-access-token'] = self.auth_token

        self.domain = ''
        # get domain UUID
        self.get_domain()
        # Authentication and connection preparation for FMC ends

    def authenticate(self) -> None:
        api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
        auth_url = "https://" + self.fmc_ip + api_auth_path

        try:
            r = requests.post(auth_url, headers=self.headers, auth=requests.auth.HTTPBasicAuth(
                self.fmc_username, self.fmc_password), verify=False)
            self.auth_headers = r.headers
            self.auth_token = self.auth_headers.get('X-auth-access-token', default=None)
            self.refresh_token = self.auth_headers.get('X-auth-refresh-token', default=None)
            if self.auth_token is None:
                log.error("Authentication not found. Exiting...")
                log.error(r.reason)
                log.error(f'Exiting...')
                sys.exit(1)

        except Exception as err:
            log.error("Error in generating Authentication token --> " + str(err))
            log.error(f'Exiting...')
            sys.exit(1)

    def get_domain(self) -> None:
        self.domain = self.auth_headers['DOMAIN_UUID']

        name_list = []
        uuid_list = []

        domains_dict = json.loads(self.auth_headers['DOMAINS'])
        domain_len = len(domains_dict)
        if domain_len > 1:
            for dict_item in domains_dict:
                name_list.append(dict_item["name"])
                uuid_list.append(dict_item["uuid"])
            i = 0
            while i < domain_len:
                print(i + 1, name_list[i], uuid_list[i])
                i = i + 1
            user_domain = int(
                input("Choose the domain from which time-ranges has to be removed (numeric value):"))
            self.domain = uuid_list[user_domain - 1]

    def get(self, api_url: str) -> List:
        chunk_size = 1000
        param = {'offset': '0', 'limit': chunk_size, 'expanded': True}

        responses = []
        response_page = self.get_request(api_url, param)
        responses.append(response_page)
        payload = response_page.json()
        if 'paging' in payload.keys():

            # while 'items' in payload.keys() and 'next' in payload['paging']:
            while 'items' in payload.keys():
                param['offset'] = str(int(param['offset']) + chunk_size)
                response_page = self.get_request(api_url, param)
                payload = response_page.json()
                if payload.get('items'):
                    responses.append(response_page)
        return responses

    def get_by_id(self, api_url: str) -> Dict:
        r = requests.get(api_url, headers=self.headers, verify=False)

        if r.status_code == 401:
            if 'Access token invalid' in str(r.json()):
                self.refresh()
                r = requests.get(api_url, headers=self.headers, verify=False)

        return r.json()

    def put(self, api_url: str, body: str) -> Dict:
        r = requests.put(api_url, headers=self.headers, data=body, verify=False)

        if r.status_code == 401:
            if 'Access token invalid' in str(r.json()):
                self.refresh()
                r = requests.put(api_url, headers=self.headers, data=body, verify=False)

        return r.json()

        '''
        if 'paging' in payload.keys():
    
            # while 'items' in payload.keys() and 'next' in payload['paging']:
            while 'items' in payload.keys():
                param['offset'] = str(int(param['offset']) + chunk_size)
                response_page = get_request(fmc_ip, fmc_username, fmc_password, api_url, param)
                payload = response_page.json()
                if payload.get('items'):
                    responses.append(response_page)
        '''

        return payload

    def get_request(self, api_url: str, param: Dict):
        r = requests.get(api_url, headers=self.headers, params=param, verify=False)

        if r.status_code == 401:
            if 'Access token invalid' in str(r.json()):
                self.refresh()
                r = self.get_request(api_url, param)

        return r

    def refresh(self) -> None:
        refresh_counter = 1

        log.info('###########################################################')

        refresh_url = "https://" + self.fmc_ip + "/api/fmc_platform/v1/auth/refreshtoken"
        if refresh_counter > 3:
            log.info('Authentication token has already been used 3 times, API re-authentication will be performed')
            self.authenticate()

        try:
            refresh_counter += 1
            r = requests.post(refresh_url, headers=self.refresh_headers, verify=False)
            auth_token = r.headers.get('X-auth-access-token', default=None)
            refresh_token = r.headers.get('X-auth-refresh-token', default=None)
            log.info('auth token-->', auth_token)
            log.info('refresh token-->', refresh_token)
            if not auth_token or not refresh_token:
                log.error('Could not refresh tokens')
                log.error(f'Exiting...')
                sys.exit(1)
            self.headers['X-auth-access-token'] = auth_token
            self.headers['X-auth-refresh-token'] = refresh_token
        except ConnectionError:
            log.error('Could not connect. Max retries exceeded with url')
            log.error(f'Exiting...')
            sys.exit(1)
        except Exception as err:
            log.error("Refresh Function Error  --> " + str(err))
            log.error(f'Exiting...')
            sys.exit(1)
        log.info('Successfully refreshed authorization token')

    def get_fmc_all_acp(self) -> List:
        api_path = "https://" + self.fmc_ip + "/api/fmc_config/v1/domain/" + \
                   self.domain + "/policy/accesspolicies"

        fmc_all_acp_list = []
        acp_range_counter = 0

        log.info('Retrieving all ACPs from FMC\nPlease Wait...')
        all_fmc_acp = self.get(api_path)

        if len(all_fmc_acp) == 1 and all_fmc_acp[0].json()['paging'].get('count') == 0:
            log.error('No ACPs on FMC')
            sys.exit(1)
        else:
            for response_page in all_fmc_acp:

                for fmc_acp in response_page.json()['items']:
                    # pprint(fmc_acp)
                    name = fmc_acp['name']
                    links = fmc_acp['links']['self']
                    fmc_all_acp_list.append([name, links])
                    log.debug(f'{acp_range_counter + 1}: name: {name}, links: {links}')

                    acp_range_counter += 1

        return fmc_all_acp_list

    def get_fmc_acp_id(self, acp_name: str) -> str:
        api_path = "https://" + self.fmc_ip + "/api/fmc_config/v1/domain/" + \
                   self.domain + "/policy/accesspolicies"

        fmc_acp_id = ''

        log.info('Retrieving all ACPs from FMC\nPlease Wait...')
        all_fmc_acp = self.get(api_path)

        if len(all_fmc_acp) == 1 and all_fmc_acp[0].json()['paging'].get('count') == 0:
            log.error('No ACPs on FMC')
            sys.exit(1)
        else:
            for response_page in all_fmc_acp:

                for fmc_acp in response_page.json()['items']:
                    name = fmc_acp['name']

                    if name == acp_name:
                        # pprint(fmc_acp)
                        fmc_acp_id = fmc_acp['id']

        return fmc_acp_id

    def get_acp_rules(self, acp_name: str, acp_id: str, logging_set_to: bool) -> List:
        api_path = "https://" + self.fmc_ip + "/api/fmc_config/v1/domain/" + \
                   self.domain + "/policy/accesspolicies/" + acp_id + "/accessrules"

        bulk_rule_list = []

        log.info(f'Retrieving access rule for ACP with name {acp_name} from FMC\nPlease Wait...')
        fmc_acp_rules = self.get(api_path)

        if fmc_acp_rules[0].status_code == 200:
            if len(fmc_acp_rules) == 1 and fmc_acp_rules[0].json()['paging'].get('count') == 0:
                log.error(f'No access rules in ACP with name {acp_name}')
                sys.exit(1)
            else:
                rules_counter = 0
                for response_page in fmc_acp_rules:
                    for fmc_access_rule in response_page.json()['items']:
                        rules_counter += 1
                        # pprint(fmc_access_rule)
                        rule_name = fmc_access_rule['name']
                        logging_end = fmc_access_rule['logEnd']
                        rule_id = fmc_access_rule['id']
                        rule_action = fmc_access_rule['action']

                        logEnd = fmc_access_rule['logEnd']
                        logBegin = fmc_access_rule['logBegin']
                        logFiles = fmc_access_rule['logFiles']
                        enableSyslog = fmc_access_rule['enableSyslog']
                        sendEventsToFMC = fmc_access_rule['sendEventsToFMC']

                        # will need to get the following fields:
                        fmc_access_rule_to_update = {}
                        fmc_access_rule_to_update['logEnd'] = logEnd
                        fmc_access_rule_to_update['logBegin'] = logBegin
                        fmc_access_rule_to_update['logFiles'] = logFiles
                        fmc_access_rule_to_update['enableSyslog'] = enableSyslog
                        fmc_access_rule_to_update['sendEventsToFMC'] = sendEventsToFMC

                        if self.is_required_to_change_log(rule_action, logging_set_to,
                                                             fmc_access_rule_to_update):
                            log.info(f"Changing logging for rule_name: {rule_name}")
                            fmc_access_rule = self.update_logging_acp_rules(acp_id, rule_id, acp_name,
                                                                            fmc_access_rule, logging_set_to)
                            bulk_rule_list.append(fmc_access_rule)
                        else:
                            log.info(f"No need to change logging for rule_name: {rule_name}")

                        # pprint(fmc_access_rule)
                        log.info(f'rule name: {rule_name}, logging_end: {logging_end}, rule_id: {rule_id}, '
                                     f'rule_action: {rule_action}, logEnd: {logEnd}, logBegin: {logBegin}, '
                                     f'logFiles: {logFiles}, enableSyslog: {enableSyslog}, '
                                     f'sendEventsToFMC: {sendEventsToFMC}')

                log.info(f"Out of {rules_counter} rules {len(bulk_rule_list)} would be changed")

        else:
            log.error(f'Received status code: {fmc_acp_rules[0].status_code}. '
                          f'The following error has occured: {fmc_acp_rules[0].text}')

        return bulk_rule_list

    def __get_acp_rules(self, acp_name: str, acp_id: str) -> List:
        api_path = "https://" + self.fmc_ip + "/api/fmc_config/v1/domain/" + \
                   self.domain + "/policy/accesspolicies/" + acp_id + "/accessrules"

        fmc_all_access_rules_list = []

        log.info(f'Retrieving access rule for ACP with name {acp_name} from FMC\nPlease Wait...')
        fmc_acp_rules = self.get(api_path)

        if fmc_acp_rules[0].status_code == 200:
            if len(fmc_acp_rules) == 1 and fmc_acp_rules[0].json()['paging'].get('count') == 0:
                log.error(f'No access rules in ACP with name {acp_name}')
                sys.exit(1)
            else:
                for response_page in fmc_acp_rules:

                    for fmc_access_rule in response_page.json()['items']:
                        # pprint(fmc_access_rule)
                        name = fmc_access_rule['name']
                        logging_end = fmc_access_rule['logEnd']
                        rule_id = fmc_access_rule['id']
                        rule_action = fmc_access_rule['action']

                        logEnd = fmc_access_rule['logEnd']
                        logBegin = fmc_access_rule['logBegin']
                        logFiles = fmc_access_rule['logFiles']
                        enableSyslog = fmc_access_rule['enableSyslog']
                        sendEventsToFMC = fmc_access_rule['sendEventsToFMC']

                        # pprint(fmc_access_rule)
                        log.info(f'rule name: {name}, logging_end: {logging_end}, rule_id: {rule_id}, '
                                     f'rule_action: {rule_action}, logEnd: {logEnd}, logBegin: {logBegin}, '
                                     f'logFiles: {logFiles}, enableSyslog: {enableSyslog}, '
                                     f'sendEventsToFMC: {sendEventsToFMC}')

                        fmc_all_access_rules_list.append([name, logging_end, rule_id, rule_action, logEnd,
                                                          logBegin, logFiles, enableSyslog, sendEventsToFMC])
        else:
            log.error(f'Received status code: {fmc_acp_rules[0].status_code}. '
                          f'The following error has occured: {fmc_acp_rules[0].text}')

        return fmc_all_access_rules_list

    @staticmethod
    def is_required_to_change_log(rule_action, logging_set_to: bool, fmc_access_rule_to_update: Dict):
        is_required_to_change_log = True

        if rule_action in ['ALLOW', 'TRUST', 'BLOCK_INTERACTIVE', 'BLOCK_RESET_INTERACTIVE', 'BLOCK', 'BLOCK_RESET']:
            # if enable logging for access rule
            if logging_set_to:
                if rule_action in ['ALLOW', 'TRUST', 'BLOCK_INTERACTIVE', 'BLOCK_RESET_INTERACTIVE']:
                    # enable logging for only "Log at End of Connection" - if it's allow and similar actions
                    if fmc_access_rule_to_update.get('logEnd', False) and \
                            not fmc_access_rule_to_update.get('logBegin', True) and \
                            fmc_access_rule_to_update.get('sendEventsToFMC', False):
                        is_required_to_change_log = False
                else:
                    # otherwise - enable logging for only "Log at Beginning of Connection"
                    if not fmc_access_rule_to_update.get('logEnd', True) and \
                            fmc_access_rule_to_update.get('logBegin', False) and \
                            fmc_access_rule_to_update.get('sendEventsToFMC', False):
                        is_required_to_change_log = False

            # if disable logging for access rule
            else:
                # disable all logging for access rule
                if not fmc_access_rule_to_update.get('logEnd', True) and \
                        not fmc_access_rule_to_update.get('logBegin', True) and \
                        not fmc_access_rule_to_update.get('logFiles', True) and \
                        not fmc_access_rule_to_update.get('enableSyslog', True) and \
                        not fmc_access_rule_to_update.get('sendEventsToFMC', True):
                    is_required_to_change_log = False

        elif rule_action == 'MONITOR':
            is_required_to_change_log = False

        else:
            log.error(f'Incorrect rule_action get: {rule_action}')
            is_required_to_change_log = False

        return is_required_to_change_log

    def update_logging_acp_rules(self, acp_id: str, rule_id: str, acp_name: str,
                                 fmc_access_rule: Dict, logging_set_to: bool) -> Dict:
        api_path = "https://" + self.fmc_ip + "/api/fmc_config/v1/domain/" + \
                   self.domain + "/policy/accesspolicies/" + \
                   acp_id + "/accessrules/" + rule_id

        log.info(f'api_path: {api_path}')

        log.info(f'Retrieving access rule for ACP with name {acp_name} and '
                     f'rule_id: {rule_id} from FMC\nPlease Wait...')

        fmc_access_rule_to_update = fmc_access_rule

        rule_action = fmc_access_rule.get("action")

        if rule_action in ['ALLOW', 'TRUST', 'BLOCK_INTERACTIVE', 'BLOCK_RESET_INTERACTIVE', 'BLOCK', 'BLOCK_RESET']:
            # if enable logging for access rule
            if logging_set_to:
                if rule_action in ['ALLOW', 'TRUST', 'BLOCK_INTERACTIVE', 'BLOCK_RESET_INTERACTIVE']:
                    # enable logging for only "Log at End of Connection" - if it's allow and similar actions
                    fmc_access_rule_to_update['logEnd'] = True
                    fmc_access_rule_to_update['logBegin'] = False
                    fmc_access_rule_to_update['sendEventsToFMC'] = True
                else:
                    # otherwise - enable logging for only "Log at Beginning of Connection"
                    fmc_access_rule_to_update['logEnd'] = False
                    fmc_access_rule_to_update['logBegin'] = True
                    fmc_access_rule_to_update['sendEventsToFMC'] = True

            # if disable logging for access rule
            else:
                # disable all logging for access rule
                fmc_access_rule_to_update['logEnd'] = False
                fmc_access_rule_to_update['logBegin'] = False
                fmc_access_rule_to_update['logFiles'] = False
                fmc_access_rule_to_update['enableSyslog'] = False
                fmc_access_rule_to_update['sendEventsToFMC'] = False

        elif rule_action == 'MONITOR':
            pass

        else:
            log.error(f'Incorrect rule_action get: {rule_action}')

        fmc_access_rule_to_update.pop('metadata')
        fmc_access_rule_to_update.pop('links')
        return fmc_access_rule_to_update

    def __update_logging_acp_rules(self, access_rule_obj: AccessRule, logging_set_to: bool) -> None:
        api_path = "https://" + self.fmc_ip + "/api/fmc_config/v1/domain/" + \
                   self.domain + "/policy/accesspolicies/" + \
                   access_rule_obj.acp_id + "/accessrules/" + access_rule_obj.rule_id

        log.info(f'api_path: {api_path}')

        log.info(f'Retrieving access rule for ACP with name {access_rule_obj.acp_name} and '
                     f'rule_id: {access_rule_obj.rule_id} from FMC\nPlease Wait...')
        fmc_access_rule = self.get_by_id(api_path)

        fmc_access_rule_to_update = fmc_access_rule

        # pprint(fmc_access_rule_to_update)

        rule_action = fmc_access_rule.get("action")

        # log.info(f'rule_action: {rule_action}')

        if rule_action in ['ALLOW', 'TRUST', 'BLOCK_INTERACTIVE', 'BLOCK_RESET_INTERACTIVE', 'BLOCK', 'BLOCK_RESET']:
            # if enable logging for access rule
            if logging_set_to:
                if rule_action in ['ALLOW', 'TRUST', 'BLOCK_INTERACTIVE', 'BLOCK_RESET_INTERACTIVE']:
                    # enable logging for only "Log at End of Connection" - if it's allow and similar actions
                    fmc_access_rule_to_update['logEnd'] = True
                    fmc_access_rule_to_update['logBegin'] = False
                    fmc_access_rule_to_update['sendEventsToFMC'] = True
                else:
                    # otherwise - enable logging for only "Log at Beginning of Connection"
                    fmc_access_rule_to_update['logEnd'] = False
                    fmc_access_rule_to_update['logBegin'] = True
                    fmc_access_rule_to_update['sendEventsToFMC'] = True

            # if disable logging for access rule
            else:
                # disable all logging for access rule
                fmc_access_rule_to_update['logEnd'] = False
                fmc_access_rule_to_update['logBegin'] = False
                fmc_access_rule_to_update['logFiles'] = False
                fmc_access_rule_to_update['enableSyslog'] = False
                fmc_access_rule_to_update['sendEventsToFMC'] = False

            fmc_access_rule_to_update.pop('metadata')
            fmc_access_rule_to_update.pop('links')
            access_rule_obj.set_access_rule_dict(fmc_access_rule_to_update)

        elif rule_action == 'MONITOR':
            pass

        else:
            log.error(f'Incorrect rule_action get: {rule_action}')

    def put_logging_acp_rules(self, acp_id: str, bulk_rule_list: List) -> None:
        api_path = "https://" + self.fmc_ip + "/api/fmc_config/v1/domain/" + \
                   self.domain + "/policy/accesspolicies/" + \
                   acp_id + "/accessrules?bulk=true"

        response = self.put(api_path, json.dumps(bulk_rule_list))
        log.info(f'put response for bulk request:\n'
                     f'{response}')

        '''
        print('###########################')
        pprint(f'fmc_access_rule_to_update:\n{fmc_access_rule_to_update}')
        print('###########################')
        '''

        # fmc_access_rule_to_update = {'action': 'ALLOW', 'logBegin': False, 'logEnd': False}

        '''
        response = self.put(api_path, json.dumps(fmc_access_rule_to_update))
        log.info(f'put response for "{access_rule_obj.rule_name}":\n'
                     f'{response}')
        '''


'''
class AccessRule(FMC):
    def __init__(self, fmc_ip: str, fmc_username: str, fmc_password: str):
        super().__init__(fmc_ip, fmc_username, fmc_password)
'''

'''
def del_time_range(fmc_ip: str, fmc_username: str, fmc_password: str, name: str, del_url: str) -> bool:
    time_range_removed = False

    try:
        r = requests.delete(del_url, headers=headers, verify=False)
        status_code = r.status_code
        resp = r.json()

        if status_code == 200 or status_code == 201:
            log.debug(f"Successfully removed {name}")
            time_range_removed = True

        elif status_code == 401:
            if 'Access token invalid' in str(resp):
                logging.warning(f"Refreshing API token")
                refresh(fmc_ip, fmc_username, fmc_password)
                time_range_removed = del_time_range(fmc_ip, fmc_username, fmc_password, name, del_url)

        else:
            log.error(f'status_code: {status_code}, '
                          f'error description: ({resp["error"]["messages"][0]["description"]})')

        return time_range_removed

    except requests.exceptions.HTTPError as err:
        log.error("Error in connection --> " + str(err))

    finally:
        if r:
            r.close()


def del_fmc_all_time_ranges(fmc_ip: str, fmc_username: str, fmc_password: str, list_time_ranges_to_del: List) -> List:
    number_of_ranges_to_del = len(list_time_ranges_to_del)
    list_of_time_ranges_unable_to_remove = []

    for counter, time_range in enumerate(list_time_ranges_to_del, start=1):
        name = time_range[0]
        link = time_range[1]

        if del_time_range(fmc_ip, fmc_username, fmc_password, name, link):
            log.info(f'fmc: removed time-range: {name}')
        else:
            logging.warning(f'fmc: unable to remove time-range: {name}')
            list_of_time_ranges_unable_to_remove.append(name)

        if counter % 10 == 0:
            log.info(f'number of time-ranges to remove: {number_of_ranges_to_del - counter}')
        else:
            pass

    return list_of_time_ranges_unable_to_remove


def get_fmc_all_time_ranges_list(fmc_ip: str, fmc_username: str, fmc_password: str, domain: str) -> List:
    api_path = "https://" + fmc_ip + "/api/fmc_config/v1/domain/" + \
               domain + "/object/timeranges"

    fmc_all_time_range_list = []
    time_range_counter = 0

    log.info('Retrieving all time-ranges from FMC\nPlease Wait...')
    all_fmc_time_ranges = get(fmc_ip, fmc_username, fmc_password, api_path)

    if len(all_fmc_time_ranges) == 1 and all_fmc_time_ranges[0].json()['paging'].get('count') == 0:
        log.error('No time-ranges present on FMC')
        exit(1)
    else:
        for response_page in all_fmc_time_ranges:

            for fmc_time_range in response_page.json()['items']:
                name = fmc_time_range['name']
                links = fmc_time_range['links']['self']
                fmc_all_time_range_list.append([name, links])
                log.debug(f'{time_range_counter + 1}: name: {name}, links: {links}')

                time_range_counter += 1

    return fmc_all_time_range_list
'''


def main():
    acp_name = config.acp_name

    # config.acp_name =

    if config.logging_mode == 'enable':
        disable_access_rule_logging = False
    elif config.logging_mode == 'disable':
        disable_access_rule_logging = True
    else:
        log.error(f'Incorrect value of "logging_mode" specified in config.py. '
                      f'Must be \'enable\' or \'disable\'. Found: \'{config.logging_mode}\'')
        sys.exit(1)

    fmc_obj = FMC(config.fmc_ip, config.fmc_username, config.fmc_password)

    # Get ACP id from FMC:
    acp_id = fmc_obj.get_fmc_acp_id(acp_name)

    if not acp_id:
        log.info(f'No ACP with name {acp_name} found')
        sys.exit(1)
    else:
        log.info(f'name: {acp_name}, acp_id: {acp_id}')
        bulk_rule_list = fmc_obj.get_acp_rules(acp_name, acp_id, not disable_access_rule_logging)

        if len(bulk_rule_list) > 0:
            n = 1000
            bulk_rule_list_list = [bulk_rule_list[i:i + n] for i in range(0, len(bulk_rule_list), n)]
            for counter, bulk_rule_list in enumerate(bulk_rule_list_list):
                log.info(f"Putting page #{counter+1} of {len(bulk_rule_list)} access rules")
                fmc_obj.put_logging_acp_rules(acp_id, bulk_rule_list)
        else:
            log.info("No access rules to update. Exiting.")

        '''
        # pprint(fmc_acp_rules)

        access_rule_obj_list = []
        for acp_rule in fmc_acp_rules:
            fmc_access_rule_to_update = {}
            rule_name = acp_rule[0]
            rule_id = acp_rule[2]
            rule_action = acp_rule[3]

            # will need to get the following fields:
            fmc_access_rule_to_update['logEnd'] = acp_rule[4]
            fmc_access_rule_to_update['logBegin'] = acp_rule[5]
            fmc_access_rule_to_update['logFiles'] = acp_rule[6]
            fmc_access_rule_to_update['enableSyslog'] = acp_rule[7]
            fmc_access_rule_to_update['sendEventsToFMC'] = acp_rule[8]

            if fmc_obj.is_required_to_change_log(rule_action, not disable_access_rule_logging,
                                                 fmc_access_rule_to_update):
                log.info(f"Changing logging for rule_name: {rule_name}")
                access_rule_obj_list.append(AccessRule(acp_name, acp_id, rule_name, rule_id, {}))
            else:
                log.info(f"No need to change logging for rule_name: {rule_name}")

        for acp_rule_obj in access_rule_obj_list:
            fmc_obj.update_logging_acp_rules(acp_rule_obj, not disable_access_rule_logging)

        bulk_rule_list = []
        for access_rule_obj in access_rule_obj_list:
            rule_dict = access_rule_obj.get_access_rule_dict()
            bulk_rule_list.append(rule_dict)

        if len(bulk_rule_list) > 0:
            fmc_obj.put_logging_acp_rules(acp_id, bulk_rule_list)
        else:
            log.info("No access rules to update. Exiting.")
        '''


    '''
    # Get all ACPs from FMC:
    list_all_fmc_acp = get_fmc_all_acp(fmc_ip, username, password, domain)
    log.info(f'Number of ACPs on FMC: {len(list_all_fmc_acp)}')
    log.info(list_all_fmc_acp)


    # Compare all time-ranges from FMC to time-ranges from ASA's config:
    list_fmc_time_ranges_to_del = get_time_ranges_to_del_list(list_all_fmc_time_ranges, list_asa_time_ranges_to_del)
    log.debug(f'time-ranges to remove from FMC: {list_fmc_time_ranges_to_del}')
    log.info(f'number of time-ranges to remove from FMC: {len(list_fmc_time_ranges_to_del)}')

    # Delay for 1 second to let logging module output all to console:
    time.sleep(1)

    input_chars_not_correct = True
    answer = ''

    while input_chars_not_correct:
        answer = input(f"Do you want to remove {len(list_fmc_time_ranges_to_del)} time-ranges from FMC? (y/n): ")
        answer = answer.lower()

        if answer not in ['y', 'n']:
            continue
        else:
            input_chars_not_correct = False

    if answer == 'y':
        # Remove from FMC time-ranges found in ASA's configuration:
        list_of_time_ranges_unable_to_remove = \
            del_fmc_all_time_ranges(fmc_ip, username, password, list_fmc_time_ranges_to_del)

        # Check whether all time-ranges have been removed:
        if list_of_time_ranges_unable_to_remove:
            logging.warning(f'There are time-ranges that script wasn\'t able to remove from FMC:')
            for time_range_name in list_of_time_ranges_unable_to_remove:
                logging.warning(f'time-range not removed: {time_range_name}')
        else:
            pass

        # Get all time-ranges from FMC after removal:
        list_all_fmc_time_ranges = get_fmc_all_time_ranges_list(fmc_ip, username, password, domain)
        log.info(f'Number of time-ranges on FMC after time-ranges removal: {len(list_all_fmc_time_ranges)}.')
        log.debug(list_all_fmc_time_ranges)
    else:
        log.info(f'You\'ve chosen not to remove time-ranges from FMC.')
    '''


if __name__ == '__main__':
    main()
