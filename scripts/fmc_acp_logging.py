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

# What this script does:
# 1. Takes Access Control Policy (ACP) name
# 2. Gets all access control rules for a specified ACP
# 3. Disables or enables logging in all* rules for a specified ACP
# *those rules that already have logging configured in a right way - skipped

import json
import logging.handlers
import requests
from requests.auth import HTTPBasicAuth
import sys
from typing import List
from typing import Dict
import warnings

from pprint import pprint

global config_file_name
config_file_name = 'config.py'
try:
    import config
except ModuleNotFoundError:
    print(f"Error: Not able to find {config_file_name} file in a directory with a script. Exiting.")
    sys.exit(1)

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
            r = requests.post(auth_url, headers=self.headers, auth=HTTPBasicAuth(
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

    def get_acp_rules_update_dict(self, acp_name: str, acp_id: str, logging_set_to: bool) -> List:
        api_path = "https://" + self.fmc_ip + "/api/fmc_config/v1/domain/" + \
                   self.domain + "/policy/accesspolicies/" + acp_id + "/accessrules"

        bulk_rule_list = []

        log.info(f'Retrieving access rules for ACP with name \'{acp_name}\' from FMC\n'
                 f'Please Wait... (might take a couple of minutes)')
        fmc_acp_rules = self.get(api_path)

        if fmc_acp_rules[0].status_code == 200:
            if len(fmc_acp_rules) == 1 and fmc_acp_rules[0].json()['paging'].get('count') == 0:
                log.error(f'No access rules in ACP with name {acp_name}')
                sys.exit(1)
            else:

                total_rules_number = 0

                for response_page in fmc_acp_rules:
                    total_rules_number += len(response_page.json()['items'])

                log.info(f'Found {total_rules_number} rules in ACP \'{acp_name}\'')

                rules_counter = 0
                for response_page in fmc_acp_rules:
                    for fmc_access_rule in response_page.json()['items']:
                        rules_counter += 1
                        # pprint(fmc_access_rule)
                        rule_name = fmc_access_rule.get('name', '')
                        rule_id = fmc_access_rule.get('id', '')
                        rule_action = fmc_access_rule.get('action', '')

                        logEnd = fmc_access_rule.get('logEnd', '')
                        logBegin = fmc_access_rule.get('logBegin', '')
                        logFiles = fmc_access_rule.get('logFiles', '')
                        enableSyslog = fmc_access_rule.get('enableSyslog', '')
                        sendEventsToFMC = fmc_access_rule.get('sendEventsToFMC', '')

                        # will need to get the following fields:
                        fmc_access_rule_to_update = {'logEnd': logEnd, 'logBegin': logBegin, 'logFiles': logFiles,
                                                     'enableSyslog': enableSyslog, 'sendEventsToFMC': sendEventsToFMC}

                        if self.is_required_to_change_log(rule_action, logging_set_to, fmc_access_rule_to_update):
                            log.info(f"{rules_counter}: Changing logging for rule_name: '{rule_name}'")

                            fmc_access_rule = self.update_logging_acp_rules(fmc_access_rule, logging_set_to)
                            bulk_rule_list.append(fmc_access_rule)

                        else:
                            log.info(f"{rules_counter}: No need to change logging for rule_name: {rule_name}")

                        # pprint(fmc_access_rule)
                        log.debug(f'rule name: {rule_name}, rule_id: {rule_id}, '
                                     f'rule_action: {rule_action}, logEnd: {logEnd}, logBegin: {logBegin}, '
                                     f'logFiles: {logFiles}, enableSyslog: {enableSyslog}, '
                                     f'sendEventsToFMC: {sendEventsToFMC}')

                log.info(f"{len(bulk_rule_list)} rules out of {rules_counter} would be updated")

        else:
            log.error(f'Received status code: {fmc_acp_rules[0].status_code}. '
                          f'The following error has occurred: {fmc_acp_rules[0].text}')

        return bulk_rule_list

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

    @staticmethod
    def update_logging_acp_rules(fmc_access_rule: Dict, logging_set_to: bool) -> Dict:
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

    def put_logging_acp_rules(self, acp_id: str, bulk_rule_list: List) -> Dict:
        api_path = "https://" + self.fmc_ip + "/api/fmc_config/v1/domain/" + \
                   self.domain + "/policy/accesspolicies/" + \
                   acp_id + "/accessrules?bulk=true"

        response = self.put(api_path, json.dumps(bulk_rule_list))
        log.debug(f'put response for bulk request:\n'
                     f'{response}')

        return response


def main():
    log.info("################################################")
    log.info(f"Got the following parameters from {config_file_name}:")
    log.info(f"log_path: '{config.log_path}'")
    log.info(f"log_level: '{config.log_level}'")
    log.info(f"fmc_ip: '{config.fmc_ip}'")
    log.info(f"fmc_username: '{config.fmc_username}'")
    log.info(f"acp_name: '{config.acp_name}'")
    log.info(f"logging_mode: '{config.logging_mode}'")
    log.info("################################################")

    if not config.log_path or not config.log_level or not config.fmc_ip or \
            not config.fmc_username or not config.acp_name or not config.logging_mode:
        log.error(f'Some of parameters in {config_file_name} is not specified. '
                  f'Please check the list above and make changes in {config_file_name}')

    else:

        acp_name = config.acp_name

        if config.logging_mode == 'enable':
            disable_access_rule_logging = False
        elif config.logging_mode == 'disable':
            disable_access_rule_logging = True
        else:
            log.error(f'Incorrect value of "logging_mode" specified in {config_file_name}. '
                          f'Must be \'enable\' or \'disable\'. Found: \'{config.logging_mode}\'')
            sys.exit(1)

        fmc_obj = FMC(config.fmc_ip, config.fmc_username, config.fmc_password)

        # Get ACP id from FMC:
        acp_id = fmc_obj.get_fmc_acp_id(acp_name)

        if not acp_id:
            log.info(f'No ACP with name {acp_name} found')
            sys.exit(1)
        else:
            log.debug(f'acp_name: {acp_name}')
            log.debug(f'acp_id: {acp_id}')
            bulk_rule_list = fmc_obj.get_acp_rules_update_dict(acp_name, acp_id, not disable_access_rule_logging)

            total_rules_to_update = len(bulk_rule_list)

            put_chunk_size = 1000
            if total_rules_to_update > 0:
                total_updated_rules_number = 0
                bulk_rule_list_list = [bulk_rule_list[i:i + put_chunk_size]
                                       for i in range(0, len(bulk_rule_list), put_chunk_size)]
                for counter, bulk_rule_list in enumerate(bulk_rule_list_list):
                    log.info(f"Putting page #{counter+1} of {total_rules_to_update} access rules. "
                             f"{round(put_chunk_size*counter*100/total_rules_to_update)} % done")
                    put_response = fmc_obj.put_logging_acp_rules(acp_id, bulk_rule_list)
                    put_response_error = put_response.get('error', '')
                    if not put_response_error:
                        updated_rules_number = len(put_response.get('items', []))

                        (lambda x, y: x if x < y else y)(total_rules_to_update, put_chunk_size)

                        if updated_rules_number == (lambda x, y: x if x < y else y)(total_rules_to_update, put_chunk_size):
                            log.info(f"Successfully updated {updated_rules_number} access rules")
                            total_updated_rules_number += updated_rules_number
                        else:
                            log.error(f"{updated_rules_number} rules has been updated which doesn\'t equal to "
                                      f"a page size: "
                                      f"{(lambda x, y: x if x < y else y)(total_rules_to_update, put_chunk_size)}. "
                                      f"Some of them might be not updated. Please check manually.")
                    else:
                        put_error_message = put_response.get('error', '').get('messages')[0].get('description')
                        log.error(f"The following error has occurred while trying to update page #{counter+1}: "
                                  f"'{put_error_message}'")

                if total_updated_rules_number == total_rules_to_update:
                    if total_rules_to_update > put_chunk_size:
                        log.info(f'Successfully updated all {total_rules_to_update} access rules')
                else:
                    log.error(f'Not all rules has been updated. '
                              f'Updated rules: {total_updated_rules_number} total rules: {total_rules_to_update}. '
                              f'Please check the log above for errors.')

            else:
                log.info("No access rules to update. Exiting.")


if __name__ == '__main__':
    main()
