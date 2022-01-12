#!/usr/bin/env python
#  -*- coding: utf-8 -*-

###############################
# ABOUT THIS SCRIPT (READ ME) #
###############################
#
# Get all time-ranges from ASA's config and remove them from FMC
# ----------------
# Author: Sergey Sazhin (sesazhin@cisco.com)
# Property of: Cisco Systems, Inc.
# Version: 0.1
# Release Date: 26/11/2021

# What this script does:
# 1. Get all time-ranges from file with ASA's configuration (file_to_parse_name).
# ASA's configuration contains all time-ranges that has to be removed from FMC
# 2. Gets all time-ranges from FMC
# 3. Removes all time-ranges from FMC that exists on ASA
# (if some time-range is used by device on FMC - it's skipped and script proceeds to the next time-range)

import json
import logging
import logging.handlers
import re
import requests
import sys
import time
from typing import List
from typing import Dict
import warnings


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(funcName)s - %(levelname)s - %(message)s')
warnings.filterwarnings('ignore', message='Unverified HTTPS request')


def get(fmc_ip: str, fmc_username: str, fmc_password: str, api_url: str):
    chunk_size = 1000
    param = {'offset': '0', 'limit': chunk_size, 'expanded': True}

    responses = []
    response_page = get_request(fmc_ip, fmc_username, fmc_password, api_url, param)
    responses.append(response_page)
    payload = response_page.json()
    if 'paging' in payload.keys():

        # while 'items' in payload.keys() and 'next' in payload['paging']:
        while 'items' in payload.keys():
            param['offset'] = str(int(param['offset']) + chunk_size)
            response_page = get_request(fmc_ip, fmc_username, fmc_password, api_url, param)
            payload = response_page.json()
            if payload.get('items'):
                responses.append(response_page)
    return responses


def get_request(fmc_ip: str, fmc_username: str, fmc_password: str, api_url: str, param: Dict):
    r = requests.get(api_url, headers=headers, params=param, verify=False)

    if r.status_code == 401:
        if 'Access token invalid' in str(r.json()):
            refresh(fmc_ip, fmc_username, fmc_password)
            r = get_request(fmc_ip, fmc_username, fmc_password, api_url, param)

    return r


def get_domain() -> str:
    domain = auth_headers['DOMAIN_UUID']

    name_list = []
    uuid_list = []

    domains_dict = json.loads(auth_headers['DOMAINS'])
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
        domain = uuid_list[user_domain - 1]

    return domain


def authenticate(fmc_ip: str, fmc_username: str, fmc_password: str):
    api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
    auth_url = "https://" + fmc_ip + api_auth_path

    try:

        r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(
            fmc_username, fmc_password), verify=False)
        auth_headers = r.headers
        auth_token = auth_headers.get('X-auth-access-token', default=None)
        refresh_token = auth_headers.get('X-auth-refresh-token', default=None)
        if auth_token is None:
            logging.error("Authentication not found. Exiting...")
            logging.error(r.reason)
            logging.error(f'Exiting...')
            sys.exit(1)
        else:
            return auth_headers, auth_token, refresh_token
    except Exception as err:
        logging.error("Error in generating Authentication token --> " + str(err))
        logging.error(f'Exiting...')
        sys.exit(1)


def refresh(fmc_ip: str, fmc_username: str, fmc_password: str) -> None:
    refresh_counter = 1

    logging.info('###########################################################')

    refresh_url = "https://" + fmc_ip + "/api/fmc_platform/v1/auth/refreshtoken"
    if refresh_counter > 3:
        logging.info('Authentication token has already been used 3 times, API re-authentication will be performed')
        authenticate(fmc_ip, fmc_username, fmc_password)

    try:
        refresh_counter += 1
        r = requests.post(refresh_url, headers=refresh_headers, verify=False)
        auth_token = r.headers.get('X-auth-access-token', default=None)
        refresh_token = r.headers.get('X-auth-refresh-token', default=None)
        logging.info('auth token-->', auth_token)
        logging.info('refresh token-->', refresh_token)
        if not auth_token or not refresh_token:
            logging.error('Could not refresh tokens')
            logging.error(f'Exiting...')
            sys.exit(1)
        headers['X-auth-access-token'] = auth_token
        headers['X-auth-refresh-token'] = refresh_token
    except ConnectionError:
        logging.error('Could not connect. Max retries exceeded with url')
        logging.error(f'Exiting...')
        sys.exit(1)
    except Exception as err:
        logging.error("Refresh Function Error  --> " + str(err))
        logging.error(f'Exiting...')
        sys.exit(1)
    logging.info('Successfully refreshed authorization token')


def del_time_range(fmc_ip: str, fmc_username: str, fmc_password: str, name: str, del_url: str) -> bool:
    time_range_removed = False

    try:
        r = requests.delete(del_url, headers=headers, verify=False)
        status_code = r.status_code
        resp = r.json()

        if status_code == 200 or status_code == 201:
            logging.debug(f"Successfully removed {name}")
            time_range_removed = True

        elif status_code == 401:
            if 'Access token invalid' in str(resp):
                logging.warning(f"Refreshing API token")
                refresh(fmc_ip, fmc_username, fmc_password)
                time_range_removed = del_time_range(fmc_ip, fmc_username, fmc_password, name, del_url)

        else:
            logging.error(f'status_code: {status_code}, '
                          f'error description: ({resp["error"]["messages"][0]["description"]})')

        return time_range_removed

    except requests.exceptions.HTTPError as err:
        logging.error("Error in connection --> " + str(err))

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
            logging.info(f'fmc: removed time-range: {name}')
        else:
            logging.warning(f'fmc: unable to remove time-range: {name}')
            list_of_time_ranges_unable_to_remove.append(name)

        if counter % 10 == 0:
            logging.info(f'number of time-ranges to remove: {number_of_ranges_to_del - counter}')
        else:
            pass

    return list_of_time_ranges_unable_to_remove


def get_time_ranges_from_file(file_to_parse: str) -> List:
    list_time_ranges = []
    try:
        with open(file_to_parse, 'r') as f:
            logging.info(f'Parsing file: {file_to_parse}')
            for line in f.readlines():
                match_time_range = re.search(r'^time-range (\w+)', line)

                if match_time_range:
                    time_range_name = match_time_range.group(1)
                    list_time_ranges.append(time_range_name)

        return list_time_ranges

    except PermissionError:

        logging.exception('Unable to read from log file: {}. We will skip this file then.'.format(file_to_parse))

        return []

    except FileNotFoundError:
        logging.exception(
            'The following file doesn\'t exist: {}. We will skip this file then.'.format(file_to_parse))

        return []


def get_fmc_all_time_ranges_list(fmc_ip: str, fmc_username: str, fmc_password: str, domain: str) -> List:
    api_path = "https://" + fmc_ip + "/api/fmc_config/v1/domain/" + \
               domain + "/object/timeranges"

    fmc_all_time_range_list = []
    time_range_counter = 0

    logging.info('Retrieving all time-ranges from FMC\nPlease Wait...')
    all_fmc_time_ranges = get(fmc_ip, fmc_username, fmc_password, api_path)

    if len(all_fmc_time_ranges) == 1 and all_fmc_time_ranges[0].json()['paging'].get('count') == 0:
        logging.error('No time-ranges present on FMC')
        exit(1)
    else:
        for response_page in all_fmc_time_ranges:

            for fmc_time_range in response_page.json()['items']:
                name = fmc_time_range['name']
                links = fmc_time_range['links']['self']
                fmc_all_time_range_list.append([name, links])
                logging.debug(f'{time_range_counter + 1}: name: {name}, links: {links}')

                time_range_counter += 1

    return fmc_all_time_range_list


def get_time_ranges_to_del_list(list_all_fmc_time_ranges: List, list_all_asa_time_ranges: List) -> List:
    list_time_ranges_to_del = []
    for name, links in list_all_fmc_time_ranges:
        if name in list_all_asa_time_ranges:
            list_time_ranges_to_del.append([name, links])
            logging.debug(f'name: {name}, links: {links}')
            logging.info(f'time-range to remove: {name}')
        else:
            pass

    return list_time_ranges_to_del


def main():
    file_to_parse_name = '<filename>'  # in the same directory with the script

    # FMC details and credentials
    fmc_ip = '<fmc_ip>'
    username = '<fmc_username>' # user with read/write privileges on FMC via API
    password = '<fmc_password>' # user with read/write privileges on FMC via API

    list_asa_time_ranges_to_del = get_time_ranges_from_file(file_to_parse_name)
    if list_asa_time_ranges_to_del:
        logging.info(f'number of time-ranges found on ASA: {len(list_asa_time_ranges_to_del)}')

        # Authentication and connection preparation for FMC starts
        global headers
        global auth_headers
        global refresh_headers
        headers = {'Content-Type': 'application/json'}
        auth_headers, auth_token, refresh_token = authenticate(fmc_ip, username, password)

        refresh_headers = {'X-auth-refresh-token': auth_headers.get(
            'X-auth-refresh-token'), 'X-auth-access-token': auth_headers.get(
            'X-auth-access-token')}

        headers['X-auth-access-token'] = auth_token

        domain = get_domain()
        # Authentication and connection preparation for FMC ends

        # Get all time-ranges from FMC:
        list_all_fmc_time_ranges = get_fmc_all_time_ranges_list(fmc_ip, username, password, domain)
        logging.info(f'Number of time-ranges on FMC: {len(list_all_fmc_time_ranges)}')
        logging.debug(list_all_fmc_time_ranges)

        # Compare all time-ranges from FMC to time-ranges from ASA's config:
        list_fmc_time_ranges_to_del = get_time_ranges_to_del_list(list_all_fmc_time_ranges, list_asa_time_ranges_to_del)
        logging.debug(f'time-ranges to remove from FMC: {list_fmc_time_ranges_to_del}')
        logging.info(f'number of time-ranges to remove from FMC: {len(list_fmc_time_ranges_to_del)}')

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
            logging.info(f'Number of time-ranges on FMC after time-ranges removal: {len(list_all_fmc_time_ranges)}.')
            logging.debug(list_all_fmc_time_ranges)
        else:
            logging.info(f'You\'ve chosen not to remove time-ranges from FMC.')

    else:
        logging.info(f'No time-ranges in {file_to_parse_name} found. Nothing to delete from FMC.')
        logging.info(f'Exiting...')
        exit(1)


if __name__ == '__main__':
    main()
