# logging
import logging.handlers as handlers
import logging
import traceback
import sys
import os
# misc
import time
import re
import csv
import pickle
import http.client
import datetime
import base64
import json
# S3 imports
# import boto3
# import json
# import io

#######################
# static declarations #
#######################

LOGGER = "cmdb"
ZOOM_CALENDAR_ID = "8_y8tfAPSHqofSOOaaTDSQ"
IGNORED_ZOOM_LOCATIONS = ["oBQf0J2ETLqXyOxHtoyWWw", "_rOFKHgiSDqDI9i-1osy9A"]
CMDB_SCHEMA = {
    "room_name": "",
    "site": "",
    "floor": 0,
    "room_capacity": 0,
    "room_email": "",
    "provider": "",
    "provider_device_id": "",
    "provider_software_version": "",
    "provider_status": "",
    "manufacturer": "",
    "model": "",
    "firmware_version": "",
    "device_type": "",
    "device_name": "",
    "serial": "",
    "ip": "",
    "mac_address": "",
    "release_date": "2000-1-1",  # user defined
    "manufacturer_eol": "2000-1-1",  # user defined
    "cost_usd": 0,  # user defined
    "bcg_eol": "2000-1-1",  # user defined
    "first_seen": "2000-1-1",  # programitically defined
    "last_seen": "2000-1-1"  # programatically defined
}
######################
# class declarations #
######################


class Zoom(object):
    """Requires account id, client id, and client secret.  
    Run .get_token() after instantion to acquire a token.
    To use this module fully it requires the following API permissions: `dashboard_zr:read:admin` `device:write:admin` `dashboard_home:read:admin` `room:write:admin`


    Args:
        account_id (Str): Zoom account ID
        client_id (Str): Zoom app client ID
        client_secret (Str): Oauth2.0 client secret
        logger (Str): The name of the logger (if using)
    """

    def __init__(self, account_id, client_id, client_secret, logger="zoom"):
        self.account_id = account_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.host = "api.zoom.us"
        self.token = None
        self.token_expiration = datetime.datetime.now(
            datetime.UTC)  # init to avoid type errors on init
        self.headers = {"Content-Type": "application/json"}
        self.timeout = 20  # seconds
        # number of calls out of 1000 milliseconds (1000 / calls per second)
        self.rate_limit = 25
        self.logger = logging.getLogger(logger)

    def call(self, method, uri, payload=None):
        """
        Args:
            method (str): GET, POST, PUT, PATCH
            uri (str): API endpoint
            payload (str): optional for post, put, patch methods
        Raises:
            ZoomRequestFailed: Generic HTTP response codes taken from API documentation

        Returns:
            Dict: Returns JSON formatted as Python Dict
        """
        conn = http.client.HTTPSConnection(self.host, timeout=self.timeout)
        api_return_value = None
        response_array = []
        base_uri = uri
        while True:
            call_rate_min_time = datetime.datetime.now(
            ) + datetime.timedelta(milliseconds=self.rate_limit)
            if payload:
                conn.request(method, uri, headers=self.headers,
                             body=json.dumps(payload))
                self.logger.debug(f"{method}: {self.host+uri}")
                self.logger.debug(f"Payload: {payload}")
            else:
                conn.request(method, uri, headers=self.headers)
                self.logger.debug(f"{method}: {self.host+uri}")
            response = conn.getresponse()
            if response.status >= 300:
                conn.close()
                raise ZoomRequestFailed(self, response)
            response_content = response.read().decode("utf-8")
            if response_content != '':
                response_content = json.loads(response_content)
            else:
                # blank return value means that
                # an action was performed successfully
                return True
            try:
                next_token = response_content['next_page_token']
            except KeyError:
                # response is not paginated
                api_return_value = response_content
                break
            # need a flag for init, might as well use the predefined array
            if response_array == []:
                # gather our value_key/total/limit for subsequent calls
                value_key = list(set(response_content.keys()).difference({'from', 'to', 'total_records', 'next_page_token', 'page_size', 'page_count', 'page_number'}))[
                    0]  # there is an insane amount of variability
                param = "&" if "?" in uri else "?"  # silly url formatting
            response_array += response_content[value_key]
            uri = f"{base_uri}{param}next_page_token={next_token}"
            if next_token == '':
                api_return_value = response_array
                break
            # stay within rate limit!
            if call_rate_min_time > datetime.datetime.now():
                self.logger.debug(
                    f"Reached rate limit, sleeping for {self.rate_limit}ms")
                # just wait a whole cycle i guess
                time.sleep(self.rate_limit/1000)  # conver to ms
        conn.close()
        return api_return_value

    def get_token(self):
        f"""Takes instantiated information client_id/client_secret and grabs a token.
        The token is placed into the header of all subsequent calls.

        Raises:
            ZoomRequestFailed: Generic HTTP response codes taken from API documentation

        Returns:
            dict: Returns JSON formatted token information as Python dictionary
        """
        creds = base64.b64encode(
            f"{self.client_id}:{self.client_secret}".encode("ascii")).decode('ascii')
        conn = http.client.HTTPSConnection("zoom.us", timeout=self.timeout)
        conn.request("POST", f"/oauth/token?grant_type=account_credentials&account_id={self.account_id}", headers={
            'Host': 'zoom.us', 'Authorization': f'Basic {creds}'})
        r = conn.getresponse()
        if r.status >= 300:  # generic 200 range is good stuff, anything above BAD
            conn.close()
            raise ZoomRequestFailed(self, r)
        else:
            self.token = json.loads(r.read().decode("utf-8"))
            self.token_expiration = datetime.datetime.now(
                datetime.UTC) + datetime.timedelta(seconds=self.token['expires_in'])
            self.headers['Authorization'] = f"Bearer {self.token['access_token']}"
        conn.close()
        return self.token

    def get_rooms(self, query_name=None):
        """Returns a list of all rooms with an optional name query that contains id, room_id, name, location_id, status, and tag_ids.
        Note: room_id is used for Dashboard API."""
        uri = f'/v2/rooms?query_name={query_name}' if query_name is not None else '/v2/rooms'
        return self.call("GET", uri)

    def get_locations(self):
        return self.call("GET", "/v2/rooms/locations")

    def get_room_devices(self, room_id):
        """ Returns device information per room """
        return self.call("GET", f'/v2/rooms/{room_id}/devices')['devices']

    def get_devices(self):
        """Returns a list of all online devces in the tenant."""
        type_translation = {0: "Zoom Rooms Computer",
                            1: "Zoom Rooms Controller",
                            2: "Zoom Rooms Scheduling Display",
                            3: "Zoom Rooms Control System",
                            4: "Zoom Rooms Whiteboard",
                            5: "Zoom Phone Appliance",
                            6: "Zoom Rooms Computer (with Controller)"
                            }
        devices = self.call(
            "GET", "/v2/devices?device_type=-1&page_size=300&device_status=1")
        for item in devices:
            item['device_type'] = type_translation[item['device_type']]
            item['device_status'] = "online"
        return devices

    def get_room_settings(self, room_id):
        """ Returns meeting and alert settings """
        meeting = self.call(
            "GET", f'/v2/rooms/{room_id}/settings?setting_type=meeting')
        alert = self.call(f"/v2/rooms/{room_id}/settings?setting_type=alert")
        result = meeting
        result['room'] = {"room_id": room_id}
        for key in alert.keys():
            result[key] = alert[key]
        return result

    def get_room_profile(self, room_id):
        """Returns additional room information such as capacity"""
        return self.call("GET", f"/v2/rooms/{room_id}")

    def get_calendars(self, sevriceID):
        return self.call("GET", f"/v2/rooms/calendar/services/{sevriceID}/resources")


class ZoomRequestFailed(Exception):
    def __init__(self, obj, request):
        response_codes = {
            400: "400 Bad Request - Invalid/missing data",
            401: "401 Unauthorized - Invalid/missing credentials",
            403: "403 Forbidden - User does not have permission or has not authorized shared access permissions.",
            404: "404 Not Found - The resource doesn't exist; invalid or non-existent user ID, for example",
            409: "409 Conflict - Trying to overwrite a resource, for example when creating a user with an email that already exists",
            429: "429 Too Many Requests - Hit an API rate limit",
            4700: "4700 Invalid Access Token - Invalid access token, does not contain scopes. The user is not authorized"
        }
        if datetime.datetime.now(datetime.UTC) > obj.token_expiration:
            raise ZoomTokenExpired()
        else:
            try:
                self.message = f"{response_codes[request.status]}\nContent:{request.read().decode('utf-8')}"
            except KeyError:
                # error outside of pre-defined codes
                self.message = f"{request.status} {request.reason}\nContent:{request.read().decode('utf-8')}"
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}"


class ZoomTokenExpired(Exception):
    def __init__(self, message="Token expired, run .get_token() to get a new one"):
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}"


class Webex(object):
    """Access tokens expire in 14 days, refresh tokens expire in 90 days.
    Generating a new access token automatically renews the lifetime of your refresh token.
    See further information here: https://developer.webex.com/docs/integrations

    To use this module fully it requires the following API permissions: `spark-admin:workspaces_write` `spark:kms` `spark-admin:devices_read` `spark:devices_write` `spark:xapi_statuses` `spark:devices_read` `spark-admin:devices_write` `spark:xapi_commands`

    Args:
        client_id (str): for authentication
        client_secret (str): for authentication
        refresh_token (str): for authentication
        logger (Str): The name of the logger (if using)
    """

    def __init__(self, client_id, client_secret, refresh_token, logger='webex'):
        self.host = "webexapis.com"
        self.headers = {"Content-Type": "application/json"}
        self.token = None
        self.client_id = client_id
        self.client_secret = client_secret
        self.refresh_token = refresh_token
        self.token_expiration = datetime.datetime.now(
            datetime.UTC)  # init to avoid type errors on init
        self.timeout = 20  # seconds
        self.logger = logging.getLogger(logger)

    def call(self, method, uri, payload=None):
        """api call operation with auto-pagination

        Args:
            method (str): GET, POST, PUT, PATCH
            uri (str): API endpoint
            payload (str): optional for post, put, patch methods

        Raises:
            WebexRequestFailed: Generic HTTP response codes taken from API documentation

        Returns:
            dict: Returns JSON formatted as Python dictionary for non-paginated responses. 
            When the response is paginated a list is returned.
        """
        conn = http.client.HTTPSConnection(self.host, timeout=self.timeout)
        api_return_value = None
        response_array = []
        while True:
            if payload:
                conn.request(method, uri, headers=self.headers,
                             body=json.dumps(payload))
                self.logger.debug(f"{method}: {self.host+uri}")
                self.logger.debug(f"Payload: {payload}")
            else:
                conn.request(method, uri, headers=self.headers)
                self.logger.debug(f"{method}: {self.host+uri}")
            response = conn.getresponse()
            if response.status >= 300:  # generic 200 range is good stuff, anything above BAD
                conn.close()
                raise WebexRequestFailed(self, response)
            response_content = json.loads(response.read().decode("utf-8"))
            try:
                response_array += response_content['items']
            except KeyError:
                # no arrays, simple query
                api_return_value = response_content
                break
            if 'link' in response.headers:
                # link value is <some_url>; rel=next
                uri = response.headers['link'][response.headers['link'].find(
                    self.host)+len(self.host):response.headers['link'].find(">")]
            else:
                api_return_value = response_array
                break

        conn.close()
        return api_return_value

    def get_token(self):
        """Passes `self.client_id` `self.client_secret` `self.refresh_token` over to authentication endpoint
        then stores token in `self.headers` for all subsequent calls.
        Also stores token expiration in `self.token_expiration` as a datetime object.
        The datetime object is set to UTC.

        Raises:
            WebexRequestFailed: Generic HTTP response codes taken from API documentation

        Returns:
            dict: JSON formatted as python dictionary
        """
        payload = {
            'grant_type': 'refresh_token',
            'refresh_token': self.refresh_token,
            'client_id': self.client_id,
            'client_secret': self.client_secret
        }
        conn = http.client.HTTPSConnection(self.host, timeout=self.timeout)
        conn.request("POST", '/v1/access_token',
                     headers=self.headers, body=json.dumps(payload))
        response = conn.getresponse()
        if response.status >= 300:
            conn.close()
            raise WebexRequestFailed(self, response)
        response_content = json.loads(response.read().decode("utf-8"))
        self.token = response_content
        self.token_expiration = datetime.datetime.now(
            datetime.UTC) + datetime.timedelta(seconds=self.token['expires_in'])
        self.headers = {
            'Authorization': f"Bearer {self.token['access_token']}"}
        conn.close()
        return self.token

    def get_devices(self):
        """Returns an array of dictionaries that contains information about all devices."""
        return self.call("GET", "/v1/devices")

    def get_codecs(self):
        """Returns an array of dictionaries that contains information about codecs."""
        return self.call("GET", "/v1/devices?type=roomdesk")

    def get_device_details(self, deviceId):
        """Return device detail information"""
        return self.call("GET", f"/v1/devices/{deviceId}")

    def get_workspaces(self):
        """Returns an array of dictionaries that includes the workspace and associated devices"""
        return self.call("GET", "/v1/workspaces")

    def get_location(self, locationId):
        return self.call("GET", f"/v1/locations/{locationId}")

    def get_floor(self, locationId, floorId):
        return self.call("GET", f"/v1/locations/{locationId}/floors/{floorId}")


class WebexRequestFailed(Exception):
    def __init__(self, obj, request):
        response_codes = {
            400: "400 Bad Request - The request was invalid or cannot be otherwise served. An accompanying error message will explain further.",
            401: "401 Unauthorized - Authentication credentials were missing or incorrect.",
            403: "403 Forbidden - The request is understood, but it has been refused or access is not allowed.",
            404: "404 Not Found - The URI requested is invalid or the resource requested, such as a user, does not exist. Also returned when the requested format is not supported by the requested method.",
            405: "405 Method Not Allowed - The request was made to a resource using an HTTP request method that is not supported.",
            409: "409 Conflict - The request could not be processed because it conflicts with some established rule of the system. For example, a person may not be added to a room more than once.",
            410: "410 Gone - The requested resource is no longer available.",
            415: "415 Unsupported Media Type - The request was made to a resource without specifying a media type or used a media type that is not supported.",
            423: "423 Locked - The requested resource is temporarily unavailable. A Retry-After header may be present that specifies how many seconds you need to wait before attempting the request again.",
            428: "428 Precondition Required - File(s) cannot be scanned for malware and need to be force downloaded.",
            429: "429 Too Many Requests - Too many requests have been sent in a given amount of time and the request has been rate limited. A Retry-After header should be present that specifies how many seconds you need to wait before a successful request can be made.",
            500: "500 Internal Server Error - Something went wrong on the server. If the issue persists, feel free to contact the Webex Developer Support team.",
            502: "502 Bad Gateway - The server received an invalid response from an upstream server while processing the request. Try again later.",
            503: "503 Service Unavailable - Server is overloaded with requests. Try again later.",
            504: "504 Gateway Timeout - An upstream server failed to respond on time. If your query uses max parameter, please try to reduce it."
        }

        if datetime.datetime.now(datetime.UTC) > obj.token_expiration:
            raise WebexTokenExpired()
        else:
            try:
                self.message = f"{response_codes[request.status]}\nContent:{request.read().decode('utf-8')}"
            except KeyError:
                # error outside of pre-defined codes
                self.message = f"{request.status} {request.reason}\nContent:{request.read().decode('utf-8')}"
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}"


class WebexTokenExpired(Exception):
    def __init__(self):
        self.message = "Token has expired, run .get_token()"
        super().__init__(self.message)

    def __str__(self):
        return f"{self.message}"

#########################
# function declarations #
#########################


def setup_logging(logger_name):
    """Global var `logger` created that incorporates a stdout stream, a debug level file, and an info level file.
    The stdout stream is set to info level by default unless 'debug' is supplied as a sys arg. The log messages included in /modules will also be captured for debug level.

    Args:
        None

    Returns:
        None
    """
    global logger
    # directory nonesense
    script_dir = os.path.dirname(os.path.realpath(__file__))
    os.chdir(script_dir)  # cron or scheduler might not exec in same dir

    # the beavers and i like logs
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.DEBUG)  # min level
    formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s [%(module)s.%(funcName)s:%(lineno)d] %(message)s')
    debug_formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s [%(module)s.%(funcName)s:%(lineno)d][%(threadName)s] %(message)s')

    # info level for first log
    # using rotating files
    info_file_handler = handlers.RotatingFileHandler(os.path.basename(
        # 5MB
        __file__).replace(".py", "_info.log"), maxBytes=5*1024*1024, backupCount=2)
    info_file_handler.setFormatter(formatter)
    info_file_handler.setLevel(logging.INFO)
    logger.addHandler(info_file_handler)

    # debug level for second log
    debug_file_handler = handlers.RotatingFileHandler(os.path.basename(
        # 5MB
        __file__).replace(".py", "_debug.log"), maxBytes=5*1024*1024, backupCount=2)
    debug_file_handler.setFormatter(debug_formatter)
    debug_file_handler.setLevel(logging.DEBUG)
    logger.addHandler(debug_file_handler)

    # for stdout
    stream_handler = logging.StreamHandler(sys.stdout)

    # default setup for stdout
    stream_handler.setFormatter(formatter)
    stream_handler.setLevel(logging.INFO)
    logger.addHandler(stream_handler)

    # check for sys args set stdout if its equal to debug
    if len(sys.argv) > 1:
        if sys.argv[1] == 'debug':
            stream_handler.setFormatter(debug_formatter)
            stream_handler.setLevel(logging.DEBUG)
            logger.addHandler(stream_handler)


def write_csv(data, filename):
    """Takes in a list of dictionaries and exports CSV"""
    shared_keys = set()
    [shared_keys.add(key) for item in data for key in item.keys()]
    for item in data:
        diff = shared_keys.difference(set(item.keys()))
        if diff:
            logger.info(f"Key discrepency: {diff}")
            [shared_keys.remove(key) for key in diff]
    header = shared_keys
    with open(filename, 'w+', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(header)
        for item in data:
            vals = [item[key] for key in header]
            writer.writerow(vals)
    logger.info(f"Wrote {len(data)} items to `{filename}`")


def get_zoom_devices(zoom):
    results = []
    # https://api.zoom.us/v2/rooms
    rooms = zoom.get_rooms()
    # example:
    """
    {'id': 'ZFU0QsEDTvGB_Ho59ucp6g',
    'room_id': '97G85O7XRgiV-amFp9G_1w',
    'name': 'AMS.3.06.Johan Thorbecke',
    'location_id': 'DuiEfOwASPSrqwfPigJbCg',
    'status': 'Available',
    'tag_ids': []}
    """
    logger.info(f"{len(rooms)} zoom rooms gathered")
    # create hashmap for location info and calendars
    # https://api.zoom.us/v2/rooms/locations
    locations = {loc['id']: loc for loc in zoom.get_locations()}
    # example:
    """
    {'id': '-2SyqNeBTjOeeY12VN5Jog',
    'name': 'Manhattan Beach - USA',
    'parent_location_id': 'pZkmb5VpT_y7eDaIZPpGug',
    'type': 'city'}
    """
    # https://api.zoom.us/v2/rooms/calendar/services/{sevriceID}/resources
    calendars = {cal['assigned_room_id']: cal for cal in zoom.get_calendars(
        ZOOM_CALENDAR_ID)}
    # example:
    """
    {'calendar_resource_email': 'DVGKaterBlau@bcg.com',
    'calendar_resource_name': 'DVG 04 Kater Blau (6)',
    'assigned_room_id': '--DmuU4pSa20F3Inm5UQVg',
    'sync_status': 'Success',
    'calendar_resource_id': '9edc2353-80f0-4488-907e-4ba488942bed'}   
    """

    # there are dev / wwom rooms that we should ignore
    # so we filter them before gathering devices
    def location_filter(room):
        # this back propogate from room -> campus level
        location = locations[room['location_id']]
        # the highest level for locations is the account ID
        while location['parent_location_id'] != zoom.account_id:
            location = locations[location['parent_location_id']]
            if location['id'] in IGNORED_ZOOM_LOCATIONS:
                return False
        return True

    rooms = list(filter(location_filter, rooms))
    logger.info(f"{len(rooms)} zoom rooms after filtering")

    for room in rooms:
        # now the fun begins to get each rooms devices.
        # zoom apis can be tricky and timeouts can happen
        MAX_ATTEMPTS = 6
        room['devices'] = []  # init
        for x in range(1, MAX_ATTEMPTS):
            logger.debug(
                f"Grabbing device information for room: {room['name']} ({room['room_id']})")
            try:
                # https://api.zoom.us/v2/rooms/{room_id}/devices
                room['devices'] = [
                    device for device in zoom.get_room_devices(room['id'])]
            except Exception as e:
                logger.debug(
                    f"Failed to gather room devices for {room['id']}:")
                logger.debug(e)
                logger.warning(
                    f"Attempt number {x+1} to gather devices for room: {room['name']} ({room['room_id']})")
                time.sleep(1)  # sleep one second.
            else:
                # exit
                break

        if room['devices'] == []:
            logger.info(
                f"Skipping device gathering logic given there are no devices for room: {room['name']} ({room['room_id']})")
            continue

        # example:
        """
        [{'id': 'poly-8L22076BFA3CFD',
        'room_name': 'AMS.3.06.Johan Thorbecke',
        'device_type': 'Controller',
        'app_version': '6.1.5 (2916)',
        'device_system': 'Android 4.1.2-211367',
        'status': 'Online',
        'device_mac_addresses': ['00:e0:db:6b:fa:3c'],
        'device_hostname': 'AMS.3.06.Johan Thorbecke',
        'device_manufacturer': 'Poly',
        'device_model': 'PolyTC8',
        'device_firmware': '4.1.2-211367',
        'ip_address': '10.44.136.13',
        'serial_number': '8L22076BFA3CFD'},
        {'id': 'poly-8L220968C53EFB',
        'room_name': 'AMS.3.06.Johan Thorbecke',
        'device_type': 'Zoom Rooms Computer',
        'app_version': '6.1.5 (5274)',
        'app_target_version': '',
        'device_system': 'Android 4.1.2-388101',
        'status': 'Online',
        'device_mac_addresses': ['00:e0:db:68:c5:3e'],
        'device_hostname': 'AMS.3.06.Johan Thorbecke Poly PolyStudioX50',
        'device_manufacturer': 'Poly',
        'device_model': 'StudioX50',
        'device_firmware': '4.1.2-388101',
        'ip_address': '10.44.136.12',
        'serial_number': '8L220968C53EFB'}]        
        """

        # have to fix the mac address...
        for device in room['devices']:
            try:
                # its an array or sometimes this attr is blank...
                # some macs are separated with '.' vs ':' and are different case
                device['device_mac_addresses'] = device['device_mac_addresses'][0].lower(
                ).replace(".", ":")
            except Exception as e:  # mac does not exist
                if "device_mac_addresses" not in device.keys():
                    logger.debug(
                        f"No mac address atrribute  for {device['id']}")
                else:
                    logger.debug(
                        f"Mac address atrribute: ({device['device_mac_addresses']}) failed for {device['id']} due to exception {e.__class__.__name__}")
                device['device_mac_addresses'] = "00:00:de:ad:be:ef"

        try:
            room['room_email'] = calendars[room['id']]['calendar_resource_email']
        except KeyError:
            room['room_email'] = "Unassigned"

        room['site'] = locations[locations[room['location_id']]
                                 # 3 letter code
                                 ['parent_location_id']]['name'][:3]

        # find digit and convert to int
        try:
            room['floor'] = int(re.search(
                pattern=r"\d+", string=locations[room['location_id']]['name']).group(0))
        except AttributeError:
            # floor will remain 0
            logger.error(f"issue parsing floor for {room['name']}")
        try:
            # need to use the room profile api to get capacity... who knows
            # https://api.zoom.us/v2/rooms/{room_id}
            room['capacity'] = int(zoom.get_room_profile(
                room['id'])['basic']['capacity'])
            # example
            """
            {'basic': {'name': 'AMS.3.06.Johan Thorbecke',
            'display_name': '',
            'zoom_room_type': 'ZoomRoom',
            'activation_code': '',
            'support_email': '',
            'support_phone': '',
            'room_passcode': '00000',
            'required_code_to_ext': True,
            'hide_room_in_contacts': False,
            'capacity': '',
            'location_id': 'DuiEfOwASPSrqwfPigJbCg',
            'calendar_resource_id': 'iicGMXyeTjCcsu17HYM7Nw',
            'tag_ids': []},
            'device': {'device_profile_id': ''},
            'setup': {'under_construction': False,
            'apply_background_image_to_all_displays': True,
            'background_image_info': [{'display_id': 'zoom_rooms_display1',
                'content_id': 'JIyXvlGuQ3mg67oI9D7Tvw',
                'download_url': 'https://file.zoom.us/file/qC0paJx7R52trBUQQtI0tQ?jwt=eyJ0eXAiOiJKV1QiLCJrIjoiN3kxa0toQW8iLCJ6bV9za20iOiJ6bV9vMm0iLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJ6ZnMiLCJ0b2tlbklkIjoiT25ETnN4bVNTYkdzbkI5bEllZFlQQSIsImFwcE5hbWUiOiJ3ZWIiLCJpc3MiOiJ3ZWIiLCJwZXJtaXNzaW9uIjoie1wiYWN0aW9uXCI6XCJyZWFkXCIsXCJlbnRpdHlcIjp7XCJjb3VudFwiOjAsXCJmaWxlSWRcIjpcInFDMHBhSng3UjUydHJCVVFRdEkwdFFcIixcIm1heFNpemVcIjowfX0iLCJleHAiOjE3MzM5MzM2MjgsInRva2VuVHlwZSI6InByZXNpZ25Ub2tlbiIsImlhdCI6MTczMzkzMDAyOH0.LPbM6jsblbQZiIni48fSbTCCENcKEjFQ9rjeXjL5x7BJdoxorySixHxdQmsAfPzoxX1wz7DGhGFGUSGDAO1jnw',
                'download_url_ttl': 3600}]}}
            """
        except Exception as e:  # capacity does not exist or is null string
            # capacity will inherit default value from schema
            logger.debug(
                f"Capacity could not be obtained for {room['name']} ({room['id']}) due to exception {e.__class__.__name__}")

    # final modified format:
    """
    {'id': 'ZFU0QsEDTvGB_Ho59ucp6g',
    'room_id': '97G85O7XRgiV-amFp9G_1w',
    'name': 'AMS.3.06.Johan Thorbecke',
    'location_id': 'DuiEfOwASPSrqwfPigJbCg',
    'status': 'Available',
    'tag_ids': [],
    'devices': [{'id': 'poly-8L22076BFA3CFD',
    'room_name': 'AMS.3.06.Johan Thorbecke',
    'device_type': 'Controller',
    'app_version': '6.1.5 (2916)',
    'device_system': 'Android 4.1.2-211367',
    'status': 'Online',
    'device_mac_addresses': '00:e0:db:6b:fa:3c',
    'device_hostname': 'AMS.3.06.Johan Thorbecke',
    'device_manufacturer': 'Poly',
    'device_model': 'PolyTC8',
    'device_firmware': '4.1.2-211367',
    'ip_address': '10.44.136.13',
    'serial_number': '8L22076BFA3CFD'},
    {'id': 'poly-8L220968C53EFB',
    'room_name': 'AMS.3.06.Johan Thorbecke',
    'device_type': 'Zoom Rooms Computer',
    'app_version': '6.1.5 (5274)',
    'app_target_version': '',
    'device_system': 'Android 4.1.2-388101',
    'status': 'Online',
    'device_mac_addresses': '00:e0:db:68:c5:3e',
    'device_hostname': 'AMS.3.06.Johan Thorbecke Poly PolyStudioX50',
    'device_manufacturer': 'Poly',
    'device_model': 'StudioX50',
    'device_firmware': '4.1.2-388101',
    'ip_address': '10.44.136.12',
    'serial_number': '8L220968C53EFB'}],
    'room_email': 'AMS.3.06.Thorbecke@bcg.com',
    'floor': 3,
    'site': 'AMS',
    'capacity': 0,
    'provider': 'Zoom'}
    """

    # convert data to CMDB schema
    device_translation_dictionary = {
        'room_name': 'room_name',
        'id': 'provider_device_id',
        'app_version': 'provider_software_version',
        'status': 'provider_status',
        'device_manufacturer': 'manufacturer',
        'device_model': 'model',
        'device_firmware': 'firmware_version',
        'device_type': 'device_type',
        'device_hostname': 'device_name',
        'serial_number': 'serial',
        'ip_address': 'ip',
        'device_mac_addresses': 'mac_address'
    }
    room_translation_dictionary = {
        'provider': 'provider',
        'site': 'site',
        'floor': 'floor',
        'capacity': 'room_capacity',
        'room_email': 'room_email',
    }
    # given that zoom does not always provide all information
    # we must find out what info we have or not
    # otherwise, the default values copied from CMDB schema will be applied

    # shallow copy of rooms array to remove rooms that failed to gather devices
    for room in rooms[:]:
        logger.debug(f"Working on room: {room['name']} ({room['room_id']})")
        if room['devices'] == []:
            logger.info(
                f"Room: {room['name']} ({room['id']}) does not contain devices. Removing.")
            rooms.remove(room)
            logger.info(
                f"{len(rooms)} total rooms to iterate through to convert to CMDB schema")
            continue
        # statically set for CMDB
        room['provider'] = "Zoom"
        for device in room['devices']:
            logger.debug(
                f"Working on device: {device['device_hostname']} ({device['id']})")
            device_details = CMDB_SCHEMA.copy()
            # start with the device attributes
            shared_keys = set(device_translation_dictionary.keys()
                              ).intersection(set(device.keys()))
            if len(device_translation_dictionary.keys()) != len(shared_keys):
                missed_keys = set(device_translation_dictionary.keys()).difference(
                    set(device.keys()))
                logger.warning(
                    f"Zoom device ID {device['id']} with room ID {room['id']} missing data for: {missed_keys}")
            for key in shared_keys:
                device_details[device_translation_dictionary[key]
                               ] = device[key]

            # now for the room attrs
            # these all should exist. but just in case lets compare...
            shared_keys = set(room_translation_dictionary.keys()
                              ).intersection(set(room.keys()))
            if len(room_translation_dictionary.keys()) != len(shared_keys):
                missed_keys = set(room_translation_dictionary.keys()).difference(
                    set(room.keys()))
                logger.warning(
                    f"Zoom device ID {device['id']} with room ID {room['id']} missing data for: {missed_keys}")
            for key in shared_keys:
                device_details[room_translation_dictionary[key]] = room[key]

            results.append(device_details)
    return results


def get_webex_devices(webex):
    results = []
    # get devices from tenant, this returns everything - including devices we dont want
    devices = webex.get_devices()  # https://webexapis.com/v1/devices
    logger.info(f"gathered {len(devices)} from webex")
    # example:
    """
    {'id': 'Y2lzY29zcGFyazovL3VybjpURUFNOnVzLWVhc3QtMl9hL0RFVklDRS9kMTgwZDMzYi04NzE4LTQ0MWItODIzYi1hZjM3NjdhYWU1MzQ=',
    'displayName': 'BEI.22.ShuiMuQingHua',
    'placeId': 'Y2lzY29zcGFyazovL3VybjpURUFNOnVzLWVhc3QtMl9hL1BMQUNFL2Q2MDVhY2EwLTMyNTgtNGNiMy04YmE1LTZlMzk5MDlkMTM3Nw==',
    'orgId': 'Y2lzY29zcGFyazovL3VzL09SR0FOSVpBVElPTi84MmE5MWRmOC1kNTE2LTRlZmMtYjEyNC0yZjFmNDM3NGZhYzM',
    'capabilities': ['xapi'],
    'permissions': ['xapi'],
    'product': 'Cisco Room Kit',
    'type': 'roomdesk',
    'tags': ['Crestron'],
    'ip': '10.67.136.104',
    'mac': 'BC:5A:56:83:F9:24',
    'serial': 'FOC2409N1VE',
    'activeInterface': 'LAN',
    'software': 'RoomOS 11.20.1.7 913a6c7c769',
    'upgradeChannel': 'Stable',
    'primarySipUrl': 'bei22shuimuqinghua@bcg.rooms.webex.com',
    'sipUrls': ['bei22shuimuqinghua@bcg.rooms.webex.com'],
    'errorCodes': ['controlsystemconnection'],
    'connectionStatus': 'connected_with_issues',
    'created': '2023-03-07T17:35:16.894Z',
    'firstSeen': '2023-03-07T17:35:16.894Z',
    'lastSeen': '2024-12-10T11:20:20.693Z',
    'workspaceLocationId': 'Y2lzY29zcGFyazovL3VybjpURUFNOnVzLWVhc3QtMl9hL1dPUktTUEFDRV9MT0NBVElPTi84MmE5MWRmOC1kNTE2LTRlZmMtYjEyNC0yZjFmNDM3NGZhYzMjZTQyY2I1YTktYzdmMS00NzE4LThiOGUtZWY1MGU2ZjAxYmMw',
    'locationId': 'Y2lzY29zcGFyazovL3VzL0xPQ0FUSU9OL2U0MmNiNWE5LWM3ZjEtNDcxOC04YjhlLWVmNTBlNmYwMWJjMA',
    'managedBy': 'CISCO',
    'devicePlatform': 'cisco',
    'lifecycle': 'ACTIVE',
    'workspaceId': 'Y2lzY29zcGFyazovL3VybjpURUFNOnVzLWVhc3QtMl9hL1BMQUNFL2Q2MDVhY2EwLTMyNTgtNGNiMy04YmE1LTZlMzk5MDlkMTM3Nw=='}
    """

    # filter on what we'd like to have
    devices = list(filter(lambda device: (
        device['product'] == "Cisco Touch 10" or device['type'] == "roomdesk"), devices))
    logger.info(f"{len(devices)} after filtering")
    workspaces = webex.get_workspaces()  # https://webexapis.com/v1/workspaces
    # example:
    """
    {'id': 'Y2lzY29zcGFyazovL3VybjpURUFNOnVzLWVhc3QtMl9hL1BMQUNFL2Q2MDVhY2EwLTMyNTgtNGNiMy04YmE1LTZlMzk5MDlkMTM3Nw==',
    'orgId': 'Y2lzY29zcGFyazovL3VzL09SR0FOSVpBVElPTi84MmE5MWRmOC1kNTE2LTRlZmMtYjEyNC0yZjFmNDM3NGZhYzM',
    'workspaceLocationId': 'Y2lzY29zcGFyazovL3VybjpURUFNOnVzLWVhc3QtMl9hL1dPUktTUEFDRV9MT0NBVElPTi84MmE5MWRmOC1kNTE2LTRlZmMtYjEyNC0yZjFmNDM3NGZhYzMjZTQyY2I1YTktYzdmMS00NzE4LThiOGUtZWY1MGU2ZjAxYmMw',
    'locationId': 'Y2lzY29zcGFyazovL3VzL0xPQ0FUSU9OL2U0MmNiNWE5LWM3ZjEtNDcxOC04YjhlLWVmNTBlNmYwMWJjMA',
    'floorId': 'Y2lzY29zcGFyazovL3VybjpURUFNOnVzLWVhc3QtMl9hL1dPUktTUEFDRV9MT0NBVElPTl9GTE9PUi9kNTViNjk1MS0wYmZiLTRmMWEtYmQyZi1jNDQwYjBjZDFkZWM=',
    'displayName': 'BEI.22.ShuiMuQingHua',
    'sipAddress': 'bei22shuimuqinghua@bcg.rooms.webex.com',
    'created': '2023-03-07T17:34:33.060Z',
    'calling': {'type': 'freeCalling'},
    'calendar': {'type': 'microsoft',
    'emailAddress': 'BEI.22.ShuiMuTsinghua@bcg.com'},
    'hotdeskingStatus': 'off',
    'deviceHostedMeetings': {'enabled': True,
    'siteUrl': 'conferencev2.webex.com'},
    'supportedDevices': 'collaborationDevices',
    'devicePlatform': 'cisco',
    'health': {'issues': [{'id': 'offline-peripherals',
        'createdAt': '2024-12-04T12:24:43.977423500Z',
        'title': 'Offline peripherals',
        'description': 'There are offline peripherals in the workspace.',
        'level': 'error'},
    {'id': 'devices-with-issues',
        'createdAt': '2024-12-04T12:24:43.977422170Z',
        'title': 'Devices with issues',
        'description': 'There are devices with issues in the workspace.',
        'recommendedAction': 'Check the device issues for more details.',
        'level': 'error'},
    {'id': 'type-not-set',
        'createdAt': '2024-11-20T11:58:22.097554025Z',
        'title': 'Workspace type not set',
        'description': 'Adding a type specifies what the workspace is used for.',
        'recommendedAction': 'Set a type for this workspace.',
        'level': 'info'},
    {'id': 'capacity-not-set',
        'createdAt': '2024-11-20T11:58:22.097553605Z',
        'title': 'Workspace capacity not set',
        'description': 'Adding a capacity specifies how many people can fit in the workspace.',
        'recommendedAction': 'Set a capacity for this workspace.',
        'level': 'info'}],
    'level': 'error'}}
    """

    # create hash map where id is key
    workspaces = {workspace['id']: workspace for workspace in workspaces}

    for device in devices:
        logger.debug(f"Working on: {device['displayName']} ({device['id']})")
        workspace = workspaces[device['workspaceId']]
        # desk devices (personal units) dont have locations
        if 'locationId' not in workspace.keys():
            logger.info(
                f"Skipping `{device['displayName']}` since its a personal unit.")
            continue
        device_details = CMDB_SCHEMA.copy()
        device_details['room_name'] = workspace['displayName']
        # https://webexapis.com/v1/locations/{locationId}
        device_details['site'] = webex.get_location(
            # 3 letter code is all we need
            workspace['locationId'])['name'][:3]
        # example:
        """
        {'id': 'Y2lzY29zcGFyazovL3VzL0xPQ0FUSU9OL2U0MmNiNWE5LWM3ZjEtNDcxOC04YjhlLWVmNTBlNmYwMWJjMA',
        'name': 'BEI - Beijing',
        'orgId': 'Y2lzY29zcGFyazovL3VzL09SR0FOSVpBVElPTi84MmE5MWRmOC1kNTE2LTRlZmMtYjEyNC0yZjFmNDM3NGZhYzM',
        'address': {'address1': 'Beijing, China', 'city': 'Beijing', 'country': 'CN'},
        'latitude': 39.904211,
        'longitude': 116.407395}
        """
        try:
            # https://webexapis.com/v1/locations/{locationId}/floors/{floorId}
            device_details['floor'] = webex.get_floor(
                workspace['locationId'], workspace['floorId'])['floorNumber']
            # example:
            """
            {'locationId': 'Y2lzY29zcGFyazovL3VzL0xPQ0FUSU9OL2U0MmNiNWE5LWM3ZjEtNDcxOC04YjhlLWVmNTBlNmYwMWJjMA',
            'id': 'Y2lzY29zcGFyazovL3VybjpURUFNOnVzLWVhc3QtMl9hL1dPUktTUEFDRV9MT0NBVElPTl9GTE9PUi9kNTViNjk1MS0wYmZiLTRmMWEtYmQyZi1jNDQwYjBjZDFkZWM=',
            'floorNumber': 22,
            'displayName': ''}
            """
        except KeyError:
            # webex dashboard doesnt require floor information
            # workspace will not have "floorId" in its attrs
            # keep default 0
            logger.warning(
                f"Failed to capture floor information for workspace: {workspace['displayName']}")
        try:
            # not all workspaces have an email associated
            device_details['room_email'] = workspace['calendar']['emailAddress']
        except KeyError:
            logger.warning(
                f"No email address associated with workspace {workspace['displayName']}")

        try:
            device_details['room_capacity'] = workspace['capacity']
        except KeyError:
            logger.debug(f"No capacity set for {workspace['displayName']}")

        device_details['provider'] = "Webex"  # manually set
        device_details['provider_device_id'] = device['id']
        device_details['provider_software_version'] = device['software']
        device_details['provider_status'] = device['connectionStatus']
        # its lowercase for some reason
        device_details['manufacturer'] = device['devicePlatform'].title()
        device_details['model'] = device['product']
        device_details['firmware_version'] = device['software']
        device_details['device_name'] = device['displayName']
        device_details['serial'] = device['serial']
        device_details['ip'] = device['ip']
        device_details['mac_address'] = device['mac']
        device_details['device_type'] = "Controller" if device['product'] == "Cisco Touch 10" else "Codec"
        # TODO update via `devices` database
        # device_details["release_date"] = datetime
        # device_details["manufacturer_eol"] = datetime
        # device_details["cost_usd"] = 0.0
        # device_details["bcg_eol"] = datetime
        # TODO keep track of offline/online
        # device_details['first_seen'] = datetime
        # device_details['last_seen'] = datetime
        results.append(device_details)

    return results


#########
# BEGIN #
#########


def main():
    setup_logging(LOGGER)
    logger.info("Starting Script . . .")

    # load the VERY magical characters
    with open(".env", 'rb') as f:
        magic = pickle.load(f)

    zoom = Zoom(magic['zoom']['account_id'],
                magic['zoom']['client_id'], magic['zoom']['client_secret'], logger=LOGGER)

    webex = Webex(magic['webex']['client_id'], magic['webex']
                  ['client_secret'], magic['webex']['refresh_token'], logger=LOGGER)

    zoom.get_token()
    webex.get_token()

    zoom_data = get_zoom_devices(zoom)
    webex_data = get_webex_devices(webex)

    all_data = zoom_data+webex_data

    write_csv(all_data, 'cmdb.csv')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        logger.critical(traceback.format_exc())

"""
# NOTES ONLY


def s3_functions():
    s3_resource = boto3.resource('s3')
    s3_bucket = s3_resource.Bucket(name='cmdb.test.bucket')
    
    # upload
    data_dict = {
    'Name': 'Daikon Retek',
    'Birthdate': "2000-1-1",
    'Subjects': ['Math', 'Science', 'History']
    }
    data_string = json.dumps(data_dict, indent=2, default=str)
    s3_bucket.put_object(
    Key='cmdb',
    Body=data_string
    )
    
    # pull
    obj = s3_resource.Object('my-bucket', 'key-to-file.json')
    data = io.BytesIO()
    obj.download_fileobj(data)
    payload = json.loads(data.getvalue().decode("utf-8"))
    print(payload)

"""
