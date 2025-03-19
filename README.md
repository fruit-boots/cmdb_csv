# CMDB_CSV
Script that gathers data from Zoom and Webex and transforms it into a CMDB schema. The output of this script is a csv in the local directory which is formatted as:
```python
CMDB_SCHEMA = {
    "room_name": str,
    "site": str,
    "floor": int,
    "room_capacity": int,
    "room_email": str,
    "provider": str,
    "provider_device_id": str,
    "provider_software_version": str,
    "provider_status": str,
    "manufacturer": str,
    "model": str,
    "firmware_version": str,
    "device_type": str,
    "device_name": str,
    "serial": str,
    "ip": str,
    "mac_address": str,
    "release_date": str,
    "manufacturer_eol": str,
    "cost_usd": int,
    "bcg_eol": str,
    "first_seen": str,
    "last_seen": str
}
```
## Requirements
* <= Python 3.11.6 - there are known compatibility issues for the datetime module on different python versions!
* Zoom API with scope: `device:read:admin room:read:admin`
* Webex API with scope: `spark-admin:locations_read spark-admin:workspace_locations_read spark-admin:workspaces_read spark:devices_read spark-admin:devices_read`
* A .env file (pickle object) that contain all the credentials necessary must be in the root directory.
     * `{'zoom': {'account_id': str, 'client_id': str, 'client_secret': str}, 'webex': {'client_id': str, 'client_secret': str, 'refresh_token': str}}`
## API references
https://developer.webex.com/docs/getting-started \
https://developers.zoom.us/docs/api/

## Logging
The stdout stream is set to `logging.INFO` level by default unless 'debug' is supplied as a sys arg. 
The log messages included in /modules will also be captured for `logging.DEBUG` level. Two files are automatically created, one for `logging.INFO` named `main_info.log` and `logging.DEBUG` named `main_debug.log`. Each of these files also rotates (max 2) when reaching 5MB.
