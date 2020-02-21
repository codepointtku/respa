import contextlib
import pytz

from .base import AccessControlDriver, RemoteError
import jsonschema
from django.core.exceptions import ValidationError
import requests
from django.conf import settings
from datetime import datetime, timedelta

REQUESTS_TIMEOUT = 30  # seconds

class AbloyToken:
    access_token: str
    # refresh_token: str
    expires_at: datetime

    def __init__(self, access_token, expires_at):
        self.access_token = access_token
        # self.refresh_token = refresh_token
        self.expires_at = expires_at

    def has_expired(self):
        now = datetime.now()
        if now > self.expires_at + timedelta(seconds=30):
            print("AbloyToken has_expired: Yup")
            return True
        print("AbloyToken has_expired: nope")
        return False

    # refresh by getting a new access token and expiration time
    def refresh(self, access_token, expires_at):
        self.access_token = access_token
        self.expires_at = expires_at

    def serialize(self):
        return dict(access_token=self.access_token, expires_at=self.expires_at.timestamp())

    @classmethod
    def deserialize(cls, data):
        try:
            access_token = data['access_token']
            expires_at = datetime.fromtimestamp(data['expires_at'])
        except Exception:
            print("AbloyToken: couldnt deserialize data....")
            return None
        return AbloyToken(access_token=access_token, expires_at=expires_at)

class AbloyDriver(AccessControlDriver):
    token: AbloyToken

    SYSTEM_CONFIG_SCHEMA = {
        "type": "object",
        "properties": {
            "api_url": {
                "type": "string",
                "format": "uri",
                "pattern": "^https?://",
            },
            "header_username": {
                "type": "string",
            },
            "header_password": {
                "type": "string",
            },
            "body_username": {
                "type": "string",
            },
            "body_password": {
                "type": "string",
            },
            "organization_name": {
                "type": "string",
            }
        },
        "required": [
            "api_url", "header_username", "header_password", "body_username", "body_password",
        ],
    }
    RESOURCE_CONFIG_SCHEMA = {
        "type": "object",
        "properties": {
            "access_point_group_name": { # resource doors to be opened? rename?
                "type": "string",
            },
        },
        "required": [
            "access_point_group_name"
        ]
    }

    DEFAULT_CONFIG = {
        "client_id": "kulkunen",
    }

    def get_system_config_schema(self):
        return self.SYSTEM_CONFIG_SCHEMA

    def get_resource_config_schema(self):
        return self.RESOURCE_CONFIG_SCHEMA

    def get_resource_identifier(self, resource):
        config = resource.driver_config or {}
        return config.get('access_point_group_name', '')

    def validate_system_config(self, config):
        try:
            jsonschema.validate(config, self.SYSTEM_CONFIG_SCHEMA)
        except jsonschema.exceptions.ValidationError as e:
            raise ValidationError(e.message)

    def validate_resource_config(self, resource, config):
        try:
            jsonschema.validate(config, self.RESOURCE_CONFIG_SCHEMA)
        except jsonschema.exceptions.ValidationError as e:
            raise ValidationError(e.message)

    def _save_token(self, token):
        self.update_driver_data(dict(token=token.serialize()))

    def _load_token(self):
        data = self.get_driver_data().get('token')
        return AbloyToken.deserialize(data)

    def api_get_token(self):
        print("api_get_token....") # remove me
        body_username = self.get_setting('body_username')
        body_password = self.get_setting('body_password')
        header_username = self.get_setting('header_username')
        header_password = self.get_setting('header_password')

        path = "oauth/token"
        url = '%s/%s' % (self.get_setting('api_url'), path)
        print("url: "+url) # remove me
        method = 'POST'
        headers = {"Content-Type": "application/x-www-form-urlencoded", "Authorization": "Basic Auth"}
        args = dict(headers=headers)
        data = dict(username=body_username, password=body_password, grant_type="password")
        args['data'] = data

        resp = requests.request(method, url, timeout=REQUESTS_TIMEOUT,
            auth=(header_username, header_password), **args)

        response_data = resp.json()
        if not response_data['access_token']:
            raise Exception("Getting access_token failed!")
        access_token = response_data["access_token"]

        expires_at = datetime.now() + timedelta(seconds=(response_data["expires_in"]))
        token = AbloyToken(access_token=access_token, expires_at=expires_at)

        print("Token: %s" % token.access_token) # remove me
        #print("Token expires at: %s" % str(token.expires_at))
        #self.logger.info("Token: %s" % token.access_token)
        return token

    @contextlib.contextmanager
    def ensure_token(self):
        print("ensure_token...") # remove me
        driver_data = self.get_driver_data()

        token = self._load_token()
        if not token or token.has_expired():
            # throw exception?
            token = self.api_get_token()

        # is saving needed if token already exists?
        self._save_token(token)

        try:
            yield token
        except Exception as e:
            raise

    def install_grant(self, grant):
        print('Installing Abloy grant: [%s]' % grant)
        assert grant.state == grant.INSTALLING

        tz = pytz.timezone('Europe/Helsinki')
        starts_at = grant.starts_at.astimezone(tz).replace(tzinfo=None)
        ends_at = grant.ends_at.astimezone(tz).replace(tzinfo=None)

        data = {
            "person": {
                "firstname": grant.reservation.user.first_name,
                "lastname": grant.reservation.user.last_name,
                "validityStart": str(starts_at),
                "validityEnd": str(ends_at),
                "ssn": str(grant.reservation.user.uuid)
            },
            "organizations": [{
                "name": self.get_setting("organization_name") or "Respa",
                "type": "company",
                "person_belongs": "true",
                "sub-organizations": [{
                    "name": grant.resource.driver_config.get("access_point_group_name"),
                    "type": "department",
                    "person_belongs": "true"
                }]
            }],
            "tokens": [{
                "surfaceMarking": "PIN-" + grant.reservation.access_code,
                "code": grant.reservation.access_code, # code might have to be unique, ensure uniqueness?
                "tokenType": "default",
                "validityStart": str(starts_at),
                "validityEnd": str(ends_at),
            }],
            "roles": [{
                "name": "Guest" # move to driver variable?
            }],
            "options": {
                "mode_organizations": "add",
                "mode_roles": "add",
                "mode_tokens": "add",
                "mode_qualifications": None,
                "mode_identification": "ssn"
            }
        }

        self.handle_api_post(data)
        grant.state = grant.INSTALLED
        grant.save()

    def remove_grant(self, grant):
        print('Removing Abloy grant: [%s]' % grant)

        tz = pytz.timezone('Europe/Helsinki')
        starts_at = grant.starts_at.astimezone(tz).replace(tzinfo=None)
        ends_at = grant.ends_at.astimezone(tz).replace(tzinfo=None)

        data = {
            "person": {
                "firstname": grant.reservation.user.first_name,
                "lastname": grant.reservation.user.last_name,
                "validityStart": str(starts_at), # only "2017-01-01 21:00" formatting?
                "validityEnd": str(ends_at), # only "2017-01-01 21:00" formatting?
                "ssn": str(grant.reservation.user.uuid)
            },
            "organizations": [{
                "name": self.get_setting("organization_name") or "Respa",
                "type": "company",
                "person_belongs": "true",
                "sub-organizations": [{
                    "name": grant.resource.driver_config.get("access_point_group_name"),
                    "type": "department",
                    "person_belongs": "true"
                }]
            }],
            "tokens": [{
                "surfaceMarking": "PIN-" + grant.reservation.access_code,
                "code": grant.reservation.access_code,
                "tokenType": "default",
                "validityStart": None, #str(datetime.now(tz).replace(tzinfo=None)),
                "validityEnd": None #str(datetime.now(tz).replace(tzinfo=None))
            }],
            "roles": [{
                "name": "Guest"
            }],
            "options": {
                "mode_organizations": None,
                "mode_roles": None,
                "mode_tokens": "replace",
                "mode_qualifications": None,
                "mode_identification": "ssn"
            }
        }

        self.handle_api_post(data)
        grant.state = grant.REMOVED
        grant.save()

    def handle_api_post(self, data):
        with self.ensure_token() as token:
            print("handle_api_post.....") # remove me
            path = "api/v1/persons-setup"
            url = '%s/%s' % (self.get_setting('api_url'), path)
            print("url: "+url) # remove me
            method = 'POST'
            headers = {"Accept": "application/json", "Authorization": "Bearer "+ token.access_token,}
            args = dict(headers=headers)
            args['json'] = data

            print("args: " + str(args)) # remove me

            resp = requests.request(method, url, timeout=REQUESTS_TIMEOUT, **args)

            print("resp status code: "+str(resp.status_code)) # remove me

            if resp.status_code not in (200, 201, 204):
                if resp.content:
                    try:
                        data = resp.json()
                        err_code = data.get('ErrorCode')
                        err_str = data.get('Message')
                    except Exception:
                        err_code = ''
                        err_str = ''
                    status_code = resp.status_code
                    # self.logger.error(f"Abloy API error [HTTP {status_code}] [{err_code}] {err_str}")
                    print(f"Abloy API error [HTTP {status_code}] [{err_code}] {err_str}")
                # raise Exception("Grant API POST failed!")

            if not resp.content:
                print("resp no content?")
            else:
                print("resp json: " + str(resp.json()))
