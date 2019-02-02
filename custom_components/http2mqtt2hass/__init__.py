"""
author: cnk700i
blog: ljr.im
tested On HA version: 0.82.1
"""
from base64 import b64decode
from base64 import b64encode
from Crypto.Cipher import AES
import binascii
from hashlib import sha1
import logging
import voluptuous as vol
import os
import ssl
import json
from json.decoder import JSONDecodeError
import requests.certs
from homeassistant import config_entries
from homeassistant.core import Event, ServiceCall, callback
from homeassistant.helpers import config_validation as cv
from homeassistant.core import callback, Context, Event
from homeassistant.components import mqtt
from homeassistant.helpers.typing import HomeAssistantType, ConfigType
from homeassistant.const import (CONF_PORT, CONF_PROTOCOL, EVENT_HOMEASSISTANT_STOP)
from . import config_flow
from voluptuous.humanize import humanize_error
import traceback

import asyncio
import async_timeout
import aiohttp
from homeassistant.helpers.aiohttp_client import async_get_clientsession

REQUIREMENTS = ['paho-mqtt>=1.4.0']

_LOGGER = logging.getLogger(__name__)
# _LOGGER.setLevel(logging.DEBUG)

DOMAIN = 'http2mqtt2hass'

DATA_HTTP2MQTT2HASS_CONFIG = 'http2mqtt2hass_config'
DATA_HTTP2MQTT2HASS_MQTT = 'http2mqtt2hass_mqtt'

CONF_APP_KEY = 'app_key'
CONF_APP_SECRET = 'app_secret'
CONF_CLIENT_ID = 'client_id'
CONF_KEEPALIVE = 'keepalive'
CONF_TOPIC = 'topic'
CONF_BROKER = 'broker'
CONF_CERTIFICATE = 'certificate'
CONF_CLIENT_KEY = 'client_key'
CONF_CLIENT_CERT = 'client_cert'
CONF_TLS_INSECURE = 'tls_insecure'
CONF_TLS_VERSION = 'tls_version'
CONF_ALLOWED_URI = 'allowed_uri'

CONF_BIRTH_MESSAGE = 'birth_message'
CONF_WILL_MESSAGE = 'will_message'

PROTOCOL_31 = '3.1'
PROTOCOL_311 = '3.1.1'

DEFAULT_BROKER = 'mqtt.ljr.im'
DEFAULT_PORT = 28883
DEFAULT_KEEPALIVE = 60
DEFAULT_QOS = 0
DEFAULT_PROTOCOL = PROTOCOL_311
DEFAULT_TLS_PROTOCOL = 'auto'

CLIENT_KEY_AUTH_MSG = 'client_key and client_cert must both be present in the MQTT broker configuration'
CONFIG_SCHEMA = vol.Schema({
    DOMAIN: vol.Schema({
        vol.Optional(CONF_CLIENT_ID): cv.string,
        vol.Optional(CONF_KEEPALIVE, default=DEFAULT_KEEPALIVE): vol.All(vol.Coerce(int), vol.Range(min=15)),
        vol.Optional(CONF_BROKER, default=DEFAULT_BROKER): cv.string,
        vol.Optional(CONF_PORT, default=DEFAULT_PORT): cv.port,
        vol.Optional(CONF_APP_KEY): cv.string,
        vol.Optional(CONF_APP_SECRET): cv.string,
        vol.Optional(CONF_CERTIFICATE): vol.Any('auto', cv.isfile),
        vol.Inclusive(CONF_CLIENT_KEY, 'client_key_auth', msg=CLIENT_KEY_AUTH_MSG): cv.isfile,
        vol.Inclusive(CONF_CLIENT_CERT, 'client_key_auth', msg=CLIENT_KEY_AUTH_MSG): cv.isfile,
        vol.Optional(CONF_TLS_INSECURE): cv.boolean,
        vol.Optional(CONF_TLS_VERSION, default=DEFAULT_TLS_PROTOCOL): vol.Any('auto', '1.0', '1.1', '1.2'),
        vol.Optional(CONF_PROTOCOL, default=DEFAULT_PROTOCOL): vol.All(cv.string, vol.In([PROTOCOL_31, PROTOCOL_311])),
        vol.Optional(CONF_TOPIC): cv.string,
        vol.Optional(CONF_ALLOWED_URI, default=[]): vol.All(cv.ensure_list, vol.Length(min=0), [cv.string]),
        })
}, extra=vol.ALLOW_EXTRA)

CONTEXT = Context(DOMAIN)

async def async_setup(hass: HomeAssistantType, config: ConfigType) -> bool:
    conf = config.get(DOMAIN, {})  # type: ConfigType

    if conf is None:
        # If we have a config entry, setup is done by that config entry.
        # If there is no config entry, this should fail.
        return bool(hass.config_entries.async_entries(DOMAIN))

    hass.data[DATA_HTTP2MQTT2HASS_CONFIG] = conf

    conf = dict(conf)
    # Only import if we haven't before.
    if not hass.config_entries.async_entries(DOMAIN):
        hass.async_create_task(hass.config_entries.flow.async_init(
            DOMAIN, context={'source': config_entries.SOURCE_IMPORT},
            data={}
        ))

    return True

async def async_setup_entry(hass, entry):
    """Load a config entry."""
    conf = hass.data.get(DATA_HTTP2MQTT2HASS_CONFIG)

    # Config entry was created because user had configuration.yaml entry
    # They removed that, so remove entry.
    if conf is None and entry.source == config_entries.SOURCE_IMPORT:
        hass.async_create_task(
            hass.config_entries.async_remove(entry.entry_id))
        return False

    # If user didn't have configuration.yaml config, generate defaults
    if conf is None:
        conf = CONFIG_SCHEMA({
            DOMAIN: entry.data,
        })[DOMAIN]
    elif any(key in conf for key in entry.data):
        _LOGGER.warning(
            "Data in your config entry is going to override your "
            "configuration.yaml: %s", entry.data)

    conf.update(entry.data)

    broker = conf[CONF_BROKER]
    port = conf[CONF_PORT]
    client_id = conf.get(CONF_CLIENT_ID)
    keepalive = conf[CONF_KEEPALIVE]
    app_key = conf.get(CONF_APP_KEY)
    app_secret = conf.get(CONF_APP_SECRET)
    certificate = conf.get(CONF_CERTIFICATE)
    client_key = conf.get(CONF_CLIENT_KEY)
    client_cert = conf.get(CONF_CLIENT_CERT)
    tls_insecure = conf.get(CONF_TLS_INSECURE)
    protocol = conf[CONF_PROTOCOL]
    allowed_uri = conf.get(CONF_ALLOWED_URI)
    decrypt_key =bytes().fromhex(sha1(app_secret.encode("utf-8")).hexdigest())[0:16]

    # For cloudmqtt.com, secured connection, auto fill in certificate
    if (certificate is None and 19999 < conf[CONF_PORT] < 30000 and
            broker.endswith('.cloudmqtt.com')):
        certificate = os.path.join(
            os.path.dirname(__file__), 'addtrustexternalcaroot.crt')

    # When the certificate is set to auto, use bundled certs from requests
    elif certificate == 'auto':
        certificate = requests.certs.where()

    if CONF_WILL_MESSAGE in conf:
        will_message = mqtt.Message(**conf[CONF_WILL_MESSAGE])
    else:
        will_message = None

    if CONF_BIRTH_MESSAGE in conf:
        birth_message = mqtt.Message(**conf[CONF_BIRTH_MESSAGE])
    else:
        birth_message = None

    # Be able to override versions other than TLSv1.0 under Python3.6
    conf_tls_version = conf.get(CONF_TLS_VERSION)  # type: str
    if conf_tls_version == '1.2':
        tls_version = ssl.PROTOCOL_TLSv1_2
    elif conf_tls_version == '1.1':
        tls_version = ssl.PROTOCOL_TLSv1_1
    elif conf_tls_version == '1.0':
        tls_version = ssl.PROTOCOL_TLSv1
    else:
        import sys
        # Python3.6 supports automatic negotiation of highest TLS version
        if sys.hexversion >= 0x03060000:
            tls_version = ssl.PROTOCOL_TLS  # pylint: disable=no-member
        else:
            tls_version = ssl.PROTOCOL_TLSv1

    hass.data[DATA_HTTP2MQTT2HASS_MQTT] = mqtt.MQTT(
        hass,
        broker=broker,
        port=port,
        client_id=client_id,
        keepalive=keepalive,
        username=app_key,
        password=app_secret,
        certificate=certificate,
        client_key=client_key,
        client_cert=client_cert,
        tls_insecure=tls_insecure,
        protocol=protocol,
        will_message=will_message,
        birth_message=birth_message,
        tls_version=tls_version,
    )

    success = await hass.data[DATA_HTTP2MQTT2HASS_MQTT].async_connect()  # type: bool

    if not success:
        return False

    async def async_stop_mqtt(event: Event):
        """Stop MQTT component."""
        await hass.data[DATA_HTTP2MQTT2HASS_MQTT].async_disconnect()

    hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, async_stop_mqtt)

    async def localHttp(resData,topic):
        url = 'https://localhost:8123'+resData['uri']
        if('content' in resData):
            try:
                session = async_get_clientsession(hass, verify_ssl=False)
                with async_timeout.timeout(5, loop=hass.loop):
                    response = await session.post(url, data=resData['content'], headers = resData.get('headers'))
            except(asyncio.TimeoutError, aiohttp.ClientError):
                _LOGGER.error("Error while accessing: %s", url)
                result = {"error":"time_out"}
        else:
            try:
                session = async_get_clientsession(hass, verify_ssl=False)
                with async_timeout.timeout(5, loop=hass.loop):
                    response = await session.get(url, headers = resData.get('headers'))
            except(asyncio.TimeoutError, aiohttp.ClientError):
                _LOGGER.error("Error while accessing: %s", url)
                result = {"error":"time_out"}
            # _LOGGER.debug(response.history) #查看重定向信息
        if response.status != 200:
            _LOGGER.error("Error while accessing: %s, status=%d",url,response.status)

        if('image' in response.headers['Content-Type'] or 'stream' in response.headers['Content-Type']):
            result = await response.read()
            result = b64encode(result).decode()
        else:
            result = await response.text()
        headers = {
            'Content-Type': response.headers['Content-Type']
        }
        res = {
            'headers': headers,
            'status': response.status,
            'content': result.encode('utf-8').decode('unicode_escape'),
            'msgId': resData.get('msgId')
        }
        _LOGGER.debug("%s response[%s]: [%s]", resData['uri'].split('/')[-1].split('?')[0], resData.get('msgId'), response.headers['Content-Type'], )
        res = AESCipher(decrypt_key).encrypt(json.dumps(res, ensure_ascii = False).encode('utf8'))

        await hass.data[DATA_HTTP2MQTT2HASS_MQTT].async_publish(topic.replace('/request/','/response/'), res, 2, False)

    @callback
    def message_received(topic, payload, qos):
        """Handle new MQTT state messages."""
        _LOGGER.debug('get encrypt message: \n {}'.format(payload))
        try:
            payload = AESCipher(decrypt_key).decrypt(payload)
            req = json.loads(payload)
            _LOGGER.debug("raw message: %s", req)
            if(allowed_uri and req.get('uri').split('?')[0] not in allowed_uri):
                _LOGGER.debug('uri not allowed: %s', req.get('uri'))
                return
            hass.add_job(localHttp(req, topic))
        except (JSONDecodeError,UnicodeDecodeError,binascii.Error):
            import sys
            ex_type, ex_val, ex_stack = sys.exc_info()
            log = ''
            for stack in traceback.extract_tb(ex_stack):
                log += str(stack)
            _LOGGER.debug('decrypt failure, abandon:%s', log)

    await hass.data[DATA_HTTP2MQTT2HASS_MQTT].async_subscribe("ai-home/http2mqtt2hass/"+app_key+"/request/#", message_received, 2, 'utf-8')
    return True

class AESCipher:
    """
    Tested under Python 3.x and PyCrypto 2.6.1.
    """

    def __init__(self, key):
        #加密需要的key值
        self.key=key
        self.mode = AES.MODE_CBC
    def encrypt(self, raw):
        # Padding for the input string --not
        # related to encryption itself.
        BLOCK_SIZE = 16  # Bytes
        pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
                        chr(BLOCK_SIZE - len(s) % BLOCK_SIZE).encode('utf8')
        raw = pad(raw)
        #通过key值，使用ECB模式进行加密
        cipher = AES.new(self.key, self.mode, b'0000000000000000')
        #返回得到加密后的字符串进行解码然后进行64位的编码
        return b64encode(cipher.encrypt(raw)).decode('utf8')

    def decrypt(self, enc):
        unpad = lambda s: s[:-ord(s[len(s) - 1:])]
        #首先对已经加密的字符串进行解码
        enc = b64decode(enc)
        #通过key值，使用ECB模式进行解密
        cipher = AES.new(self.key, self.mode, b'0000000000000000')
        return unpad(cipher.decrypt(enc)).decode('utf8')
