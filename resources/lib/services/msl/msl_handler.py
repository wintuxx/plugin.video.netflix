# -*- coding: utf-8 -*-
# Author: trummerjo
# Module: MSLHttpRequestHandler
# Created on: 26.01.2017
# License: MIT https://goo.gl/5bMj3H
"""Proxy service to convert manifest and provide license data"""
from __future__ import unicode_literals

import re
import zlib
import json
import time
import base64
from functools import wraps
import requests
import xbmcaddon

from resources.lib.globals import g
import resources.lib.common as common
import resources.lib.kodi.ui as ui

from .request_builder import MSLRequestBuilder
from .profiles import enabled_profiles
from .converter import convert_to_dash
from .exceptions import MSLError

CHROME_BASE_URL = 'https://www.netflix.com/nq/msl_v1/cadmium/'
ENDPOINTS = {
    'manifest': CHROME_BASE_URL + 'pbo_manifests/%5E1.0.0/router',
    'license': CHROME_BASE_URL + 'pbo_licenses/%5E1.0.0/router'
    #'license': 'http://www.netflix.com/api/msl/NFCDCH-LX/cadmium/license'	
}


def display_error_info(func):
    """Decorator that catches errors raise by the decorated function,
    displays an error info dialog in the UI and reraises the error"""
    # pylint: disable=missing-docstring
    @wraps(func)
    def error_catching_wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as exc:
            ui.show_error_info(common.get_local_string(30028), exc.message,
                               unknown_error=not exc.message,
                               netflix_error=isinstance(exc, MSLError))
            raise
    return error_catching_wrapper


class MSLHandler(object):
    """Handles session management and crypto for license and manifest
    requests"""
    last_drm_context = ''
    last_playback_context = ''
    last_license_url = ''
    session = requests.session()

    def __init__(self):
        # pylint: disable=broad-except
        try:
            self.request_builder = MSLRequestBuilder()
            msl_data = json.loads(common.load_file('msl_data.json'))
            if self.request_builder.crypto.check_mastertoken_validity(
                msl_data['tokens']['mastertoken']):
                self.request_builder = MSLRequestBuilder(msl_data)
                common.debug('Loaded MSL data from disk')
            else:
                #Expired mastertoken
                self.perform_key_handshake()
                #Load renewed msl_data
                self.request_builder = MSLRequestBuilder(json.loads(
                    common.load_file('msl_data.json')))
                common.debug('Renewed MSL data')
        except Exception:
            import traceback
            common.debug(traceback.format_exc())
            common.debug('Stored MSL data expired or not available')
            self.request_builder = MSLRequestBuilder()
            self.perform_key_handshake()
            self.request_builder = MSLRequestBuilder(json.loads(
                common.load_file('msl_data.json')))
        common.register_slot(
            signal=common.Signals.ESN_CHANGED,
            callback=self.perform_key_handshake)

    @display_error_info
    @common.time_execution(immediate=True)
    def perform_key_handshake(self, data=None):
        """Perform a key handshake and initialize crypto keys"""
        # pylint: disable=unused-argument
        esn = data or g.get_esn()
        if not esn:
            common.info('Cannot perform key handshake, missing ESN')
            return

        common.debug('Performing key handshake. ESN: {}'.format(esn))

        response = _process_json_response(
            self._post(ENDPOINTS['manifest'],
                       self.request_builder.handshake_request(esn)))
        headerdata = json.loads(
            base64.standard_b64decode(response['headerdata']))
        self.request_builder.crypto.parse_key_response(
            headerdata, not common.is_edge_esn(esn))
        common.debug('Key handshake successful')

    @display_error_info
    @common.time_execution(immediate=True)
    def load_manifest(self, viewable_id):
        """
        Loads the manifets for the given viewable_id and
        returns a mpd-XML-Manifest

        :param viewable_id: The id of of the viewable
        :return: MPD XML Manifest or False if no success
        """
        manifest = self._load_manifest(viewable_id, g.get_esn())
        # Disable 1080p Unlock for now, as it is broken due to Netflix changes
        # if (g.ADDON.getSettingBool('enable_1080p_unlock') and
        #         not g.ADDON.getSettingBool('enable_vp9_profiles') and
        #         not has_1080p(manifest)):
        #     common.debug('Manifest has no 1080p viewables, trying unlock')
        #     manifest = self.get_edge_manifest(viewable_id, manifest)
        return self.__tranform_to_dash(manifest)

    def get_edge_manifest(self, viewable_id, chrome_manifest):
        """Load a manifest with an EDGE ESN and replace playback_context and
        drm_context"""
        common.debug('Loading EDGE manifest')
        esn = g.get_edge_esn()
        common.debug('Switching MSL data to EDGE')
        self.perform_key_handshake(esn)
        manifest = self._load_manifest(viewable_id, esn)
        manifest['playbackContextId'] = chrome_manifest['playbackContextId']
        manifest['drmContextId'] = chrome_manifest['drmContextId']
        common.debug('Successfully loaded EDGE manifest')
        common.debug('Resetting MSL data to Chrome')
        self.perform_key_handshake()
        return manifest

    @common.time_execution(immediate=True)
    def _load_manifest(self, viewable_id, esn):
        common.debug('Requesting manifest for {} with ESN {}'
                     .format(viewable_id, esn))
        profiles = enabled_profiles()
        import pprint
        common.debug('Requested profiles:\n{}'
                     .format(pprint.pformat(profiles, indent=2)))
        '''
        manifest_request_data = {
            'method': 'manifest',
            'lookupType': 'PREPARE',
            'viewableIds': [viewable_id],
            'profiles': profiles,
            'drmSystem': 'widevine',
            'appId': '14673889385265',
            'sessionParams': {
                'pinCapableClient': False,
                'uiplaycontext': 'null'
            },
            'sessionId': '14673889385265',
            'trackId': 0,
            'flavor': 'PRE_FETCH',
            'secureUrls': False,
            'supportPreviewContent': True,
            'forceClearStreams': False,
            'languages': ['de-DE'],
            'clientVersion': '4.0004.899.011',
            'uiVersion': 'akira'
        }
        '''
        ia_addon = xbmcaddon.Addon('inputstream.adaptive')
        hdcp = ia_addon is not None and ia_addon.getSetting('HDCPOVERRIDE') == 'true'

##        esn = self.nx_common.get_esn()
        id = int(time.time() * 10000)
        manifest_request_data = {
            'version': 2,
            'url': '/manifest',
            'id': id,
            'esn': esn,
##            'languages': self.locale_id,
            'languages' : ['en-US'],
            'uiVersion': 'shakti-v25d2fa21',
            'clientVersion': '6.0011.474.011',
            'params': {
                'type': 'standard',
                'viewableId': [viewable_id],
                'profiles': profiles,                
                'flavor': 'PRE_FETCH',
                'drmType': 'widevine',
                'drmVersion': 25,
                'usePsshBox': True,
                'isBranching': False,
                'useHttpsStreams': False,
                'imageSubtitleHeight': 1080,
                'uiVersion': 'shakti-vb45817f4',
                'clientVersion': '6.0011.511.011',
                'supportsPreReleasePin': True,
                'supportsWatermark': True,
                'showAllSubDubTracks': False,
                'titleSpecificData': {},
                'videoOutputInfo': [{
                    'type': 'DigitalVideoOutputDescriptor',
                    'outputType': 'unknown',
                    'supportedHdcpVersions': [],
                    'isHdcpEngaged': False
                }],
                'preferAssistiveAudio': False,
                'isNonMember': False
            }
        }
        #common.save_file('manifest_request_data.json', str(manifest_request_data))
        manifest = self._chunked_request(ENDPOINTS['manifest'],
                                         manifest_request_data, esn)
        common.save_file('manifest.json', json.dumps(manifest))
##        return manifest['result']['viewables'][0]
        return manifest['result']
    @display_error_info
    @common.time_execution(immediate=True)
    def get_license(self, challenge, sid):
        """
        Requests and returns a license for the given challenge and sid
        :param challenge: The base64 encoded challenge
        :param sid: The sid paired to the challengew
        :return: Base64 representation of the licensekey or False unsuccessfull
        """
        common.debug('Requesting license')
##        license_request_data = {
##            'method': 'license',
##            'licenseType': 'STANDARD',
##            'clientVersion': '4.0004.899.011',
##            'uiVersion': 'akira',
##            'languages': ['de-DE'],
##            'playbackContextId': self.last_playback_context,
##            'drmContextIds': [self.last_drm_context],
##            'challenges': [{
##                'dataBase64': challenge,
##                'sessionId': sid
##            }],
##            'clientTime': int(time.time()),
##            'xid': int((int(time.time()) + 0.1612) * 1000)
##        }
        id = int(time.time() * 10000)
        ##challange_hd = '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'
        license_request_data = {
            'version': 2,
            'url': self.last_license_url,
            'id': id,
            'esn': g.get_esn(),
            'languages': ['en-US'],
            'uiVersion': 'shakti-v25d2fa21',
            'clientVersion': '6.0011.511.011',
            'params': [{
                'sessionId': sid,
                'clientTime': int(id / 10000),
                'challengeBase64': challenge,
                'xid': str(id + 1610)
            }],
            'echo': 'sessionId'
        }
        #common.save_file('license_request_data.json', str(license_request_data))        

        response = self._chunked_request(ENDPOINTS['license'],
                                         license_request_data, g.get_esn())
#        return response['result']['licenses'][0]['data']
        #common.save_file('lic_response.json', str(response['result'][0]['licenseResponseBase64']))        
        return response['result'][0]['licenseResponseBase64']

    @common.time_execution(immediate=True)
    def __tranform_to_dash(self, manifest):
        self.last_license_url = manifest['links']['license']['href']
        self.last_playback_context = manifest['playbackContextId']
        self.last_drm_context = manifest['drmContextId']
        return convert_to_dash(manifest)

    @common.time_execution(immediate=True)
    def _chunked_request(self, endpoint, request_data, esn):
        """Do a POST request and process the chunked response"""
        return self._process_chunked_response(
            self._post(endpoint,
                       self.request_builder.msl_request(request_data, esn)))

    @common.time_execution(immediate=True)
    def _post(self, endpoint, request_data):
        """Execute a post request"""
        common.debug('Executing POST request to {}'.format(endpoint))
        start = time.clock()
        response = self.session.post(endpoint, request_data)
        common.debug('Request took {}s'.format(time.clock() - start))
        common.debug('Request returned response with status {}'
                     .format(response.status_code))
        response.raise_for_status()
        return response

    @common.time_execution(immediate=True)
    def _process_chunked_response(self, response):
        """Parse and decrypt an encrypted chunked response. Raise an error
        if the response is plaintext json"""
        try:
            # if the json() does not fail we have an error because
            # the expected response is a chunked json response
            return _raise_if_error(response.json())
        except ValueError:
            # json() failed so parse and decrypt the chunked response
            common.debug('Received encrypted chunked response')
            response = _parse_chunks(response.text)
            decrypted_response = _decrypt_chunks(response['payloads'],
                                                 self.request_builder.crypto)
            return _raise_if_error(decrypted_response)


@common.time_execution(immediate=True)
def _process_json_response(response):
    """Execute a post request and expect a JSON response"""
    try:
        return _raise_if_error(response.json())
    except ValueError:
        raise MSLError('Expected JSON response, got {}'.format(response.text))


def _raise_if_error(decoded_response):
    if ('errordata' in decoded_response or
            not decoded_response.get('success', True)):
        common.error('Full MSL error information:')
        common.error(json.dumps(decoded_response))
        raise MSLError(_get_error_details(decoded_response))
    return decoded_response


def _get_error_details(decoded_response):
    if 'errordata' in decoded_response:
        return json.loads(
            base64.standard_b64decode(
                decoded_response['errordata']))['errormsg']
    elif decoded_response.get('result', {}).get('errorDisplayMessage'):
        return decoded_response['result']['errorDisplayMessage']
    elif decoded_response.get('result', {}).get('errorDetails'):
        return decoded_response['result']['errorDetails']
    return ''


@common.time_execution(immediate=True)
def _parse_chunks(message):
    header = message.split('}}')[0] + '}}'
    payloads = re.split(',\"signature\":\"[0-9A-Za-z=/+]+\"}',
                        message.split('}}')[1])
    payloads = [x + '}' for x in payloads][:-1]
    return {'header': header, 'payloads': payloads}


@common.time_execution(immediate=True)
def _decrypt_chunks(chunks, crypto):
    decrypted_payload = ''
    for chunk in chunks:
        payloadchunk = json.loads(chunk)
        payload = payloadchunk.get('payload')
        decoded_payload = base64.standard_b64decode(payload)
        encryption_envelope = json.loads(decoded_payload)
        # Decrypt the text
        plaintext = crypto.decrypt(
            base64.standard_b64decode(encryption_envelope['iv']),
            base64.standard_b64decode(encryption_envelope.get('ciphertext')))
        # unpad the plaintext
        plaintext = json.loads(plaintext)
        data = plaintext.get('data')

        # uncompress data if compressed
        if plaintext.get('compressionalgo') == 'GZIP':
            decoded_data = base64.standard_b64decode(data)
            data = zlib.decompress(decoded_data, 16 + zlib.MAX_WBITS)
        else:
            data = base64.standard_b64decode(data)
        decrypted_payload += data
    decrypted_payload = json.loads(decrypted_payload)
##    decrypted_payload = base64.standard_b64decode(decrypted_payload)
##    return json.loads(decrypted_payload)
    return decrypted_payload

def has_1080p(manifest):
    """Return True if any of the video tracks in manifest have a 1080p profile
    available, else False"""
    return any(video['width'] >= 1920
               for video in manifest['videoTracks'][0]['downloadables'])
