# -*- coding: utf-8 -*-
"""Manifest format conversion"""
from __future__ import unicode_literals
import re
import base64
import uuid
import xml.etree.ElementTree as ET

import resources.lib.common as common


def convert_to_dash(manifest):
    """Convert a Netflix style manifest to MPEGDASH manifest"""
    seconds = manifest['duration'] / 1000
    init_length = seconds / 2 * 12 + 20 * 1000
    duration = "PT" + str(seconds) + ".00S"

    root = _mpd_manifest_root(duration)
    period = ET.SubElement(root, 'Period', start='PT0S', duration=duration)
    protection = _protection_info(manifest)
    

    for video_track in manifest['video_tracks']:
        _convert_video_track(
            video_track, period, init_length, protection)

    for index, audio_track in enumerate(manifest['audio_tracks']):
        # Assume that first listed track is the default
        _convert_audio_track(audio_track, period, init_length,
                             default=(index == 0))
        
    #common.save_file('timedtexttracks.log',  str(manifest['timedtexttracks']))
    for text_track in manifest['timedtexttracks']:
        #common.save_file('text_track.log',  str(text_track))
        _convert_text_track(text_track, period)

    xml = ET.tostring(root, encoding='utf-8', method='xml')
    common.save_file('manifest.mpd', xml)
    return xml.replace('\n', '').replace('\r', '')


def _mpd_manifest_root(duration):
    root = ET.Element('MPD')
    root.attrib['xmlns'] = 'urn:mpeg:dash:schema:mpd:2011'
    root.attrib['xmlns:cenc'] = 'urn:mpeg:cenc:2013'
    root.attrib['mediaPresentationDuration'] = duration
    return root


def _protection_info(manifest):
    try:
##        pssh = manifest['psshb64'][0]
##        psshbytes = base64.standard_b64decode(pssh)
##        if len(psshbytes) == 52:
##            keyid = psshbytes[36:]
        pssh = None
        keyid = None
        if 'drmHeader' in manifest:
            keyid = manifest['drmHeader']['keyId']
            pssh = manifest['drmHeader']['bytes']            
    except (KeyError, AttributeError, IndexError):
        pssh = None
        keyid = None
    return {'pssh': pssh, 'keyid': keyid}


def _convert_video_track(video_track, period, init_length, protection):
    adaptation_set = ET.SubElement(
        parent=period,
        tag='AdaptationSet',
        mimeType='video/mp4',
        contentType='video')
    _add_protection_info(adaptation_set, **protection)
    for downloadable in video_track['streams']:
        _convert_video_downloadable(
            downloadable, adaptation_set, init_length)


def _add_protection_info(adaptation_set, pssh, keyid):
    if keyid:
        protection = ET.SubElement(
            parent=adaptation_set,
            tag='ContentProtection',
            value='cenc',
            schemeIdUri='urn:mpeg:dash:mp4protection:2011').set(
                'cenc:default_KID', str(uuid.UUID(bytes=keyid)))
    protection = ET.SubElement(
        parent=adaptation_set,
        tag='ContentProtection',
        schemeIdUri='urn:uuid:EDEF8BA9-79D6-4ACE-A3C8-27DCD51D21ED')
    ET.SubElement(
        parent=protection,
        tag='widevine:license',
        robustness_level='HW_SECURE_CODECS_REQUIRED')
    if pssh:
        ET.SubElement(protection, 'cenc:pssh').text = pssh


def _convert_video_downloadable(downloadable, adaptation_set,
                                init_length):
    codec = 'h264'
    if 'hevc' in downloadable['content_profile']:
        codec = 'hevc'
    elif 'vp9' in downloadable['content_profile']:
        lp = re.search('vp9-profile(.+?)-L(.+?)-dash', downloadable['content_profile'])
        codec = 'vp9.' + lp.group(1) + '.' + lp.group(2)

    hdcp_versions = '0.0'
    representation = ET.SubElement(
        parent=adaptation_set,
        tag='Representation',
        width=str(downloadable['res_w']),
        height=str(downloadable['res_h']),
        bandwidth=str(downloadable['bitrate'] * 1024),
##        hdcp=_determine_hdcp_version(downloadable['hdcpVersions']),
        hdcp=hdcp_versions,
        nflxContentProfile=str(downloadable['content_profile']),
        codecs=_determine_video_codec(downloadable['content_profile']),
        mimeType='video/mp4')
    _add_base_url(representation, downloadable)
    _add_segment_base(representation, init_length)


def _determine_hdcp_version(hdcp_versions):
    hdcp_version = '0.0'
##    for hdcp in hdcp_versions:
##        if hdcp != 'none':
##            hdcp_version = hdcp if hdcp != 'any' else '1.0'
    return hdcp_version


def _determine_video_codec(content_profile):
    if 'hevc' in content_profile:
        return 'hevc'
    elif 'vp9' in content_profile:
        return 'vp9.0.' + content_profile[14:16]
    return 'h264'


def _convert_audio_track(audio_track, period, init_length, default):
    languageMap = {}
    channelCount = {'1.0':'1', '2.0':'2', '5.1':'6', '7.1':'8'}
    impaired = 'true' if audio_track['trackType'] == 'ASSISTIVE' else 'false'
    original = 'true' if audio_track['isNative'] else 'false'
    default = 'false' if audio_track['language'] in languageMap else 'true'
    languageMap[audio_track['language']] = True
    adaptation_set = ET.SubElement(
        parent=period,
        tag='AdaptationSet',
        lang=audio_track['language'],
        contentType='audio',
        mimeType='audio/mp4',
##        impaired=str(audio_track.get('trackType') == 'ASSISTIVE').lower(),
##        original=str(audio_track.get('language', '').find('[') > 0).lower(),
##        default=str(default).lower())
        impaired=impaired,
        original=original,
        default=default)
    for downloadable in audio_track['streams']:
        _convert_audio_downloadable(
            downloadable, adaptation_set, init_length,
            audio_track.get('channelsCount'))


def _convert_audio_downloadable(downloadable, adaptation_set, init_length,
                                channels_count):
    representation = ET.SubElement(
        parent=adaptation_set,
        tag='Representation',
        codecs='ec-3' if 'ddplus' in downloadable['content_profile'] else 'aac',
#       codecs='ec-3' if 'ddplus' in downloadable['contentProfile'] else 'aac',

        bandwidth=str(downloadable['bitrate'] * 1024),
        mimeType='audio/mp4')
    ET.SubElement(
        parent=representation,
        tag='AudioChannelConfiguration',
        schemeIdUri='urn:mpeg:dash:23003:3:audio_channel_configuration:2011',
        value=str(channels_count))
    _add_base_url(representation, downloadable)
    _add_segment_base(representation, init_length)


def _convert_text_track(text_track, period):
    # Only one subtitle representation per adaptationset
    #common.save_file('ptext_track.log', str(text_track)) 
    downloadable = text_track['ttDownloadables']
    
#        is_ios8 = downloadable.get('contentProfile') == 'webvtt-lssdh-ios8'
    #common.save_file('downloadable.log', str(downloadable))
    try:
        content_profile = downloadable.keys()[0]
        #common.save_file('downloadable_content_profile.log', str(downloadable[content_profile]))
        adaptation_set = ET.SubElement(
            parent=period,
            tag='AdaptationSet',
            lang=text_track.get('language'),
            codecs='wvtt' if content_profile == 'webvtt-lssdh-ios8' else 'stpp',
            contentType='text',
            mimeType='text/vtt' if content_profile == 'webvtt-lssdh-ios8' else 'application/ttml+xml')
        ET.SubElement(
            parent=adaptation_set,
            tag='Role',
            schemeIdUri='urn:mpeg:dash:role:2011',
            value = 'forced' if text_track.get('isForcedNarrative') else 'main')
        representation = ET.SubElement(
            parent=adaptation_set,
            tag='Representation',
            nflxProfile=content_profile)
        _add_base_url(representation, downloadable[content_profile])
    except:
        pass


def _add_base_url(representation, downloadable):
    try:
        ET.SubElement(
            parent=representation,
            tag='BaseURL').text = downloadable['urls'][0]['url']
    except:
        #common.save_file('downloadable_url.log', str(downloadable['downloadUrls'].values()[0]))
        base_url = downloadable['downloadUrls'].values()[0]
        ET.SubElement(
            parent=representation,
            tag='BaseURL').text = base_url

def _add_segment_base(representation, init_length):
    ET.SubElement(
        parent=representation,
        tag='SegmentBase',
        indexRange='0-' + str(init_length),
        indexRangeExact='true')
