# -*- coding: utf_8 -*-
"""Module for iOS App Plist Analysis."""

import io
import os
import subprocess
import plistlib

from buildEnv import env
from util import isFileExists


def convert_bin_xml(bin_xml_file):
    """Convert Binary XML to Readable XML"""
    plutil = "/usr/bin/plutil"
    try:
        args = [plutil, '-convert', 'xml1', bin_xml_file]
        dat = subprocess.check_output(args)
        with io.open(bin_xml_file, mode='r', encoding="utf8", errors="ignore") as flip:
            dat = flip.read()
        return dat
    except:
        print("[ERROR] Converting Binary XML to Readable XML")


def __check_permissions(p_list):
    '''Check the permissions the app requests.'''
    # List taken from
    # https://developer.apple.com/library/content/documentation/General/Reference/InfoPlistKeyReference/Articles/CocoaKeys.html
    print("[LOG] Checking Permissions")
    permissions = []
    if "NSAppleMusicUsageDescription" in p_list:
        permissions.append(
            (
                "NSAppleMusicUsageDescription",
                "Access Apple Media Library.",
                p_list["NSAppleMusicUsageDescription"]
            )
        )
    if "NSBluetoothPeripheralUsageDescription" in p_list:
        permissions.append(
            (
                "NSBluetoothPeripheralUsageDescription",
                "Access Bluetooth Interface.",
                p_list["NSBluetoothPeripheralUsageDescription"]
            )
        )
    if "NSCalendarsUsageDescription" in p_list:
        permissions.append(
            (
                "NSCalendarsUsageDescription",
                "Access Calendars.",
                p_list["NSCalendarsUsageDescription"]
            )
        )
    if "NSCameraUsageDescription" in p_list:
        permissions.append(
            (
                "NSCameraUsageDescription",
                "Access the Camera.",
                p_list["NSCameraUsageDescription"]
            )
        )
    if "NSContactsUsageDescription" in p_list:
        permissions.append(
            (
                "NSContactsUsageDescription",
                "Access Contacts.",
                p_list["NSContactsUsageDescription"]
            )
        )
    if "NSHealthShareUsageDescription" in p_list:
        permissions.append(
            (
                "NSHealthShareUsageDescription",
                "Read Health Data.",
                p_list["NSHealthShareUsageDescription"]
            )
        )
    if "NSHealthUpdateUsageDescription" in p_list:
        permissions.append(
            (
                "NSHealthUpdateUsageDescription",
                "Write Health Data.",
                p_list["NSHealthUpdateUsageDescription"]
            )
        )
    if "NSHomeKitUsageDescription" in p_list:
        permissions.append(
            (
                "NSHomeKitUsageDescription",
                "Access HomeKit configuration data.",
                p_list["NSHomeKitUsageDescription"]
            )
        )
    if "NSLocationAlwaysUsageDescription" in p_list:
        permissions.append(
            (
                "NSLocationAlwaysUsageDescription",
                "Access location information at all times.",
                p_list["NSLocationAlwaysUsageDescription"]
            )
        )
    if "NSLocationUsageDescription" in p_list:
        permissions.append(
            (
                "NSLocationUsageDescription",
                "Access location information at all times (< iOS 8).",
                p_list["NSLocationUsageDescription"]
            )
        )
    if "NSLocationWhenInUseUsageDescription" in p_list:
        permissions.append(
            (
                "NSLocationWhenInUseUsageDescription",
                "Access location information when app is in the foreground.",
                p_list["NSLocationWhenInUseUsageDescription"]
            )
        )
    if "NSMicrophoneUsageDescription" in p_list:
        permissions.append(
            (
                "NSMicrophoneUsageDescription",
                "Access microphone.",
                p_list["NSMicrophoneUsageDescription"]
            )
        )
    if "NSMotionUsageDescription" in p_list:
        permissions.append(
            (
                "NSMotionUsageDescription",
                "Access the device’s accelerometer.",
                p_list["NSMotionUsageDescription"]
            )
        )
    if "NSPhotoLibraryUsageDescription" in p_list:
        permissions.append(
            (
                "NSPhotoLibraryUsageDescription",
                "Access the user’s photo library.",
                p_list["NSPhotoLibraryUsageDescription"]
            )
        )
    if "NSRemindersUsageDescription" in p_list:
        permissions.append(
            (
                "NSRemindersUsageDescription",
                "Access the user’s reminders.",
                p_list["NSRemindersUsageDescription"]
            )
        )
    if "NSVideoSubscriberAccountUsageDescription" in p_list:
        permissions.append(
            (
                "NSVideoSubscriberAccountUsageDescription",
                "Access the user’s TV provider account.",
                p_list["NSVideoSubscriberAccountUsageDescription"]
            )
        )

    return permissions


def __check_insecure_connections(p_list):
    '''Check info.plist for insecure connection configurations.'''
    print("[LOG] Checking for Insecure Connections")

    insecure_connections = []

    if 'NSAppTransportSecurity' in p_list:
        ns_app_trans_dic = p_list['NSAppTransportSecurity']
        if 'NSExceptionDomains' in ns_app_trans_dic:
            for key in ns_app_trans_dic['NSExceptionDomains']:
                insecure_connections.append(key)

    return insecure_connections


def plist_analysis(src):

    #Plist Analysis
    try:
        print("[LOG] iOS Info.plist Analysis Started")
        plist_info = {}
        plist_info["bin_name"] = ""
        plist_info["bin"] = ""
        plist_info["id"] = ""
        plist_info["ver"] = ""
        plist_info["sdk"] = ""
        plist_info["pltfm"] = ""
        plist_info["min"] = ""
        plist_info["plist_xml"] = ""
        plist_info["permissions"] = []
        plist_info["inseccon"] = []
        info_plist_content = ''

        xml_file = os.path.join(src, "Info.plist")
        if not isFileExists(xml_file):
            print("[WARNING] Cannot find Info.plist file. Skipping Plist Analysis.")
        else:
            info_plist_content = convert_bin_xml(xml_file)
        #Generic Plist Analysis
        plist_info["plist_xml"] = info_plist_content
        if isinstance(info_plist_content, unicode):
            info_plist_content = info_plist_content.encode("utf-8", "replace")
        plist_obj = plistlib.readPlistFromString(info_plist_content)
        if "CFBundleDisplayName" in plist_obj:
            plist_info["bin_name"] = plist_obj["CFBundleDisplayName"]
        else:
            plist_info["bin_name"] = plist_obj["CFBundleName"]
        if "CFBundleExecutable" in plist_obj:
            plist_info["bin"] = plist_obj["CFBundleExecutable"]
        if "CFBundleIdentifier" in plist_obj:
            plist_info["id"] = plist_obj["CFBundleIdentifier"]
        if "CFBundleVersion" in plist_obj:
            plist_info["ver"] = plist_obj["CFBundleVersion"]
        if "DTSDKName" in plist_obj:
            plist_info["sdk"] = plist_obj["DTSDKName"]
        if "DTPlatformVersion" in plist_obj:
            plist_info["pltfm"] = plist_obj["DTPlatformVersion"]
        if "MinimumOSVersion" in plist_obj:
            plist_info["min"] = plist_obj["MinimumOSVersion"]
        # Check possible app-permissions
        plist_info["permissions"] = __check_permissions(plist_obj)
        plist_info["inseccon"] = __check_insecure_connections(plist_obj)


        result=[]
        result.append(plist_info["bin_name"])
        result.append(plist_info["bin"])
        result.append(plist_info["id"])
        result.append(plist_info["ver"])
        result.append(plist_info["sdk"])
        result.append(plist_info["pltfm"])
        result.append(plist_info["min"])
        result.extend(plist_info["permissions"])
        result.extend(plist_info["inseccon"])

        return (plist_info, 'InfoPlist')
    except:
        print("[ERROR] - Reading from Info.plist")
