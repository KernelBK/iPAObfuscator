#!/usr/bin/python
# -*- coding: UTF-8 -*-

#!/usr/bin/python
#-*-coding:utf-8 -*-

import hashlib
import os
import platform
import re
import shutil
import sys
import zipfile

import util
from cmd import *
from binary_analysis import binary_analysis
from plist_analysis import (convert_bin_xml, plist_analysis)

from buildEnv import env

class fileParse(object):

    Other = 0
    IPA = 1
    ZIP = 2
    xcarchive = 3
    app = 4

    def __init__(self, args=None):
        if args is None:
            return
        self.initState(args)

    def initState(self, args):
        self.inputFile = args.input_file
        fname = os.path.basename(self.inputFile)
        if fname.lower().endswith('ipa'):
            self.fileType = fileParse.IPA
        elif fname.lower().endswith('zip'):
            self.fileType = fileParse.ZIP
        elif fname.lower().endswith('xcarchive'):
            self.fileType = fileParse.xcarchive
        elif fname.lower().endswith('.app'):
            self.fileType = fileParse.app
        else:
            self.fileType = fileParse.Other

    def zipdir(self, dirname, zipfilename):
        filelist = []
        if os.path.isfile(dirname):
            filelist.append(dirname)
        else:
            for root, dirs, files in os.walk(dirname):
                for name in files:
                    filelist.append(os.path.join(root, name))

        zf = zipfile.ZipFile(zipfilename, "w", zipfile.zlib.DEFLATED)
        for tar in filelist:
            arcname = tar[len(dirname):]
            zf.write(tar, arcname)
        zf.close()
    def unzip(self, app_path, ext_path):
        print("[LOG] Unzipping")
        files = []
        with zipfile.ZipFile(app_path, "r") as zipptr:
            for fileinfo in zipptr.infolist():
                filename = fileinfo.filename
                if not isinstance(filename, unicode):
                    filename = unicode(
                        filename, encoding="utf-8", errors="replace")
                files.append(filename)
                zipptr.extract(fileinfo, ext_path)
        print("[LOG] Extract Done!")
        return files

    def md5_ipa_builder(self, filecnt):
        """
        Write Uploaded File
        """
        md5 = hashlib.md5()  # modify if crash for large
        md5.update(filecnt)
        md5sum = md5.hexdigest()
        return md5sum


    def app_list_files(self, src, subdir, binary_form):

        files = []
        plists = []
        cers = []
        databases = []

        cer_dir = os.path.join(src, 'cer')
        db_dir = os.path.join(src, 'db')
        plist_dir = os.path.join(src, 'plist')

        cer_dir_exists = util.auto_make_dir(cer_dir)
        db_dir_exists = util.auto_make_dir(db_dir)
        plist_dir_exits = util.auto_make_dir(plist_dir)

        try:
            for dirname,_,files in os.walk(os.path.join(src, subdir)):
                for jfile in files:
                    if not jfile.endswith('.DS_Store') and not cer_dir_exists\
                            and not db_dir_exists and not plist_dir_exits:
                        file_path = os.path.join(src, dirname, jfile)
                        if "+" in jfile:
                            plugx = os.path.join(src, dirname, jfile.replace("+", "v"))
                            shutil.move(file_path, plugx)
                            file_path = plugx
                        fileParam = file_path.replace(src,'')
                        files.append(fileParam)
                        ext = jfile.split('.')[-1]
                        #本地证书存储
                        if re.search('cer|pem|cert|crt|pub|key|pfx|p12', ext):
                            cers.append((self.read_cer(file_path),fileParam))
                            #第一次才需要分类文件
                            shutil.move(file_path, cer_dir)
                        #本地数据库存储
                        if re.search('db|sqlitedb|sqlite', ext):
                            databases.append((self.read_db(file_path, fileParam)))
                            shutil.move(file_path, db_dir)
                        #plist存储与转换成可阅读模式
                        if jfile.endswith('.plist'):
                            plists.append(fileParam)
                            shutil.move(file_path, plist_dir)
                            if binary_form:
                                rat = convert_bin_xml(file_path)
                    else:
                        pass
            result=[]
            result.extend(files)
            result.extend(plists)
            result.extend(databases)
            result.extend(cers)

            return result, 'IPA'
        except:
            print("[LOG] This is not A payLoad dir!")


    def read_db(self, path):
        with open(path, 'r') as db:
            return db.read()

    def read_cer(self, path):
        with open(path, 'r') as cer:
            return cer.read()

    def installOutDir(self, outDict, task_id, outDir):
        if self.fileType == fileParse.IPA:
            payLoadDir = outDict['unzip_dir']
            self.zipdir(payLoadDir, os.path.join(outDir, '%s.unsigned.ipa' % task_id))
        elif self.fileType == fileParse.Other:
            taskId_Dir = outDict['unzip_dir']
            self.zipdir(taskId_Dir, os.path.join(outDir, '%s.unsigned.zip' % task_id))
    def getRealFile(self,task_id):
        tmpPath = 'tmp/' + task_id
        desfile = os.path.join(os.getcwd(), tmpPath, os.path.basename(self.inputFile))
        if not os.path.exists(tmpPath):
            os.makedirs(tmpPath)
        if not os.path.exists(desfile):
            CopyFile(self.inputFile, os.path.join(os.getcwd(), tmpPath)).runCmd()
        pro_dict = {}
        pro_dict['filetype'] = self.fileType
        srcPath = desfile
        fname = os.path.basename(srcPath)
        if self.fileType == fileParse.Other:
            pro_dict['BinName'] = srcPath
            pro_dict['unzip_dir'] = os.path.join(util.BASE_DIR, tmpPath)
            print("[LOG] 文件不是ipa或zip 返回原始Input")
            return pro_dict

        #IPA ZIP
        if self.fileType == fileParse.IPA or self.fileType == fileParse.ZIP:
            fileBasName = fname.split(".")[0]
            pro_dict['md5'] = self.md5_ipa_builder(fname)
            pro_dict['unzip_dir'] = os.path.join(util.BASE_DIR, tmpPath, fileBasName)
            print("[LOG] Extracting IPA File")
            # EXTRACT IPA
            if not os.path.exists(pro_dict['unzip_dir']):
                self.unzip(srcPath, pro_dict['unzip_dir'])
            PayLoadPath = os.path.join(pro_dict['unzip_dir'], 'Payload')
            pathDir = os.listdir(PayLoadPath)
            for allDir in pathDir:
                if allDir.endswith('.app'):
                    pro_dict['appName'] = allDir
                    break
            pro_dict['plistPath'] = os.path.join(pro_dict['unzip_dir'], 'Payload', pro_dict['appName'])
        #xcarchive
        elif self.fileType == fileParse.xcarchive:
            appPath = os.path.join(srcPath, 'Products', 'Applications')
            pathDir = os.listdir(appPath)
            for allDir in pathDir:
                if allDir.endswith('.app'):
                    appName = os.path.join(srcPath, 'Products', 'Applications', allDir)
                    pro_dict['appName'] = appName
                    pro_dict['plistPath'] = appName
                    break
            # isFind = False
            # for dirName in os.walk(appPath):
            #     if isFind:
            #         break
            #     for item in dirName:
            #         if item[0].endswith('.app'):
            #             appName = os.path.join(srcPath, 'Products', 'Applications', item[0])
            #             pro_dict['appName'] = appName
            #             pro_dict['plistPath'] = appName
            #             isFind = True
            #             break
        # app
        elif self.fileType == fileParse.app:
            pro_dict['plistPath'] = srcPath

        pro_dict['toolpath'] = os.path.join(util.BASE_DIR, 'StaticAnalyzer', 'tools')

        #IPA原始文件处理
        #ipa_info = self.app_list_files(pro_dict['unzip_dir'], 'Payload', False)
        print("[LOG] check All kind of files Done!")
        #针对db和cer暂时不处理，只是列出来
        plist_info = plist_analysis(pro_dict['plistPath'])
        #二进制文件处理
        #binary_list_info = binary_analysis(os.path.join(pro_dict['unzip_dir'], 'Payload'),pro_dict['toolpath'],pro_dict['unzip_dir'])

        pro_dict['BinName'] = plist_info[0]['bin']
        #return [ipa_info,plist_info]
        #binName = os.path.join(pro_dict['plistPath'], plist_info[0]['bin'])
        return pro_dict





fParse = fileParse()