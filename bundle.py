#!/usr/bin/python
# -*- coding: UTF-8 -*-
import os
from cmd import Xar,Clang,Ld
from buildEnv import env

import xml.etree.ElementTree as ET
import  subprocess

class BitcodeBuildFailure(Exception):

    """Error happens during the build"""
    pass

class XarFile(object):

      def __init__(self,input):
        self.input = input
        self.dir = env.creatTmpDir()
        ExtraxmlCmd = ["-d","-","-f",input]
        retInfo = Xar(ExtraxmlCmd).run()
        self.xml = ET.fromstring(retInfo.stdout)
        Extracmd = ["-x","-C",self.dir,"-f", input]
        retInfo2 = Xar(Extracmd).run()
        cmd = ['/bin/chmod', "-R", "+r", self.dir]
        try:
            out = subprocess.check_output(cmd)
        except subprocess.CalledProcessError:
            print  "error"

      @property
      def subdoc(self):
          return self.xml.find("subdoc")
      @property
      def toc(self):
          return self.xml.find("toc")

class BitcodeBundle(XarFile):

      def __init__(self, arch, bundle, output):
          self.arch = arch
          self.bundle = bundle
          self.output = os.path.realpath(output)
          super(BitcodeBundle,self).__init__(bundle)

          self.platform = self.subdoc.find("platform").text
          self.sdk_version = self.subdoc.find("sdkversion").text
          self.version = self.subdoc.find("version").text
      def getAllFiles(self, type):
          return filter(lambda x: x.find("file-type").text == type, self.toc.findall("file"))

      def getobf(self):
          return ["-mllvm", "-bcf", "-mllvm", "-bcf_loop=3", "-mllvm", "-bcf_prob=40","-mllvm", "-fla","-mllvm", "-split", "-mllvm", "-split_num=2"]

      def constructObjJob(self, xmlNode):
          name = os.path.join(self.dir,xmlNode.find("name").text)
          output = name + ".o"
          if xmlNode.find("clang") is not None:
            clang = Clang([name], [output])

            options = [x.text if x.text is not None else "" for x in xmlNode.find("clang").findall("cmd")]
          if '-disable-llvm-passes' in options:
              options.remove('-disable-llvm-passes')
          if '-Os' in options:
              options.remove('-Os')
          if '-O1' in options:
              options.remove('-O1')
          if '-O2' in options:
              options.remove('-O2')
          if '-O3' in options:
              options.remove('-O3')
          clang.addArgs(options)
          clang.addArgs(self.getobf())
          return clang

      def run_job(self, job):
          """Run sub command and catch errors"""
          try:
              rv = job.run()
          except BitcodeBuildFailure:
              # Catch and log an error
              print BitcodeBuildFailure
          else:
              return rv
      @property
      def LdOptions(self):
          linker_options = [x.text if x.text is not None else "" for x in
                            self.subdoc.find("link-options").findall("option")]

          linker_options.extend(["-syslibroot", env.getSdk()])

          linker_options.extend(["-sdk_version", self.sdk_version])
          return linker_options
      def run(self):
          # 获取所有的类型为Bitcode类型的file
          linker_inputs = []
          linker = Ld(self.output)
          linker.addArgs(["-arch", self.arch])
          linker.addArgs(self.LdOptions)

          bitcodefiles = self.getAllFiles("Bitcode")

          if len(bitcodefiles) > 0:
             bitcodeBundle = map(self.constructObjJob,bitcodefiles)
             linker_inputs.extend(bitcodeBundle)

             map(self.run_job,linker_inputs)
             inputs = sorted([os.path.basename(x.output[0]) for x in linker_inputs])
             LinkFileList = os.path.join(self.dir, self.output + ".LinkFileList")
             with open(LinkFileList, 'w') as f:
                 for i in inputs:
                     f.write(os.path.join(self.dir, i))
                     f.write('\n')
             linker.addArgs(["-filelist", LinkFileList])
             dylibs_node = self.subdoc.find("dylibs")
             if dylibs_node is not None:
                 for lib_node in dylibs_node.iter():
                     if lib_node.tag == "lib":
                         lib_path = env.resolveDylibs(self.arch, lib_node.text)
                         linker.addArgs([lib_path])
                     elif lib_node.tag == "weak":
                          print  "weak"
             linker.addArgs([env.getlibclang_rt(self.arch)])
             # linking
             try:
                 retinfo = self.run_job(linker)
                 print retinfo
             except BitcodeBuildFailure as e:
                 print e
             else:
                 return self
             print bitcodeBundle