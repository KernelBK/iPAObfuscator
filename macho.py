#!/usr/bin/python
# -*- coding: UTF-8 -*-

import os
import cmd
import buildEnv
import bundle
import shutil

class MachType(object):
    @staticmethod
    def getType(input):
        with open(input, "r") as f:
            magic = f.read(4)
            if (magic == "cafebabe".decode("hex") or
                    magic == "bebafeca".decode("hex")):
                return 2
            elif (magic == "feedface".decode("hex") or
                  magic == "feedfacf".decode("hex") or
                  magic == "cefaedfe".decode("hex") or
                  magic == "cffaedfe".decode("hex")):
                return 1
            else:
                return 0
    @staticmethod
    def getArchs(input):
        #lipo -info
        lipoInfo =["-info",input]
        retinfo = cmd.Lipo(lipoInfo).run()
        if retinfo.returncode != 0:
            print "无效的Macho文件"
        elif retinfo.stdout.startswith("Non-fat"):
            arch = retinfo.stdout.split()[-1]  # Last phrase is arch
            return [arch]
        else:
            msg = retinfo.stdout.split()
            try:
                index = msg.index("are:") + 1
            except ValueError:
                print "无法找到架构"
            else:
                return  msg[index:]
class MachO(object):

    def __init__(self,input):
        self.inputfile = input
        self.baseName = os.path.basename(input)
        self.type = MachType.getType(input)
        self.archs = MachType.getArchs(input);
        self.slices = dict()
        self.xarOutPath =dict()
        self.tmpdir = buildEnv.BuildEnv.creatTmpDir(self.baseName)
        self.output_slices = []
    def getArchs(self):
        return self.archs
    #lipo -thin
    def getSlices(self,arch):
        if arch not in self.archs:
            print "无效的Arch"
        elif self.type == 1:
            self.slices[arch] = self.inputfile
            self.xarOutPath[arch] = self.inputfile + "_.xar"
            return  self.inputfile
        elif self.type == 2:
            self.slices[arch] = self.tmpdir + "/" + self.baseName +"_" + arch
            self.xarOutPath[arch] = self.tmpdir + "/" + self.baseName + "_.xar"
            slicesCmd = ["-thin",arch,self.inputfile,"-o"]
            retInfo = cmd.Lipo(slicesCmd,[self.slices[arch]]).run()

            if retInfo.returncode !=0:
                print "执行lipo -thin 错误"
            else:
                return self.slices[arch]
    def getXar(self,arch):
        print  "获取Xar"
        sliceOut = self.getSlices(arch)
        if sliceOut is not  None:
            xarCmd = [sliceOut, "-extract" , "__LLVM" , "__bundle"]
            retInfo =cmd.Segedit(xarCmd,[self.xarOutPath[arch]]).run()
            if retInfo.returncode !=0:
                print "获取Xar错误"
            else:
                return self.xarOutPath[arch]
    def buildBitcode(self,arch):
        print "编译bitcode ", arch
        # 1.获取Xar
        xarOut = self.getXar(arch)
        print xarOut
        output_path = os.path.join(self.tmpdir,self.baseName + "." + arch + ".out")
        bitcode_bundle = bundle.BitcodeBundle(arch,xarOut,output_path).run()
        self.output_slices.append(bitcode_bundle)
        return bitcode_bundle
        # 2.获取Xar xar -d - -f
        # 3.将Xar 拆分获取bc文件
        # 4.获取每个bc文件的clang命令 过滤 添加(我们的混淆命令) 进行编译
        # 5.获取ld 命令 进行连接
    def installOutput(self, path):
        if len(self.output_slices) == 0:
            print("Install failed: no bitcode build yet")
        elif len(self.output_slices) == 1:
            try:
                shutil.move(self.output_slices[0].output, path)
            except IOError:
                print(u"Install failed: can't create {}".format(path))
        else:
            cmd.LipoCreate([x.output for x in self.output_slices],
                               path).run()
        print path