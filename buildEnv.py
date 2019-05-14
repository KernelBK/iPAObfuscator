#!/usr/bin/python
# -*- coding: UTF-8 -*-
import os
import subprocess
import  cmd
import tempfile

class BuildEnv(object):
    PLATFORM = {"iPhoneOS": "iphoneos",
                "iOS": "iphoneos",
                "MacOSX": "macosx",
                "macOS": "macosx",
                "AppleTVOS": "appletvos",
                "tvOS": "appletvos",
                "watchOS": "watchos"}

    XCRUN_ENV = {"TOOLCHAINS": "default"}
    SDK = ""
    def __init__(self, args=None):
        self.platform = "iOS"

        self.xcrun = ["/usr/bin/xcrun", "--sdk", self.getPlatform()]

        self.sdk = self.getSdk()

        self._tool_cache = dict()
    def getSdk(self):
        cmd = self.xcrun + ["--show-sdk-path"]
        try:
            sdk = subprocess.check_output(cmd, env=self.XCRUN_ENV)
        except subprocess.CalledProcessError:
            env.error("Could not infer SDK path")

        return  sdk.split()[0]

    def getPlatform(self):
        if self.platform is not None:
            return self.PLATFORM[self.platform]
        else:
            self.error("Platform unset")

    @staticmethod
    def creatTmpDir(Prefix=""):
        return tempfile.mkdtemp(prefix=Prefix)

    def resolveDylibs(self, arch, lib, allow_failure=False):
        # do all the path computation with raw encoding
        if isinstance(lib, unicode):
            lib = lib.encode('utf-8')
        # Search for system framework and dylibs
        if lib.startswith("{SDKPATH}"):
            # Check if framework upgrading is needed
            lib = FrameworkUp.translate(lib[9:])
            # this is mapped to one of the real sdk
            lib_path = self.sdk + lib
            found = self.findLibraryInDir(os.path.dirname(lib_path),
                                          os.path.basename(lib_path))
            if found:
                print ("Found framework/dylib: {}".format(found))
                return found
    def getlibclang_rt(self, arch):
        """Use a trick to get the correct libclang_rt"""
        try:
            tool = self._tool_cache["libclang_rt"]
        except KeyError:
            clang = os.getcwd() + "/bin/clang"
            out = subprocess.check_output(
                [clang, "-arch", arch, "/dev/null",
                    "-isysroot", self.getSdk(), "-###"],
                stderr=subprocess.STDOUT)
            clang_rt = out.split('\"')[-2]
            self._tool_cache["libclang_rt"] = clang_rt
            return clang_rt
        else:
            return tool
    def findLibraryInDir(self, directory, lib, framework_dir=False):
        lib_path = os.path.join(directory, lib)
        if os.path.isfile(lib_path):
            return lib_path
        # Remap the file type (stubs <-> tbd file)
        if lib_path.endswith(".dylib"):
            lib_path = lib_path[:-6] + ".tbd"
        elif lib_path.endswith(".tbd"):
            if os.path.basename(lib_path).startswith("lib"):
                lib_path = lib_path[:-4] + ".dylib"
            else:
                lib_path = lib_path[:-4]
        else:
            lib_path = lib_path + ".tbd"
        if os.path.isfile(lib_path):
            return lib_path
        # check the framework path if needed
        if framework_dir:
            return self.findLibraryInDir(
                    os.path.join(directory, os.path.splitext(lib)[0] +
                                 ".framework"),
                    lib, False)
        # return None if not found
        return None
class FrameworkUp:

    LIBRARY_MAP = {
        "/usr/lib/libextension":
            "/System/Library/Frameworks/Foundation.framework/Foundation"
    }

    @staticmethod
    def translate(lib):
        libname = os.path.splitext(lib)[0]
        return FrameworkUp.LIBRARY_MAP.get(libname, lib)

env = BuildEnv()
