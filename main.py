#!/usr/bin/python
# -*- coding: UTF-8 -*-

import sys
import os
import argparse
import random
from buildEnv import env
from fileParse import fParse
from macho import MachO,MachType
def parse_args(args):

    parser = argparse.ArgumentParser(
        description="Recompile MachO from bitcode.", )

    parser.add_argument("input_file", type=str,
                        help="The input file suppert iPA、zip、macho")
    parser.add_argument("-t","--taskId", type=str, dest="task_id",
                        help="taskID")
    parser.add_argument("-o", "--output", type=str, dest="output",
                        default="a.out", help="Output file")



    args = parser.parse_args(args[1:])

    return args
def main(args=None):
    if args is None:
        args = sys.argv
    args = parse_args(args)

    try:

        fParse.initState(args)
        outDict = fParse.getRealFile(args.task_id)
        if outDict['filetype'] == fParse.Other:
            realInputFile = outDict['BinName']
        elif outDict['filetype'] == fParse.IPA:
            realInputFile = os.path.join(outDict['plistPath'], outDict['BinName'])
        realOutputFile = realInputFile

        if not os.path.isfile(realInputFile):
            env.error(u"Input macho file doesn't exist: {}".format(realInputFile))

        input_macho = MachO(realInputFile)
        map(input_macho.buildBitcode, input_macho.getArchs())




        # 最后的ipa 打包
        fParse.installOutDir(outDict, args.task_id, args.output)
    finally:
        pass



if __name__ == "__main__":
   main(sys.argv)