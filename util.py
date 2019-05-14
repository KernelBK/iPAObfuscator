#!/usr/bin/python
#-*-coding:utf-8 -*-
import os

#获取当前工程的主目录
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def auto_make_dir(*paths):
    for path in paths:
        if not os.path.exists(path):
            os.mkdir(path)
            return False
        else:
            return True

def isFileExists(file_path):
    if os.path.isfile(file_path):
        return True
    else:
        return False

def isDirExists(path):
    if os.path.exists(path):
        return True
    else:
        return False



if __name__ == '__main__':
    print BASE_DIR