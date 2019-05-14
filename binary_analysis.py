# -*- coding: utf_8 -*-
"""
Module for iOS IPA Binary Analysis.
_OBJC_CLASS_$_Foo 是 Foo Objective-C 类的符号
对于某个符号，有undefined，external，non-external等描述
external的意思是指对于这个目标文件该类不是私有的，相反
non-external的符号则表示对于目标文件是私有的。
在目标文件引用了某个类，但没有实现它，因此定义为undefined

当我们将目标文件和动态库进行链接处理时，链接器会尝试解析所有的undefined符号。
当连接器通过动态库成功解析一个符号时，它会在最终的连接图记录这个符号时通过动态库进行解析的。

在运行时，动态连接器dyld可以解析这些undefined符号。
"""

import re
import os
import subprocess
import shutil

from util import isFileExists, auto_make_dir

def strings_on_ipa(bin_path):
    """Extract Strings from IPA"""
    try:
        otool_bin = "otool"
        args = [otool_bin, '-v', '-X', '-s', '__TEXT ', '__cstring', bin_path]
        strings = unicode(subprocess.check_output(args), 'utf-8')
        return strings
    except:
        print("[Error] Performing Otool Cstring Fail!")

def symboltable_on_ipa(bin_path):
    #Extract Symbol Table from IPA
    try:
        nm_bin = "nm"
        args = [nm_bin, '-j', bin_path]
        symbol_table = unicode(subprocess.check_output(args), 'utf-8')
        return symbol_table
    except:
        print("[Error] Perfoming NM Symbol Table Fail!")

def otool_analysis(bin_name, bin_path, bin_dir):
    """OTOOL Analysis of Binary"""
    try:
        print("[INFO] Starting Otool Analysis")
        otool_dict = {}
        otool_dict["libs"] = ''
        otool_dict["anal"] = ''
        print("[INFO] Running otool against Binary : " + bin_name)
        otool_bin = "otool"
        #Display  the  names  and  version  numbers of the shared libraries that the object file uses, as well as the shared
        #      library ID if the file is a shared library.
        args = [otool_bin, '-L', bin_path]
        libs = unicode(subprocess.check_output(args), 'utf-8')
        otool_dict["libs"] = libs
        # PIE Display the Mach header.
        args = [otool_bin, '-hv', bin_path]
        pie_dat = subprocess.check_output(args)
        if "PIE" in pie_dat:
            pie_flag = "fPIE -pie flag is Found" + \
                "App is compiled with Position Independent Executable (PIE) flag. " + \
                "This enables Address Space Layout Randomization (ASLR), a memory protection" +\
                " mechanism for exploit mitigation."
        else:
            pie_flag = "fPIE -pie flag is not Found" +\
                " with Position Independent Executable (PIE) flag. So Address Space Layout " +\
                "Randomization (ASLR) is missing. ASLR is a memory protection mechanism for" +\
                " exploit mitigation."
        # Stack Smashing Protection & ARC
        #Display the indirect symbol table.
        args = [otool_bin, '-Iv', bin_path]
        dat = subprocess.check_output(args)
        if "stack_chk_guard" in dat:
            ssmash = "fstack-protector-all flag is Found" +\
                " Stack Smashing Protector (SSP) flag and is having protection against Stack" +\
                " Overflows/Stack Smashing Attacks."
        else:
            ssmash = "fstack-protector-all flag is not Found" +\
                "not compiled with Stack Smashing Protector (SSP) flag. It is vulnerable to " +\
                "Stack Overflows/Stack Smashing Attacks."
        # ARC
        if "_objc_release" in dat:
            arc_flag = "fobjc-arc flag is Found" +\
                "with Automatic Reference Counting (ARC) flag. ARC is a compiler feature " +\
                "that provides automatic memory management of Objective-C objects and is an" +\
                " exploit mitigation mechanism against memory corruption vulnerabilities."
        else:
            arc_flag = "fobjc-arc flag is not Found" +\
                "App is not compiled" +\
                " with Automatic Reference Counting (ARC) flag. ARC is a compiler feature that" +\
                " provides automatic memory management of Objective-C objects and protects from" +\
                " memory corruption vulnerabilities"

        banned_apis = ''
        baned = re.findall(
            r"_alloca|_gets|_memcpy|_printf|_scanf|_sprintf|_sscanf|_strcat|StrCat|_strcpy|" +
            r"StrCpy|_strlen|StrLen|_strncat|StrNCat|_strncpy|StrNCpy|_strtok|_swprintf|_vsnprintf|" +
            r"_vsprintf|_vswprintf|_wcscat|_wcscpy|_wcslen|_wcsncat|_wcsncpy|_wcstok|_wmemcpy|" +
            r"_fopen|_chmod|_chown|_stat|_mktemp", dat)
        baned = list(set(baned))
        baned_s = ', '.join(baned)
        if len(baned_s) > 1:
            banned_apis = "Binary make use of banned API(s" +\
                "The binary " +\
                "may contain the following banned API(s) </br><strong>" + \
                str(baned_s)
        weak_cryptos = ''
        weak_algo = re.findall(
            r"kCCAlgorithmDES|kCCAlgorithm3DES||kCCAlgorithmRC2|kCCAlgorithmRC4|" +
            r"kCCOptionECBMode|kCCOptionCBCMode", dat)
        weak_algo = list(set(weak_algo))
        weak_algo_s = ', '.join(weak_algo)
        if len(weak_algo_s) > 1:
            weak_cryptos = "Binary make use of some Weak Crypto API(s)" +\
                "Insecure The binary may use " +\
                "the following weak crypto API(s)" + \
                str(weak_algo_s)
        crypto = ''
        crypto_algo = re.findall(
            r"CCKeyDerivationPBKDF|CCCryptorCreate|CCCryptorCreateFromData|" +
            r"CCCryptorRelease|CCCryptorUpdate|CCCryptorFinal|CCCryptorGetOutputLength|" +
            r"CCCryptorReset|CCCryptorRef|kCCEncrypt|kCCDecrypt|kCCAlgorithmAES128|" +
            r"kCCKeySizeAES128|kCCKeySizeAES192|kCCKeySizeAES256|kCCAlgorithmCAST|" +
            r"SecCertificateGetTypeID|SecIdentityGetTypeID|SecKeyGetTypeID|SecPolicyGetTypeID|" +
            r"SecTrustGetTypeID|SecCertificateCreateWithData|SecCertificateCreateFromData|" +
            r"SecCertificateCopyData|SecCertificateAddToKeychain|SecCertificateGetData|" +
            r"SecCertificateCopySubjectSummary|SecIdentityCopyCertificate|" +
            r"SecIdentityCopyPrivateKey|SecPKCS12Import|SecKeyGeneratePair|SecKeyEncrypt|" +
            r"SecKeyDecrypt|SecKeyRawSign|SecKeyRawVerify|SecKeyGetBlockSize|" +
            r"SecPolicyCopyProperties|SecPolicyCreateBasicX509|SecPolicyCreateSSL|" +
            r"SecTrustCopyCustomAnchorCertificates|SecTrustCopyExceptions|" +
            r"SecTrustCopyProperties|SecTrustCopyPolicies|SecTrustCopyPublicKey|" +
            r"SecTrustCreateWithCertificates|SecTrustEvaluate|SecTrustEvaluateAsync|" +
            r"SecTrustGetCertificateCount|SecTrustGetCertificateAtIndex|SecTrustGetTrustResult|" +
            r"SecTrustGetVerifyTime|SecTrustSetAnchorCertificates|" +
            r"SecTrustSetAnchorCertificatesOnly|SecTrustSetExceptions|SecTrustSetPolicies|" +
            r"SecTrustSetVerifyDate|SecCertificateRef|" +
            r"SecIdentityRef|SecKeyRef|SecPolicyRef|SecTrustRef", dat)
        crypto_algo = list(set(crypto_algo))
        crypto_algo_s = ', '.join(crypto_algo)
        if len(crypto_algo_s) > 1:
            crypto = "Binary make use of the following Crypto API(s)" +\
                "The binary may use the" +\
                " following crypto API(s)" + \
                str(crypto_algo_s)
        weak_hashes = ''
        weak_hash_algo = re.findall(
            r"CC_MD2_Init|CC_MD2_Update|CC_MD2_Final|CC_MD2|MD2_Init|" +
            r"MD2_Update|MD2_Final|CC_MD4_Init|CC_MD4_Update|CC_MD4_Final|CC_MD4|MD4_Init|" +
            r"MD4_Update|MD4_Final|CC_MD5_Init|CC_MD5_Update|CC_MD5_Final|CC_MD5|MD5_Init|" +
            r"MD5_Update|MD5_Final|MD5Init|MD5Update|MD5Final|CC_SHA1_Init|CC_SHA1_Update|" +
            r"CC_SHA1_Final|CC_SHA1|SHA1_Init|SHA1_Update|SHA1_Final", dat)
        weak_hash_algo = list(set(weak_hash_algo))
        weak_hash_algo_s = ', '.join(weak_hash_algo)
        if len(weak_hash_algo_s) > 1:
            weak_hashes = "Binary make use of the following Weak HASH API(s)" +\
                "The binary " +\
                "may use the following weak hash API(s)" + \
                str(weak_hash_algo_s)
        hashes = ''
        hash_algo = re.findall(
            r"CC_SHA224_Init|CC_SHA224_Update|CC_SHA224_Final|CC_SHA224|" +
            r"SHA224_Init|SHA224_Update|SHA224_Final|CC_SHA256_Init|CC_SHA256_Update|" +
            r"CC_SHA256_Final|CC_SHA256|SHA256_Init|SHA256_Update|SHA256_Final|" +
            r"CC_SHA384_Init|CC_SHA384_Update|CC_SHA384_Final|CC_SHA384|SHA384_Init|" +
            r"SHA384_Update|SHA384_Final|CC_SHA512_Init|CC_SHA512_Update|CC_SHA512_Final|" +
            r"CC_SHA512|SHA512_Init|SHA512_Update|SHA512_Final", dat)
        hash_algo = list(set(hash_algo))
        hash_algo_s = ', '.join(hash_algo)
        if len(hash_algo_s) > 1:
            hashes = "Binary make use of the following HASH API(s)" +\
                "The binary may use the" +\
                " following hash API(s)" + \
                str(hash_algo_s)
        randoms = ''
        rand_algo = re.findall(r"_srand|_random", dat)
        rand_algo = list(set(rand_algo))
        rand_algo_s = ', '.join(rand_algo)
        if len(rand_algo_s) > 1:
            randoms = "Binary make use of the insecure Random Function(s)" +\
                "InsecureThe binary may " +\
                "use the following insecure Random Function(s)" + \
                str(rand_algo_s)
        logging = ''
        log = re.findall(r"_NSLog", dat)
        log = list(set(log))
        log_s = ', '.join(log)
        if len(log_s) > 1:
            logging = "Binary make use of Logging Function" +\
                "The binary may " +\
                "use  NSLogfunction for logging."
        malloc = ''
        mal = re.findall(r"_malloc", dat)
        mal = list(set(mal))
        mal_s = ', '.join(mal)
        if len(mal_s) > 1:
            malloc = "Binary make use of malloc Function" +\
                "InsecureThe binary may use " +\
                "malloc function instead of calloc</td></tr>"
        debug = ''
        ptrace = re.findall(r"_ptrace", dat)
        ptrace = list(set(ptrace))
        ptrace_s = ', '.join(ptrace)
        if len(ptrace_s) > 1:
            debug = "Binary calls ptrace Function for anti-debugging." +\
                "warning The binary" +\
                " may use ptrace function. It can be used to detect and prevent" +\
                " debuggers. Ptrace is not a public API and Apps that use non-public APIs will" +\
                " be rejected from AppStore."
        otool_dict["anal"] = pie_flag + ssmash + arc_flag + banned_apis + weak_cryptos + \
            crypto + weak_hashes + hashes + randoms + logging + malloc + \
            debug
        return otool_dict
    except:
        print("[ERROR] Performing Otool Analysis of Binary")


def class_dump_z(tools_dir, bin_path, app_dir):
    """Running Classdumpz on binary"""
    try:
        webview = ''
        print("[INFO] Running class-dump-z against the Binary")

        class_dump_z_bin = os.path.join(tools_dir, 'class-dump-z')
        subprocess.call(["chmod", "777", class_dump_z_bin])
        class_dump = subprocess.check_output([class_dump_z_bin, bin_path])
        dump_file = os.path.join(app_dir, "classdump.txt")
        with open(dump_file, "w") as flip:
            flip.write(class_dump)
        if "UIWebView" in class_dump:
            webview = "Binary uses WebView Component"
        return webview
    except:
        print("[INFO] class-dump-z does not work on iOS apps developed in Swift")
        print("[ERROR] - Cannot perform class dump")


def binary_analysis(src, tools_dir, app_dir):
    """
    Binary Analysis of IPA
    src:Payload目录
    tools_dir:class-dump目录
    app_dir:md5目录
    """
    try:
        binary_analysis_dict = {}
        print("[INFO] Starting Binary Analysis")
        dirs = os.listdir(src)
        dot_app_dir = ""
        for dir_ in dirs:
            if dir_.endswith(".app"):
                dot_app_dir = dir_
                break
        # Bin Dir - Dir/Payload/x.app/
        bin_dir = os.path.join(src, dot_app_dir)
        bin_name = dot_app_dir.replace(".app", "")
        # Bin Path - Dir/Payload/x.app/x
        bin_path = os.path.join(bin_dir, bin_name)
        #这里我想把binary单独拿出来，方便可能其他的操作处理
        bin_dir_self = os.path.join(src.replace("Payload", ''), 'bin')
        if not auto_make_dir(bin_dir_self):
            shutil.move(bin_path, bin_dir_self)
        bin_dir_self = os.path.join(bin_dir_self, bin_name)
        binary_analysis_dict["libs"] = ''
        binary_analysis_dict["bin_res"] = ''
        binary_analysis_dict["strings"] = ''
        binary_analysis_dict['symbol_table'] = ''
        if not isFileExists(bin_dir_self):
            print("[WARNING] MobSF Cannot find binary in " + bin_dir_self)
            print("[WARNING] Skipping Otool, Classdump and Strings")
        else:
            otool_dict = otool_analysis(bin_name, bin_dir_self, bin_dir)
            cls_dump = class_dump_z(tools_dir, bin_dir_self, app_dir)
            #Classdumpz can fail on swift coded binaries
            if not cls_dump:
                cls_dump = ""
            strings_in_ipa = strings_on_ipa(bin_dir_self)
            symbol_table = symboltable_on_ipa(bin_dir_self)
            binary_analysis_dict["libs"] = otool_dict["libs"]
            #暂时不加class-dump
            #binary_analysis_dict["bin_res"] = otool_dict["anal"] + cls_dump
            binary_analysis_dict["strings"] = strings_in_ipa
            binary_analysis_dict['symbol_table'] = symbol_table

        return ([binary_analysis_dict["libs"], binary_analysis_dict["bin_res"],binary_analysis_dict["strings"],binary_analysis_dict['symbol_table']], 'binary')
    except:
        print("[ERROR] iOS Binary Analysis")

