from packaging.version import Version, parse
import re

def comparetolist(current_version,support_versions):
    if support_versions is None:
        return False
    ver1 = parse(current_version)
    ver = re.split(".el(\d+_*\d*)\.*",current_version)
    #ver  ['22.1-6', '10_7', '3']
    for support_version in support_versions:
        ver2 = parse(support_version)
        support_ver = re.split(".el(\d+_*\d*)\.*",support_version)
        if ver[1] == support_ver[1]:
            return ver1 >= ver2
    return False

def get_version(rpmversion,prestr):
    #split .noarch  .x86_64
    version = rpmversion.rsplit(".", 1)[0]
    ver = version.split(prestr)[1]
    return ver

def is_support(version,case_name,support_cases,main_support_versions,backport_versions):
    if support_cases is not None and case_name in support_cases:
        return True
    if "_" in version:
        pre_ver = version.split('_')[0]
        if comparetolist(pre_ver,main_support_versions):
            return True
        elif comparetolist(version, backport_versions):
             return True
        else:
            return False
    else:
        if comparetolist(version,main_support_versions):
            return True
        else:
            return False