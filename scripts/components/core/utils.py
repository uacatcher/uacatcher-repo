import sys
import time
import re
import os
from termcolor import colored

from typing import List, Dict, Tuple

from . import config, api, dstruct


def get_row_from_derived_location(location):
    r = re.search(r'(.+):(\d+):(\d+)', location)
    return int(r.group(2))


def get_order_by_derived_location(loc1, loc2, allow_equl):
    if allow_equl:
        if get_row_from_derived_location(loc1) <= get_row_from_derived_location(loc2):
            return True
        else:
            return False
    else:
        if get_row_from_derived_location(loc1) < get_row_from_derived_location(loc2):
            return True
        else:
            return False


def get_first_by_derived_location(locs: list):
    mini_location = sys.maxsize
    mini_index = -1
    for index, loc in enumerate(locs):
        row = get_row_from_derived_location(loc)
        if row < mini_location:
            mini_location = row
            mini_index = index
    return mini_index


def get_relpath_from_derived_location(dlocation: str):
    # relative_path:startline:endline
    return dlocation[:dlocation.index(":")]


def elem_count(d: dict):
    result = []
    for x in d.values():
        result += x
    return len(result)


class Clock:

    def __init__(self):
        self.start = time.monotonic()

    def delta(self):
        now = time.monotonic()
        delta = now - self.start
        self.start = now
        return delta


class Logger:

    def log(content):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        print(
            colored("----- LOG {} --------------------".format(timestamp),
                    "cyan"))
        print(colored(content, "cyan"))
        sys.stdout.flush()

    def log_no_head(content):
        print(colored(content, "cyan"))
        sys.stdout.flush()

    def debug(content):
        if config.debug:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            print(
                colored("----- DEBUG {} ------------------".format(timestamp),
                        "yellow"))
            print(colored(content, "yellow"))
            print()
            sys.stdout.flush()

    def error(content):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        print(colored("----- ERROR {} ------------------".format(timestamp),
                      "magenta"),
              file=sys.stderr)
        print(colored(content, "red"), file=sys.stderr)
        print(file=sys.stderr)
        sys.stderr.flush()
        # the redirect command already dump error
        # dump to tmp error
        # with open("/tmp/errlog.txt", "a") as f:
        #     f.write(content)

    def warn(content):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        print(colored("----- WARN {} -------------------".format(timestamp),
                      "magenta"),
              file=sys.stderr)
        print(colored(content, "magenta"), file=sys.stderr)
        print(file=sys.stderr)
        sys.stderr.flush()

    def info(content):
        print(content)
        print()
        sys.stdout.flush()


class MarkdownReport:

    def sum2report(summary: api.UACAnlsSummary) -> str:
        output = ""
        output += "# UAC SUMMARY\n"
        # Print deallocation infos
        output += "## deallocation site\n"
        siteloc = summary.dealloc_site.location
        sitecallee = summary.dealloc_site.callTo
        output += "Location: `{}`\n\n".format(siteloc)
        output += "Call Func: `{}`\n\n".format(sitecallee)

        output += "## dereference sites\n"
        index = 0
        for siteloc, sitepacked in summary.deref_sites.items():
            site, reachable_entries = sitepacked
            output += "### {}\n".format(index)
            index += 1
            output += "Location: `{}`\n\n".format(siteloc)
            # TODO: site.pointsto is list of data structure now
            # output += "PointsTo: `{}`\n\n".format(site.pointsto)
            locationlist = []
            for pointsto in site.pointsto:
                locationlist.append(pointsto.location)
            output += "PointsTo: `{}`\n\n".format(locationlist)

            output += "Reachable Entries: {}\n\n".format(reachable_entries)

        return output

    def detect2report(detectreport: api.DetectReport) -> str:
        output = ""
        # since algortihm is already unveiled by report name
        # so we actually don't need to repeat
        uac_count = len(detectreport.uac)
        output += "find total **{}** UAC pairs (actualy deref sites) \n".format(
            uac_count)
        output += "--- \n"
        for index, packed in enumerate(detectreport.uac):
            uacpair, uac_chain_combinations = packed
            deref_site: dstruct.DerefSite = uacpair[1]
            output += "## deref site - {} \n".format(index)
            output += "site location: `{}` \n\n".format(deref_site.location)
            output += "**to deref this, possible {} chain combinatinos** \n\n".format(
                len(uac_chain_combinations))

            for i, combination in enumerate(uac_chain_combinations):
                output += "### combination - {} \n".format(i)
                # no idea how to make it works
                combination: dstruct.UACChainCombination = combination
                this_dealloc_chain = combination.dealloc_chain
                this_deref_chain = combination.deref_chain
                output += "dealloc chain: `{}` \n\n".format(
                    this_dealloc_chain.path)
                output += "deref chain: `{}` \n\n".format(
                    this_deref_chain.path)

                if detectreport.algorithm == "lockset":
                    locksetdict = combination.extra
                    output += "lock set: `{}` \n\n".format(
                        locksetdict["lockset"])

                elif detectreport.algorithm == "routine-switch":
                    extradict = combination.extra
                    output += "joint_locks: `{}` \n\n".format(
                        extradict["joint_locks"])
                    output += "switchA: `{}` \n\n".format(extradict["switchA"])
                    output += "switchB: `{}` \n\n".format(extradict["switchB"])

        output += "--- \n"
        return output

    def layerdetect2report(layername: str, layerdict: dict) -> str:
        output = ""
        output += "## {}\n\n".format(layername)
        
        for dealloc_identifier, valuedict in layerdict.items():
            output += "### {}\n".format(dealloc_identifier)
            bitmap = [False, False]
            
            if "lockset" in valuedict.keys():
                bitmap[0] = True
            
            if "routine-switch" in valuedict.keys():
                bitmap[1] = True
            
            if bitmap == [False, True]:
                # lockset detects nothing but routine-switch find something
                output += "routine-switch detects {} UAC dereference location but lockset detects nothing :) \n".format(
                    len(valuedict["routine-switch"]["uac"]))
            elif bitmap == [True, False]:
                # lockset detects something but routine-switch does not
                output += "lockset detects {} UAC dereference location but routine-switch detects nothing :(\n".format(
                    len(valuedict["lockset"]["uac"]))
            else:
                # need to do detaily commparsion
                packed_lockset = valuedict["lockset"]
                packed_routine = valuedict["routine-switch"]
                output += "lockset detects {} UAC while routine-switch detects {}\n".format(
                    len(packed_lockset["uac"]), len(packed_routine["uac"]))
                locationlist1 = packed_lockset["uac"]
                locationlist2 = packed_routine["uac"]
                locations_joint = list(set(locationlist1).intersection(locationlist2))
                output += "UAC deref sites both algorithm both revealed: ... (don't matter)\n"
                if set(locationlist1) - set(locations_joint):
                    output += "UAC deref sites only revealed by **lockset**: `{}`\n\n".format(list(
                        set(locationlist1) - set(locations_joint)
                    ))
                if set(locationlist2) - set(locations_joint):
                    output += "UAC deref sites only revealed by **routine-switch**: `{}`\n\n".format(list(
                        set(locationlist2) - set(locations_joint)
                    ))
                output += "---\n"
                for loc in locations_joint:
                    output += "**site at `{}`**\n\n".format(loc)
                    combine_lockset = packed_lockset["uac combination"][loc]
                    combine_routine = packed_routine["uac combination"][loc]
                    combine_joint = list(set(combine_lockset).intersection(set(combine_routine)))
                    output += "there are {} combinations both agree\n".format(len(combine_joint))
                    output += "\n... (don't care) ...\n\n"
                    # for c in combine_joint:
                    #     output += "`{}`\n\n".format(c)
                    combine1 = list(set(combine_lockset) - set(combine_joint))
                    if combine1:
                        output += "there are {} combinations only lockset agree\n".format(len(combine1))
                        for c in combine1:
                            output += "`{}`\n\n".format(c)
                    combine2 = list(set(combine_routine) - set(combine_joint))
                    if combine2:
                        output += "there are {} combinations only routine-switch agree\n".format(len(combine2))
                        for c in combine2:
                            output += "`{}`\n\n".format(c)
                output += "---\n\n"
        
        return output
    

def extract_kver(kpath: str) -> str:
    '''
    derive the kernel version from top makefile
    '''
    topmkfile_path = os.path.join(kpath, "Makefile")
    if not os.path.exists(topmkfile_path):
        print("top makefile {} not found, leaving".format(topmkfile_path))
        return ""
    try:
        with open(topmkfile_path, "r") as f:
            topmkfile_data_partial = f.readlines()

        # basic format below
        # SPDX-License-Identifier: GPL-2.0
        # VERSION = 6
        # PATCHLEVEL = 0
        # SUBLEVEL = 0
        # EXTRAVERSION =
        # NAME = Hurr durr I'ma ninja sloth
        version_line = topmkfile_data_partial[1]
        patchlevel_line = topmkfile_data_partial[2]
        sublevel_line = topmkfile_data_partial[3]
        extra_line = topmkfile_data_partial[4]
        ret = '.'.join([
            x.split('=')[1].strip()
            for x in [version_line, patchlevel_line, sublevel_line]
        ])
        if len(extra_line.split("=")) == 2:
            ret += "{}".format(extra_line.split("=")[1].strip())
        return ret
    except Exception as err:
        print(err)
        return ""