'''
Different from data structure that used in actual (internal) pipeline,
this file defines necessary class that pass between different components
'''

import json
import hashlib
from typing import List, Dict, Tuple
from . import dstruct


class Base:

    def __init__(self) -> None:
        pass

    def tojson(self) -> str:
        return ""


# miner, collector will prepare LayerDescriptor to analyzer


class LayerDescriptor(Base):

    def __init__(self, name: str, kernel_version: str, database: str, files: list,
                 relpath: str) -> None:
        super().__init__()
        self.name = name
        self.version = kernel_version
        self.database = database
        self.files = files
        self.relpath = relpath
        # empty meta initialize
        self.unreg = []
        self.deref = []
        self.type = []
        self.upper = []

    # those methods may better not to include in class :(
    def tojson(self) -> str:
        data = {}
        data["name"] = self.name
        data["kernel version"] = self.version
        data["database"] = self.database
        data["files"] = self.files
        data["directory"] = self.relpath
        data["unreg"] = []
        for d in self.unreg:
            data["unreg"].append({"name": d.name, "file": d.file})
        data["deref"] = []
        for d in self.deref:
            data["deref"].append({"name": d.name, "file": d.file})
        data["upper"] = self.upper
        data["type"] = self.type

        return json.dumps(data)


# analayzer wll prepare UACAnlsSummary to dectector


class UACAnlsSummary(Base):

    def __init__(self, dealloc_site: dstruct.DeallocSite,
                 dealloc_chains: Dict[str, List[dstruct.FChain]],
                 deref_sites: Dict[str, Tuple[dstruct.DerefSite, List[str]]],
                 deref_chains: Dict[str, Dict[str, List[dstruct.FChain]]],
                 descriptor: LayerDescriptor) -> None:
        super().__init__()
        self.dealloc_site = dealloc_site
        self.dealloc_chains = dealloc_chains
        self.deref_sites = deref_sites
        self.deref_chains = deref_chains
        self.descriptor = descriptor

    # although there are mainly binary representation
    # json can help with manual audition
    def tojson(self) -> str:
        # TODO
        pass
        return ""

    def getDumpID(self) -> str:
        # each summary is supposed to be different at deallocation site
        # we can add information on that
        enclosefunc = self.dealloc_site.attr["func"].name
        deallocfunc, _ = dstruct.parse_funcid(self.dealloc_site.callTo)
        deallocloc = self.dealloc_site.location
        id = (enclosefunc + "-" + deallocfunc + "_" +
              str(len(self.deref_sites)) + "_" +
              hashlib.sha256(deallocloc.encode()).hexdigest()[:12])
        return id


class DetectReport(Base):
    # DetetReport granularity: organized in summary based
    def __init__(self, summary_name: str, algorithm: str,
                 dealloc_site: dstruct.DeallocSite) -> None:
        super().__init__()
        self.summary_name = summary_name
        self.uac = []
        self.algorithm = algorithm
        self.dealloc_site = dealloc_site

    def getDumpFName(self):
        return "report_" + self.algorithm + "_" + str(len(
            self.uac)) + "_" + self.summary_name

    def addUACPair(self, uacpair: Tuple[dstruct.DeallocSite,
                                        dstruct.DerefSite],
                   combinations: List[dstruct.UACChainCombination]):
        self.uac.append((uacpair, combinations))

    def tojson(self) -> str:
        data = {}
        data["name"] = self.summary_name
        data["algorithm"] = self.algorithm
        data["dealloc location"] = self.dealloc_site.location
        data["uac count"] = len(self.uac)
        data["uac details"] = []
        for packed in self.uac:
            cell = {}
            uacpair, uac_chain_combinations = packed
            deref_site: dstruct.DerefSite = uacpair[1]
            cell["deref location"] = deref_site.location
            cell["detected combination count"] = len(uac_chain_combinations)
            cell["detected combinations"] = []
            for combination in uac_chain_combinations:
                icell = {}
                # no idea how to make it works
                combination: dstruct.UACChainCombination = combination
                this_dealloc_chain = combination.dealloc_chain
                this_deref_chain = combination.deref_chain
                icell["dealloc chain"] = this_dealloc_chain.path
                icell["deref chain"] = this_deref_chain.path
                if self.algorithm == "lockset":
                    locksetdict = combination.extra
                    icell["lockset"] = locksetdict["lockset"]
                elif self.algorithm == "routine-switch":
                    extradict = combination.extra
                    icell["joint locks"] = extradict["joint locks"]
                    if icell["joint locks"]:
                        icell["switchA"] = extradict["switchA"].location
                        icell["switchB"] = extradict["switchB"].location
                        icell["condition checks"] = {}
                        for funcid, checklist in extradict["constraints check"].items():
                            icell["condition checks"][funcid] = []
                            checklist: List[dstruct.Condition] = checklist
                            for check in checklist:
                                iicell = {}
                                checktype = check.getType()
                                if checktype == "bittest":
                                    iicell["macro"] = check.bitMacro
                                    iicell["value"] = check.bitValue
                                    iicell["expect"] = check.expectation
                                elif checktype == "pointerfield":
                                    iicell["struct"] = check.struct
                                    iicell["field"] = check.field
                                    iicell["expect"] = check.expectation
                                icell["condition checks"][funcid].append(iicell)
                        icell["condition writes"] = {}
                        for funcid, writelist in extradict["constraints write"].items():
                            icell["condition writes"][funcid] = []
                            writelist: List[dstruct.ConditionW] = writelist
                            for write in writelist:
                                iicell = {}
                                writetype = write.getType()
                                if writetype == "bitwrite":
                                    iicell["macro"] = write.bitMacro
                                    iicell["value"] = write.bitValue
                                    iicell["clear"] = write.clear
                                elif writetype == "pointerfield":
                                    iicell["struct"] = write.struct
                                    iicell["field"] = write.field
                                icell["condition writes"][funcid].append(iicell)
                cell["detected combinations"].append(icell)
            data["uac details"].append(cell)
        return json.dumps(data)
