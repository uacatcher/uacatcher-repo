import re
import hashlib
from typing import Dict, List, Tuple
import networkx as nx


def parse_funcid(id: str) -> Tuple[str, str]:
    return id.split("%")[:2]


def parse_structid(id: str) -> Tuple[str, str]:
    return id.split("%")[:2]


def hash_signature(start: str, end: str) -> str:
    return hashlib.sha256(start.encode() + end.encode()).hexdigest()[:16]


class FuncMeta:

    def __init__(self, funcname, funcfile) -> None:
        self.name = funcname
        # even for static same name function
        # file position is enough to distinguish
        self.file = funcfile

    def getID(self) -> str:
        return self.name + "%" + self.file


class Unregfunc(FuncMeta):

    def __init__(self, funcname, funcfile, type) -> None:
        super().__init__(funcname, funcfile)
        self.type = type


class Dereffunc(FuncMeta):

    def __init__(self, funcname, funcfile, fieldname, structid) -> None:
        super().__init__(funcname, funcfile)
        self.fieldname = fieldname
        self.structid = structid


def meta2cache(meta: FuncMeta):
    return meta.name + hash_signature(meta.name, meta.file) + ".bin"


# just like func meta, in case same name struct here
class StructMeta:

    def __init__(self, structname, structfile) -> None:
        self.name = structname
        # even for static same name function
        # file position is enough to distinguish
        self.file = structfile

    def getID(self) -> str:
        return self.name + "%" + self.file


class CallInfo:

    def __init__(self, location: str, type: str, caller: FuncMeta,
                 bbid: str) -> None:
        self.location = location
        self.type = type
        self.caller = caller
        self.bbid = bbid
        self.callee = []
        self.constantarg = []
        self.functionarg = []


class LockunLockInfo(CallInfo):

    def __init__(self, location: str, type: str, caller: FuncMeta, bbid: str,
                 lock: bool, identifierType: str, identifier: str) -> None:
        super().__init__(location, type, caller, bbid)
        self.lock = lock
        self.identifierType = identifierType
        self.identifier = identifier


class BitsRWInfo(CallInfo):

    def __init__(self, location: str, type: str, caller: FuncMeta, bbid: str,
                 write: bool, valueMarco: str, value: int,
                 present: str) -> None:
        super().__init__(location, type, caller, bbid)
        self.write = write
        self.valueMarco = valueMarco
        self.value = value
        self.present = present


class ControlFlowGraph:
    """
    ControlFlowGraph is the DAG of BasicBlocks
    """

    def __init__(self, source) -> None:
        self.graph = nx.DiGraph()
        self.source = source

    # callinfo shouldn't lost information about BB
    def getAll_callinfos(self) -> List[CallInfo]:
        result = []
        bbs = self.graph.nodes()
        bbids = list(bbs)
        for bbid in bbids:
            bbcallinfo = bbs[bbid]["callinfo"]
            for info in bbcallinfo:
                result.append(info)
        return result

    def getShortest_path_to(self, end):
        return list(nx.shortest_path(self.graph, self.source, end))

    def getAll_path_to(self, end):
        return list(nx.all_simple_paths(self.graph, self.source, end))


class CallGraph:
    """
    CallGraph is the [DAG] of Functions (or may have circle)
    """

    def __init__(self, entryfunc: FuncMeta) -> None:
        # think about it again, different callgraph has different
        # digraph is better
        self.graph = nx.DiGraph()
        self.entryfuncname = entryfunc.name
        self.entryfuncmeta = entryfunc

    def getAll_paths(self, source, dest) -> list:
        return list(nx.all_simple_paths(self.graph, source, dest))


class Site:

    def __init__(self, loc, attr) -> None:
        self.location = loc
        self.attr = attr
        # basic attr: {"func":, "bbid", }


class PointSite(Site):
    # since we now only consider pointed functioncall ...
    def __init__(self, loc, attr, calledfunc: FuncMeta) -> None:
        super().__init__(loc, attr)
        self.calledfunc = calledfunc


class DeallocSite(Site):

    def __init__(self, loc, attr, callTo: str, freeArgIdx: int) -> None:
        super().__init__(loc, attr)
        self.callTo = callTo
        self.freeArgIdx = freeArgIdx


class DerefSite(Site):

    def __init__(self, loc, attr, pointsto: List[PointSite]) -> None:
        super().__init__(loc, attr)
        self.pointsto = pointsto


class Chain:

    def __init__(self, start, end, graph) -> None:
        self.start = start
        self.end = end
        self.graph = graph

    def setpath(self, path):
        self.path = path


class FChain(Chain):

    def __init__(self, start: str, end: str, graph: CallGraph,
                 site: Site) -> None:
        super().__init__(start, end, graph)
        self.endsite = site
        self.chainInfo = {}

    # chainInfo also designed for destbb dictionary
    def addinfo(self, funcid, destbb, bchain):
        if funcid in self.chainInfo.keys():
            if destbb in self.chainInfo[funcid]:
                self.chainInfo[funcid][destbb].append(bchain)
            else:
                self.chainInfo[funcid][destbb] = [bchain]
        else:
            self.chainInfo[funcid] = {}
            self.chainInfo[funcid][destbb] = [bchain]

    def getIdentifier(self) -> str:
        # what can mark a function chain
        # => the call path + endsite location
        ident = "-".join(self.path)
        ident += "-" + self.endsite.location
        return ident


class BChain(Chain):

    def __init__(self, start: str, end: str, graph: ControlFlowGraph,
                 funcid: str, info: CallInfo) -> None:
        super().__init__(start, end, graph)
        self.name = funcid
        self.info = info


class UACChainCombination:

    def __init__(self, deref_chain: FChain, dealloc_chain: FChain,
                 extra: dict) -> None:
        self.deref_chain = deref_chain
        self.dealloc_chain = dealloc_chain
        self.extra = extra


class Condition:

    def __init__(self, expectation: bool) -> None:
        self.expectation = expectation

    def getType(self) -> str:
        return "base"


class BitTestCondition(Condition):

    def __init__(self, expectation: bool, bitMacro: str, bitValue: int,
                 present: str) -> None:
        super().__init__(expectation)
        self.bitMacro = bitMacro
        self.bitValue = bitValue
        self.present = present

    def getType(self) -> str:
        return "bittest"


class PFCondition(Condition):

    def __init__(self, expectation: bool, value: int, field: str, struct: str,
                 notnull: bool) -> None:
        super().__init__(expectation)
        self.field = field
        self.struct = struct
        self.value = value
        # if not null is True, value is not important then
        self.notnull = notnull

    def getType(self) -> str:
        return "pointerfield"


class ConditionW:

    def __init__(self) -> None:
        pass

    def getType(self) -> str:
        return "base"


class BitConditionW(ConditionW):

    def __init__(self, bitMacro: str, bitValue: int, present: str,
                 type: str) -> None:
        super().__init__()
        self.bitMacro = bitMacro
        self.bitValue = bitValue
        self.present = present
        if type == "clear_bit":
            self.clear = True
        else:
            self.clear = False

    def getType(self) -> str:
        return "bitwrite"


class PFConditionW(ConditionW):

    def __init__(self, field: str, struct: str) -> None:
        super().__init__()
        self.field = field
        self.struct = struct

    def getType(self) -> str:
        return "pointerfield"


def parseGenCondition(expect: bool, conditionWords: list) -> Condition:
    first = conditionWords[0]
    if first == "[NOT]":
        return parseGenCondition(not expect, conditionWords[1:])
    elif first == "[EQExpr]":
        # [1] is PFA
        v = int(conditionWords[1])
        field = conditionWords[2]
        struct = conditionWords[3]
        return PFCondition(expect, v, field, struct, False)
    elif first == "[NEExpr]":
        v = int(conditionWords[2])
        field = conditionWords[3]
        struct = conditionWords[4]
        return PFCondition(not expect, v, field, struct, False)
    elif first == "[FunctionCall]":
        macro = conditionWords[1]
        v = int(conditionWords[2])
        present = conditionWords[3]
        return BitTestCondition(expect, macro, v, present)
    elif first == "[PointerFieldAccess]":
        field = conditionWords[1]
        struct = conditionWords[2]
        return PFCondition(expect, 0, field, struct, True)
    else:  # unknown
        return None
