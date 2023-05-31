from . import codeql, dstruct, utils, config, analyze, api
import copy
import networkx as nx
import pickle
import os
import itertools, json
from typing import List, Dict, Tuple

# ------------------------------ globals --------------------------------
holding_locks_cache = {}
held_locks_cache = {}

# ------------------------------ interface ------------------------------


def coming(database: str) -> None:
    utils.Logger.log("detect setting up")
    codeql.ql_special_callinfo_process_detect(database)


def detect_uacpair(
        uacpair: Tuple[dstruct.DeallocSite, dstruct.DerefSite],
        uacchains: Tuple[Dict[str, List[dstruct.FChain]],
                         Dict[str, List[dstruct.FChain]]], 
        descriptor: api.LayerDescriptor,
        algorithm: str,
        all: bool,
        database: str) -> Tuple[bool, List[dstruct.UACChainCombination]]:
    # optimize the entire loop, not chain + chain anymore but graph + graph
    # may speed up the detection
    # ---------------- (e) Routine Swtich Algorithm -----------------
    utils.Logger.log("Start with {} algorithm".format(algorithm))
    if algorithm == "routine-switch":
        return detect_uacpair_routineswitch(uacpair, uacchains, descriptor, all, database)
    # ---------------- Lockset Algorithm ----------------------------
    elif algorithm == "lockset":
        return detect_uacpair_lockset(uacpair, uacchains, descriptor, all, database)


def detect_uacpair_routineswitch(
        uacpair: Tuple[dstruct.DeallocSite, dstruct.DerefSite],
        uacchains: Tuple[Dict[str, List[dstruct.FChain]],
                         Dict[str, List[dstruct.FChain]]],
        descriptor: api.LayerDescriptor,
        all: bool,
        database: str) -> Tuple[bool, List[dstruct.UACChainCombination]]:

    # unpack
    dealloc_site, deref_site = uacpair
    dealloc_chains, deref_chains = uacchains
    confirm_uac = False
    chains_combination = []

    # merge those chains into one list
    dealloc_chains_onelist = []
    deref_chains_onelist = []
    for _, chains in dealloc_chains.items():
        dealloc_chains_onelist += chains
    for _, chains in deref_chains.items():
        deref_chains_onelist += chains

    # loop
    for dealloc_chain, deref_chain in itertools.product(
            dealloc_chains_onelist, deref_chains_onelist):
        # 1. get deallocation site held locks in this chain
        _, accurate_held, _, probably_held = get_site_held_locks_and_minimize(
            dealloc_chain, database)
        held_lock_identifiers = list(set(accurate_held + probably_held))

        # 2. reverse traverse deref chain to collect constraints check +
        #    find out routine switch point A
        switchA, constraints_check, joint_locks = reverse_traverse_get_switchA(
            held_lock_identifiers, deref_chain, database)
        # constraints_check: Dict[str, List[dstruct.Condition]] = constraints_check

        # check switchA legality
        if switchA and not check_switchA_valid(switchA, deref_chain):
            # invalid
            utils.Logger.warn(
                "skip this switchA at {} for its inlegality".format(
                    switchA.location))
            continue

        extra = {}
        switchB = None
        if joint_locks:
            # 3. lock jointed, still possible,
            #    traverse dealloc chain to collect constraints write + find
            #    routine switch point B
            switchB, constraints_write = forward_traverse_get_switchB(
                joint_locks, dealloc_chain, database)
            # constraints_write: Dict[str, List[dstruct.ConditionW]] = constraints_write

            extra["switchA"] = switchA
            extra["switchB"] = switchB
            extra["constraints write"] = constraints_write

            # 4. check constraints conflict
            detect_result, conflict_rw = constraints_check_write_detect(
                constraints_check, constraints_write)

            extra["conflicts"] = conflict_rw

            if not detect_result:
                # goto another combination
                continue

        extra["joint locks"] = joint_locks
        extra["constraints check"] = constraints_check

        confirm_uac = True
        chains_combination.append(
            dstruct.UACChainCombination(deref_chain, dealloc_chain, extra))

        if not all:
            break

    return confirm_uac, chains_combination


def detect_uacpair_lockset(
        uacpair: Tuple[dstruct.DeallocSite, dstruct.DerefSite],
        uacchains: Tuple[Dict[str, List[dstruct.FChain]],
                         Dict[str, List[dstruct.FChain]]],
        descriptor: api.LayerDescriptor,
        all: bool,
        database: str) -> Tuple[bool, List[dstruct.UACChainCombination]]:

    # unpack
    dealloc_site, deref_site = uacpair
    dealloc_chains, deref_chains = uacchains
    confirm_uac = False
    chains_combination = []

    # merge those chains into one list
    dealloc_chains_onelist = []
    deref_chains_onelist = []
    for _, chains in dealloc_chains.items():
        dealloc_chains_onelist += chains
    for _, chains in deref_chains.items():
        deref_chains_onelist += chains

    # loop
    for dealloc_chain, deref_chain in itertools.product(
            dealloc_chains_onelist, deref_chains_onelist):
        # 1. get holding locks
        _, dealloc_site_holding_locks_identifiers = get_site_holding_locks_identifier(
            dealloc_chain)
        _, deref_site_holding_locks_identifiers = get_site_holding_locks_identifier(
            deref_chain)

        # 2. calculation lockset
        lockset = list(
            set(dealloc_site_holding_locks_identifiers).intersection(
                set(deref_site_holding_locks_identifiers)))

        # 3. check
        if not lockset:
            confirm_uac = True
            chains_combination.append(
                dstruct.UACChainCombination(deref_chain, dealloc_chain,
                                            {"lockset": lockset}))
            if not all:
                break

    return confirm_uac, chains_combination


def get_site_holding_locks_identifier(
        fchain: dstruct.FChain) -> Tuple[Dict[str, List[str]], List[str]]:
    # The relations between FChain and BChain are charming
    # FuncA -> FuncB, there can be several call sites in A
    # (and for one site, there can be several BChains)
    # From the view of lock/unlock, hope it won't bring much troubles

    # TODO: implement global cache
    global holding_locks_cache

    cache_identifier = fchain.getIdentifier()
    if cache_identifier in holding_locks_cache:
        return holding_locks_cache[cache_identifier]

    holding_locks_identifier_list = []
    debug_used_dict = {}
    for index, funcid in enumerate(fchain.path[:-1]):
        funcinfo_dict = fchain.chainInfo[funcid]
        holding_locks_func_ident = []
        holding_locks_func_ident_assigned = False
        pick_bbid = None
        for bbid, bchains in funcinfo_dict.items():
            # since we currently only collect the shortest path
            # assert(len(bchains) == 1)
            bchain = bchains[0]
            bchain_locks_identifier = get_site_holding_locks_bchain(
                bchain, None, True, fchain.graph)
            if not holding_locks_func_ident_assigned:  # first result
                holding_locks_func_ident_assigned = True
                holding_locks_func_ident = bchain_locks_identifier
                pick_bbid = bbid
            elif len(bchain_locks_identifier) != len(holding_locks_func_ident):
                # this is just so weird
                utils.Logger.warn(
                    "we find there are different holding locks towards same callee...\nCheck it: caller {}, callee {}"
                    .format(fchain.path[index], fchain.path[index + 1]))
                # find a smaller set
                if len(bchain_locks_identifier) < len(
                        holding_locks_func_ident):
                    holding_locks_func_ident = bchain_locks_identifier
                    pick_bbid = bbid
        debug_used_dict[funcid] = holding_locks_func_ident
        holding_locks_identifier_list += holding_locks_func_ident
        # also conduct minimization
        fchain.chainInfo[funcid] = {pick_bbid: funcinfo_dict[pick_bbid]}

    # site enclosing function
    ending_funcid = fchain.path[-1]
    ending_funcinfo_dict = fchain.chainInfo[ending_funcid]
    holding_locks_func_ident = []
    # we don't really need a loop here
    assert (len(ending_funcinfo_dict) == 1)
    ending_only_bbid = next(iter(ending_funcinfo_dict))
    bchains = ending_funcinfo_dict[ending_only_bbid]
    bchain = bchains[0]
    holding_locks_func_ident = get_site_holding_locks_bchain(
        bchain, fchain.endsite, True, fchain.graph)
    debug_used_dict[ending_funcid] = holding_locks_func_ident
    holding_locks_identifier_list += holding_locks_func_ident

    holding_locks_cache[cache_identifier] = (debug_used_dict,
                                             holding_locks_identifier_list)
    return debug_used_dict, holding_locks_identifier_list


def get_site_held_locks_and_minimize(
    fchain: dstruct.FChain,
    database: str
) -> Tuple[Dict[str, List[str]], List[str], Dict[str, List[str]], List[str]]:
    # Different from collecting holding locks, this traversal
    # need to go through not only the chain and also the callee branch to
    # do a rough one

    global held_locks_cache
    cache_identifer = fchain.getIdentifier()
    if cache_identifer in held_locks_cache:
        return held_locks_cache[cache_identifer]

    accurate_held_dict = {}
    accurate_held_locks = []

    probably_held_dict = {}
    probably_held_locks = []

    # ---------- accurate ----------
    for index, funcid in enumerate(fchain.path[:-1]):
        funcinfo_dict = fchain.chainInfo[funcid]
        held_locks_func_ident = []
        held_locks_assigned = False
        for _, bchains in funcinfo_dict.items():
            # since we currently only collect the shortest path
            # assert(len(bchains) == 1)
            bchain = bchains[0]
            bchain_locks_ident = get_site_holding_locks_bchain(
                bchain, None, False, fchain.graph)
            if not held_locks_assigned:  # first result
                held_locks_assigned = True
                held_locks_func_ident = bchain_locks_ident
            elif len(bchain_locks_ident) != len(held_locks_func_ident):
                # we believe the holding locks should be same
                # otherwise is so weird
                utils.Logger.warn(
                    "we find there are different holding locks towards same callee...\nCheck it: caller {}, callee {}"
                    .format(fchain.path[index], fchain.path[index + 1]))
                # if such thing happens, we choose the smaller one
                if len(bchain_locks_ident) < len(held_locks_func_ident):
                    utils.Logger.warn(
                        "we pick the easy one without notifying you :p")
                    held_locks_func_ident = bchain_locks_ident
        accurate_held_dict[funcid] = bchain_locks_ident
        accurate_held_locks += bchain_locks_ident

    # site enclosing function
    ending_funcid = fchain.path[-1]
    ending_funcinfo_dict = fchain.chainInfo[ending_funcid]
    held_locks_func_ident = []
    # we don't really need a loop here
    assert (len(ending_funcinfo_dict) == 1)
    ending_only_bbid = next(iter(ending_funcinfo_dict))
    bchains = ending_funcinfo_dict[ending_only_bbid]
    bchain = bchains[0]
    held_locks_func_ident = get_site_holding_locks_bchain(
        bchain, fchain.endsite, False, fchain.graph)
    accurate_held_dict[ending_funcid] = held_locks_func_ident
    accurate_held_locks += held_locks_func_ident

    # ---------- probably ----------
    # we do *minimization* here
    for funcid in fchain.path[:-1]:
        funcinfo_dict = fchain.chainInfo[funcid]
        held_locks_func_ident = []
        held_locks_assigned = False
        pick_endbbid = None
        for endbbid, bchains in funcinfo_dict.items():
            # since we currently only collect the shortest path
            # assert(len(bchains) == 1)
            bchain = bchains[0]
            bchain_locks_ident = get_held_locks_ext(bchain, None, fchain.graph)
            if not held_locks_assigned:  # first result
                held_locks_assigned = True
                held_locks_func_ident = bchain_locks_ident
                pick_endbbid = endbbid
            else:  # find a smaller set
                if len(bchain_locks_ident) < len(held_locks_func_ident):
                    held_locks_func_ident = bchain_locks_ident
                    pick_endbbid = endbbid
        # we only save the chain picked
        # aka. minimization
        fchain.chainInfo[funcid] = {pick_endbbid: funcinfo_dict[pick_endbbid]}
        probably_held_dict[funcid] = held_locks_func_ident
        probably_held_locks += held_locks_func_ident

    # site enclosing function
    ending_funcid = fchain.path[-1]
    ending_funcinfo_dict = fchain.chainInfo[ending_funcid]
    held_locks_func_ident = []
    # we don't really need a loop here
    assert (len(ending_funcinfo_dict) == 1)
    ending_only_bbid = next(iter(ending_funcinfo_dict))
    bchains = ending_funcinfo_dict[ending_only_bbid]
    bchain = bchains[0]
    held_locks_func_ident = get_held_locks_ext(bchain, fchain.endsite,
                                               fchain.graph)
    probably_held_dict[ending_funcid] = held_locks_func_ident
    probably_held_locks += held_locks_func_ident

    held_locks_cache[cache_identifer] = (accurate_held_dict,
                                         accurate_held_locks,
                                         probably_held_dict,
                                         probably_held_locks)
    return accurate_held_dict, accurate_held_locks, probably_held_dict, probably_held_locks


def reverse_traverse_get_switchA(lockhistory: list,
                                 deref_chain: dstruct.FChain,
                                 database: str):
    # 1. there is probability that locks disjoint, in that case
    #    we can confidently regard it as UAC
    switchA = None
    constraints_checks = {}
    _, holding_locks_identifiers = get_site_holding_locks_identifier(
        deref_chain)
    joint_lock_identifiers = list(
        set(lockhistory).intersection(holding_locks_identifiers))
    if len(joint_lock_identifiers):
        # 2. reverse traverse the chain to find `location` where
        #    joint_lock is empty
        #    that is to say, check our lock/unlock function
        remain_joint_lock_identifiers = copy.copy(joint_lock_identifiers)
        ending_funcid = deref_chain.path[-1]
        ending_funcinfo_dict = deref_chain.chainInfo[ending_funcid]
        # if there is several bchains to different bbid
        # we prefer the one eliminate more lock identifiers
        # TODO: this prefer is dangerous though
        assert (len(ending_funcinfo_dict) == 1)
        ending_only_bbid = next(iter(ending_funcinfo_dict))
        bchains = ending_funcinfo_dict[ending_only_bbid]
        bchain = bchains[0]
        tmp_update_joint, tmp_switchA = reverse_traverse_bbchain_update_joint(
            remain_joint_lock_identifiers, bchain, deref_chain.endsite,
            deref_chain.graph)
        if len(tmp_update_joint) == 0:
            switchA = tmp_switchA
        remain_joint_lock_identifiers = tmp_update_joint
        # we possilby find the switchA :D
        if not switchA:
            # keep reversely search
            # now you have to pay attention, since there is possibility you need
            # to process more than one bb chain
            for funcid in deref_chain.path[-2::-1]:
                funcinfo_dict = deref_chain.chainInfo[funcid]
                chain_remain_lock = []
                chain_remain_lock_assigned = False
                pick_bbid = None
                for sitebbid, bchains in funcinfo_dict.items():
                    bchain = bchains[0]
                    tmp_update_joint, tmp_switchA = reverse_traverse_bbchain_update_joint(
                        remain_joint_lock_identifiers, bchain, None,
                        deref_chain.graph)
                    if len(tmp_update_joint) == 0:
                        switchA = tmp_switchA
                        # one switchA is found, it should only belong to the
                        # necessary chain, which means it may mean nothing to other bb chain
                        pick_bbid = sitebbid
                        break
                    if not chain_remain_lock_assigned:
                        chain_remain_lock = tmp_update_joint
                        pick_bbid = sitebbid
                    elif len(chain_remain_lock) > len(tmp_update_joint):
                        # this means the looping bbchain eliminate more locks
                        chain_remain_lock = tmp_update_joint
                        pick_bbid = sitebbid
                remain_joint_lock_identifiers = chain_remain_lock
                # well, do relentlessly minimization
                deref_chain.chainInfo[funcid] = {
                    pick_bbid: funcinfo_dict[pick_bbid]
                }
                if switchA:
                    break
        # TODEBUG: we suppose to find out swithA at least
        assert (switchA)
        # we can append conditions information hence
        analyze.fillin_constraintinfo_chain_intermediate(
            deref_chain, False, switchA, deref_chain.endsite, database)
        # collect constant check constraints by traversing again
        constraints_checks = get_constraints_fchain_intermediate(
            deref_chain, False, switchA, deref_chain.endsite)

    return switchA, constraints_checks, joint_lock_identifiers


def forward_traverse_get_switchB(joint_lock_identifiers: list,
                                 dealloc_chain: dstruct.FChain,
                                 database: str):
    # Just go through from the entry function and sink at the unlock which
    # make the joint_lock_identifier clear
    # There are several things deserves attention
    # (1) the switchB can be after the endSite (even not in one function)
    # (2) the conditions write also need to be conducted with extended search

    # therefore, its traversal is quite special
    # let's roughly find the stoper first

    # TODO: need cache???
    switchB = None

    for funcid in dealloc_chain.path:
        funcinfo_dict = dealloc_chain.chainInfo[funcid]
        # for chain to different bb, assume same result
        # TODO: add warning like this for other places
        #
        # This TODO leaves a huge mess of data structures here
        # since we are possibly handling different BB chains here
        # that is to say, the switchB is not a single one but should be
        # a dict controlled one at least
        # The switchA is currently don't bother this because its reverse
        # execution characteristics
        lockunlock_pairs_collected = {}
        assert (len(funcinfo_dict) == 1)  # since we have minimized this
        minimized_remain_bbid = next(iter(funcinfo_dict))
        bchains = funcinfo_dict[minimized_remain_bbid]
        bchain = bchains[0]
        lockunlock_pairs_collected = get_lockunlock_pairs_bbchain_consider_site(
            bchain, dealloc_chain.graph)

        lockunlock_ident_collected = list(lockunlock_pairs_collected.keys())
        intersect_identifiers = list(
            set(joint_lock_identifiers).intersection(
                set(lockunlock_ident_collected)))
        # the complex case
        # we here use >= 1 is because once the locks joined, it means the
        # very start
        if len(intersect_identifiers) >= 1:
            lockunlock_infos_list = [
                lockunlock_pairs_collected[ident]
                for ident in intersect_identifiers
            ]
            # through these intersected packed, we just need to find the
            # tuple whose lock is the very earliest one XP
            packed_tuple_list = []
            for tuples in lockunlock_infos_list:
                packed_tuple_list += tuples

            # there are more than 1 lock, we want the most early one
            first_one_index = utils.get_first_by_derived_location(
                [info[0].location for info in packed_tuple_list])
            # assign the callinfo as switchB
            switchB = packed_tuple_list[first_one_index][1]
        else:
            # well, go to next function then
            # no intersection here
            continue

    # TODEBUG: debug other cases rather than smp
    assert (switchB)

    # Then collect constraints write from entry to this info
    # since this write can be out of the chain, need to be careful then

    # prepare entry as starter, so we find a bbchain here
    # quite ungly for now ...
    entryfunc_dict = dealloc_chain.chainInfo[dealloc_chain.start]
    entryfunc_bbchain_endbbid_one = next(iter(entryfunc_dict))
    entryfunc_bbchain = entryfunc_dict[entryfunc_bbchain_endbbid_one][0]
    entryfuncname, entryfuncfile = dstruct.parse_funcid(dealloc_chain.start)
    entryfunc_meta = dstruct.FuncMeta(entryfuncname, entryfuncfile)
    entryfunc_cfg = entryfunc_bbchain.graph
    entryfunc_cfg_nx_graph = entryfunc_cfg.graph
    entrySite = dstruct.Site(
        entryfunc_cfg_nx_graph.nodes[entryfunc_bbchain.path[0]]["start"], {
            "func": entryfunc_meta,
            "bbid": entryfunc_bbchain.path[0]
        })
    # endSite is always the call of unlock function
    # or may be the return of a wrapper, we need to assume this location being executed
    endSite = dstruct.Site(switchB.location, {
        "func": switchB.caller,
        "bbid": switchB.bbid
    })
    # switchB have variants
    # 1. inside dealloc_chain just like switchA, this is easy to handle and we can get
    #    somewhat accurate constraints write
    # 2. outside dealloc_chain
    #    2.a. at the last function of dealloc_chain, this means we at least will not miss
    #         any conconcrete func
    #    2.b  at other function of dealloc_chain, in such cases, may miss some function calls
    # Because our bb chain only reach the info and site, not return.
    # when we need to analyze a fully called and returned function, we need to use flow-insensitive
    # manner
    analyze.fillin_constraintinfo_chain_intermediate(dealloc_chain, True,
                                                     entrySite,
                                                     dealloc_chain.endsite,
                                                     database)

    constraints_fchain = get_constraints_fchain_intermediate(
        dealloc_chain, True, entrySite, endSite)

    return switchB, constraints_fchain


def get_constraints_fchain_intermediate(chain: dstruct.FChain,
                                        deallocation: bool,
                                        starter: dstruct.Site,
                                        ender: dstruct.Site):
    reach_starter = False
    constraints_fchain = {}
    for funcid in chain.chainInfo.keys():
        # skip to start first
        if not reach_starter and funcid != starter.attr["func"].getID():
            continue

        infosdict = chain.chainInfo[funcid]
        if not reach_starter:
            # starter enclosing func
            reach_starter = True
            # well, bad logic, since the starter and enter
            # could live in one function, have to consider this case
            if starter.attr["func"].getID() == ender.attr["func"].getID():
                for _, infos in infosdict.items():
                    constraints_fchain[
                        funcid] = traverse_bbchain_collect_constraints(
                            infos, deallocation, starter, ender, chain.endsite, chain.graph)
                break
            else:
                for _, infos in infosdict.items():
                    constraints_fchain[
                        funcid] = traverse_bbchain_collect_constraints(
                            infos, deallocation, starter, None, chain.endsite, chain.graph)

        elif funcid == ender.attr["func"].getID():
            # ending one (and not equal to the starter)
            for _, infos in infosdict.items():
                constraints_fchain[
                    funcid] = traverse_bbchain_collect_constraints(
                        infos, deallocation, None, ender, chain.endsite, chain.graph)
            break

        else:
            # middle one
            for _, infos in infosdict.items():
                constraints_fchain[
                    funcid] = traverse_bbchain_collect_constraints(
                        infos, deallocation, None, None, chain.endsite, chain.graph)
    # pack in dict
    return constraints_fchain


def constraints_check_write_detect(
        constraints_check_dict: Dict[str, List[dstruct.Condition]],
        constrains_write_dict: Dict[str, List[dstruct.ConditionW]]):
    constrains_check_pack = []
    constrains_write_pack = []

    # pack and deconstruct first
    for _, constraints_checks in constraints_check_dict.items():
        constrains_check_pack += constraints_checks

    for _, constrains_writes in constrains_write_dict.items():
        constrains_write_pack += constrains_writes

    # let's detect the conflicts
    for check in constrains_check_pack:
        check_type = check.getType()
        if check_type == "bittest":
            for write in constrains_write_pack:
                if write.getType(
                ) == "bitwrite" and write.bitMacro == check.bitMacro:
                    if (check.expectation and write.clear) or \
                            (not check.expectation and not write.clear):
                        return False, [check, write]
        if check_type == "pointerfield":
            for write in constrains_write_pack:
                if write.getType() == "pointerfield" and \
                        check.struct == write.struct and check.field == write.field:
                    if check.notnull or check.value != 0:
                        return False, [check, write]
    return True, []


# ------------------------------ internals ------------------------------

def find_descriptor(name, path):
    for root, _, files in os.walk(path):
        if name in files:
            return os.path.join(root, name)


drop_dealloc_site_locations = []
def check_dealloc_site_location_strict(
        descriptor: api.LayerDescriptor, deallocSite: dstruct.DeallocSite,
        deallocChains: Dict[str, List[dstruct.FChain]]) -> bool:
    global drop_dealloc_site_locations
    # 1. check is this layer has upper layers
    if not descriptor.upper:
        # top layer, we cannot decide it
        return True

    # 2. check cache
    if deallocSite.location in drop_dealloc_site_locations:
        utils.Logger.log(
            "discard this deallocation because we alreaday cache it")
        return False

    # do check
    # otherwise, we check if the deallocation happens after layer upper call
    upper_unreg_names = []
    for upperlayer in descriptor.upper:
        upperlayer_desc_path = find_descriptor(
            upperlayer + ".json",
            os.path.join(config.project_path, "configs/completed"))
        with open(upperlayer_desc_path, "r") as f:
            upper_descriptor_json = json.load(f)

        for d in upper_descriptor_json["unreg"]:
            upper_unreg_names.append(d["name"])

    upper_unreg_names = list(set(upper_unreg_names))

    # 3. check every dealloc chain
    for _, dealloc_chains in deallocChains.items():
        test_chain = dealloc_chains[0]
        callgraph: dstruct.CallGraph = test_chain.graph
        # we need to translate name to bb first
        upper_unreg_ids = []
        for nodeid in callgraph.graph.nodes:
            nodename, _ = dstruct.parse_funcid(nodeid)
            if nodename in upper_unreg_names:
                upper_unreg_ids.append(nodeid)

        # iterate each function
        for funcid in test_chain.path:
            funcinfo_dict = test_chain.chainInfo[funcid]
            for bbid, bchains in funcinfo_dict.items():
                bchain: dstruct.BChain = bchains[0]
                cfg: dstruct.ControlFlowGraph = bchain.graph
                # cfg_nx_graph = cfg.graph
                # in strict mode, we will not traverse the bbchain
                # but based on graph algorithm
                callinfos_withinfunc = cfg.getAll_callinfos()
                # TODO: in future verify strict predeccesor relation
                decider = test_chain.endsite.location if funcid == test_chain.path[
                    -1] else bchain.info.location
                callinfos_possible = [
                    info for info in callinfos_withinfunc
                    if utils.get_order_by_derived_location(info.location, decider, False)
                ]  # sound, allow FP
                # if there is goto we die XD
                for callinfo in callinfos_possible:
                    callinfo: dstruct.CallInfo = callinfo
                    for calleepacked in callinfo.callee:
                        calleename, calleefile = dstruct.parse_funcid(
                            calleepacked)
                        calleepackedid = dstruct.FuncMeta(
                            calleename, calleefile).getID()
                        if calleepackedid in upper_unreg_ids:
                            utils.Logger.log(
                                "callinfo at {} calls upper {} hence we discard site at {}"
                                .format(callinfo.location, calleename,
                                        deallocSite.location))
                            drop_dealloc_site_locations.append(
                                deallocSite.location)
                            return False
                        # if this callee reaches upper unreg ever since
                        for upper_unreg_id in upper_unreg_ids:
                            if nx.has_path(
                                callgraph.graph, calleepackedid, upper_unreg_id):
                                drop_dealloc_site_locations.append(
                                    deallocSite.location)
                                utils.Logger.log(
                                    "callinfo at {} calls {} which can reach upper {} hence we discard site at {}"
                                    .format(callinfo.location, calleename, upper_unreg_id,
                                            deallocSite.location))
                                return False
    return True


def check_dealloc_site_location(descriptor: api.LayerDescriptor,
                                deallocSite: dstruct.DeallocSite,
                                deallocChains: Dict[str, List[dstruct.FChain]]) -> bool:
    # 1. check is this layer has upper layers
    if not descriptor.upper:
        # top layer, we cannot decide it
        return True
    
    # otherwise, we check if the deallocation happens after layer upper call
    upper_unreg_names = []
    for upperlayer in descriptor.upper:
        upperlayer_desc_path = find_descriptor(
            upperlayer + ".json",
            os.path.join(config.project_path, "configs/picked")
        )
        with open(upperlayer_desc_path, "r") as f:
            upper_descriptor_json = json.load(f)
                    
        for d in upper_descriptor_json["unreg"]:
            upper_unreg_names.append(d["name"])
    
    upper_unreg_names = list(set(upper_unreg_names))
    
    # !!! caution here, if the layer has multiple upper layers
    # !!! cannot determine which resouce belongs to which layer...
    # !!! to reduce FP, the deallocation must happen before all upper unreg
    
    # algorithm is to make sure the chain towards the dealloc site
    # has no callinfo to these upper
    
    # give every entry a check
    for dealloc_entry, dealloc_chains in deallocChains.items():
        test_chain = dealloc_chains[0]
        callgraph: dstruct.CallGraph = test_chain.graph
        # we need to translate name to bb first
        upper_unreg_ids = []
        for nodeid in callgraph.graph.nodes:
            nodename, nodefile = dstruct.parse_funcid(nodeid)
            if nodename in upper_unreg_names:
                upper_unreg_ids.append(nodeid)
        
        # iterate each function
        for index, funcid in enumerate(test_chain.path[:-1]):
            funcinfo_dict = test_chain.chainInfo[funcid]
            for bbid, bchains in funcinfo_dict.items():
                bchain = bchains[0]
                cfg = bchain.graph
                cfg_nx_graph = cfg.graph
                
                # iterate each BB
                for bbid in bchain.path[:-1]:
                    basicblock = cfg_nx_graph.nodes[bbid]
                    
                    # iterate each callinfo in BB
                    for callinfo in basicblock["callinfo"]:
                        callinfo: dstrcut.CallInfo = callinfo
                        for calleepacked in callinfo.callee:
                            calleename, calleefile = dstruct.parse_funcid(calleepacked)
                            calleepackedid = dstruct.FuncMeta(calleename, calleefile).getID()
                            # if this callee is upper unreg
                            if calleepackedid in upper_unreg_ids:
                                utils.Logger.log(
                                    "callinfo at {} calls upper {} hence we discard site at {}".format(
                                        callinfo.location, calleename, deallocSite.location
                                    ))
                                return False
                            # if this callee reaches upper unreg ever since
                            for upper_unreg_id in upper_unreg_ids:
                                if callgraph.graph.has_edge(calleepackedid, upper_unreg_id):
                                    return False
                            # till now, callee deems okay
                
                # last BB
                ending_bbid = bchain.path[-1]
                ending_basicblock = cfg_nx_graph.nodes[ending_bbid]
                decider = bchain.info.location
                for callinfo in ending_basicblock["callinfo"]:
                    callinfo: dstrcut.CallInfo = callinfo
                    for calleepacked in callinfo.callee:
                        if not utils.get_order_by_derived_location(callinfo.location, decider,
                                           False):
                            continue
                        calleename, calleefile = dstruct.parse_funcid(calleepacked)
                        calleepackedid = dstruct.FuncMeta(calleename, calleefile).getID()
                        if calleepackedid in upper_unreg_ids:
                            utils.Logger.log(
                                "callinfo at {} calls upper {} hence we discard site at {}".format(
                                    callinfo.location, calleename, deallocSite.location
                                ))
                            return False
                        for upper_unreg_id in upper_unreg_ids:
                            if callgraph.graph.has_edge(calleepackedid, upper_unreg_id):
                                return False

        # last function iteration
        ending_funcid = test_chain.path[-1]
        ending_funcinfo_dict = test_chain.chainInfo[ending_funcid]
        for bbid, bchains in ending_funcinfo_dict.items():
            bchain = bchains[0]
            cfg = bchain.graph
            cfg_nx_graph = cfg.graph
            for bbid in bchain.path[:-1]:
                basicblock = cfg_nx_graph.nodes[bbid]
                for callinfo in basicblock["callinfo"]:
                    callinfo: dstrcut.CallInfo = callinfo
                    for calleepacked in callinfo.callee:
                        calleename, calleefile = dstruct.parse_funcid(calleepacked)
                        calleepackedid = dstruct.FuncMeta(calleename, calleefile).getID()
                        if calleepackedid in upper_unreg_ids:
                            utils.Logger.log(
                                "callinfo at {} calls upper {} hence we discard site at {}".format(
                                    callinfo.location, calleepackedid, deallocSite.location
                                ))
                            return False
                        for upper_unreg_id in upper_unreg_ids:
                            if callgraph.graph.has_edge(calleepackedid, upper_unreg_id):
                                utils.Logger.log(
                                    "callinfo at {} can reach upper {} hence we discard site at {}".format(
                                        callinfo.location, upper_unreg_id, deallocSite.location
                                    ))
                                return False            
            # last BB
            ending_bbid = bchain.path[-1]
            ending_basicblock = cfg_nx_graph.nodes[ending_bbid]
            decider = test_chain.endsite.location
            for callinfo in ending_basicblock["callinfo"]:
                callinfo: dstruct.CallInfo = callinfo
                for calleepacked in callinfo.callee:
                    if not utils.get_order_by_derived_location(callinfo.location, decider,
                                        False):
                        continue
                    calleename, calleefile = dstruct.parse_funcid(calleepacked)
                    calleepackedid = dstruct.FuncMeta(calleename, calleefile).getID()
                    if calleepackedid in upper_unreg_ids:
                        utils.Logger.log(
                            "callinfo at {} calls upper {} hence we discard site at {}".format(
                                callinfo.location, calleename, deallocSite.location
                            ))
                        return False
                    for upper_unreg_id in upper_unreg_ids:
                        if callgraph.graph.has_edge(calleepackedid, upper_unreg_id):
                            utils.Logger.log(
                                "callinfo at {} can reach upper {} hence we discard site at {}".format(
                                    callinfo.location, upper_unreg_id, deallocSite.location
                                ))
                            return False
    
    return True


def get_site_holding_locks_bchain(bchain: dstruct.BChain,
                                  endSite: dstruct.Site, holding: bool,
                                  callgraph: dstruct.CallGraph):
    # Since the smallest granularity of the built CFG is BB instead of Stmt, we
    # have to be careful as we don't the site is in what position of this BB
    # For now we use the row number to indicate the possible order
    lock_ident_stack = []
    lock_ident_wrap_stack = []
    # Go through the BB and derive all lockunlock call
    cfg = bchain.graph
    cfg_nx_graph = cfg.graph
    for bbid in bchain.path[:-1]:
        basicblock = cfg_nx_graph.nodes[bbid]
        for callinfo in basicblock["callinfo"]:
            lockunlock = codeql.is_callinfo_lockunlock(callinfo)
            if lockunlock:
                if lockunlock.lock:  # locking function
                    lock_ident_stack.append(lockunlock.identifier)
                elif holding:  # unlocking function
                    if not lock_ident_stack:
                        utils.Logger.error("lock stack is emptry but seems unlock at {}".format(callinfo.location))
                    if lock_ident_stack:  # because lock can be wrapper and not in stack
                        last_lock = lock_ident_stack.pop()
                        # TODEBUG: symmetric rule
                        if last_lock != lockunlock.identifier:
                            utils.Logger.error("lock unlock asymmetrical with callinfo at {}".format(lockunlock.location))
                            utils.Logger.error("last identifier is {}".format(last_lock))
                        assert (last_lock == lockunlock.identifier)
            else:
                # we need to watch out (damn) lock wrap function
                r = codeql.is_callinfo_lock_wrapper(callinfo, callgraph)
                if r:
                    lock_ident_wrap_stack.append(r)
                else:
                    r = codeql.is_callinfo_unlock_wrapper(callinfo, callgraph)
                    if r and not lock_ident_wrap_stack:
                        utils.Logger.error("lock stack is emptry but seems unlock at {}".format(callinfo.location))
                    if r and holding and lock_ident_wrap_stack:
                        last_lock = lock_ident_wrap_stack.pop()
                        if last_lock != r:
                            utils.Logger.error("lock unlock asymmetrical with callinfo (wrap) at {}".format(callinfo.location))
                            utils.Logger.error("last identifier is {}".format(last_lock))
                        assert (last_lock == r)

    # just additional care for ending bb
    ending_bbid = bchain.path[-1]
    ending_basicblock = cfg_nx_graph.nodes[ending_bbid]
    for callinfo in ending_basicblock["callinfo"]:
        if endSite == None:
            decider = bchain.info.location
        else:
            decider = endSite.location
        lockunlock = codeql.is_callinfo_lockunlock(callinfo)
        if lockunlock:
            if utils.get_order_by_derived_location(lockunlock.location, decider,
                                           False):
                # this lockunlock is supposed before the expected site
                if lockunlock.lock:  # locking function
                    lock_ident_stack.append(lockunlock.identifier)
                elif holding:  # unlocking function
                    if not lock_ident_stack:
                        utils.Logger.error("lock stack is emptry but seems unlock at {}".format(callinfo.location))
                    if lock_ident_stack:
                        last_lock = lock_ident_stack.pop()
                        # symmetric rule
                        if last_lock != lockunlock.identifier:
                            utils.Logger.error("lock unlock asymmetrical with callinfo at {}".format(lockunlock.location))
                            utils.Logger.error("last identifier is {}".format(last_lock))
                        assert (last_lock == lockunlock.identifier)
        else:
            if utils.get_order_by_derived_location(callinfo.location, decider, False):
                r = codeql.is_callinfo_lock_wrapper(callinfo, callgraph)
                if r:
                    lock_ident_wrap_stack.append(r)
                r = codeql.is_callinfo_unlock_wrapper(callinfo, callgraph)
                if r and not lock_ident_wrap_stack:
                    utils.Logger.error("lock stack is emptry but seems unlock at {}".format(callinfo.location))
                if r and holding and lock_ident_wrap_stack:
                    last_lock = lock_ident_wrap_stack.pop()
                    if last_lock != r:
                        utils.Logger.error("lock unlock asymmetrical with callinfo (wrap) at {}".format(callinfo.location))
                        utils.Logger.error("last identifier is {}".format(last_lock))
                    assert (last_lock == r)

    return lock_ident_stack + lock_ident_wrap_stack


def get_held_locks_ext(bchain: dstruct.BChain, endSite: dstruct.Site,
                       callgraph: dstruct.CallGraph):
    lock_stack_ident = []
    cfg = bchain.graph
    cfg_nx_graph = cfg.graph
    for bbid in bchain.path[:-1]:
        basicblock = cfg_nx_graph.nodes[bbid]
        for callinfo in basicblock["callinfo"]:
            # watch out, we only care not lock/unlock call info here
            if codeql.is_callinfo_lockunlock(callinfo):
                continue
            # this call may have several targets hence we join them
            idents = []
            for calleeid in callinfo.callee:
                calleename, calleefile = dstruct.parse_funcid(calleeid)
                calleemta = dstruct.FuncMeta(calleename, calleefile)
                idents += get_probably_function_held_lock(calleemta, callgraph)
            # coarse-grained handling ...
            idents = list(set(idents))
            lock_stack_ident += idents

    ending_bbid = bchain.path[-1]
    ending_basicblock = cfg_nx_graph.nodes[ending_bbid]
    for callinfo in ending_basicblock["callinfo"]:
        if codeql.is_callinfo_lockunlock(callinfo):
            continue
        if endSite == None:
            decider = bchain.info.location
        else:
            decider = endSite.location

        if utils.get_order_by_derived_location(callinfo.location, decider, False):
            idents = []
            for calleeid in callinfo.callee:
                calleename, calleefile = dstruct.parse_funcid(calleeid)
                calleemta = dstruct.FuncMeta(calleename, calleefile)
                idents += get_probably_function_held_lock(calleemta, callgraph)
            idents = list(set(idents))
            lock_stack_ident += idents

    return lock_stack_ident


def get_probably_function_held_lock(func: dstruct.FuncMeta,
                                    callgraph: dstruct.CallGraph):
    result = []
    cfgDAG = callgraph.graph
    funcid = func.getID()
    _lockunlock_callinfo_identifiers = codeql.lockunlock_callinfo_identifiers
    _lock_callinfo_ident = [
        ident for ident in _lockunlock_callinfo_identifiers
        if ident[4] == "locking"
    ]  # tedious bug
    _lock_callinfo_meta = [
        dstruct.FuncMeta(ident[5], ident[6]) for ident in _lock_callinfo_ident
    ]

    for i, ident in enumerate(_lock_callinfo_ident):
        meta = _lock_callinfo_meta[i]
        if funcid in cfgDAG.nodes and meta.getID() in cfgDAG.nodes and \
                nx.has_path(cfgDAG, funcid, meta.getID()):
            result.append(ident)
    # extract identifier is enough
    result = [r[3] for r in result]
    return result


def get_probably_function_write_null(funcidpacks: List[str],
                                     callgraph: dstruct.CallGraph):
    result = []
    callgraph_nx_graph = callgraph.graph

    # for bbid in cfg_nx_graph.nodes:
    #     basicblock = cfg_nx_graph.nodes[bbid]
    #     result += basicblock["conditionw"]
    for funcidpack in funcidpacks:
        funcname, funcfile = dstruct.parse_funcid(funcidpack)
        funcmeta = dstruct.FuncMeta(funcname, funcfile)
        funcid = funcmeta.getID()
        cfg: dstruct.ControlFlowGraph = callgraph_nx_graph.nodes[funcid]["cfg"]
        if cfg:
            cfg_nx_graph = cfg.graph
            for bbid in cfg_nx_graph.nodes:
                basicblock = cfg_nx_graph.nodes[bbid]
                result += basicblock["conditionw"]
    
    return result


def get_probably_function_write_bits(funcidpacks: List[str],
                                     callgraph: dstruct.CallGraph):
    result = []
    callgraph_nx_graph = callgraph.graph
    _bitsw_identifiers = codeql.bits_w_identifiers
    _bitsw_meta = [
        dstruct.FuncMeta(ident[4], ident[5]) for ident in _bitsw_identifiers
    ]

    for i, ident in enumerate(_bitsw_identifiers):
        meta = _bitsw_meta[i]
        # since one callsite perhaps into multiple callee
        # we roughly get the total set ...
        for funcidpack in funcidpacks:
            funcname, funcfile = dstruct.parse_funcid(funcidpack)
            funcmeta = dstruct.FuncMeta(funcname, funcfile)
            funcid = funcmeta.getID()
            if funcid in callgraph_nx_graph.nodes and meta.getID() in callgraph_nx_graph.nodes and \
                    nx.has_path(callgraph_nx_graph, funcid, meta.getID()):
                if ident not in result:
                    result.append(ident)

    return result


def reverse_traverse_bbchain_update_joint(curr_joints: list,
                                          bchain: dstruct.BChain,
                                          endSite: dstruct.Site,
                                          callgraph: dstruct.CallGraph):
    ret_joints = copy.copy(curr_joints)
    cfg = bchain.graph
    cfg_nx_graph = cfg.graph

    ending_bbid = bchain.path[-1]
    ending_basicblock = cfg_nx_graph.nodes[ending_bbid]
    # reverse updating is not like simple holding locks getting
    # since we need to find the site, it is necessary to *reverse* the order
    callinfos = ending_basicblock["callinfo"]
    # sorted callinfos based on location
    sorted(callinfos,
           key=lambda info: utils.get_row_from_derived_location(info.location),
           reverse=True)
    for callinfo in callinfos:
        if endSite == None:
            decider = bchain.info.location
        else:
            decider = endSite.location
        if utils.get_order_by_derived_location(callinfo.location, decider, False):
            r = codeql.is_callinfo_lockunlock(callinfo)
            if r:
                if r.lock and r.identifier in ret_joints:
                    ret_joints.remove(r.identifier)
                    if 0 == len(ret_joints):
                        # prepare the site
                        site = dstruct.Site(callinfo.location, {
                            "func": callinfo.caller,
                            "bbid": callinfo.bbid
                        })
                        return ret_joints, site
            else:
                r = codeql.is_callinfo_lock_wrapper(callinfo, callgraph)
                if r and r in ret_joints:
                    ret_joints.remove(r)
                    if 0 == len(ret_joints):
                        # prepare the site
                        site = dstruct.Site(callinfo.location, {
                            "func": callinfo.caller,
                            "bbid": callinfo.bbid
                        })
                        return ret_joints, site

    for bbid in bchain.path[-2::-1]:
        basicblock = cfg_nx_graph.nodes[bbid]
        callinfos = basicblock["callinfo"]
        sorted(callinfos,
               key=lambda info: utils.get_row_from_derived_location(info.location),
               reverse=True)
        for callinfo in callinfos:
            r = codeql.is_callinfo_lockunlock(callinfo)
            if r:
                if r.lock and r.identifier in ret_joints:
                    ret_joints.remove(r.identifier)
                    if 0 == len(ret_joints):
                        # prepare the site
                        site = dstruct.Site(callinfo.location, {
                            "func": callinfo.caller,
                            "bbid": callinfo.bbid
                        })
                        return ret_joints, site
            else:
                r = codeql.is_callinfo_lock_wrapper(callinfo, callgraph)
                if r and r in ret_joints:
                    ret_joints.remove(r)
                    if 0 == len(ret_joints):
                        # prepare the site
                        site = dstruct.Site(callinfo.location, {
                            "func": callinfo.caller,
                            "bbid": callinfo.bbid
                        })
                        return ret_joints, site

    return ret_joints, None


def traverse_bbchain_collect_constraints(chains: list, deallocation: bool,
                                         starter: dstruct.Site,
                                         ender: dstruct.Site,
                                         guard: dstruct.Site,
                                         callgraph: dstruct.CallGraph):
    constraints_assigned = False
    constraints = []
    for bbchain in chains:
        cfg = bbchain.graph
        cfg_nx_graph = cfg.graph
        # first traverse to starter inside BB if arg is given
        if starter:
            try:
                starter_bb_index = bbchain.path.index(starter.attr["bbid"])
            except ValueError as ve:
                # this could happen since we find out swithA harshly
                # not really care about the multi-chain case
                # however, this should not happen basically since the
                # the switchA is lock function call
                utils.Logger.warn(
                    "switch-A {} not present in BB path {}".format(
                        starter.location, bbchain.path))
                continue
        else:
            starter_bb_index = 0

        # ATTENTION: ender may not present in chain (when finding switchB)
        traverse_path = bbchain.path
        if ender: # active points out ender
            if ender.attr["bbid"] in bbchain.path:
                ender_bb_index = bbchain.path.index(ender.attr["bbid"]) + 1
                bbchain_ext = False
                # even though in same BB but still can be extension
                if bbchain.info:    # has info, intermediate chain
                    guard_location = bbchain.info.location
                    if utils.get_order_by_derived_location(bbchain.info.location, ender.location, False):
                        bbchain_ext = True
                else: # has no info, bbchain ending, use guard
                    guard_location = guard.location
                    if utils.get_order_by_derived_location(guard.location, ender.location, False):
                        bbchain_ext = True
            else:
                # well, we need to craft a extend bb path
                ext_path = list(
                    nx.shortest_path(cfg_nx_graph, bbchain.path[-1],
                                     ender.attr["bbid"]))
                traverse_path = bbchain.path + ext_path[1:]
                ender_bb_index = len(traverse_path)
                if bbchain.info:
                    guard_location = bbchain.info.location
                else:
                    guard_location = guard.location
                bbchain_ext = True
        else:
            ender_bb_index = len(bbchain.path)
            guard_location = bbchain.info.location # no ender must has callinfo
            bbchain_ext = False

        # constrains write or check
        if deallocation:
            constraints_chain_nullw = []
            constraints_chain_bitsw = []
            constraints_chain_bitsw_probably = []
            for bbid in traverse_path[starter_bb_index:ender_bb_index - 1]:
                basicblock = cfg_nx_graph.nodes[bbid]
                if "conditionw" not in basicblock.keys():
                    utils.Logger.error(
                        "Oh you need to debug this issue\nbb {} has no 'conditionw' field, weird\n"
                        .format(basicblock["start"]))
                constraints_chain_nullw += basicblock["conditionw"]
                for callinfo in basicblock["callinfo"]:
                    bitsrw = codeql.is_callinfo_bitrw(callinfo)
                    if bitsrw:
                        if bitsrw.write:
                            constraints_chain_bitsw.append(bitsrw)
                for callinfo in basicblock["callinfo"]:
                    if codeql.is_callinfo_lockunlock(
                            callinfo) or codeql.is_callinfo_bitrw(callinfo):
                        continue
                    if bbchain_ext and callinfo.location == guard_location:
                        # in actual running, will enter into this function need to get
                        constraints_chain_nullw += get_probably_function_write_null(
                            callinfo.callee, callgraph)
                    # not interesting normal function
                    constraints_chain_bitsw_probably += get_probably_function_write_bits(
                        callinfo.callee, callgraph)

            ending_bbid = traverse_path[ender_bb_index - 1]
            ending_bb = cfg_nx_graph.nodes[ending_bbid]
            # we need to take care the last bb
            if ender == None:
                decider = bbchain.info.location
            else:
                decider = ender.location

            if "conditionw" not in ending_bb:
                utils.Logger.error(
                    "Oh you need to debug this issue\nending bb {} has no 'conditionw' field, weird\n"
                    .format(ending_bb["start"]))

            for info in ending_bb["conditionw"]:
                # 0 struct 1 ptr 2 location
                if utils.get_order_by_derived_location(info[2], decider, True):
                    constraints_chain_nullw.append(info)
            for callinfo in ending_bb["callinfo"]:
                bitsrw = codeql.is_callinfo_bitrw(callinfo)
                if bitsrw:
                    if bitsrw.write and utils.get_order_by_derived_location(
                            bitsrw.location, decider, True):
                        constraints_chain_bitsw.append(bitsrw)
            for callinfo in ending_bb["callinfo"]:
                if codeql.is_callinfo_lockunlock(
                        callinfo) or codeql.is_callinfo_bitrw(callinfo):
                    continue
                if utils.get_order_by_derived_location(callinfo.location, decider,
                                               True):
                    if callinfo.location == guard_location:
                        if bbchain_ext:
                            constraints_chain_nullw += get_probably_function_write_null(
                                callinfo.callee, callgraph)
                        else:
                            # else we just reach the function that will be analyzed in
                            # next chain
                            continue
                    constraints_chain_bitsw_probably += get_probably_function_write_bits(
                        callinfo.callee, callgraph)

            # pack it. for write. for different chain cases, we pick the one with minimum writes
            if not constraints_assigned or \
                len(constraints[0] + constraints[1] +
                    constraints[2]) > len(constraints_chain_nullw +
                                          constraints_chain_bitsw +
                                          constraints_chain_bitsw_probably):
                constraints_assigned = True
                # nullw, bitsw, bitsw_probably
                constraints = []
                for condition_w in constraints_chain_nullw:
                    constraints.append(
                        dstruct.PFConditionW(condition_w[1], condition_w[0]))

                for condition_w in constraints_chain_bitsw:
                    calleepack = condition_w.callee[0]
                    calleename, _ = dstruct.parse_funcid(calleepack)
                    constraints.append(
                        dstruct.BitConditionW(condition_w.valueMarco,
                                              condition_w.value,
                                              condition_w.present, calleename))

                for condition_w in constraints_chain_bitsw_probably:
                    constraints.append(
                        dstruct.BitConditionW(condition_w[1], condition_w[2],
                                              condition_w[3], condition_w[6]))

        else:
            constraints_chain = []
            for i in range(
                    len(traverse_path[starter_bb_index:ender_bb_index - 1])):
                bbstart_id = traverse_path[i]
                bbend_id = traverse_path[i + 1]
                bb_edge = cfg_nx_graph.edges[(bbstart_id, bbend_id)]
                if "conditionc" in bb_edge.keys(
                ) and bb_edge["conditionc"] != None:
                    constraints_chain.append(bb_edge["conditionc"])

            # pack it. for check. for different chain cases, we pick the one with minimum checks
            if not constraints_assigned:
                constraints_assigned = True
                constraints = constraints_chain
            elif len(constraints) > len(constraints_chain):
                constraints = constraints_chain

    return constraints


def get_lockunlock_pairs_bbchain_consider_site(bbchain: dstruct.BChain,
                                               callgraph: dstruct.CallGraph):
    # upgrade: we should confront on bbchain at a time
    # the *_consider_site naming is because we don't simply acquire the pair here
    # the ultra goal for us is to find the *unlock* which involve the chain

    lockunlock_result = {}

    cfg = bbchain.graph
    cfg_nx_graph = cfg.graph

    for bbid in bbchain.path:
        basicblock = cfg_nx_graph.nodes[bbid]
        for callinfo in basicblock["callinfo"]:
            handling_lock_ident = ""
            r = codeql.is_callinfo_lockunlock(callinfo)
            if r and r.lock:
                handling_lock_ident = r.identifier
            else:
                r = codeql.is_callinfo_lock_wrapper(callinfo, callgraph)
                if r:
                    handling_lock_ident = r

            if handling_lock_ident:
                # well, we need to not just traverse chain but traverse
                # the entire bb graph to find unlock
                for _basicblockid in cfg_nx_graph.nodes:
                    # !!! we need to check if this bb can be reached
                    # (1) unlock should after the lock
                    if not nx.has_path(cfg_nx_graph, bbid, _basicblockid):
                        continue
                    # (2) involve the site (ending bbid here)
                    if not (_basicblockid in bbchain.path or nx.has_path(
                            cfg_nx_graph, bbchain.path[-1], _basicblockid)):
                        continue
                    _basicblock = cfg_nx_graph.nodes[_basicblockid]
                    for _callinfo in _basicblock["callinfo"]:
                        # sadness, lockflow is a hard question
                        # because (1) one lock can have many unlock position
                        # and moreover, (2) one lock can be acquired several times
                        # in just one function
                        # we ignore (2) for clarity here
                        handling_unlock_ident = ""
                        r = codeql.is_callinfo_lockunlock(_callinfo)
                        if r and not r.lock:
                            handling_unlock_ident = r.identifier
                        else:
                            r = codeql.is_callinfo_unlock_wrapper(
                                _callinfo, callgraph)
                            if r:
                                handling_unlock_ident = r
                        if handling_unlock_ident and handling_unlock_ident == handling_lock_ident:
                            # find the pair
                            if handling_lock_ident not in lockunlock_result.keys(
                            ):
                                lockunlock_result[handling_lock_ident] = [
                                    (callinfo, _callinfo)
                                ]
                            else:
                                lockunlock_result[handling_lock_ident].append(
                                    (callinfo, _callinfo))

        # we also need to traverse extended cases
        for callinfo in basicblock["callinfo"]:
            if codeql.is_callinfo_lockunlock(callinfo):
                continue
            if codeql.is_callinfo_lock_wrapper(callinfo, callgraph) or \
                    codeql.is_callinfo_unlock_wrapper(callinfo, callgraph):
                continue

            idents = []
            for calleeid in callinfo.callee:
                calleename, calleefile = dstruct.parse_funcid(calleeid)
                calleemta = dstruct.FuncMeta(calleename, calleefile)
                idents += get_probably_function_held_lock(calleemta, callgraph)
            # coarse-grained handling ...
            ext_lockunlock_idnets = list(set(idents))

            for ident in ext_lockunlock_idnets:
                if ident not in lockunlock_result.keys():
                    lockunlock_result[ident] = [(callinfo, callinfo)]
                else:
                    lockunlock_result[ident].append((callinfo, callinfo))

    return lockunlock_result


def check_switchA_valid(switchA: dstruct.Site,
                        deref_chain: dstruct.FChain) -> bool:
    # there is an additional watchout hence we need to check
    # switchA legality

    # Checker.1: switchA to deref site cannot cover pointed allocation
    callgraph: dstruct.CallGraph = deref_chain.graph

    deref_endsite: dstruct.DerefSite = deref_chain.endsite
    pointstolist = deref_endsite.pointsto

    ## keep tracing and determining is trival
    ## we just do a quick BB collection + callinfo collection then
    bb_collect = {}
    callinfo_collect = {}

    switchA_enclosefuncid = switchA.attr["func"].getID()
    assert (switchA_enclosefuncid in deref_chain.path)
    switchA_enclosebbid = switchA.attr["bbid"]

    ## the big loop (need to wrap this loop someday)
    for funcid in deref_chain.path[deref_chain.path.index(switchA_enclosefuncid
                                                          ):]:
        funcinfo_dict = deref_chain.chainInfo[funcid]
        bb_collect[funcid] = []
        callinfo_collect[funcid] = []
        for _, bchains in funcinfo_dict.items():
            bchain: dstruct.BChain = bchains[0]
            cfg: dstruct.ControlFlowGraph = bchain.graph
            cfg_nx_graph = cfg.graph

            if funcid == switchA_enclosefuncid:
                # head, bb not from original start
                bbpath = bchain.path[bchain.path.index(switchA_enclosebbid) +
                                     1:] if bchain.path.index(
                                         switchA_enclosebbid) + 1 < len(
                                             bchain.path) else []
                for callinfo in cfg_nx_graph.nodes[switchA_enclosebbid][
                        "callinfo"]:
                    callinfo: dstruct.CallInfo = callinfo
                    if utils.get_order_by_derived_location(switchA.location,
                                                   callinfo.location, False):
                        callinfo_collect[funcid].append(callinfo)
            elif funcid == deref_chain.path[-1]:
                # tail, bb ending careful
                bbpath = bchain.path[:-1]
                endingbbid = bchain.path[-1]
                for callinfo in cfg_nx_graph.nodes[endingbbid]["callinfo"]:
                    callinfo: dstruct.CallInfo = callinfo
                    if utils.get_order_by_derived_location(callinfo.location,
                                                   deref_endsite.location,
                                                   False):
                        callinfo_collect[funcid].append(callinfo)
            else:
                bbpath = bchain.path[:-1]
                endingbbid = bchain.path[-1]
                for callinfo in cfg_nx_graph.nodes[endingbbid]["callinfo"]:
                    callinfo: dstruct.CallInfo = callinfo
                    if utils.get_order_by_derived_location(callinfo.location,
                                                   bchain.info.location,
                                                   False):
                        callinfo_collect[funcid].append(callinfo)

            bb_collect[funcid] += bbpath
            for bbid in bbpath:
                for callinfo in cfg_nx_graph.nodes[bbid]["callinfo"]:
                    callinfo_collect[funcid].append(callinfo)

    # we have bb_collect, callinfo_collect infos
    # check if any points allocation call here
    for points in pointstolist:
        points_enclosebbid = points.attr["bbid"]
        points_enclosefuncid = points.attr["func"].getID()
        if points_enclosefuncid in bb_collect.keys() and \
            points_enclosebbid in bb_collect[points_enclosefuncid]:
            utils.Logger.log(
                "Between switchA {} to endSite {} accross pointed call at {}".
                format(switchA.location, deref_endsite.location,
                       points.location))
            return False
    # called case, we will check if being called function
    # can reach the enclosed one
    for _, callinfos in callinfo_collect.items():
        for callinfo in callinfos:
            calleepackeds = callinfo.callee
            for calleepack in calleepackeds:
                calleefuncname, calleefuncfile = dstruct.parse_funcid(
                    calleepack)
                calleemeta = dstruct.FuncMeta(calleefuncname, calleefuncfile)
                calleefuncid = calleemeta.getID()
                for points in pointstolist:
                    points_enclosefuncid = points.attr["func"].getID()
                    if calleefuncid in callgraph.graph.nodes and \
                        points_enclosefuncid in callgraph.graph.nodes and \
                            nx.has_path(callgraph.graph, calleefuncid,
                                    points_enclosefuncid):
                        utils.Logger.log(
                            "Between switchA {} to endSite {} may reach pointed function {}"
                            .format(switchA.location, deref_endsite.location,
                                    points_enclosefuncid))
                        return False

    ## okay we here pass checker
    return True