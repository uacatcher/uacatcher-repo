from . import codeql, dstruct, config, utils, api
import pickle
import os
import re
import tqdm
from code import interact
import networkx as nx
from typing import List, Tuple, Dict
import random
import filelock

# ------------------------------ globals --------------------------------
nodePool = {}
sanitize_opt_cache = {}
# ------------------------------ interface ------------------------------


def coming(descriprtor: api.LayerDescriptor, poolopt: bool, cache_dir: str) -> None:
    # If the nodePool (data structures that contains detailed infromation in
    # BB granularity) is built already, it can be used to speed up the entire
    # analysis
    global nodePool
    global sanitize_opt_cache

    utils.Logger.log("analysis setting up")

    # for this database, will first globally take care of some functions
    codeql.ql_special_callinfo_process_analyze(descriprtor.database)
    
    pool_dir = os.path.join(cache_dir, descriprtor.version)

    if not os.path.exists(pool_dir):
        os.system("mkdir -p {}".format(pool_dir))

    pool_path = os.path.join(pool_dir, descriprtor.name + ".nodepool")
    gpool_path = os.path.join(pool_dir, descriprtor.version + ".gnodepool")

    if os.path.exists(pool_path):
        utils.Logger.log(
            "find exisiting nodepool for this layer at {}".format(pool_path))
        with open(pool_path, "rb") as f:
            nodePool = pickle.load(f)
    else:
        if poolopt:
            nodePool = build_node_pools_batch(gpool_path, pool_path, descriprtor.database)
        else:
            utils.Logger.warn(
                "you are suggested to build nodepool(batch) first")

    # loading sanitize cache
    sanitize_path = os.path.join(cache_dir,
                                 descriprtor.version,
                                 descriprtor.name + ".sanitize")
    if os.path.exists(sanitize_path):
        with open(sanitize_path, "rb") as f:
            sanitize_opt_cache = pickle.load(f)


def leaving(descriprtor: api.LayerDescriptor, cache_dir: str):
    # saving sanitize cache
    sanitize_path = os.path.join(cache_dir,
                                 descriprtor.version,
                                 descriprtor.name + ".sanitize")

    with open(sanitize_path, "wb") as f:
        pickle.dump(sanitize_opt_cache, f)


def build_node_pools_batch(gpool_path: str, pool_path: str, database: str):
    utils.Logger.warn(
        "pre build CFG nodes for the entire database\nIt will take a while...")

    h_funcmetas = codeql.ql_get_defined_h_funcs(database)
    h_defined_funcmetas = [
        dstruct.FuncMeta(name, file) for name, file in h_funcmetas
    ]

    c_funcmetas = codeql.ql_get_defined_c_funcs(database)
    utils.Logger.info("processing {} defined functions".format(len(c_funcmetas)))
    c_defined_funcmetas = [
        dstruct.FuncMeta(name, file) for name, file in c_funcmetas
    ]

    # some of the header defined functions may be already cached in gnode pool
    h_result, h_remain_metas = upload_from_gpool(gpool_path, h_defined_funcmetas)
    utils.Logger.info(
        "with help with gpool, only need to handle {} functions".format(
            len(h_remain_metas)))
    
    all_result = {}
    all_remain_metas = h_remain_metas + c_defined_funcmetas

    for i in tqdm.tqdm(range(0, len(all_remain_metas), config.BATCH_SIZE)):
        j = i + config.BATCH_SIZE
        if j > len(all_remain_metas):
            j = len(all_remain_metas)
        funcmates_batch = all_remain_metas[i:j]
        tmp = traverse_batchfunc(funcmates_batch, database)
        all_result = {**all_result, **tmp}

    for meta in h_remain_metas:
        funcid = meta.getID()
        h_result[funcid] = all_result[funcid]
    
    refill_to_gpool(h_result, h_remain_metas, gpool_path)

    with open(pool_path, "wb") as f:
        pickle.dump(all_result, f)

    return all_result


def upload_from_gpool(
    gpool_path: str,
    expected_meta: List[dstruct.FuncMeta]
) -> Tuple[Dict[str, dstruct.ControlFlowGraph], List[dstruct.FuncMeta]]:
    # https://py-filelock.readthedocs.io/en/latest/index.html
    # lock when read
    result = {}
    remain_meta = []

    # if the file is not exists, create one with empty dict first
    if not os.path.exists(gpool_path):
        with open(gpool_path, "wb") as f:
            pickle.dump({}, f)

    with open(gpool_path, "rb") as f:
        gpool = pickle.load(f)

    # traverse to check if gpool contains wanted meta
    for meta in expected_meta:
        func_id = meta.getID()
        # cross layer need to check the specical define cases
        if func_id in gpool and gpool[func_id]:
            result[func_id] = gpool[func_id]
        else:
            remain_meta.append(meta)

    return result, remain_meta


def refill_to_gpool(pool: Dict[str, dstruct.ControlFlowGraph],
                    added: List[dstruct.FuncMeta],
                    gpool_path: str) -> None:
    # read doesn't need lock
    with open(gpool_path, "rb") as f:
        gpool = pickle.load(f)

    for meta in added:
        func_id = meta.getID()
        if pool[func_id]:
            gpool[func_id] = pool[func_id]

    lock = filelock.FileLock(gpool_path, timeout=1800)
    with lock:
        with open(gpool_path, "wb") as f:
            pickle.dump(gpool, f)


def build_cgraphs(
        entries: List[dstruct.FuncMeta],
        type: str,
        bounds: List[dstruct.FuncMeta],
        database: str) -> Dict[str, dstruct.CallGraph]:
    cgraphs = {}
    for entryfunc in entries:
        cgraphs[entryfunc.getID()] = build_cgraph(entryfunc, type, bounds, database)
    return cgraphs


def build_cgraph(entry: dstruct.FuncMeta,
                 type: str,
                 bounds: List[dstruct.FuncMeta],
                 database: str) -> dstruct.CallGraph:
    cgraph = dstruct.CallGraph(entry)
    build_cgraph_internal(cgraph, type, bounds, database)
    return cgraph


def get_deallocation_sites_from_cgraphs(
    graphs: Dict[str, dstruct.CallGraph],
    database: str
) -> Dict[str, Tuple[dstruct.DeallocSite, List[str]]]:
    result = {}
    for entryfuncid, graph in graphs.items():
        graph_sites = get_deallocation_sites_from_cgraph(graph, database)
        for site in graph_sites:
            if site.location not in result:
                result[site.location] = (site, [entryfuncid])
            else:
                result[site.location][1].append(entryfuncid)
    return result


def get_deallocation_sites_from_cgraph(
        callgraph: dstruct.CallGraph,
        database: str) -> List[dstruct.DeallocSite]:
    result = []
    # find all deallocation function node first
    callgraph_entry_reachable_nodes = list(callgraph.graph.nodes)
    reachable_dealloc_nodes, reachable_dealloc_arg = codeql.ql_get_dealloc_funcnode(
        callgraph_entry_reachable_nodes, database)

    # find all other function nodes that have edges to these function
    edges = list(callgraph.graph.edges)
    dealloc_edges = [
        e for e in edges if e[1] in reachable_dealloc_nodes
        and e[0] not in reachable_dealloc_nodes
    ]
    for e in dealloc_edges:
        edge = callgraph.graph.edges[e]
        callinfos: List[dstruct.CallInfo] = edge["callinfos"]  # list of dicts
        for callinfo in callinfos:
            site = dstruct.DeallocSite(
                callinfo.location,
                {
                    "func": callinfo.caller,
                    "bbid": callinfo.bbid,
                },
                e[1],
                int(reachable_dealloc_arg[reachable_dealloc_nodes.index(
                    e[1])]),
            )
            result.append(site)

    return result


def get_dereference_sites_with_pointsto_and_reduce(
        site: dstruct.DeallocSite,
        layer_identifier: str,
        database: str) -> List[dstruct.DerefSite]:
    r = codeql.ql_get_pointsTo_call(site.location, site.freeArgIdx, layer_identifier, database)

    if not r:
        utils.Logger.warn("Failed to find pointsTo target for site {}".format(
            site.location))
        return []

    if len(r) > config.d1_pointsto_bar:
        utils.Logger.warn(
            "PointsTo analysis for site at {} deduce {} results.... can we believe this?"
            .format(site.location, len(r)))
        utils.Logger.warn("launch accuracy-tolerable version")
        r = codeql.ql_get_pointsTo_allowinacc(
            site.location, site.freeArgIdx, layer_identifier, database)
    else:
        locations = [rsite[2] for rsite in r]
        r = codeql.ql_get_dereference_sites_with_pointsto(
            locations, layer_identifier, database)

    result = []
    loclogs = []

    for rsite in r:
        confidence, loc, bbidentifier, enclosefunc, enclosefuncfile, pointsto = rsite

        confidence_value = float(confidence)
        if confidence_value < config.d2_pointsto_bar:
            utils.Logger.warn("pointsTo analysis confidence {} too low at location {}".format(
                confidence_value, loc))

            dealloc_enclosefile = utils.get_relpath_from_derived_location(site.location)
            deref_enclosefile = utils.get_relpath_from_derived_location(loc)
            if dealloc_enclosefile != deref_enclosefile:
                continue
            
        _, pcallloc, pbbidentifier, ptargetfunc, ptargetfuncfile, penclosefunc, penclosefuncfile = pointsto.split(
            '---')
        pbbstart, pbbend = pbbidentifier.split('+')
        pointsite = dstruct.PointSite(
            pcallloc, {
                "func": dstruct.FuncMeta(penclosefunc, penclosefuncfile),
                "bbid": dstruct.hash_signature(pbbstart, pbbend)
            }, dstruct.FuncMeta(ptargetfunc, ptargetfuncfile))

        if loc not in loclogs:
            # new one
            loclogs.append(loc)
            bbstart, bbend = bbidentifier.split('+')
            dsite = dstruct.DerefSite(
                loc, {
                    "func": dstruct.FuncMeta(enclosefunc, enclosefuncfile),
                    "bbid": dstruct.hash_signature(bbstart, bbend)
                }, [pointsite])

            result.append(dsite)
        else:
            dsite: dstruct.DerefSite = result[loclogs.index(loc)]
            dlist = [
                _pointsite for _pointsite in dsite.pointsto
                if _pointsite.location == pointsite.location
            ]
            if not dlist:
                dsite.pointsto.append(pointsite)

    return result


def filter_dereference_sites_with_cgraphs(
    sites: List[dstruct.DerefSite], graphs: Dict[str, dstruct.CallGraph]
) -> Dict[str, Tuple[dstruct.DerefSite, List[str]]]:

    result = {}

    for site in sites:
        sitefuncid = site.attr["func"].getID()
        reachable_entries = []
        for entryfuncid, callgraph in graphs.items():
            if sitefuncid in callgraph.graph.nodes and \
                    nx.has_path(callgraph.graph, entryfuncid, sitefuncid):
                # the sitefunc is reachable
                cfg = callgraph.graph.nodes[sitefuncid]["cfg"]
                if site.attr["bbid"] in list(cfg.graph.nodes):
                    # the bb is reachable, cool
                    reachable_entries.append(entryfuncid)
        if reachable_entries:
            # filter some results here
            result[site.location] = (site, reachable_entries)

    return result


def get_chains(
    sites_dict: Dict[str, Tuple[dstruct.Site,
                                List[str]]], graphs: Dict[str,
                                                          dstruct.CallGraph]
) -> Dict[str, Dict[str, List[dstruct.FChain]]]:
    # Hah, the most difficult part
    # We need to traverse all the paths in callgraph granularity
    result = {}

    for site_location, site_tuple in sites_dict.items():
        site, entryfuncids = site_tuple
        chains_dict = {}
        for entryfuncid in entryfuncids:
            callgraph = graphs[entryfuncid]
            chains_dict[entryfuncid] = get_chains_onesite(site, callgraph)
        result[site_location] = chains_dict

    return result


def fillin_constraintinfo_chain_intermediate(
        chain: dstruct.FChain,
        deallocation: bool,
        starter: dstruct.Site,
        ender: dstruct.Site,
        database: str):
    utils.Logger.log(
        "fill in constraints essential information for intermediate chain starts at {}, ends at {}"
        .format(starter.location, ender.location))

    reach_starter = False
    for funcid in chain.chainInfo.keys():
        # skip to start first
        if not reach_starter and funcid != starter.attr["func"].getID():
            continue
        else:
            reach_starter = True

        infosdict = chain.chainInfo[funcid]
        for _, infos in infosdict.items():
            fillin_constraintinfo_bbchains(infos, deallocation, database)

        if funcid == ender.attr["func"].getID():
            # settle down the ender
            break


def filter_deallocation_site_with_errorhandling(
        dealloc_site: dstruct.DeallocSite,
        deref_sites: List[dstruct.DerefSite]) -> bool:
    # the error handling deallocation is of no use here
    for deref_site in deref_sites:
        pointsto_infos = deref_site.pointsto
        for pointsto_info in pointsto_infos:
            enclosefunc = pointsto_info.attr["func"]
            enclosefuncid = enclosefunc.getID()
            # if the pointed function is same with dellocation, bad
            if enclosefuncid == dealloc_site.attr["func"].getID():
                return False
    return True


def filter_by_ancestors(
    deref_sites: Dict[str, Tuple[dstruct.DerefSite, List[str]]],
    deref_sites_chains_dict: Dict[str, Dict[str, List[dstruct.FChain]]],
    dealloc_chains_dict: Dict[str, List[dstruct.FChain]]
) -> Tuple[Dict[str, Tuple[dstruct.DerefSite, List[str]]], Dict[str, Dict[
        str, List[dstruct.FChain]]]]:
    # This hint is just like Bai's paper, which means the deref should not
    # cross with the deref ones
    update_deref_sites = {}
    update_deref_sites_chains_dict = {}
    for deref_site_loc, deref_chains_dict in deref_sites_chains_dict.items():
        packed = {}
        for entryfuncid, deref_chains in deref_chains_dict.items():
            # if these is one chain pass the filter, this entryfuncid is just
            # applicable
            disjoint_deref_chains = []
            for deref_chain in deref_chains:
                deref_chain_path = deref_chain.path
                found_common = False
                for _, dealloc_chains in dealloc_chains_dict.items():
                    for dealloc_chain in dealloc_chains:
                        dealloc_chain_path = dealloc_chain.path
                        if len(
                                set(dealloc_chain_path).intersection(
                                    set(deref_chain_path))) > 0:
                            # there is a common ancester
                            found_common = True
                            break
                    if found_common:
                        break
                if not found_common:
                    disjoint_deref_chains.append(deref_chain)
            if disjoint_deref_chains:
                packed[entryfuncid] = disjoint_deref_chains
        if packed:
            update_deref_sites_chains_dict[deref_site_loc] = packed
            update_deref_sites[deref_site_loc] = (
                deref_sites[deref_site_loc][0], list(packed.keys()))

    # Cool, another filter is that the deref should has ancestor cross
    # with the pointed allocation
    update_again_deref_sites = {}
    update_again_deref_sites_chains_dict = {}
    for deref_site_loc, deref_chains_dict in update_deref_sites_chains_dict.items(
    ):
        packed = {}
        for entryfuncid, deref_chains in deref_chains_dict.items():
            passed_chains = []
            for deref_chain in deref_chains:
                deref_chain_path = deref_chain.path
                deref_site = deref_chain.endsite
                pointsto_infos = deref_site.pointsto
                # well, there could be many pointsTo result,
                # be strict, cannot be overlapped with any one of them
                found_common = False
                for pointsto_info in pointsto_infos:
                    enclosefunc = pointsto_info.attr["func"]
                    enclosefuncid = enclosefunc.getID()
                    if enclosefuncid in deref_chain_path:
                        found_common = True
                        break
                if not found_common:
                    passed_chains.append(deref_chain)
            if passed_chains:
                packed[entryfuncid] = passed_chains
        if packed:
            update_again_deref_sites_chains_dict[deref_site_loc] = packed
            update_again_deref_sites[deref_site_loc] = (
                update_deref_sites[deref_site_loc][0], list(packed.keys()))

    # above are quick filters, however, not that accurate
    # to this end, add another two mode:
    # FUTURE WORK
    # 1. strict mode: deref func chain can never allow to call the pointed part
    # last_deref_sites = {}
    # last_deref_sites_chains_dict = {}
    # for deref_site_loc, deref_chains_dict in update_again_deref_sites_chains_dict.items(
    # ):
    #     packed = {}
    #     for entryfuncid, deref_chains in deref_chains_dict.items():
    #         passed_chains = []
    #         for deref_chain in deref_chains:
    #             deref_chain_path = deref_chain.path
    #             deref_site = deref_chain.endsite
    #             pointsto_infos = deref_site.pointsto
    #             #
    #             ever_reachable = False
    #             for pointsto_info in pointsto_infos:
    #                 _, _, _, wrapfuncname, wrapfuncfile = pointsto_info
    #                 wrapfuncid = dstruct.FuncMeta(wrapfuncname,
    #                                               wrapfuncfile).getID()

    # 2. relax mode: one depth function call not cover pointsTo target

    return update_again_deref_sites, update_again_deref_sites_chains_dict


def filter_by_constant_propagation(
    deref_sites: Dict[str, Tuple[dstruct.DerefSite, List[str]]],
    deref_sites_chains_dict: Dict[str, Dict[str, List[dstruct.FChain]]],
    database: str
) -> Tuple[Dict[str, Tuple[dstruct.DerefSite, List[str]]], Dict[str, Dict[
        str, List[dstruct.FChain]]]]:
    # very similar structure
    update_deref_sites = {}
    update_deref_sites_chains_dict = {}
    for deref_site_loc, deref_chains_dict in deref_sites_chains_dict.items():
        packed = {}
        for entryfuncid, deref_chains in deref_chains_dict.items():
            ok_deref_chains = []
            for deref_chain in deref_chains:
                if sanitize_fchain(deref_chain, database):
                    ok_deref_chains.append(deref_chain)
            if ok_deref_chains:
                packed[entryfuncid] = ok_deref_chains
        if packed:
            update_deref_sites_chains_dict[deref_site_loc] = packed
            update_deref_sites[deref_site_loc] = (
                deref_sites[deref_site_loc][0], list(packed.keys()))

    return update_deref_sites, update_deref_sites_chains_dict


def fpath_possible(path: List[str], callgraph: dstruct.CallGraph) -> bool:
    # 1. argcall sanitize
    if len(path) >= 3:
        edges = []
        for i in range(len(path) - 2):
            edges.append((path[i], path[i + 1], path[i + 2]))
        graph = callgraph.graph
        for edge in edges:
            grandid, parentid, childid = edge
            edge_callinfos = graph.edges[(grandid, parentid)]["callinfos"]
            # if these callinfo contains function parameters
            functionparam = {}
            # list of callinfos mean there can be several callsites in caller
            for info in edge_callinfos:  # info is dstruct.Callinfo
                for functionargpacked, functionargidx in info.functionarg:
                    if functionargidx not in functionparam.keys():
                        functionparam[functionargidx] = []
                    functionparam[functionargidx].append(functionargpacked)

            if not functionparam:  # not function arguments at all
                continue

            # now grand pass function to parent, we need to check if child satisify this
            # argument
            _edge_callinfos: List[dstruct.CallInfo] = graph.edges[(
                parentid, childid)]["callinfos"]
            have_edge = False
            for info in _edge_callinfos:
                if info.type == "argcall":
                    # if all info to child is argcall
                    # we have to make sure childid is what functionparam passed
                    for calleepacked in info.callee:
                        _, _, callee_parmidx = calleepacked.split("%")
                        # this means that the path child (can)) provided
                        # as the argcall parameter
                        if childid in functionparam[callee_parmidx]:
                            have_edge = True

                else:
                    # there is other call to child, okay
                    have_edge = True

            if not have_edge:
                allow_function_list = [
                    dstruct.parse_funcid(x)[0]
                    for x in functionparam[callee_parmidx]
                ]
                utils.Logger.log(
                    "argcall remove chain {}->{}->{} because passing argument is {}..."
                    .format(
                        dstruct.parse_funcid(grandid)[0],
                        dstruct.parse_funcid(parentid)[0],
                        dstruct.parse_funcid(childid)[0], allow_function_list))
                return False

    return True


# ------------------------------ internals ------------------------------


def build_cgraph_internal(callgraph: dstruct.CallGraph, type: str,
                          bounds: List[dstruct.FuncMeta],
                          database: str) -> None:
    utils.Logger.log("start build callgraph for {} entry".format(
        callgraph.entryfuncmeta.name))

    # finialize the entry function first
    # because all analysis in one layer share on graph, we need to operate carefully
    callgraph.graph.add_nodes_from([(callgraph.entryfuncmeta.getID(), {
        "cfg": None
    })])

    # start the journey of recursive traversal
    history = []
    Q : List[Tuple[dstruct.FuncMeta, dstruct.FuncMeta, str]]= [(None, callgraph.entryfuncmeta, type)]
    while len(Q) != 0:
        parentmeta, activemeta, activetype = Q.pop(0)
        activeid = activemeta.getID()
        # there are specical bounds that we stop its search
        activename = activemeta.name
        for meta in bounds:
            # sorry, but this cannot work out again
            # if activemeta.getID() == meta.getID():
            #     continue
            metaname = meta.name
            if activename == metaname:
                utils.Logger.log(
                    "reach boundary function {}, hope the name is not hit with each other".format(metaname))
                continue
            
        # for untraversed function, build cfg and update
        if activeid in history:
            continue
        history.append(activeid)
        activecfg = traverse_onefunc(activemeta, database)

        # if turn off cache, this will rewrite existing cfg
        # anyhow, should do no harms
        callgraph.graph.nodes[activeid]["cfg"] = activecfg

        if activecfg == None:
            # empty CFG (out of range function)
            continue

        if activetype != "net_notifier":
            callinfos = activecfg.getAll_callinfos()
        else:
            # since the switch-case in notifier has clear pattern
            # we now support note based methods to decrease the false
            # results. This is not elegant, but pracitical for now
            callinfos = codeql.ql_get_unreg_functions_from_notifier(activemeta, database)

        for callinfo in callinfos:
            # new version callinfo
            for calleepacked in callinfo.callee:
                calleename, calleefile = dstruct.parse_funcid(calleepacked)
                # calleeid here is special, it could contains addition
                calleemeta = dstruct.FuncMeta(calleename, calleefile)
                calleeid_actual = calleemeta.getID()
                if (activeid,
                        calleeid_actual) not in list(callgraph.graph.edges):
                    callgraph.graph.add_edges_from([(
                        activeid,
                        calleeid_actual,
                        {
                            "callinfos": [callinfo]
                        },
                    )])
                else:
                    callgraph.graph.edges[(
                        activeid,
                        calleeid_actual)]["callinfos"].append(callinfo)

                Q.append((activemeta, calleemeta, "default"))


def traverse_onefunc(funcmeta: dstruct.FuncMeta,
                     database: str) -> dstruct.ControlFlowGraph:
    # check if we can load CFG from the pool
    funcid = funcmeta.getID()
    if funcid in nodePool.keys():
        return nodePool[funcid]

    utils.Logger.log("traverse function {} to build CFG".format(funcmeta.name))

    # obtain bb relation info
    bbinfo = get_basic_blocks([funcmeta], database)[funcid]

    if not bbinfo:
        return None  # export function, not defined

    # source is settle down
    cfg = dstruct.ControlFlowGraph(
        dstruct.hash_signature(bbinfo["entry"][0], bbinfo["entry"][1]))

    for info in bbinfo["edge"]:
        # hope there are no bbs own same start&end
        start, end, nstart, nend = info
        bbid = dstruct.hash_signature(start, end)
        nbbid = dstruct.hash_signature(nstart, nend)
        if bbid == nbbid:  # self edge
            cfg.graph.add_nodes_from(  # repeating is okay
                [
                    (bbid, {
                        "start": start,
                        "end": end
                    }),
                ])
        else:
            cfg.graph.add_nodes_from([
                (bbid, {
                    "start": start,
                    "end": end
                }),
                (nbbid, {
                    "start": nstart,
                    "end": nend
                }),
            ])
            cfg.graph.add_edge(bbid, nbbid)

    # obtain and update bb call info
    bbs = cfg.graph.nodes
    get_basic_blocks_callinfo(funcmeta, bbs, database)

    # now the function control flow graph is built
    # and updated with call infos

    # refill to the pool
    nodePool[funcmeta.getID()] = cfg
    return cfg


def traverse_batchfunc(
        funcmetas: List[dstruct.FuncMeta],
        database: str
) -> Dict[str, dstruct.ControlFlowGraph]:
    result = {}
    # obtain bbinfo in function granularity
    bbinfos = get_basic_blocks(funcmetas, database)

    for funcid, bbinfo in bbinfos.items():
        if not bbinfo:
            result[funcid] = None
            continue

        cfg = dstruct.ControlFlowGraph(
            dstruct.hash_signature(bbinfo["entry"][0], bbinfo["entry"][1]))
        for info in bbinfo["edge"]:
            start, end, nstart, nend = info
            bbid = dstruct.hash_signature(start, end)
            nbbid = dstruct.hash_signature(nstart, nend)
            if bbid == nbbid:  # self edge
                cfg.graph.add_nodes_from([
                    (bbid, {
                        "start": start,
                        "end": end
                    }),
                ])
            else:
                cfg.graph.add_nodes_from([
                    (bbid, {
                        "start": start,
                        "end": end
                    }),
                    (nbbid, {
                        "start": nstart,
                        "end": nend
                    }),
                ])
                cfg.graph.add_edge(bbid, nbbid)

        result[funcid] = cfg

    get_basic_blocks_callinfo_batch(result, database)
    return result


def get_basic_blocks(funcmetas: List[dstruct.FuncMeta], database: str) -> dict:
    _funcmeta = [[x.name, x.file] for x in funcmetas]
    basic_blocks = codeql.ql_get_basic_blocks(_funcmeta, database)
    result = {}
    # processing results into dict
    for idx, funcmeta in enumerate(funcmetas):
        bbs = basic_blocks[idx]
        if bbs:  # weird, how can we find empty bb ???
            funcbbs = {"entry": [], "edge": []}
            for bbedgeinfo in bbs:
                # bbedgeinfo[0] always stands for entry bb
                funcbbs["entry"] = bbedgeinfo[0].strip().split("+")
                bbedgeinfos = bbedgeinfo[1].strip().split(";")
                pbbstart, pbbend = bbedgeinfos[0].split('+')
                nbbstart, nbbend = bbedgeinfos[1].split('+')
                funcbbs["edge"].append([
                    pbbstart, pbbend, nbbstart, nbbend
                ])
            result[funcmeta.getID()] = funcbbs
        else:
            utils.Logger.warn("find no BB in function {} ???".format(
                funcmeta.getID()))
            result[funcmeta.getID()] = {}

    return result


def get_basic_blocks_callinfo(funcmeta: dstruct.FuncMeta,
                              bbs,
                              database: str) -> None:
    packed_callinfos = codeql.ql_get_callinfos_infunction(funcmeta, database)

    for bbid in list(bbs):
        infos = []
        if bbid not in packed_callinfos:
            bbs[bbid]["callinfo"] = []
            continue
        for _, callinfo in packed_callinfos[bbid].items():
            infos.append(callinfo)

        bbs[bbid]["callinfo"] = infos


def get_basic_blocks_callinfo_batch(
        cfgdict: Dict[str, dstruct.ControlFlowGraph],
        database: str) -> None:
    callfinfos_packed = codeql.ql_get_callinfos_cfgs(cfgdict, database)

    for funcid, cfg in cfgdict.items():
        if not cfg:
            continue
        for bbid in list(cfg.graph.nodes):
            # handle callinfo here
            infos = []
            if bbid not in callfinfos_packed[funcid].keys():
                # this bb not has function calls
                cfg.graph.nodes[bbid]["callinfo"] = []
                continue

            for _, callinfo in callfinfos_packed[funcid][bbid].items():
                infos.append(callinfo)

            cfg.graph.nodes[bbid]["callinfo"] = infos


def get_chains_onesite(site: dstruct.Site,
                       callgraph: dstruct.CallGraph) -> List[dstruct.FChain]:
    tmp_chains = []
    site_enclosefuncmeta = site.attr["func"]
    site_enclosefuncid = site_enclosefuncmeta.getID()

    # find all function paths first
    if callgraph.entryfuncmeta.getID() == site_enclosefuncid:
        # cool, same function
        fchain = dstruct.FChain(site_enclosefuncid, site_enclosefuncid,
                                callgraph, site)
        fchain.setpath([site_enclosefuncid])
        tmp_chains.append(fchain)
    else:
        paths = callgraph.getAll_paths(callgraph.entryfuncmeta.getID(),
                                       site_enclosefuncid)
        # TODO: paths here are flow-insensitive
        # which means some of them are impossible to construct a path
        # processing intermediate functions
        for p in paths:
            if not fpath_possible(p, callgraph):
                continue
            fchain = dstruct.FChain(p[0], p[-1], callgraph, site)
            fchain.setpath(p)
            for index, _ in enumerate(p[:-1]):
                callerid = p[index]
                calleeid = p[index + 1]
                callnodeCFG = callgraph.graph.nodes[callerid]["cfg"]
                # find which BB has callinfo to this expected callee
                destbbs = []
                for bbid in list(callnodeCFG.graph.nodes):
                    callinfos: List[
                        dstruct.
                        CallInfo] = callnodeCFG.graph.nodes[bbid]["callinfo"]
                    for info in callinfos:
                        for calleepacked in info.callee:
                            calleename, calleefile = dstruct.parse_funcid(
                                calleepacked)
                            _calleeid = dstruct.FuncMeta(
                                calleename, calleefile).getID()
                            if _calleeid == calleeid:
                                destbbs.append([bbid, info])
                                break

                # for each dest, we currently find one shortest path
                # this could cause false negatives, thus just find all paths
                for dest, dinfo in destbbs:
                    bbpath = callnodeCFG.getShortest_path_to(dest)
                    bchain = dstruct.BChain(bbpath[0], bbpath[-1], callnodeCFG,
                                            callerid, dinfo)
                    bchain.setpath(bbpath)
                    fchain.addinfo(callerid, dest, bchain)

                    # deprecated
                    # sadness, even with networkx, all paths hangs the
                    # entire program
                    # all_bbpaths = callnodeCFG.getAll_path_to(dest)
                    # for bbpath in all_bbpaths:
                    #     bchain = dstruct.BChain(bbpath[0], bbpath[-1],
                    #                             callnodeCFG.graph, callerid, dinfo)
                    #     bchain.setpath(bbpath)
                    #     fchain.addinfo(callerid, dest, bchain)

            tmp_chains.append(fchain)

    # Till now, all chain in tmp_chains have to process
    # the end function
    lastCFG = callgraph.graph.nodes[site_enclosefuncid]["cfg"]

    lastpath = lastCFG.getShortest_path_to(site.attr["bbid"])
    lastbchain = dstruct.BChain(lastpath[0], lastpath[-1], lastCFG,
                                site_enclosefuncid, None)
    lastbchain.setpath(lastpath)

    for fchain in tmp_chains:
        fchain.addinfo(site_enclosefuncid, site.attr["bbid"], lastbchain)

    return tmp_chains


def fillin_constraintinfo_bbchains(chains: List[dstruct.BChain],
                                   deallocation: bool,
                                   database: str):
    for bbchain in chains:
        funcid = bbchain.name
        cfg: dstruct.ControlFlowGraph = bbchain.graph

        if deallocation:
            # ------ constant write info ------
            # update, may confronts ext path so do for all nodes
            path_bbnodes = [
                cfg.graph.nodes[bbid] for bbid in list(cfg.graph.nodes)
            ]

            new_path_bbnodes = [
                node for node in path_bbnodes
                if "conditionw" not in node.keys()
            ]
            new_bbnode_identifiers = [node["start"] + '+' + node["end"] for node in new_path_bbnodes]
            # new_bbnode_starts = [node["start"] for node in new_path_bbnodes]
            if len(new_path_bbnodes) > 0:
                bbnode_nullw = codeql.ql_get_snullwrite_bbs(
                    new_bbnode_identifiers, database)
                # not similar packing because not similar to callinfo
                for i in range(len(new_path_bbnodes)):
                    node = path_bbnodes[i]
                    nullwinfos = bbnode_nullw[i]
                    node["conditionw"] = nullwinfos

        else:
            # ------ constant check info ------
            unsolved_bb_edges = []
            unsolved_bb_edges_identifiers = []
            for i in range(len(bbchain.path[:-1])):
                bbstart_id = bbchain.path[i]
                bbend_id = bbchain.path[i + 1]
                bb_edge = cfg.graph.edges[(bbstart_id, bbend_id)]
                if "conditionc" not in bb_edge.keys():
                    unsolved_bb_edges.append(bb_edge)
                    unsolved_bb_edges_identifiers.append([
                        cfg.graph.nodes[bbstart_id]["start"] + '+' + cfg.graph.nodes[bbstart_id]["end"],
                        cfg.graph.nodes[bbend_id]["start"] + '+' + cfg.graph.nodes[bbend_id]["end"]
                    ])

            if len(unsolved_bb_edges_identifiers) > 0:
                innerfunc_name = dstruct.parse_funcid(funcid)[0]
                bbconditions = codeql.ql_get_bbconditions(
                    innerfunc_name, unsolved_bb_edges_identifiers, database)
                # pack these conditions into edges information
                for i in range(len(unsolved_bb_edges)):
                    edge = unsolved_bb_edges[i]
                    edge["conditionc"] = bbconditions[i]


def sanitize_fchain(chain: dstruct.FChain, database: str) -> bool:
    global sanitize_opt_cache

    # The callinfo between the functions carry the parameter
    # If these is constant call parameter, we should propagate the constant
    # to check if this chain hold
    # Though this can be fairly different between chains
    # we can cache it to optimize the efficancy

    callgraph = chain.graph
    need_sanitize_function = {}
    for index in range(len(chain.path) - 1):
        chain_caller_id = chain.path[index]
        chain_callee_id = chain.path[index + 1]
        call_edges: List[dstruct.CallInfo] = callgraph.graph.edges[(
            chain_caller_id, chain_callee_id)]["callinfos"]
        # find callinfo that has constant param
        # Xp. one unexpected bug, we only collect the first constant argument
        # nevermind for now
        for callinfo in call_edges:
            # [0] lucky or constant value
            # [1] constant arg index
            if callinfo.constantarg:
                if chain_callee_id not in need_sanitize_function.keys():
                    need_sanitize_function[chain_callee_id] = [callinfo]
                else:
                    need_sanitize_function[chain_callee_id].append(callinfo)

    # suppose we want to check one callinfo with constant parameter
    # we need to query the callee function to make sure this constant
    # will allow to CFG to reach the expected site
    # in another word, if there are conditions act as obstacles
    if need_sanitize_function:
        # we introduce sanitize optimizing cache here
        # to speedup the detection (ql is slow)
        sanitize_conditions = {}
        uncached_sanitize_function_keys = []
        tmp = []
        for index, funcid in enumerate(need_sanitize_function.keys()):
            if funcid not in sanitize_opt_cache.keys():
                uncached_sanitize_function_keys.append(funcid)
                sanitize_conditions[funcid] = []
                tmp.append(funcid)
            else:
                sanitize_conditions[funcid] = sanitize_opt_cache[funcid]

        if uncached_sanitize_function_keys:
            uncached_sanitize_conditions = codeql.ql_get_sanitize_conditions(
                uncached_sanitize_function_keys, database)

        # stupid but useful cache here
        for index, funcid in enumerate(tmp):
            sanitize_conditions[funcid] = uncached_sanitize_conditions[index]
            sanitize_opt_cache[funcid] = uncached_sanitize_conditions[index]

        if not utils.elem_count(
                sanitize_conditions):  # fail to find conditions, early return
            return True

        # check if the conditions conflict with the params
        for funcid, callinfos in need_sanitize_function.items():
            conditions = sanitize_conditions[funcid]
            pack_conditions = {}
            for condition in conditions:
                prebbidentifier = condition[0]
                subbbidentifier = condition[1]
                # pre_start, pre_end = condition[0], condition[1]
                # sub_start, sub_end = condition[2], condition[3]
                pre_start, pre_end = prebbidentifier.split('+')
                sub_start, sub_end = subbbidentifier.split('+')
                relation = True if condition[2] == "True" else False
                param, paramidx = condition[3], condition[4]
                if param.startswith('!'):
                    relation = not relation
                pack_conditions[(dstruct.hash_signature(pre_start, pre_end),
                                 dstruct.hash_signature(
                                     sub_start,
                                     sub_end))] = [relation, paramidx]
            # generally, there can be different callinfos
            # and there can be several bbchain in callee function
            # we here adopts strict rule: once there is one callinfo param
            # obstacle one bb chain, this chain is broke

            # TODO: since for each CFG, we now only provide the shortest path
            # However, it may contains several paths to essential callinfo
            # the sanitizer here may ruin this because it strictly follow BB relation
            # the temporary solution here is to require the sanitizer only check
            # (critical) BB path
            for bbid in chain.chainInfo[funcid]:
                bbchains: List[dstruct.BChain] = chain.chainInfo[funcid][bbid]
                for bbchain in bbchains:
                    bbcfg: dstruct.ControlFlowGraph = bbchain.graph
                    bbpath = bbchain.path
                    for index in range(len(bbpath) - 1):
                        bbedge_pre = bbpath[index]
                        bbedge_sub = bbpath[index + 1]
                        if (bbedge_pre, bbedge_sub) in pack_conditions.keys():
                            # there is condition that can obstackle this chain
                            # well, is this bb edge a critical one?
                            # that is, the bbedge_pre has no other path to bbedge_sub
                            cfg = bbcfg.graph
                            pre_sub_paths = list(
                                nx.all_simple_paths(cfg, bbedge_pre,
                                                    bbedge_sub))
                            if not (len(pre_sub_paths) == 1
                                    and [bbedge_pre, bbedge_sub
                                         ] == pre_sub_paths[0]):
                                # that is not a critical one
                                continue

                            relation, paramidx = pack_conditions[(bbedge_pre,
                                                                  bbedge_sub)]
                            for callinfo in callinfos:
                                # there are multiple possible constant argument
                                for constantargidx, constantargval in callinfo.constantarg:
                                    # index mathcing
                                    if constantargidx == paramidx:
                                        if (relation
                                                and not int(constantargval)
                                            ) or (not relation
                                                  and int(constantargval)):
                                            utils.Logger.log(
                                                "sanitize {}() -> {}() {}-st parameter value {} broken chain"
                                                .format(
                                                    callinfo.caller.name,
                                                    dstruct.parse_funcid(
                                                        funcid)[0],
                                                    int(constantargidx),
                                                    constantargval))
                                            return False

    return True