from .pbase import Component
import os
import pickle
import re
import hashlib
import tqdm
import networkx as nx
from concurrent.futures import ProcessPoolExecutor

from typing import List, Tuple, Dict

from .core import utils, codeql, dstruct, api, config

class LayersPrepare(Component):
    """
    Component that perform phase-1 pipeline
    * find all driver types in kernel
    * find the driver unreg function with collected types and marked pointers
    * --- create database for those driver layers ---
    * bottom-top to find other unreg functions for upper layers
    * --- build stack layers structure ---
    * // top-down to find interface functions 
    * // ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    #   do this somewhere else :)
    """
    def __init__(self, values_dict: dict) -> None:
        self.kernel_src_path = values_dict["kernel_src"]
        self.kernel_db_path = values_dict["kernel_db"]
        self.data_path = values_dict["data"]
        self.codeql_cli_path = values_dict["codeql_cli"]
        self.codeql_search_path = values_dict["codeql_search"]
        self.timer = utils.Clock()
    
    def setup(self) -> str:
        os.environ["codeql_cli_path"] = self.codeql_cli_path
        os.environ["codeql_search_path"] = self.codeql_search_path
        os.environ["kernel_version"] = utils.extract_kver(self.kernel_src_path)
        # TODO: check validity, like check db exists
        return ""
    
    def perform(self) -> str:
        # step-1: get driver types (structs)
        driver_types_result_cache = os.path.join(self.data_path, "driver_types.bin")
        if not os.path.exists(driver_types_result_cache):
            self.timer.delta()
            driver_types = codeql.ql_get_all_driver_types(self.kernel_db_path)
            utils.Logger.info(
                "find {} driver types, costs {} secs".format(len(driver_types), self.timer.delta()))
            with open(driver_types_result_cache, "wb") as f:
                pickle.dump(driver_types, f)
        
        # step-2: get unreg functions for those drivers
        driver_unreg_functions_cache = os.path.join(self.data_path, "driver_unreg_functions.bin")
        if not os.path.exists(driver_unreg_functions_cache):
            self.timer.delta()
            driver_unreg_functions = codeql.ql_get_driver_unreg_functions(self.kernel_db_path)
            utils.Logger.info(
                "find {} driver unreg functions, costs {} secs".format(
                    len(driver_unreg_functions), self.timer.delta()))
            with open(driver_unreg_functions_cache, "wb") as f:
                pickle.dump(driver_unreg_functions, f)
        else:
            with open(driver_unreg_functions_cache, "rb") as f:
                driver_unreg_functions = pickle.load(f)
        
        # step-3: find unreg functions for upper layers
        upper_unreg_functions_cache = os.path.join(self.data_path, "upper_unreg_functions.bin")
        if not os.path.exists(upper_unreg_functions_cache):
            self.timer.delta()
            upper_unreg_functions = codeql.ql_get_upper_unreg_functions(self.kernel_db_path)
            utils.Logger.info(
                "find {} upper unreg functions, costs {} secs".format(
                    len(upper_unreg_functions), self.timer.delta()))
            with open(upper_unreg_functions_cache, "wb") as f:
                pickle.dump(upper_unreg_functions, f)
        else:
            with open(upper_unreg_functions_cache, "rb") as f:
                upper_unreg_functions = pickle.load(f)
        
        # step-4: layer-based database building
        self.timer.delta()
        driver_impressions, driver_descriptors, driver_fails = \
            build_layer_databases(driver_unreg_functions,
                              self.kernel_src_path,
                              "driver",
                              os.path.join(self.data_path, "database_driver"))
            
        upper_impressions, upper_descriptors, upper_fails = \
            build_layer_databases(upper_unreg_functions,
                              self.kernel_src_path,
                              "upper",
                              os.path.join(self.data_path, "database_upper"))
            
        utils.Logger.info(
                "build {} databases, costs {} secs, {} of them fail".format(
                    len(driver_impressions) + len(upper_impressions),
                    self.timer.delta(),
                    len(driver_fails) + len(upper_fails)))
        
        with open(os.path.join(self.data_path, "database_driver_fails.bin"), "wb") as f:
            pickle.dump(driver_fails, f)
        with open(os.path.join(self.data_path, "database_upper_fails.bin"), "wb") as f:
            pickle.dump(upper_fails, f)
        
        with open(os.path.join(self.data_path, "driver_impressions.bin"), "wb") as f:
            pickle.dump(driver_impressions, f)
        with open(os.path.join(self.data_path, "upper_impressions.bin"), "wb") as f:
            pickle.dump(upper_impressions, f)
        
        # step-5: keep mine new unreg functions based on call relation
        #         this should be finished recursively
        self.timer.delta()
        more_descriptors, relation_edges, new_fails = do_mine_more_upper_layers(
            driver_descriptors, 
            upper_descriptors, 
            self.data_path, 
            self.kernel_db_path,
            self.kernel_src_path, 
            os.path.join(self.data_path, "database_upper_new"))
        utils.Logger.info("mine new {} databases, costs {} secs. {} of them fail".format(
            len(more_descriptors),
            self.timer.delta(),
            len(new_fails)
        ))
        with open(os.path.join(self.data_path, "database_driver_mine.bin"), "wb") as f:
            pickle.dump(new_fails, f)
        
        # step-6: add other callsites with call xref
        xref_cache = os.path.join(self.data_path, "xref_cache.bin")
        if os.path.exists(xref_cache):
            with open(xref_cache, "rb") as f:
                xref_callsites = pickle.load(f)
        else:
            xref_callsites = {}
            utils.Logger.info(
                "scan the allyes database to cross xref callsites, cost a lot of time"
            )

            xref_callsites = get_unregfunc_callsite_batch(upper_impressions, self.kernel_db_path)

            with open(xref_cache, "wb") as f:
                pickle.dump(xref_callsites, f)
        
        #        update the edges
        descriptors_all = {**driver_descriptors, **upper_descriptors, **more_descriptors}
        
        forget_other_layers = []
        for layer_name, callsites in xref_callsites.items():
            for callsitepath in callsites:
                callsite_layer_name, _, _, _ = get_layer_impression_from_file(
                    callsitepath, self.kernel_src_path)
                if callsite_layer_name:
                    # xref find a new layer which not belong to existing layer
                    if callsite_layer_name not in descriptors_all:
                        utils.Logger.warn(
                            "may still forget a layer of {} ".format(callsite_layer_name))
                        forget_other_layers.append(
                            (callsite_layer_name, layer_name, callsitepath))
                        continue
                    else:
                        if callsite_layer_name not in relation_edges.keys():
                            relation_edges[callsite_layer_name] = []

                        if callsite_layer_name != layer_name and \
                                layer_name not in relation_edges[callsite_layer_name]:
                            relation_edges[callsite_layer_name].append(layer_name)
                
        # step-6: find interface functions for each layer
        #         build the graph first
        graph = nx.Graph()
        for layer_name in descriptors_all:
            graph.add_node(layer_name)
        
        for parent, childs in relation_edges.items():
            for child in childs:
                if parent in descriptors_all and child in descriptors_all:
                    graph.add_edge(parent, child)
                    parent_desc = descriptors_all[parent]
                    if child not in parent_desc.upper:
                        parent_desc.upper.append(child)
                else:
                    if parent not in descriptors_all:
                        utils.Logger.warn("{} in edge but not in descriptors".format(parent))
                    else:
                        utils.Logger.warn("{} in edge but not in descriptors".format(child))

        #        graph actualy contains several components (stacked layers)
        componenets = nx.connected_components(graph)
        stacked_componenets = [x for x in componenets if len(x) > 1]
        picked_layers = []
        for component in stacked_componenets:
            picked_layers += component
        picked_layers = list(set(picked_layers))
        
        utils.Logger.info("finally pick {} layers".format(len(picked_layers)))
        
        result_graph = nx.DiGraph()
        # even not stacked, we believe the heuristics case
        for name, desc in descriptors_all.items():
            if name not in picked_layers and name not in upper_descriptors:
                continue
            desc: api.LayerDescriptor = desc
            result_graph.add_node(name)
            outpath_dir = os.path.join(self.data_path, "p1output")
            if not os.path.exists(outpath_dir):
                os.mkdir(outpath_dir)
            outpath = os.path.join(outpath_dir, "{}.json".format(name))
            outputdata = desc.tojson()
            with open(outpath, "w") as f:
                f.write(outputdata)
            utils.Logger.log(
                "successfully dump picked (partial) descirption to {}".format(outpath))
        
        for parent, childs in relation_edges.items():
            for child in childs:
                if parent in result_graph.nodes and child in result_graph.nodes:
                    result_graph.add_edge(parent, child)
        
        with open(os.path.join(self.data_path, "result_graph.bin"), "wb") as f:
            pickle.dump(result_graph, f)
        
        # TODO: add error handling
        return ""
    
    def cleanup(self) -> str:
        return ""
    
    def get_name(self) -> str:
        return "LayersPrepare"

#
# Helpers
#

class KPaths:
    # paths are just cumbersome
    def __init__(self, filepath_rel: str, kernelpath_abs: str) -> None:
        # relative
        self.filepath_rel = filepath_rel
        self.dirpath_rel = os.path.dirname(self.filepath_rel)
        
        # absolute
        self.dirpath_abs = os.path.join(kernelpath_abs, self.dirpath_rel)
        self.makefilepath_abs = os.path.join(self.dirpath_abs, "Makefile")
        
        # others
        self.dir = os.path.basename(self.dirpath_abs)
        self.file = os.path.basename(filepath_rel)


class MakefileDescriptor:
    # we rewrite this to accurate parse Makefile

    def __init__(self, makefilepath: str) -> None:
        import pymake
        import pymake.parser
        import pymake.parserdata
        
        self.path = makefilepath
        # TODO, makesure this makefile path exists
        self.raw = open(makefilepath, "r").read().strip()
        self.stmts = pymake.parser.parsestring(self.raw, "Makefile")

        # table is key - objects map
        self.table = {}
        
        # traverse each SetVariable stmt
        for stmt in self.stmts:
            if not isinstance(stmt, pymake.parserdata.SetVariable):
                if isinstance(stmt, pymake.parserdata.ConditionBlock):
                    # need internal traverse (two branches so double loop)
                    self.stmts += unpack_ConditionBlock(stmt)
                continue
            values = stmt.value.strip().split()
            # [0][0] for goal, [1][0] for condition behalf
            if len(stmt.vnameexp) == 1:
                # no confition
                keyword = stmt.vnameexp[0][0]
            elif len(stmt.vnameexp) == 2: # assume one condition
                if hasattr(stmt.vnameexp[1][0], "vname"):
                    keyword = "{}{}".format(stmt.vnameexp[0][0], stmt.vnameexp[1][0].vname.s)
                else:
                    keyword = "{}{}".format(stmt.vnameexp[0][0],
                                            hashlib.md5(str(stmt.vnameexp[1][0]).encode()).hexdigest()[:6]
                                        )
            else:
                utils.Logger.warn("cannot decide keyword for stmt {} in Makefile {}".format(
                    stmt.to_source(), makefilepath
                ))
                keyword = "{}-{}".format(stmt.vnameexp[0][0], len(stmt.vnameexp))
                
            if keyword not in self.table.keys():
                self.table[keyword] = []
            self.table[keyword] += values

    def obj_to_keyword(self, objectname: str) -> str:
        for keyword, objects in self.table.items():
            if objectname in objects:
                return keyword
        # we find nothing, possible because the prefix directory
        # try it again
        for keyword, objects in self.table.items():
            for object in objects:
                if os.path.basename(object) == objectname:
                    return keyword
        return ""


class LImpression():

    def __init__(self, layer_name: str, absdir: str, reldir: str, keyword: str,
                 objs: List[str]) -> None:
        # to distinguish a layer
        self.layer_name = layer_name
        self.absdir = absdir
        self.reldir = reldir
        self.makefile_keyword = keyword
        self.makefile_objs = objs
        self.unregfuncs = []

    def record_unreg_func(self, unregfunc: dstruct.Unregfunc) -> None:
        self.unregfuncs.append(unregfunc)


def unpack_ConditionBlock(conditionblock):
    import pymake.parserdata
    # need to do it recursively
    result = []
    for conditionexpand in conditionblock:
        for stmt in conditionexpand[1]:
            if not isinstance(stmt, pymake.parserdata.SetVariable):
                if isinstance(stmt, pymake.parserdata.ConditionBlock):
                    result += unpack_ConditionBlock(stmt)
            else:
                result.append(stmt)
    return result


def build_layer_databases(
    unregfunctions: List[dstruct.Unregfunc], kernel_src: str,
    layer_type: str, database_out: str):
    # load codeql
    codeql_cli_path: str = os.getenv("codeql_cli_path")
    codeql_search_path: str = os.getenv("codeql_search_path")
    # 1. generate layer impression
    impressions:Dict[str, LImpression] = {}
    for unregfunc in unregfunctions:
        layer_name, paths, makefile_keyword, objects = get_layer_impression_from_unreg(
            unregfunc, kernel_src)
        if not layer_name:
            utils.Logger.warn(
                "fail to find impression for layer with unreg function at {}".format(unregfunc.getID()))
            # therefore, 
            
            continue
        
        if layer_name in impressions.keys():
            impression = impressions[layer_name]
            impression.record_unreg_func(unregfunc)
        else:
            impression = LImpression(layer_name, paths.dirpath_abs,
                                     paths.dirpath_rel, makefile_keyword,
                                     objects)
            impression.record_unreg_func(unregfunc)
            impressions[layer_name] = impression
    
    # 2. build database with impression
    descriptors = {}
    database_fail_logs = []
    
    for layer_name, impression in tqdm.tqdm(impressions.items()):
        _, res = database_build_worker(
            layer_type, layer_name, impression, True,
            database_out, kernel_src, codeql_cli_path, codeql_search_path)
        res: api.LayerDescriptor = res
        if res and os.path.exists(os.path.join(res.database, "db-cpp")):
            if layer_name in descriptors.keys():
                # we don't update the unreg here to avoid conflicts
                descriptors[layer_name].type.append(layer_type)
            else:
                descriptors[layer_name] = res
                # need to fillin some other information
                impression = impressions[layer_name]
                for unregfunc in impression.unregfuncs:
                    descriptors[layer_name].unreg.append(unregfunc)
        else:
            if res:
                os.system("rm -rf {}".format(res.database))
            database_fail_logs.append(layer_name)
    
    return impressions, descriptors, database_fail_logs


def get_layer_impression_from_unreg(
        unregfunc: dstruct.Unregfunc, kernelabs: str) -> Tuple[str, KPaths, str, List[str]]:
    return get_layer_impression_from_file(unregfunc.file, kernelabs)


def get_layer_impression_from_file(
        filepath: str, kernel_path: str) -> Tuple[str, KPaths, str, List[str]]:
    # since path orgranization is too trivial, make a class for it
    paths = KPaths(filepath, kernel_path)
    try:
        makefile = MakefileDescriptor(paths.makefilepath_abs)
        unreg_enclosefile_obj = paths.file.replace(".c", ".o")
        makefile_keyword = makefile.obj_to_keyword(unreg_enclosefile_obj)
        if not makefile_keyword:
            # test if have exactly object related file
            objects = [paths.file]
            makefile_keyword = paths.file.replace(".c", "-objs")
            utils.Logger.error("didn't find keyword in Makefile {} for {}".format(
                paths.makefilepath_abs, unreg_enclosefile_obj))

        layer_name = get_layer_name(keyword=makefile_keyword, paths=paths)
        objects = makefile.table[makefile_keyword]
    except FileNotFoundError as err:
        utils.Logger.error(
            "error {} when parsing Makefile at {}, ignore it".format(
                err, paths.makefilepath_abs))
        # if makefile not found, could build this directory as database
        layer_name = get_layer_name(keyword="entire", paths=paths)
        makefile_keyword = "entire"
        objects = "" # leave empty
    except Exception as err:
        utils.Logger.error(
            "error {} when parsing Makefile at {}, ignore it".format(
                err, paths.makefilepath_abs))
        makefile = None
        layer_name = ""
        makefile_keyword = ""
        objects = ""
    return layer_name, paths, makefile_keyword, objects


def _get_layer_name(enclosedir: str, keyword: str, relative_path: str) -> str:
    return "layer_{}_{}{}".format(
        enclosedir,
        hashlib.md5(keyword.encode()).hexdigest()[:8],
        hashlib.md5(relative_path.encode()).hexdigest()[:8])


def get_layer_name(keyword: str, paths: KPaths):
    return _get_layer_name(enclosedir=paths.dir,
                           keyword=keyword,
                           relative_path=paths.dirpath_rel)


def database_build_worker(layer_type: str,
                          layer_name: str,
                          impression: LImpression,
                          genornot: bool,
                          databaseout: str,
                          kernel_src: str,
                          codeql_cli_path: str,
                          codeql_search_path: str) -> Tuple[str, api.LayerDescriptor]:
    try:
        database_name = get_layer_database_name(layer_name)
        if not os.path.exists(databaseout):
            os.mkdir(databaseout)
        database_path = os.path.join(databaseout, database_name)
        if not os.path.exists(database_path) or config.overwrite:       
            success = setup_layer_database(
                impression, kernel_src, database_path, genornot, codeql_cli_path, codeql_search_path)
            if not success:
                raise Exception("database failed")
        else:
            # already built this database ? skip
            pass
        kver = os.getenv("kernel_version")

        desc = api.LayerDescriptor(layer_name, kver, database_path,
                                   impression.makefile_objs, impression.reldir)
        desc.type.append(layer_type)
        return layer_name, desc
    except Exception as err:
        utils.Logger.error("error {} build database {}".format(
            err, database_path))
        return layer_name, None


def get_layer_database_name(name):
    return "linux_{}_{}".format(os.getenv("kernel_version"), name)


def setup_layer_database(impression: LImpression,
                         kernelpath: str,
                         databasepath: str,
                         genornot: bool,
                         codeql_cli_path: str,
                         codeql_search_path: str) -> bool:
    del_cmd = "cd {dir}; rm -f {objfiles}".format(
        dir=impression.absdir, objfiles=' '.join(impression.makefile_objs))

    if impression.makefile_keyword != "entire":
        packed_objectslist = []
        for obj in impression.makefile_objs:
            packed_objectslist.append(os.path.join(impression.reldir, obj))
        build_cmd = "make -j4 {}".format(" ".join(packed_objectslist))
    else:
        # else all objects is what we expect
        build_cmd = "make -j4 {}".format(impression.reldir +
                                         "/")  # need to append "/" here

    if os.path.exists(databasepath):
        utils.Logger.info("You already build the database for this layer?")
        return True
    else:
        if genornot:
            utils.Logger.log("Executing command:")
            utils.Logger.log_no_head(del_cmd)
            os.system(del_cmd)
            cmd = '{codeql} database create {out} -s={input} --search-path={repo} --language=cpp -j2 --command="{cmd}" --overwrite'.format(
                codeql=codeql_cli_path,
                out=databasepath,
                input=kernelpath,
                repo=codeql_search_path,
                cmd=build_cmd)
            utils.Logger.log_no_head(cmd)
            success = os.system(cmd)
            return not success
        else:
            # dump build command here
            cmd = '{codeql} database create {out} -s={input} --search-path={repo} --language=cpp -j2 --command="{cmd}" --overwrite'.format(
                codeql=codeql_cli_path,
                out=databasepath,
                input=kernelpath,
                repo=codeql_search_path,
                cmd=build_cmd)
            cmd_all = del_cmd + '\n' + cmd
            with open(
                    os.path.join(config.project_path, "output/helpers/",
                                 impression.layer_name + ".sh"), "w") as f:
                f.write(cmd_all)
            return True


def do_mine_more_upper_layers(descriptors_drv: Dict[str, api.LayerDescriptor],
                              descriptors_upper: Dict[str, api.LayerDescriptor],
                              datadir: str,
                              kdatabase_path: str,
                              ksrc_path: str,
                              database_out: str,
                              ) -> Tuple[Dict[str, api.LayerDescriptor], Dict[str, List[str]], List[str]]:
    # load codeql
    codeql_cli_path: str = os.getenv("codeql_cli_path")
    codeql_search_path: str = os.getenv("codeql_search_path")
    
    # already done perhaps
    mined_descriptors_cache_path = os.path.join(datadir, "mined.bin")
    if os.path.exists(mined_descriptors_cache_path):
        with open(mined_descriptors_cache_path, "rb") as f:
            descriptors_more, unreg_relation_edges = pickle.load(f)
        return descriptors_more, unreg_relation_edges, []   # forget about the failed one

    # -- 1 -- prepare necessary data structures
    database_fail_logs_total: List[str] = []
    candidates: List[Tuple[str, str]] = []
    unregfunc_old: List[str] = []
    unregfunc_new: List[str] = []
    newlayer_names: List[str] = []
    unreg_relation_edges: Dict[str, List[str]] = {}
    descriptors_new = {}

    for layer_name, desc in descriptors_drv.items():
        unregfuncs: List[dstruct.Unregfunc] = desc.unreg
        # the recursive mine starts from driver
        for unreg in unregfuncs:
            unregfunc_old.append(unreg.getID())
            candidates.append((unreg.getID(), desc.database))
    
    for layer_name, desc in descriptors_upper.items():
        for unreg in unregfuncs:
            unregfunc_old.append(unreg.getID())

    # -- 2 -- main recusive loop
    candidate_id_log = []
    while True:
        # intermediate
        unreg_call_map: List[str, List[str]] = {}

        executor = ProcessPoolExecutor(max_workers=6)
        response_process = []
        
        # pack to avoid database overlap
        packed_candidates = {}
        for candidate_id, candidate_database in candidates:
            if candidate_id in candidate_id_log:
                continue
            
            candidate_name, candidate_file = dstruct.parse_funcid(candidate_id)
            candidate_meta = dstruct.FuncMeta(candidate_name, candidate_file)

            if candidate_database not in packed_candidates.keys():
                packed_candidates[candidate_database] = []
            packed_candidates[candidate_database].append(candidate_meta)
            candidate_id_log.append(candidate_id)

        for database, unregfuncs in packed_candidates.items():
            response_process.append(
                executor.submit(get_upper_unreg_name_from_unreg,
                                unregfuncs, database)
            )

        new_mined_unregs_names: List[str] = []

        for index, r in enumerate(tqdm.tqdm(response_process)):
            relevant_packed_key = list(packed_candidates.keys())[index]
            relevant_unregs = packed_candidates[relevant_packed_key]

            candidate_possible_upper_unreg_names = r.result()

            if not candidate_possible_upper_unreg_names:
                continue

            new_mined_unregs_names += candidate_possible_upper_unreg_names

            # add edges
            for candidate_meta in relevant_unregs:
                if candidate_meta.getID() not in unreg_call_map.keys():
                    unreg_call_map[candidate_meta.getID()] = []
                for name in candidate_possible_upper_unreg_names:
                    unreg_call_map[candidate_meta.getID()].append(name)

        new_mined_unregs_names = list(set(new_mined_unregs_names))

        if not new_mined_unregs_names:
            utils.Logger.log("the loop is over at exit-1")
            break

        funcmetas = codeql.ql_translate_names_to_funcmetas_batch(
            new_mined_unregs_names, kdatabase_path)

        funcmetas_id = [funcmeta.getID() for funcmeta in funcmetas]
        
        # construct edges (even old we need to connect)
        for unregfuncid in funcmetas_id:
            funcname, funcfile = dstruct.parse_funcid(unregfuncid)
            for unregid, edgenames in unreg_call_map.items():
                if funcname in edgenames:
                    if unregid not in unreg_relation_edges.keys():
                        unreg_relation_edges[unregid] = []
                    unreg_relation_edges[unregid].append(unregfuncid)
        
        new_funcmetas_id = list(set(funcmetas_id) - set(unregfunc_old))
        if not new_funcmetas_id:
            utils.Logger.log("the loop is over at exit-2")
            break

        unregfunc_new += new_funcmetas_id   # save new
        unregfunc_old += new_funcmetas_id   # update old
        candidates_update = []

        # to this end, if this unreg stands for new layer, need to build database
        # for old layer, need to update descriptor
        for unregfuncid in new_funcmetas_id:
            funcname, funcfile = dstruct.parse_funcid(unregfuncid)
            unregfunc = dstruct.Unregfunc(funcname, funcfile, "upper")
            layer_name, paths, makefile_keyword, objects = get_layer_impression_from_unreg(
                unregfunc, ksrc_path)
            if layer_name:
                if layer_name in descriptors_drv:
                    # just update desc
                    desc = descriptors_drv[layer_name]
                    desc.unreg.append(unregfunc)
                elif layer_name in descriptors_upper:
                    desc = descriptors_upper[layer_name]
                    desc.unreg.append(unregfunc)
                else:
                    # new layer, need to build database
                    impression = LImpression(layer_name, paths.dirpath_abs,
                                             paths.dirpath_rel, makefile_keyword,
                                             objects)
                    impression.record_unreg_func(unregfunc)
                    _, desc = database_build_worker(
                        "upper", layer_name, impression, True,
                        database_out, ksrc_path, codeql_cli_path, codeql_search_path)

                    if desc and os.path.exists(os.path.join(desc.database, "db-cpp")):
                        for _unregfunc in impression.unregfuncs:
                            desc.unreg.append(_unregfunc)
                        descriptors_new[layer_name] = desc
                        newlayer_names.append(layer_name)
                        candidates_update.append((unregfuncid, desc.database))
                    else:
                        if desc:
                            os.system("rm -rf {}".format(desc.database))
                        database_fail_logs_total.append(layer_name)

            else:
                utils.Logger.warn(
                    "fail to find impression for layer with new mined unreg function at {}".format(unregfunc.getID()))
                continue
        
        # next loop will based on new unregs
        candidates = candidates_update

    # -- 3 -- get the results
    with open(mined_descriptors_cache_path, "wb") as f:
        pickle.dump((descriptors_new, unreg_relation_edges), f)

    utils.Logger.log(
        "bottom-up mine {} new unreg functions".format(len(unregfunc_new))
    )
    utils.Logger.log(
        "which related to {} new layers".format(len(newlayer_names))
    )
    utils.Logger.error(
        "At same time, {} database building fail, dump at /tmp/mine_databasefail.dump".format(
            len(database_fail_logs_total))
    )

    return descriptors_new, unreg_relation_edges, database_fail_logs_total


def get_upper_unreg_name_from_unreg(
        unregfuncs: List[dstruct.FuncMeta], database: str) -> List[str]:
    packed_result = []
    try:
        for unregfunc in unregfuncs:
            tmp = codeql.ql_get_upper_unreg_name_from_unreg(unregfunc, database)
            packed_result += tmp

        if packed_result:
            utils.Logger.log(
                "find {} upper unreg functions for from database {}".format(len(tmp), database))
        else:
            utils.Logger.warn(
                "failed to find upper unreg for function for database {}".format(
                    database)
            )
    # need to do this or our entire time is waste
    except Exception as err:
        utils.Logger.error(err)

    return packed_result


def get_unregfunc_callsite_batch(impressions_heuristics: Dict[str, LImpression],
                                 kdb_path: str) -> Dict[str, List[str]]:
    batch = 15
    result = {}
    for i in tqdm.tqdm(range(0, len(impressions_heuristics), batch)):
        j = i + batch if i + \
            batch < len(impressions_heuristics) else len(impressions_heuristics)
        cnt = []
        layernames_batch = list(impressions_heuristics.keys())[i: j]
        impressions_batch = [impressions_heuristics[name]
                             for name in layernames_batch]
        unregfuncs_batch = [
            impression.unregfuncs for impression in impressions_batch]
        # need to mark this
        unregfuncs_batch_serialize = []
        for unregfuncs in unregfuncs_batch:
            cnt.append(len(unregfuncs))
            unregfuncs_batch_serialize += unregfuncs

        callsite_locations = codeql.ql_find_callsites_batch(unregfuncs_batch_serialize,
                                                            kdb_path)
        # recover to dict
        marker = 0
        for index, layername in enumerate(layernames_batch):
            picked = []
            markcnt = cnt[index]
            for k in range(marker, marker + markcnt):
                picked += callsite_locations[k]
            result[layername] = [utils.get_relpath_from_derived_location(
                pick[0]) for pick in picked]
            result[layername] = list(set(result[layername]))
            marker += markcnt

    return result
