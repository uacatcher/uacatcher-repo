from multiprocessing.spawn import prepare
import os
import hashlib
import subprocess
import re
import tqdm

from typing import List, Tuple, Dict

from . import config, template, utils, dstruct, queries


class CodeQLException(Exception):
    pass


class CodeQLTable:

    def __init__(self, name, colnames, content):
        self.name = name
        self.colnames = colnames
        self.content = content
        self.num_col = len(self.colnames)
        self.num_row = len(self.content)


# TODO: query to avoid hardcoding
ignore_kfunctions = [
    "_printk", "arch_static_branch_jump", "arch_static_branch",
    "____wrong_branch_error", "__dynamic_pr_debug"
]  # boring utils func

ignore_kfunctions_pattern = [
    r"__builtin.*",
    r"__le64.*",
    r"__le32.*",
    r"__le16.*",
    r"__compiletime.*",
    r"__dynamic_.*",
    r"kasan_.*",
    r"kcsan_.*",
]

# added
specific_callback_functions = {}


def prepare_ql_string(s: str):
    return '"' + s + '"'


def prepare_ql_string_list(l: list):
    result = '['
    for s in l:
        result += prepare_ql_string(s)
        result += ","
    # addition comma here
    result = result[:-1] + ']'
    return result


def useful_function(funcname: str) -> bool:
    if funcname in ignore_kfunctions:
        return False
    for pattern in ignore_kfunctions_pattern:
        if re.search(pattern, funcname) != None:
            return False
    return True


def split_ql_table(table, num_tag):
    if table.colnames[0] != "tag":
        raise CodeQLException("not a splittable CodeQLTable")
    result = [[] for i in range(num_tag)]
    for line in table.content:
        result[int(line[0])].append(line[1:])
    return result


def run_command(cmd, timeout):
    ret = subprocess.run(
        cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8",
        timeout=timeout,
    )
    if ret.returncode != 0:
        raise CodeQLException("{} {}".format(cmd, ret.stderr))
    return (ret.stdout, ret.stderr)


def parse_output(out, query_name):
    lines = out.strip().split("\n")
    if len(lines) == 1 and len(lines[0]) == 0:
        return CodeQLTable(query_name, [], [[]])
    colnames = [x.strip() for x in lines[0].split("|")[1:-1]]
    content = [[x.strip() for x in line.split("|")[1:-1]]
               for line in lines[2:]]
    return CodeQLTable(query_name, colnames, content)


def run_codeql(
    query,
    database,
    timeout=config.default_timeout,
    query_name="test",
):
    filename = hashlib.md5(query_name.encode()).hexdigest() + ".ql"
    path = os.path.join(config.tmp_path, filename)
    open(path, "w").write(query)
    
    codeql_cli_path = os.getenv("codeql_cli_path")
    codeql_repo_path = os.getenv("codeql_repo_path")
    
    command = "{} query run {} --database {} --search-path {} -j{}".format(
        codeql_cli_path, path, database, codeql_repo_path,
        config.multithread)
    if config.debug:
        utils.Logger.log("{} -> {}".format(query_name, path))
        utils.Logger.log(query)
    out, err = run_command(command, timeout)
    if config.debug:
        utils.Logger.log(out)
        utils.Logger.log(err)
    return parse_output(out, query_name)

# 
# Queries Wrapper P1 Relevant
#
def ql_get_all_driver_types(database: str) -> List[str]:
    result = run_codeql(
        query=queries.QueriesDict["getDriverType"],
        database=database,
        timeout=config.allyes_timeout,
        query_name="GetAllDriverTypes"
    )
    return [r[0] for r in result.content]


def ql_get_driver_unreg_functions(database: str) -> List[dstruct.Unregfunc]:
    result = run_codeql(
        query=queries.QueriesDict["getDriverUnreg"],
        database=database,
        timeout=config.allyes_timeout,
        query_name="getDriverUnreg"
    )
    return [dstruct.Unregfunc(r[0], r[1], r[2]) for r in result.content]


def ql_get_upper_unreg_functions(database: str) -> List[dstruct.FuncMeta]:
    result = run_codeql(
        query=queries.QueriesDict["getUpperUnreg"],
        database=database,
        timeout=config.allyes_timeout,
        query_name="getUpperUnreg"
    )
    return [dstruct.Unregfunc(r[0], r[1], r[2]) for r in result.content]


def ql_get_upper_unreg_name_from_unreg(unregfunc: dstruct.FuncMeta, database: str) -> List[str]:
    result = run_codeql(
        query=queries.QueriesDict["UnregUpperName"].format(
            funcname=unregfunc.name, funcfile=unregfunc.file),
        query_name="UnregUpperName{}".format(unregfunc.getID()),
        database=database)
    return [r[0] for r in result.content]


def ql_translate_names_to_funcmetas_batch(names: List[str], database: str) -> List[dstruct.Unregfunc]:
    parsed_result = []
    for i in tqdm.tqdm(range(0, len(names), config.BATCH_SIZE)):
        j = min(i + config.BATCH_SIZE, len(names))
        # i + BATCH if i + BATCH < len(names) else len(names)

        constraints = prepare_ql_string_list(names[i: j])
        result = run_codeql(
            query=queries.QueriesDict["TranslateName2Meta"].format(constraints = constraints),
            query_name="UnregUpper_{}".format(constraints),
            database=database,
            timeout=config.allyes_timeout)

        for r in result.content:
            name, file = r
            parsed_result.append(dstruct.Unregfunc(name, file, "upper"))

    return parsed_result


def ql_find_callsites_batch(functions: List[dstruct.FuncMeta], database: str) -> List[List[str]]:
    query = template.CodeQLTemplate(queries.QueriesDict["GetCallSites"])
    for function in functions:
        query.begin_group()
        query.add_item(prepare_ql_string(function.name),
                       prepare_ql_string(function.file))
        query.end_group()

    result = run_codeql(query.get_query(),
                        query_name="GetCallSite_{}".format(database),
                        database=database,
                        timeout=config.allyes_timeout)

    result = split_ql_table(result, query.next_tag)
    
    return result


# 
# Queries Wrapper P1.1 Relevant
#
def ql_find_dereffunc_struct(
        constaraint: str, database: str) -> Dict[str, List[dstruct.Dereffunc]]:
    # better use CodeQL class to implement the logic
    # can refer to the old get_all_proto_ops() and get_general_deref_ops()
    common_part = queries.QueriesDict["DerefCommon"]
    # constraint the variable location
    select_code_gvar = queries.QueriesDict["DerefGVar1"] % (constaraint)

    gvar_result = run_codeql(common_part + select_code_gvar,
                             query_name="derefgvar_{}".format(database),
                             database=database,
                             timeout=config.default_timeout)
    # well, we need to pack the result in structure + variable granularity
    gvar_result_dict = {}
    for r in gvar_result.content:
        struct_name, struct_file, gvar_name, gvar_file, field_name, function_name, function_file = r
        struct_meta = dstruct.StructMeta(struct_name, struct_file)
        struct_id = struct_meta.getID()
        if struct_id not in gvar_result_dict.keys():
            gvar_result_dict[struct_id] = {}
        if gvar_name not in gvar_result_dict[struct_id].keys():
            gvar_result_dict[struct_id][gvar_name] = []
        gvar_result_dict[struct_id][gvar_name].append(
            dstruct.Dereffunc(function_name, function_file, field_name,
                              struct_id))

    select_code_gvar2 = queries.QueriesDict["DerefGVar2"] % (constaraint)

    gvar_result2_dict = {}
    gvar_result2 = run_codeql(common_part + select_code_gvar2,
                              query_name="derefgvar2_{}".format(database),
                              database=database,
                              timeout=config.default_timeout)

    for r in gvar_result2.content:
        struct_name, struct_file, field_name, function_name, function_file = r
        struct_meta = dstruct.StructMeta(struct_name, struct_file)
        struct_id = struct_meta.getID()
        if struct_id not in gvar_result2_dict.keys():
            gvar_result2_dict[struct_id] = []

        gvar_result2_dict[struct_id].append(
            dstruct.Dereffunc(function_name, function_file, field_name,
                              struct_id))

    select_code_infunc = queries.QueriesDict["DerefDyn1"] % (constaraint)
    infunc_result = run_codeql(common_part + select_code_infunc,
                               query_name="derefinfunc_{}".format(database),
                               database=database,
                               timeout=config.default_timeout)
    infunc_result_dict = {}
    for r in infunc_result.content:
        struct_name, struct_file, initfunc_name, field_name, function_name, function_file = r
        struct_meta = dstruct.StructMeta(struct_name, struct_file)
        struct_id = struct_meta.getID()
        # do a simple filter, we believe one initfunc will not just init one function
        if struct_id not in infunc_result_dict.keys():
            infunc_result_dict[struct_id] = {}
        if initfunc_name not in infunc_result_dict[struct_id].keys():
            infunc_result_dict[struct_id][initfunc_name] = []
        infunc_result_dict[struct_id][initfunc_name].append(
            dstruct.Dereffunc(function_name, function_file, field_name,
                              struct_id))

    select_code_infunc2 = queries.QueriesDict["DerefDyn2"] % (constaraint)
    infunc_result2 = run_codeql(common_part + select_code_infunc2,
                                query_name="derefinfunc2_{}".format(database),
                                database=database,
                                timeout=config.default_timeout)
    infunc_result_dict2 = {}
    for r in infunc_result2.content:
        struct_name, struct_file, initfunc_name, field_name, function_name, function_file = r
        struct_meta = dstruct.StructMeta(struct_name, struct_file)
        struct_id = struct_meta.getID()
        # do a simple filter, we believe one initfunc will not just init one function
        if struct_id not in infunc_result_dict2.keys():
            infunc_result_dict2[struct_id] = {}
        if initfunc_name not in infunc_result_dict2[struct_id].keys():
            infunc_result_dict2[struct_id][initfunc_name] = []
        infunc_result_dict2[struct_id][initfunc_name].append(
            dstruct.Dereffunc(function_name, function_file, field_name,
                              struct_id))

    # okay, going to merge the result
    packed_result = {}
    packed_result_contain_log = []
    for struct_id, var_dict in gvar_result_dict.items():
        for _, funclist in var_dict.items():
            if len(funclist
                   ) < 2:  # ops structure contains more than one funciton
                # just too strict
                utils.Logger.warn(
                    "only find one function in gvar within {}".format(struct_id))
            if struct_id not in packed_result.keys():
                packed_result[struct_id] = []
            for func in funclist:
                if func.getID() not in packed_result_contain_log:
                    packed_result[struct_id].append(func)
                    packed_result_contain_log.append(func.getID())

    for struct_id, functions in gvar_result2_dict.items():
        if struct_id in packed_result.keys():
            utils.Logger.warn(
                "weird, the global var deref is overlapped with recursive global deref at structure {}"
                .format(struct_id))
        if struct_id not in packed_result.keys():
            packed_result[struct_id] = []
        for func in functions:
            if func.getID() not in packed_result_contain_log:
                packed_result[struct_id].append(func)
                packed_result_contain_log.append(func.getID())

    for struct_id, func_dict in infunc_result_dict.items():
        if struct_id in packed_result.keys():
            utils.Logger.warn(
                "weird, the global var deref is overlapped with infunc deref at structure {}"
                .format(struct_name))

        for _, funclist in func_dict.items():
            if len(
                    funclist
            ) < 2:  # ops structure contains more than one funciton (init)
                # just too strict
                utils.Logger.warn(
                    "only find one function in dynamic struct (pfa) assign within {}".format(struct_id))
            if struct_id not in packed_result.keys():
                packed_result[struct_id] = []
            for func in funclist:
                if func.getID() not in packed_result_contain_log:
                    packed_result[struct_id].append(func)
                    packed_result_contain_log.append(func.getID())

    for struct_id, func_dict in infunc_result_dict2.items():
        if struct_id in packed_result.keys():
            utils.Logger.warn(
                "weird, the global var deref is overlapped with infunc2 deref at structure {}"
                .format(struct_name))

        for _, funclist in func_dict.items():
            if len(
                    funclist
            ) < 2:  # ops structure contains more than one funciton (init)
                utils.Logger.warn(
                    "only find one function in dynamic struct (vfa) assign within {}".format(struct_id))
            if struct_id not in packed_result.keys():
                packed_result[struct_id] = []
            for func in funclist:
                if func.getID() not in packed_result_contain_log:
                    packed_result[struct_id].append(func)
                    packed_result_contain_log.append(func.getID())

    return packed_result


def ql_check_struct_call_exists(struct_ids: List[str], database: str) -> List[dstruct.StructMeta]:
    query = template.CodeQLTemplate(queries.QueriesDict["GetStFieldCallSound"])
    
    for struct_id in struct_ids:
        struct_name, struct_file = dstruct.parse_structid(struct_id)
        query.begin_group()
        query.add_item(prepare_ql_string(struct_name),
                       prepare_ql_string(struct_file))
        query.end_group()
    
    result = run_codeql(query.get_query(),
                        query_name="GetStFieldCallSonud_{}".format(database),
                        database=database)
    result = split_ql_table(result, query.next_tag)
    
    packed_result = []
    log = []
    for r in result:
        for struct_name, struct_file in r:
            struct_meta = dstruct.StructMeta(struct_name, struct_file)
            struct_id = struct_meta.getID()
            if struct_id not in log:
                packed_result.append(struct_meta)
                log.append(struct_id)
    return packed_result

def ql_check_struct_defined_and_used_somewhere_else(
        struct_field_dict: Dict[str, List[str]],
        unregfuncs: List[dstruct.Unregfunc],
        database: str) -> Dict[str, List[str]]:
    structids = list(struct_field_dict.keys())
    result = run_codeql(
        query=queries.QueriesDict["GetFuncDeclara"].format(
        prepare_ql_string_list([func.name for func in unregfuncs])),
        query_name="GetFuncDeclara_{}".format(database),
        database=database)
    declara_files = []
    for _, file in result.content:
        declara_files.append(file)
    declara_files = list(set(declara_files))

    # filter out structs that defined in those files
    filtered_structids = []
    for struct_id in structids:
        _, struct_file = dstruct.parse_structid(struct_id)
        if struct_file not in filtered_structids:
            filtered_structids.append(struct_id)

    # cool, we can filter out some structid keys
    filer_result_1 = {}
    for struct_id, fieldlist in struct_field_dict.items():
        if struct_id in filtered_structids:
            filer_result_1[struct_id] = fieldlist

    # next we have to make sure the field call never happen in current database
    query = template.CodeQLTemplate(queries.QueriesDict["GetStFieldCall"])
    for struct_id, fieldlist in filer_result_1.items():
        struct_name, struct_file = dstruct.parse_structid(struct_id)
        query.begin_group()
        query.add_item(prepare_ql_string(struct_name),
                       prepare_ql_string(struct_file),
                       prepare_ql_string_list(fieldlist))
        query.end_group()

    result = run_codeql(query.get_query(),
                        query_name="GetStFieldCallrev_{}".format(database),
                        database=database)
    result = split_ql_table(result, query.next_tag)

    discard_struct_field_pack = {}
    for r in result:
        for struct_name, struct_file, field_name in r:
            struct_meta = dstruct.StructMeta(struct_name, struct_file)
            struct_id = struct_meta.getID()
            if struct_id not in discard_struct_field_pack.keys():
                discard_struct_field_pack[struct_id] = []
            if field_name not in discard_struct_field_pack[struct_id]:
                discard_struct_field_pack[struct_id].append(field_name)

    filer_result_2 = {}
    for struct_id, fieldlist in filer_result_1.items():
        for field_name in fieldlist:
            if struct_id in discard_struct_field_pack.keys() and \
                    field_name in discard_struct_field_pack[struct_id]:
                continue
            if struct_id not in filer_result_2.keys():
                filer_result_2[struct_id] = []
            filer_result_2[struct_id].append(field_name)

    return filer_result_2


def ql_find_netlink_derefs(constaraint: str, database: str) -> List[dstruct.Dereffunc]:
    # idea is simple, find initializer for struct genl_ops and small_genl_ops
    # get doit function field
    query = queries.QueriesDict["GetNetlinkOps"] % (constaraint)
    result = run_codeql(query,
                        query_name="netlink_derefs_{}".format(database),
                        database=database,
                        timeout=config.default_timeout)
    packed_result = []
    logs = []
    for r in result.content:
        struct_name, struct_file, field_name, function_name, function_file = r
        deref_func = dstruct.Dereffunc(
            function_name, function_file, field_name, dstruct.StructMeta(struct_name, struct_file).getID)
        if deref_func.getID() not in logs:
            logs.append(deref_func.getID())
            packed_result.append(deref_func)

    return packed_result


def ql_find_pre_gather_derefs(constaraint: str, database: str) -> List[dstruct.Dereffunc]:
    query = queries.QueriesDict["GetPreGVarOps"] % (constaraint)
    result = run_codeql(query,
                        query_name="derefpregvar_{}".format(database),
                        database=database,
                        timeout=config.default_timeout)
    # well, we need to pack the result in structure + variable granularity
    packed_result = []
    logs = []
    for r in result.content:
        struct_name, struct_file, field_name, function_name, function_file = r
        deref_func = dstruct.Dereffunc(
            function_name, function_file, field_name, dstruct.StructMeta(struct_name, struct_file).getID)
        if deref_func.getID() not in logs:
            logs.append(deref_func.getID())
            packed_result.append(deref_func)

    return packed_result


#
# Queries Wrapper P2 Relevant
#
dealloc_kfunctions = []


def ql_special_callinfo_process_analyze(database: str) -> None:
    utils.Logger.log("processing deallocation functions")

    global dealloc_kfunctions
    result = run_codeql(
        query=queries.QueriesDict["HeapCommon"] + queries.QueriesDict["GetDealloc"],
        query_name="GetDealloc_{}".format(database),
        database=database
    )
    for r in result.content:
        dealloc_kfunctions.append(
            [dstruct.FuncMeta(r[0], r[1]), r[2]])


def ql_get_defined_h_funcs(database: str) -> list:
    result = run_codeql(
        query=queries.QueriesDict["GetHDef"],
        query_name="GetHDef_{}".format(database),
        database=database)
    return result.content


def ql_get_defined_c_funcs(database: str) -> list:
    result = run_codeql(
        query=queries.QueriesDict["GetCDef"],
        query_name="GetCDef_{}".format(database),
        database=database)
    return result.content


def ql_get_defined_funcs(database: str) -> list:
    result = run_codeql(
        query=queries.QueriesDict["GetDef"],
        query_name="GetDef_{}".format(database),
        database=database)
    return result.content


def ql_get_basic_blocks(funcmetas: list, database: str):
    query = template.CodeQLTemplate(queries.QueriesDict["GetBasicBlock"])
    for funcname, funcfile in funcmetas:
        query.begin_group()
        query.add_item(prepare_ql_string(funcname),
                       prepare_ql_string(funcfile))
        query.end_group()
    result = run_codeql(query.get_query(),
                        query_name="GetBasicBlock_{}".format(database),
                        database=database)
    result = split_ql_table(result, query.next_tag)
    return result


def ql_get_callinfos_cfgs(
    cfgs: Dict[str, dstruct.ControlFlowGraph],
    database: str
) -> Dict[str, Dict[str, Dict[str, dstruct.CallInfo]]]:
    query = template.CodeQLTemplate(queries.QueriesDict["GetCallInfoBatch"])
    funcids = list(cfgs.keys())
    # prepare arguments (function enough)
    for funcid in funcids:
        funcfile, funcname = dstruct.parse_funcid(funcid)
        query.begin_group()
        query.add_item(prepare_ql_string(funcfile),
                       prepare_ql_string(funcname))
        query.end_group()

    result = run_codeql(query=query.get_query(),
                        query_name="GetCallInfoBatch_{}".format(database),
                        database=database)
    result = split_ql_table(result, query.next_tag)
    # now result is indexed by funcid, inside each funcid there will be multiple information
    packed_result = {}
    for index, rr in enumerate(result):
        funcid = funcids[index]
        funcname, funcfile = dstruct.parse_funcid(funcid)
        funcmeta = dstruct.FuncMeta(funcname, funcfile)
        packed_result[funcid] = {}
        for r in rr:
            calltype, callloc, calleepacked, bbidentifier, constantargval, constantargidx, functionargpacked, functionargidx = r
            # the found function may be boring, forget about it
            if not useful_function(dstruct.parse_funcid(calleepacked)[0]):
                continue
            bbstart, bbend = bbidentifier.split('+')
            bbid = dstruct.hash_signature(bbstart, bbend)
            if bbid not in packed_result[funcid].keys():
                packed_result[funcid][bbid] = {}

            if callloc not in packed_result[funcid][bbid].keys():
                info = dstruct.CallInfo(callloc, calltype, funcmeta, bbid)
                info.callee.append(calleepacked)
                if constantargval != "lucky":
                    info.constantarg.append((constantargidx, constantargval))
                if functionargpacked != "lucky":
                    info.functionarg.append(
                        (functionargpacked, functionargidx))
                packed_result[funcid][bbid][callloc] = info
            else:
                # possible more informations here
                info = packed_result[funcid][bbid][callloc]
                assert (calltype == info.type)
                if calleepacked not in info.callee:
                    info.callee.append(calleepacked)
                if constantargval != "lucky" and (
                        constantargidx,
                        constantargval) not in info.constantarg:
                    info.constantarg.append((constantargidx, constantargval))
                if functionargpacked != "lucky" and (
                        functionargpacked,
                        functionargidx) not in info.functionarg:
                    info.functionarg.append(
                        (functionargpacked, functionargidx))

    return packed_result


def ql_get_callinfos_infunction(
        funcmeta: dstruct.FuncMeta,
        database: str) -> Dict[str, Dict[str, dstruct.CallInfo]]:
    query = queries.QueriesDict["GetCallInfo"] % \
        (prepare_ql_string(funcmeta.name), prepare_ql_string(funcmeta.file))
    result = run_codeql(
        query=query,
        query_name="GetCallInfo_{}".format(database),
        database=database)

    packed_result = {}
    for r in result.content:
        calltype, callloc, calleepacked, bbidentifier, constantargval, constantargidx, functionargpacked, functionargidx = r
        # the found function may be boring, forget about it
        if not useful_function(dstruct.parse_funcid(calleepacked)[0]):
            continue
        bbstart, bbend = bbidentifier.split('+')
        bbid = dstruct.hash_signature(bbstart, bbend)
        if bbid not in packed_result.keys():
            packed_result[bbid] = {}
        # check if this call is already inside the list
        if callloc not in packed_result[bbid].keys():
            info = dstruct.CallInfo(callloc, calltype, funcmeta, bbid)
            info.callee.append(calleepacked)
            # FUTRUE WORK: the async delayed mechanism for now just ignore
            # moreover, check if this loc is specific
            # if callloc in specific_callback_functions.keys():
            #     info.callee.append(
            #         specific_callback_functions[callloc].getID())

            if constantargval != "lucky":
                info.constantarg.append((constantargidx, constantargval))
            if functionargpacked != "lucky":
                info.functionarg.append((functionargpacked, functionargidx))
            packed_result[bbid][callloc] = info
        else:
            # possible more informations here
            info = packed_result[bbid][callloc]
            assert (calltype == info.type)
            if calleepacked not in info.callee:
                info.callee.append(calleepacked)
            if constantargval != "lucky" and (
                    constantargidx, constantargval) not in info.constantarg:
                info.constantarg.append((constantargidx, constantargval))
            if functionargpacked != "lucky" and (
                    functionargpacked, functionargidx) not in info.functionarg:
                info.functionarg.append((functionargpacked, functionargidx))

    return packed_result


def ql_get_unreg_functions_from_notifier(
        unregfunc: dstruct.FuncMeta,
        database: str) -> List[dstruct.CallInfo]:
    query = queries.QueriesDict["GetUnregFromNotifier"] % (
        prepare_ql_string(unregfunc.name),
        prepare_ql_string(unregfunc.file)
    )
    result = run_codeql(query=query,
                        query_name="GetUnregFromNotifier_{}".format(database),
                        database=database)
    callinfos_ret = []
    for r in result.content:
        callee = dstruct.FuncMeta(r[1], r[2])
        calleeid = callee.getID()
        bbstart, bbend = r[3].split('+')
        info = dstruct.CallInfo(
            r[0],
            "direct",
            unregfunc,
            bbid=dstruct.hash_signature(bbstart, bbend),
        )
        info.callee.append(calleeid)
        callinfos_ret.append(info)

    return callinfos_ret


def ql_get_dealloc_funcnode(funcids: list, database = "") -> list:
    # recover funcid to meta
    deallocfuncids = [info[0].getID() for info in dealloc_kfunctions]
    l1 = list(set(funcids).intersection(set(deallocfuncids)))
    l2 = [dealloc_kfunctions[deallocfuncids.index(name)][1] for name in l1]
    return l1, l2


def ql_get_pointsTo_call(
    location: str, argidx: int, identifier: str, database: str) -> list:
    query = queries.QueriesDict["HeapCommon"] + queries.QueriesDict["PointsToAnlysisS1"] % (
        prepare_ql_string(location),
        argidx,
        identifier)
    result = run_codeql(query=query,
                        query_name="PointsToAnlysisS1_{}".format(database),
                        database=database)
    return result.content


def ql_get_dereference_sites_with_pointsto(
    locations: List[str], identifier: str, database: str) -> list:
    locations_parsed = ''
    for location in locations:
        locations_parsed += prepare_ql_string(location)
        locations_parsed += ', '
    locations_parsed = locations_parsed[:-2]

    query = queries.QueriesDict["HeapCommon"] + queries.QueriesDict["PointsToAnlysisS2"] % (
        identifier,
        locations_parsed
    )
    result = run_codeql(query=query,
                        query_name="PointsToAnlysisS2_{}".format(database),
                        database=database)
    return result.content


def ql_get_pointsTo_allowinacc(
    location: str, argidx: int, identifier: str, database: str) -> list:
    query = queries.QueriesDict["PointsToAnalysis"] + queries.QueriesDict["PointsToAnalysis"] % (
        prepare_ql_string(location),
        argidx,
        identifier
    )
    result = run_codeql(query=query,
                        query_name="PointsToAnlysis_{}".format(database),
                        database=database)
    return result.content


def ql_get_sanitize_conditions(functionsMeta: list, database: str) -> list:
    query = template.CodeQLTemplate(
        queries.QueriesDict["GetSanitizeConditions"])
    for meta in functionsMeta:
        funcname, funcfile = dstruct.parse_funcid(meta)
        query.begin_group()
        query.add_item(prepare_ql_string(funcname),
                       prepare_ql_string(funcfile))
        query.end_group()
    result = run_codeql(query.get_query(),
                        query_name="GetSanitizeConditions_{}".format(database),
                        database=database)
    result = split_ql_table(result, query.next_tag)
    return result

#
# Queries Wrapper P3 Relevant
#

lock_kfunctions = []
unlock_kfunctions = []
# Add lock types to repor in the future
bits_r_kfunctions = []
bits_w_kfunctions = []

# identifiers
lockunlock_callinfo_identifiers = []
lockunlock_callinfo_identifiers_dict = {}
bits_r_identifiers = []
bits_w_identifiers = []

def ql_get_snullwrite_bbs(bbs, database: str) -> list:
    query = template.CodeQLTemplate(queries.QueriesDict["GetSNullWrite"])
    for loc in bbs:
        query.begin_group()
        query.add_item(prepare_ql_string(loc))
        query.end_group()
    result = run_codeql(query.get_query(),
                        query_name="GetSNullWrite_{}".format(database),
                        database=database)
    result = split_ql_table(result, query.next_tag)
    return result


def ql_get_bbconditions(innerfunc: str, bbidentifiers, database: str) -> list:
    query = template.CodeQLTemplate(queries.QueriesDict["GetBBConditions"])
    for identifiers in bbidentifiers:
        query.begin_group()
        query.add_item(prepare_ql_string(identifiers[0]),
                       prepare_ql_string(identifiers[1]))
        query.end_group(prepare_ql_string(innerfunc))
    result = run_codeql(query.get_query(),
                        query_name="GetBBConditions_{}".format(database),
                        database=database)
    result = split_ql_table(result, query.next_tag)
    # well, we need to parse return condition
    parsed_result = []
    for index, r in enumerate(result):
        if not len(r):
            utils.Logger.error(
                "GetBBConditions with argument func: {}, bb {}-{} returns empty result???"
                .format(innerfunc, bbidentifiers[index][0], bbidentifiers[index][1]))
            parsed_result.append(None)
            continue

        conditionInfo = r[0]
        if len(r) > 1:
            # buggy.. find first one not unknown
            for index in range(len(r)):
                if r[index] != "unknown":
                    conditionInfo = r[index]
                    break
        expect_tag = conditionInfo[0]
        if expect_tag == "unknown":
            parsed_result.append(None)
        else:
            if expect_tag == "true":
                expect = True
            elif expect_tag == "false":
                expect = False
            conditionwords = conditionInfo[1].split('---')
            parsed_result.append(
                dstruct.parseGenCondition(expect, conditionwords))
    assert (len(bbidentifiers) == len(parsed_result))
    return parsed_result


def ql_special_callinfo_process_detect(database: str) -> None:
    # In practice, seperately handle them in everytime is time consuming
    # hence we can collect them here to speedup the procedure
    do_lockunlock_callinfo_process(database)
    do_bitw_callinfo_process(database)

    # in future
    # add specific indirect callinfo here
    # which means: queue_work, queue_delayed_work, and mod_timer


def is_callinfo_lockunlock(info: dstruct.CallInfo) -> dstruct.LockunLockInfo:
    callloc = info.location
    if callloc not in lockunlock_callinfo_identifiers_dict:
        return None
    _, _, identifier, lockornot, _, _ = lockunlock_callinfo_identifiers_dict[callloc]
    lockornotbool = True if lockornot == "locking" else False
    lockinfo = dstruct.LockunLockInfo(info.location, info.type,
                                        info.caller, info.bbid,
                                        lockornotbool, "default",
                                        identifier)
    lockinfo.caller = info.callee
    lockinfo.constantarg = info.constantarg
    lockinfo.functionarg = info.functionarg
    return lockinfo


def is_callinfo_lock_wrapper(info: dstruct.CallInfo,
                             graph: dstruct.CallGraph) -> str:
    # simply check if there the callee satisify
    # (1) has only one lock call, no more other lock calls
    # (2) no unlock call at all

    # multi-target indirect call cannot be wrapper
    if len(info.callee) > 1:
        return ""

    # non-direct call target cannot be wrapper
    if info.type != "direct":
        return ""

    calleename, calleefile = dstruct.parse_funcid(info.callee[0])
    calleeMeta = dstruct.FuncMeta(calleename, calleefile)
    callee_id = calleeMeta.getID()
    if callee_id not in graph.graph.nodes:
        return ""
    callee_node = graph.graph.nodes[callee_id]
    if "cfg" not in callee_node or not callee_node["cfg"]:
        return ""
    callee_cfg = callee_node["cfg"]
    callee_callinfos = callee_cfg.getAll_callinfos()
    lock_call_count = 0
    lock_call_ident = ""
    for callinfo in callee_callinfos:
        r = is_callinfo_lockunlock(callinfo)
        if r:
            if r.lock:
                lock_call_count += 1
                if lock_call_count > 1:
                    return ""
                lock_call_ident = r.identifier
            else:
                return ""
    return lock_call_ident


def is_callinfo_unlock_wrapper(info: dstruct.CallInfo,
                               graph: dstruct.CallGraph) -> str:
    # simply check if there the callee satisify
    # (1) has only one unlock call, no more other unlock calls
    # (2) no lock call at all
    # multi-target indirect call cannot be wrapper
    if len(info.callee) > 1:
        return ""

    # non-direct call target cannot be wrapper
    if info.type != "direct":
        return ""

    calleename, calleefile = dstruct.parse_funcid(info.callee[0])
    calleeMeta = dstruct.FuncMeta(calleename, calleefile)
    callee_id = calleeMeta.getID()
    if callee_id not in graph.graph.nodes:
        return ""
    callee_node = graph.graph.nodes[callee_id]
    if "cfg" not in callee_node or not callee_node["cfg"]:
        return ""
    callee_cfg = callee_node["cfg"]
    callee_callinfos = callee_cfg.getAll_callinfos()
    unlock_call_count = 0
    unlock_call_ident = ""
    for callinfo in callee_callinfos:
        r = is_callinfo_lockunlock(callinfo)
        if r:
            if not r.lock:
                unlock_call_count += 1
                if unlock_call_count > 1:
                    return ""
                unlock_call_ident = r.identifier
            else:
                return ""
    return unlock_call_ident


def do_lockunlock_callinfo_process(database: str) -> None:
    global lockunlock_callinfo_identifiers_dict

    utils.Logger.log("processing locking/unlocking functions")
    # Type-A: identifier based locks and unlocks

    #   1. simple global lock (rwlock_t, spinlock_t, mutex), global variable location as identifier
    result = run_codeql(query=queries.QueriesDict["GetGlobalLockSimple"],
                        query_name="GetGlobalLockSimpleIdent_{}".format(database),
                        database=database)

    # callinfo location | callinfo target function name | callinfo target function file | identifier | locking or unlocking | call enclose function name and file
    for r in result.content:
        callinfo_loc, callinfo_target_funcname, callinfo_target_funcfile, identifier, lockornot, enclosename, enclosefile = r
        lockunlock_callinfo_identifiers_dict[callinfo_loc] = (callinfo_target_funcname, callinfo_target_funcfile, identifier, lockornot, enclosename, enclosefile)

    #   2. global lock in struct (rwlock_t, spinlock_t, mutex), also variable location as identifier
    result = run_codeql(query=queries.QueriesDict["GetGStructLock"],
                        query_name="GetGStructLockIdent_{}".format(database),
                        database=database)
    for r in result.content:
        callinfo_loc, callinfo_target_funcname, callinfo_target_funcfile, identifier, lockornot, enclosename, enclosefile = r
        lockunlock_callinfo_identifiers_dict[callinfo_loc] = (callinfo_target_funcname, callinfo_target_funcfile, identifier, lockornot, enclosename, enclosefile)

    #   3. dynamic locks, complex
    #   we first find lock initialization place (all marco)
    #   we get their location which will used for later pointsTo analysis

    query = queries.QueriesDict["GetDLockLocations"]
    result = run_codeql(query=query,
                        query_name="GetDLockLocations_{}".format(database),
                        database=database)
    
    for r in result.content:
        callinfo_loc, callinfo_target_funcname, callinfo_target_funcfile, identifier, lockornot, enclosename, enclosefile = r
        # if callinfo_loc exists, nevermind, just occupy it
        if callinfo_loc in lockunlock_callinfo_identifiers_dict and identifier != lockunlock_callinfo_identifiers_dict[callinfo_loc][2]:
            utils.Logger.warn("call location overlap, one identifier is {} and another is {}".format(
                identifier, lockunlock_callinfo_identifiers_dict[callinfo_loc][2]))
        lockunlock_callinfo_identifiers_dict[callinfo_loc] = (callinfo_target_funcname, callinfo_target_funcfile, identifier, lockornot, enclosename, enclosefile)

    # Type-B: simple unified lock and unlocks
    # --- lock_sock and release_sock ---
    # --- rtnl_lock and rtnl_unlock ---
    result = run_codeql(query=queries.QueriesDict["GetALock"],
                        query_name="GetALock_{}".format(database),
                        database=database)

    for r in result.content:
        callinfo_loc, callinfo_target_funcname, callinfo_target_funcfile, identifier, lockornot, enclosename, enclosefile = r
        lockunlock_callinfo_identifiers_dict[callinfo_loc] = (callinfo_target_funcname, callinfo_target_funcfile, identifier, lockornot, enclosename, enclosefile)


def is_callinfo_bitrw(info: dstruct.CallInfo):
    # Traverse with call location
    callloc = info.location
    for identifiers in bits_w_identifiers:
        # 0: call location
        # 1: valueMacro
        # 2. value
        # 3. present
        # 4. call function
        # 5. call file
        # 6. call target
        if identifiers[0] == callloc:
            # found one
            bitw_info = dstruct.BitsRWInfo(info.location, info.type,
                                           info.caller, info.bbid, True,
                                           identifiers[1], identifiers[2],
                                           identifiers[3])
            bitw_info.callee = info.callee
            bitw_info.constantarg = info.constantarg
            bitw_info.functionarg = info.functionarg
            return bitw_info
    for identifiers in bits_r_identifiers:
        if identifiers[0] == callloc:
            # found one
            bitr_info = dstruct.BitsRWInfo(info.location, info.type,
                                           info.caller, info.bbid, False,
                                           identifiers[1], identifiers[2],
                                           identifiers[3])
            bitr_info.callee = info.callee
            bitr_info.constantarg = info.constantarg
            bitr_info.functionarg = info.functionarg
            return bitr_info
    return None


def do_bitw_callinfo_process(database: str) -> None:
    utils.Logger.log("processing bits read/write functions")

    global bits_r_identifiers, bits_w_identifiers

    bitsw_funcnames = [
        "set_bit",
        "clear_bit",
        "change_bit",
        "test_and_clear_bit",
        # "test_and_change_bit"
    ]
    functionsStr = "["
    for func in bitsw_funcnames:
        functionsStr += prepare_ql_string(func)
        functionsStr += ", "
    functionsStr += "]"
    query = queries.QueriesDict["GetBitsOps"] % (functionsStr)

    result1 = run_codeql(query=query,
                         query_name="GetBitsOps1_{}".format(database),
                         database=database)
    bits_w_identifiers = result1.content

    bitsw_funcnames = ["test_bit", "test_and_clear_bit", "test_and_change_bit"]
    functionsStr = "["
    for func in bitsw_funcnames:
        functionsStr += prepare_ql_string(func)
        functionsStr += ", "
    functionsStr += "]"
    query = queries.QueriesDict["GetBitsOps"] % (functionsStr)

    result2 = run_codeql(query=query,
                         query_name="GetBitsOps2_{}".format(database),
                         database=database)
    bits_r_identifiers = result2.content