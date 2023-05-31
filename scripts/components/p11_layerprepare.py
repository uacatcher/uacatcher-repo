from .pbase import Component
from .core import dstruct, api, utils, codeql
from typing import List, Tuple, Dict

import json
import os

class LayerPrepare(Component):
    """
    Component that perform phase-1.1 pipeline
    * that is, phase-1 gets unreg function entry, but since the interface
      functions are better to be collected via layer-granularity. do it here
    """
    def __init__(self, values_dict: dict) -> None:
        self.inputdesc_path = values_dict["inputdesc"]
        self.data_path = values_dict["data"]
        self.codeql_cli_path = values_dict["codeql_cli"]
        self.codeql_search_path = values_dict["codeql_search"]
        self.timer = utils.Clock()
        
        # load descriptor from json
        with open(self.inputdesc_path, "r") as f:
            self.partial_descriptor_json = json.load(f)
        
        self.descriptor = api.LayerDescriptor(
            name=self.partial_descriptor_json["name"],
            kernel_version=self.partial_descriptor_json["kernel version"],
            database=self.partial_descriptor_json["database"],
            files=self.partial_descriptor_json["files"],
            relpath=self.partial_descriptor_json["directory"],
        )
        self.descriptor.type = self.partial_descriptor_json["type"]

        # keep the code for unreg collecting just for some time simple usage
        if self.partial_descriptor_json["unreg"]:
            for d in self.partial_descriptor_json["unreg"]:
                self.descriptor.unreg.append(dstruct.FuncMeta(
                    d["name"], d["file"]
                ))
            self.need_to_collect_unreg = False
        else:
            self.need_to_collect_unreg = True

        if self.partial_descriptor_json["deref"]:
            for d in self.partial_descriptor_json["deref"]:
                self.descriptor.deref.append(dstruct.FuncMeta(
                    d["name"], d["file"]
                ))
            self.need_to_collect_deref = False
        else:
            self.need_to_collect_deref = True

        self.descriptor.upper = self.partial_descriptor_json["upper"]
        self.outputdesc_dir_path = os.path.join(
            self.data_path,
            "p11output",
        )
        
        if not os.path.exists(self.outputdesc_dir_path):
            os.system("mkdir -p {}".format(self.outputdesc_dir_path))
   
    def setup(self) -> str:
        os.environ["codeql_cli_path"] = self.codeql_cli_path
        os.environ["codeql_search_path"] = self.codeql_search_path
        os.environ["partial_dir"] = os.path.join(self.data_path, "p1output")
        
        # TODO: arg check
        if not self.descriptor.name \
                or not self.descriptor.database \
            or not self.descriptor.files \
                or not self.descriptor.relpath:
            return "no meet minimum requests"
        return ""

    def perform(self) -> str:
        if self.need_to_collect_unreg:
            if not complete_layer_urneg():
                utils.Logger.error(
                    "Collector failed to find unreg functions for {}\nPlease manually complete it".format(self.descriptor.name))
                return "failed to find unreg"

        if self.need_to_collect_deref:
            if not complete_layer_deref(self.descriptor):
                utils.Logger.warn(
                    "Collector failed to find interface functions for {}\n".format(self.descriptor.name))
                # still have chance ...
                if not self.descriptor.upper:
                    utils.Logger.error(
                        "Collector failed to find deref functions for layer (no upper) {}\nPlease manually complete it".format(self.descriptor.name))
                    return "not found"
                else:
                    utils.Logger.warn(
                        "Collector failed to find deref functions for layer {}\nBut since it has upper, hack it".format(self.descriptor.name))
                    self.outputdesc_dir_path = os.path.join(self.outputdesc_dir_path, "uncertain")

        output_data = self.descriptor.tojson()
        output_data_path = os.path.join(self.outputdesc_dir_path, self.descriptor.name + ".json")
        utils.Logger.log(
            "complete the config of layer {} at {}\nbetter check it".format(
                self.descriptor.name, output_data_path))

        with open(output_data_path, "w") as f:
            f.write(output_data)
            

    def cleanup(self) -> str:
        return ""

    def get_name(self) -> str:
        return "LayerPrepare"

#
# Helpers
#

def complete_layer_urneg() -> bool:
    # TODO: as for now miner will at least find the unreg
    return False


def complete_layer_deref(descriptor: api.LayerDescriptor) -> bool:
    # 1 - Find the structure candidates:
    # PLAN A
    #     there is a global whose initializer contains several indirect pointer assignment
    #     if the upper layer is given, will find if these field is called by upper layer
    #     otherwise, guess it by its name and the place where it defines.
    # PLAN B
    #     if planA fails, try to get help with existing database to find structure
    # Otherwise fail
    deref_funcs = find_deref_planA(descriptor)
    
    deref_funcs += find_deref_planB(descriptor)
    
    if not deref_funcs:
        return False

    # 2 - fill into descriptors
    logs = []
    for deref_func in deref_funcs:
        if deref_func.getID() not in logs:
            logs.append(deref_func.getID())
            descriptor.deref.append(dstruct.FuncMeta(
                deref_func.name, deref_func.file))
    
    return True


def find_deref_planA(descriptor: api.LayerDescriptor) -> List[dstruct.Dereffunc]:
    # 1 - find structure and functions
    deref_dict = codeql.ql_find_dereffunc_struct(
        descriptor.relpath, descriptor.database)

    # 2 - the dict is keyed by structure id, next step is confirm
    #     if this structure is expected
    if deref_dict:
        # deref_dict = structs_fields_qualified(deref_dict)
        deref_dict = structs_fields_qualified_beta(deref_dict, descriptor)

    # 3 - return and beg for luck
    deref_func_list = []
    for _, func_list in deref_dict.items():
        deref_func_list += func_list
    return deref_func_list


def find_descriptor(name, path):
    for root, _, files in os.walk(path):
        if name in files:
            return os.path.join(root, name)


def structs_fields_qualified_beta(deref_dict: Dict[str, List[dstruct.Dereffunc]],
                                  descriptor: api.LayerDescriptor
                                  ) -> Dict[str, List[dstruct.Dereffunc]]:
    struct_field_dict = {}
    for struct_id, func_list in deref_dict.items():
        struct_field_dict[struct_id] = []
        for func in func_list:
            struct_field_dict[struct_id].append(func.fieldname)
        struct_field_dict[struct_id] = list(
            set(struct_field_dict[struct_id]))

    peek_upper = False
    if descriptor.upper:
        checked_struct_field_dict = {}

        for upperlayer in descriptor.upper:
            upperlayer_desc_path = find_descriptor(
                upperlayer + ".json", os.getenv("partial_dir")
            )

            if os.path.exists(upperlayer_desc_path):
                peek_upper = True

                with open(upperlayer_desc_path, "r") as f:
                    upper_descriptor_json = json.load(f)

                upper_descriptor = api.LayerDescriptor(
                    name=upper_descriptor_json["name"],
                    kernel_version=upper_descriptor_json["kernel version"],
                    database=upper_descriptor_json["database"],
                    files=upper_descriptor_json["files"],
                    relpath=upper_descriptor_json["directory"],
                )
                upper_descriptor.type = upper_descriptor_json["type"]
                need_to_confirm_structids = list(struct_field_dict.keys())

                after_confirm_struct_metas = codeql.ql_check_struct_call_exists(
                    need_to_confirm_structids, upper_descriptor.database)

                for struct_meta in after_confirm_struct_metas:
                    struct_id = struct_meta.getID()
                    if struct_id not in checked_struct_field_dict:
                        checked_struct_field_dict[struct_id] = []
                    checked_struct_field_dict[struct_id] += struct_field_dict[struct_id]

            else:
                utils.Logger.error(
                    "upper layer {} should exists but not ...".format(upperlayer))

    # no upper or upper path ...
    if not peek_upper:
        # otherwise we need to make sure the structure delcaration position
        # inaccurate but what should we do ...
        utils.Logger.warn(
            "deduce deref operations without upper layer, could be inaccurate T.T")

        # have to makesure unreg is okay here
        checked_struct_field_dict = codeql.ql_check_struct_defined_and_used_somewhere_else(
            struct_field_dict, descriptor.unreg, descriptor.database)

    # re organize
    update_deref_dict = {}
    for struct_id, func_list in deref_dict.items():
        update_deref_dict[struct_id] = []
        for func in func_list:
            if struct_id in checked_struct_field_dict and \
                    func.fieldname in checked_struct_field_dict[struct_id]:
                update_deref_dict[struct_id].append(func)
    
    return update_deref_dict
    

def find_deref_planB(descriptor: api.LayerDescriptor) -> List[dstruct.Dereffunc]:
    # TODO: need to do more data collection

    # planB is what we 'believe' must be dereferences
    # proto_ops, and proto <= included in A so don't worry
    # netlink !!!
    result = []
    result += codeql.ql_find_netlink_derefs(descriptor.relpath, descriptor.database)
    result += codeql.ql_find_pre_gather_derefs(descriptor.relpath, descriptor.database)
    return result

