from .pbase import Component
from .core import dstruct, api, utils, analyze
from typing import List, Tuple, Dict

import os
import pickle
import json

class DPairLocate(Component):
    """
    Component that perform phase-2 pipeline
    * setup callgraph and CFG
    * find deallocation site
        * build chain
    * find dereference site
        * build chain
    """
    def __init__(self, values_dict: dict) -> None:
        self.inputdesc_path = values_dict["inputdesc"]
        self.data_path = values_dict["data"]
        self.codeql_cli_path = values_dict["codeql_cli"]
        self.codeql_search_path = values_dict["codeql_search"]
        self.timer = utils.Clock()

        self.descriptor = load_descriptor(self.inputdesc_path)
        self.upper_unregs = []
        
        if self.descriptor.upper:
            for upperlayer in self.descriptor.upper:
                upper_descriptor = load_descriptor_layer(
                    upperlayer, os.path.dirname(self.inputdesc_path))
                if not upper_descriptor:
                    utils.Logger.error(
                        "fail to find descriptor for layer {}".format(self.descriptor.upper))
                    exit(-1)
                
                for d in upper_descriptor.unreg:
                    self.upper_unregs.append(d)

        self.outputsummary_dir_path = os.path.join(
            self.data_path,
            "p2output",
            self.descriptor.name + "_dir"
        )

        if not os.path.exists(self.outputsummary_dir_path):
            os.system("mkdir -p {}".format(self.outputsummary_dir_path))


    def setup(self) -> str:
        # TODO
        os.environ["codeql_cli_path"] = self.codeql_cli_path
        os.environ["codeql_search_path"] = self.codeql_search_path

        analyze.coming(self.descriptor, True, os.path.join(self.data_path, "cache"))
        return ""


    def perform(self) -> str:
        self.timer.delta()
        # STEP-1: traverse from the unreg-entries
        #         and find out deallocation sites
        unreg_cgraphs = analyze.build_cgraphs(
            self.descriptor.unreg,
            core_type(self.descriptor.type),
            self.upper_unregs,
            self.descriptor.database
        )

        deallocation_sites_dict = analyze.get_deallocation_sites_from_cgraphs(
            unreg_cgraphs, self.descriptor.database)

        utils.Logger.log("STEP-1 costs {} secs".format(self.timer.delta()))

        # STEP-2: construct deallocation chain for each
        #         deallocation site
        self.timer.delta()
        deallocation_chains_dict = analyze.get_chains(deallocation_sites_dict,
                                                  unreg_cgraphs)

        utils.Logger.log("STEP-2 costs {} secs".format(self.timer.delta()))
        if not deallocation_chains_dict:
            utils.Logger.warn(
                "STEP1-2 fail to find any deallocation sites at layer {}:(".format(
                    self.descriptor.name))
            return "no deallocation sites"

        if not self.descriptor.deref and self.descriptor.upper:
            utils.Logger.warn(
                "seems you and collector leaves a tedious task to analyzer " +
                "that want to pinpoint dPairs even without gathered derefs. " +
                "it is doable, but bare the risk yourself.")
            return "no possible interface"

        self.timer.delta()
        deref_cgraphs = analyze.build_cgraphs(
            self.descriptor.deref, "", [], self.descriptor.database)
        utils.Logger.log("STEP-3 costs {} secs".format(self.timer.delta()))

        # STEP-4: pointsTo analysis to find out dereference sites
        dealloc_site_cnt_total_with_deref = 0
        deref_site_cnt_total = 0
        dealloc_site_cnt_filtered_with_deref = 0
        deref_site_cnt_filtered = 0

        for site_location, site_tuple in deallocation_sites_dict.items():
            site, _ = site_tuple
            dealloc_chains_dict = deallocation_chains_dict[site_location]
            self.timer.delta()
            dereference_sites_1 = analyze.get_dereference_sites_with_pointsto_and_reduce(
                site, self.descriptor.relpath, self.descriptor.database)

            utils.Logger.log("STEP-4 poinsTo costs {} secs".format(self.timer.delta()))

            if not dereference_sites_1:
                utils.Logger.log(
                    "pointsTo analysis failed to find dereference sites for deallocation site at {}"
                    .format(site_location))
                continue

            # till now, at least get some dPairs, we can record the total count
            # following operations are all filters
            dealloc_site_cnt_total_with_deref += 1
            deref_site_cnt_total += len(dereference_sites_1)

            if not analyze.filter_deallocation_site_with_errorhandling(
                dealloc_site=site, deref_sites=dereference_sites_1):
                utils.Logger.log(
                    "this deallocation site {} is possible temporary of error handling use"
                    .format(site_location))
                continue

            dereference_sites_2 = analyze.filter_dereference_sites_with_cgraphs(
            dereference_sites_1, deref_cgraphs)
            if not dereference_sites_2:
                utils.Logger.log(
                    "there is no dereference sites left in deref call graph for {}"
                    .format(site_location))
                continue

            dereference_chains_dict = analyze.get_chains(dereference_sites_2,
                                                     deref_cgraphs)

            dereference_sites_filter_1, dereference_chains_filter_1 = analyze.filter_by_ancestors(
                dereference_sites_2, dereference_chains_dict, dealloc_chains_dict)
            if not dereference_sites_filter_1:
                utils.Logger.log(
                    "there is no dereference sites left after ancestor filterring for {}"
                    .format(site_location))
                continue

            # const propagating filters
            dereference_sites_filter_2, dereference_chains_filter_2 = analyze.filter_by_constant_propagation(
                dereference_sites_filter_1, dereference_chains_filter_1, self.descriptor.database)
            if not dereference_sites_filter_2:
                utils.Logger.log(
                    "there is no dereference sites left after constant propagation filterring for {}"
                    .format(site_location))
                continue
        
            dealloc_site_cnt_filtered_with_deref += 1
            deref_site_cnt_filtered += len(dereference_sites_filter_2)

            # generate the summary
            summary = api.UACAnlsSummary(site, dealloc_chains_dict,
                                        dereference_sites_filter_2,
                                        dereference_chains_filter_2, self.descriptor)

            # STEP-last: dump summary
            dump_sum_name = summary.getDumpID() + ".sum"
            with open(os.path.join(self.outputsummary_dir_path, dump_sum_name), "wb") as f:
                utils.Logger.info("write summary to {}".format(dump_sum_name))
                pickle.dump(summary, f)

        return ""


    def cleanup(self) -> str:
        analyze.leaving(self.descriptor, os.path.join(self.data_path, "cache"))
        return ""


    def get_name(self) -> str:
        return "DPairLocate"


#
# Helpers
#
def load_descriptor(path: str) -> api.LayerDescriptor:
    with open(path, "r") as f:
        descriptor_json = json.load(f)
    
    descriptor = api.LayerDescriptor(
        name=descriptor_json["name"],
        kernel_version=descriptor_json["kernel version"],
        database=descriptor_json["database"],
        files=descriptor_json["files"],
        relpath=descriptor_json["directory"],
    )

    descriptor.type = descriptor_json["type"]
    descriptor.upper = descriptor_json["upper"]

    for d in descriptor_json["unreg"]:
        descriptor.unreg.append(dstruct.FuncMeta(d["name"], d["file"]))
    for d in descriptor_json["deref"]:
        descriptor.deref.append(dstruct.FuncMeta(d["name"], d["file"]))

    return descriptor


def load_descriptor_layer(layername: str, configsdir: str) -> api.LayerDescriptor:
    layerfile = layername + ".json"
    for root, _, files in os.walk(configsdir):
        if layerfile in files:
            path = os.path.join(root, layerfile)
            break
    else:
        return None

    return load_descriptor(path)


def core_type(types: List[str]) -> str:
    if 'net_notifier' in types:
        return 'net_notifier'  # this need additional care
    else:
        return types[0]