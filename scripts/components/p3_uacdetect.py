from .pbase import Component
from .core import dstruct, api, utils, detect
from typing import List, Tuple, Dict

import os
import pickle

class UACDetect(Component):
    """
    Component that perform phase-3 pipeline
    * can choose between manual/lockset/routine-switch
    """
    def __init__(self, values_dict: dict) -> None:
        self.summary_path = values_dict["summary"]
        self.summary_filename = os.path.splitext(
            os.path.basename(self.summary_path))[0]
        self.algorithm = values_dict["algorithm"]
        self.explore = values_dict["explore"]
        self.data_path = values_dict["data"]
        self.codeql_cli_path = values_dict["codeql_cli"]
        self.codeql_search_path = values_dict["codeql_search"]
        self.timer = utils.Clock()

        with open(self.summary_path, "rb") as f:
            self.summary: api.UACAnlsSummary = pickle.load(f)

        self.report_dir = os.path.join(
            self.data_path,
            "p3output",
            self.summary.descriptor.name
        )

        if not os.path.exists(self.report_dir):
            os.system("mkdir -p {}".format(self.report_dir))


    def setup(self) -> str:
        os.environ["codeql_cli_path"] = self.codeql_cli_path
        os.environ["codeql_search_path"] = self.codeql_search_path

        # TODO: args check
        detect.coming(self.summary.descriptor.database)
        return ""


    def perform(self) -> str:
        # for manual auditting
        if self.algorithm == 'manual':
            report = utils.MarkdownReport.sum2report(self.summary)
            report_path = os.path.join(self.report_dir,
                                       self.summary.getDumpID() + "_report.md")
            with open(report_path, "w") as f:
                f.write(report)
            utils.Logger.log("dump manual report at {}".format(report_path))
            return

        # auto ones
        dealloc_site = self.summary.dealloc_site
        deref_sites_dict = self.summary.deref_sites

        dealloc_chains = self.summary.dealloc_chains
        deref_chains_dict = self.summary.deref_chains

        # initialize the report and starts roll
        detectReport = api.DetectReport(self.summary_filename,
                                        self.algorithm,
                                        dealloc_site)
        
        for deref_loc, (deref_site, _) in deref_sites_dict.items():

            deref_chains = deref_chains_dict[deref_loc]

            possible_uacpair = (dealloc_site, deref_site)
            possible_uacpair_chains = (dealloc_chains, deref_chains)

            is_uac, uac_chain_combinations = detect.detect_uacpair(
                possible_uacpair,
                possible_uacpair_chains,
                self.summary.descriptor,
                self.algorithm,
                self.explore,
                self.summary.descriptor.database
            )
            
            if is_uac:
                utils.Logger.info(
                    "Cool the site {} and {} constitute a UAC site pair :)".
                    format(dealloc_site.location, deref_site.location))
                detectReport.addUACPair(possible_uacpair,
                                        uac_chain_combinations)
            else:
                utils.Logger.info("site {} and {} seems quite safe >_<".format(
                    dealloc_site.location, deref_site.location))

        if detectReport.uac:
            filename_main = detectReport.getDumpFName()
            jsonfilename = filename_main + ".json"
            jsonreport_path = os.path.join(self.report_dir, jsonfilename)
            jsonreport = detectReport.tojson()
            with open(jsonreport_path, "w") as f:
                f.write(jsonreport)


    def cleanup(self) -> str:
        return ""

    def get_name(self) -> str:
        return "UACDetect"