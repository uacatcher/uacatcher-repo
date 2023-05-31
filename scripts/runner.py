import argparse
from components import *
import time
import sys

def setup_args():
    parser = argparse.ArgumentParser()

    parser.add_argument(
                    "--data",
                    type=str,
                    required=True,
                    help="directory for storing all data")

    parser.add_argument(
                    "--component",
                    type=str,
                    required=False,
                    help="run which component (p1, p11, p2, p3)")

    parser.add_argument(
                    "--codeqlcli",
                    type=str,
                    required=True,
                    help="codeql cli binary path")

    parser.add_argument(
                    "--codeqlrepo",
                    type=str,
                    required=True,
                    help="codeql repo search path")

    # p1
    parser.add_argument(
                    "--kernelsrc",
                    type=str,
                    required=False,
                    help="kernel source code path")
    parser.add_argument(
                    "--kerneldb",
                    type=str,
                    required=False,
                    help="kernel database path")
    # p11

    # p2
    parser.add_argument(
                    "--inputdesc",
                    type=str,
                    required=False,
                    help="input descriptor json path")

    # p3
    parser.add_argument(
                    "--inputsum",
                    type=str,
                    required=False,
                    help="input summary path")
    parser.add_argument(
                    "--algorithm",
                    type=str,
                    required=False,
                    help="algorithm type (manual|routine-switch|lockset)")
    parser.add_argument('--explore', action='store_true')

    return parser


def main():
    arg_parser = setup_args()
    parsed_args = arg_parser.parse_args()
    if parsed_args.component == "p1":
        active_component = LayersPrepare({
            "kernel_src": parsed_args.kernelsrc,
            "kernel_db": parsed_args.kerneldb,
            "data": parsed_args.data,
            "codeql_cli": parsed_args.codeqlcli,
            "codeql_search": parsed_args.codeqlrepo,
        })
    elif parsed_args.component == "p11":
        active_component = LayerPrepare({
            "inputdesc": parsed_args.inputdesc,
            "data": parsed_args.data,
            "codeql_cli": parsed_args.codeqlcli,
            "codeql_search": parsed_args.codeqlrepo,
        })
    elif parsed_args.component == "p2":
        active_component = DPairLocate({
            "inputdesc": parsed_args.inputdesc,
            "data": parsed_args.data,
            "codeql_cli": parsed_args.codeqlcli,
            "codeql_search": parsed_args.codeqlrepo,
        })
    elif parsed_args.component == "p3":
        active_component = UACDetect({
            "summary": parsed_args.inputsum,
            "algorithm": parsed_args.algorithm,
            "explore": parsed_args.explore,
            "data": parsed_args.data,
            "codeql_cli": parsed_args.codeqlcli,
            "codeql_search": parsed_args.codeqlrepo,
        })
    else:
        raise Exception("bad component")
    
    run_component(active_component)
        

def run_component(component_obj):
    setup_msg = component_obj.setup()
    
    if not setup_msg:
        print("""
         _      ___      _       _
 /\ /\  /_\    / __\__ _| |_ ___| |__   ___ _ __
/ / \ \//_\\\\  / /  / _` | __/ __| '_ \ / _ \ '__|
\ \_/ /  _  \/ /__| (_| | || (__| | | |  __/ |
 \___/\_/ \_/\____/\__,_|\__\___|_| |_|\___|_|

        >>>>>>>> {} <<<<<<<<\n""".format(component_obj.get_name()))
        component_obj.perform()
        component_obj.cleanup()
    else:
        print("Setup failed for component:", component_obj.get_name(), ", with Error:", setup_msg)
    return False

if __name__ == "__main__":
    main()