from lib.cve_database import get_conn, ConnSearcher
from lib.codebase_manager import codebaseManager
from lib.prompt_generator import PromptGenerator
from lib.cve_folder import CVEFolder
import os
from lib.pipeline import run_whole_pipeline
from lib.utils import clone_repo, unit_test_generate, fix_cve
from lib.validate_utils import validate_fix
import json

#SCRIPT_PATH = os.path.realpath(__file__)
HOME_PATH = os.path.abspath('.')
DATA_PATH = "INPUT your CVEFixes /Data folder path"#"/Users/whilebug/Desktop/Projects/CVEfixes_repo/Data"

TRAJ_PATH = "INPUT the SWE-agent/trajectories/USER/ path"#"/Users/whilebug/Desktop/Projects/SWE-agent/trajectories/whilebug/"
TRAJ_PREFIX = "azure-gpt4__"
TRAJ_SUFFIX = "__default_from_url__t-0.00__p-0.95__c-3.00__install-1"
TRAJ_DICT = {
    "path":TRAJ_PATH,
    "prefix":TRAJ_PREFIX,
    "suffix":TRAJ_SUFFIX
}

# 0. Initialize database
conn=get_conn(DATA_PATH=DATA_PATH)
conn_searcher = ConnSearcher(conn=conn)
# 0. Initialize prompt generator
prompt_generator = PromptGenerator(conn_searcher=conn_searcher)
# 0. Initialize codebase manager
codebase_manager = codebaseManager()

def generate_fix(cves_folder_path):
    cve_repos = os.listdir(cves_folder_path)

    for cve_id in cve_repos:
        if "unit_test" in cve_id:
            continue
        for fix_level in [1, 2, 3]:
            cve_folder = CVEFolder(
                cve_id=cve_id,
                cve_home_path=cves_folder_path+"/"+cve_id
            )
            try:
                fix_cve(
                        cve_folder=cve_folder,
                        home_path=HOME_PATH,
                        fix_level=fix_level,
                        prompt_generator=prompt_generator,
                        traj_dict=TRAJ_DICT
                )
                print(cve_id, "fix_level:", fix_level, "fix generated")
            except:
                print(cve_id, "fix_level:", fix_level, "fix failed to generate")


generate_fix("cves/JavaScript")
generate_fix("cves/Java")
generate_fix("cves/Python")
generate_fix("cves/PHP")