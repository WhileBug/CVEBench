from lib.cve_database import get_conn, ConnSearcher
from lib.codebase_manager import codebaseManager
from lib.prompt_generator import PromptGenerator
import os
from lib.pipeline import run_whole_pipeline
from lib.utils import clone_repo, unit_test_generate, fix_cve
from lib.validate_utils import validate_fix
import json

#SCRIPT_PATH = os.path.realpath(__file__)
HOME_PATH = os.path.abspath('.')
CVE_ID = "CVE-2015-8213"
DATA_PATH = "/Users/whilebug/Desktop/Projects/CVEfixes_repo/Data"

TRAJ_PATH = "/Users/whilebug/Desktop/Projects/SWE-agent/trajectories/whilebug/"
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

def repo_clone(cve_id_list, folder_path="cves/Python"):
    if os.path.exists(folder_path):
        pass
    else:
        os.mkdir(folder_path)
    for cve_id in cve_id_list:
        if cve_id not in os.listdir(folder_path):
            print(cve_id)
            try:
                clone_repo(
                    cve_id=cve_id,
                    conn_searcher=conn_searcher,
                    codebase_manager=codebase_manager,
                    folder_path=folder_path
                )
                print(cve_id, "cloned")
            except Exception as e:
                print(cve_id, "failed", e)
        else:
            pass

with open("cves/cve-list-Python-5000.json", "r")as f:
    cve_id_list = json.load(f)
    repo_clone(cve_id_list, folder_path="cves/Python")

with open("cves/cve-list-Java-5000.json", "r")as f:
    cve_id_list = json.load(f)
    repo_clone(cve_id_list, folder_path="cves/Java")

with open("cves/cve-list-JavaScript-10000.json", "r")as f:
    cve_id_list = json.load(f)
    repo_clone(cve_id_list, folder_path="cves/JavaScript")

with open("cves/cve-list-PHP-10000.json", "r")as f:
    cve_id_list = json.load(f)
    repo_clone(cve_id_list, folder_path="cves/PHP")