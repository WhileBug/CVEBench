from lib.cve_database import get_conn, ConnSearcher
from lib.codebase_manager import codebaseManager
from lib.prompt_generator import PromptGenerator
import os
from lib.pipeline import run_whole_pipeline
import json

SCRIPT_PATH = os.path.realpath(__file__)
HOME_PATH = os.path.dirname(SCRIPT_PATH)
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

'''
run_whole_pipeline(
    cve_id=CVE_ID,
    conn_searcher=conn_searcher,
    codebase_manager=codebase_manager,
    prompt_generator=prompt_generator,
    home_path=HOME_PATH,
    traj_dict=TRAJ_DICT,
    fix_level=3,
    python_version="2.7"
)
'''