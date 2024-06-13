from lib.utils import clone_repo, unit_test_generate, fix_cve
from lib.validate_utils import validate_fix

from lib.cve_database import ConnSearcher
from lib.codebase_manager import codebaseManager
from lib.prompt_generator import PromptGenerator

def run_whole_pipeline(
        cve_id,
        conn_searcher:ConnSearcher,
        codebase_manager:codebaseManager,
        prompt_generator:PromptGenerator,
        home_path,
        traj_dict,
        fix_level=3,
        python_version="2.7"
):
    clone_repo(
            cve_id=cve_id,
            conn_searcher=conn_searcher,
            codebase_manager=codebase_manager
    )


    fix_cve(
        cve_id=cve_id,
        home_path=home_path,
        fix_level=fix_level,
        prompt_generator=prompt_generator,
        traj_dict=traj_dict
    )

    validate_fix(
        cve_id=cve_id,
        repo_path=home_path+"/test_repos/"+cve_id,
        fix_repo_path=home_path+"/test_repos/"+cve_id+"-fix-3",
        unit_test_repo_path=home_path+"/test_repos/"+cve_id+"-unit_test",
        python_version=python_version
    )