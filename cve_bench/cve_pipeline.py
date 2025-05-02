from cve_bench.cve_database import CVEDatabase
from cve_bench.cve_repo import CVERepo
from cve_bench.repair_agent import RepairAgent
import ast
import json

class CVEBenchPipeline:
    def __init__(self, cve_database:CVEDatabase, cve_id:str):
        self.cve_database = cve_database
        self.cve_id = cve_id

    def repair_cve(self, cve_info_dict:dict, info_level, model_choice="openai", model_name="gpt-4o-mini", openai_api_key=None, ollama_base_url=None, tools_allowed=['ls','cat','git','bandit'], patch_folder:str=None, patch_filename:str=None):
        cve_desc = cve_info_dict['cve_desc']
        code_path = cve_info_dict["old_path"]
        code_content = cve_info_dict["code_before"]
        if info_level=="blackbox":
            info_content = "cve description:{cve_desc}".format(cve_desc=cve_desc)
        elif info_level=="midbox":
            info_content = "cve description:{cve_desc}, code path:{code_path}".format(cve_desc=cve_desc, code_path=code_path)
        elif info_level=="whitebox":
            info_content = "cve description:{cve_desc}, code path:{code_path}, code_content:{code_content}".format(cve_desc=cve_desc, code_path=code_path, code_content=code_content)
        agent=RepairAgent(
            vuln_path=cve_info_dict['old_path'],
            info_level=info_level,
            info_content=info_content,
            tools_allowed=tools_allowed,
            model_choice=model_choice,
            model_name=model_name,
            openai_api_key=openai_api_key,
            ollama_base_url=ollama_base_url
        )
        agent.setup_environment()
        agent.run_react_loop()
        agent.extract_patch(patch_filename,patch_folder)
        agent.cleanup()

    def extract_info(self):
        try:
            cve_info_dict = self.cve_database.get_commit_info(cve_id=self.cve_id)

            cve_id = cve_info_dict['cve_id']
            commit_hash = cve_info_dict['hash']
            repo_url = cve_info_dict['repo_url']
            if cve_info_dict['parents'] != None and cve_info_dict['parents'] != "":
                parent_commit_hash = ast.literal_eval(cve_info_dict['parents'])[0]
            else:
                parent_commit_hash = None
            repo_dir = "data/cve_repos/{cve_id}".format(cve_id=cve_id)

            file_change_records = self.cve_database.get_file_change_by_hash(
                hash = commit_hash
            )
            file_change_records = file_change_records[['filename', 'file_change_id', 'old_path', 'new_path', 'code_before', 'code_after', 'programming_language']]
            old_path = file_change_records.loc[0, "old_path"]
            code_before = file_change_records.loc[0, "code_before"]
            code_after = file_change_records.loc[0, "code_after"]

            cve_desc = self.cve_database.get_cve_desc(
                cve_id=cve_id
            )

            cve_repo = CVERepo(
                cve_id=cve_id,
                repo_url = repo_url,
                commit_hash=commit_hash,
                repo_dir=repo_dir,
                old_path=old_path,
                code_before=code_before,
                code_after=code_after,
                parent_commit_hash=parent_commit_hash
            )
            cve_repo.clone_and_checkout_previous_commit()
            return {
                "cve_id": cve_id,
                "commit_hash": commit_hash,
                "repo_url": repo_url,
                "parent_commit_hash": parent_commit_hash,
                "old_path": old_path,
                "code_before": code_before,
                "code_after": code_after
            }
        except:
            print("{cve_id} failed to init repository".format(cve_id=cve_id))
            return None