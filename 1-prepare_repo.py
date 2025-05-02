from cve_bench.cve_database import CVEDatabase
from cve_bench.cve_repo import CVERepo
import ast
from cve_bench.unit_test_agent import main
import json
import os

cve_database = CVEDatabase()

def run_pipeline(cve_id):
    try:
        cve_info_dict = cve_database.get_commit_info(cve_id=cve_id)

        cve_id = cve_info_dict['cve_id']
        commit_hash = cve_info_dict['hash']
        repo_url = cve_info_dict['repo_url']
        if cve_info_dict['parents'] != None and cve_info_dict['parents'] != "":
            parent_commit_hash = ast.literal_eval(cve_info_dict['parents'])[0]
        else:
            parent_commit_hash = None
        repo_dir = "data/cve_repos/{cve_id}".format(cve_id=cve_id)

        file_change_records = cve_database.get_file_change_by_hash(
            hash = commit_hash
        )
        print(file_change_records)
        file_change_records = file_change_records[['filename', 'file_change_id', 'old_path', 'new_path', 'code_before', 'code_after', 'programming_language']]
        old_path = file_change_records.loc[0, "old_path"]
        code_before = file_change_records.loc[0, "code_before"]
        code_after = file_change_records.loc[0, "code_after"]

        cve_desc = cve_database.get_cve_desc(
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
    except:
        print("{cve_id} failed to init repository".format(cve_id=cve_id))

cve_id_map = json.load(open("cves/cve_list.json", "r"))
for cve_id in cve_id_map["Java"]+cve_id_map["Javascript"]+cve_id_map["PHP"]+cve_id_map["Python"]:
    if os.path.exists("cves/{cve_id}.json".format(cve_id=cve_id)):
        pass
    else:
        run_pipeline(cve_id)