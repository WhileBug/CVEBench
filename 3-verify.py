from cve_bench.repair_agent import RepairAgent
import ast
from cve_bench.cve_database import CVEDatabase
from cve_bench.cve_pipeline import CVEBenchPipeline
import json
from cve_bench.verify_agent import VerifyAgent
# Example usage
if __name__ == '__main__':
    cve_database = CVEDatabase()
    verify_agent = VerifyAgent(backend="ollama", model_name="qwen2.5-coder")
    cve_id_map = json.load(open("cves/cve_list.json", "r"))
    for cve_id in cve_id_map["Java"]+cve_id_map["Javascript"]+cve_id_map["PHP"]+cve_id_map["Python"]:
        cve_pipeline = CVEBenchPipeline(
            cve_database=cve_database,
            cve_id=cve_id
        )
        for info_level in ["blackbox", "midbox", "whitebox"]:
            patch_path = "cves/" + cve_id+"-"+info_level + ".patch"
            cve_repo_path = "data/cve_repos/{cve_id}".format(cve_id=cve_id)
            unit_test_dict = json.load(open("cves/{cve_id}.json".format(cve_id=cve_id), "r"))
            verify_agent.verify(patch_path, cve_repo_path, unit_test_dict)