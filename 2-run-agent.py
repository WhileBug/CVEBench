from cve_bench.repair_agent import RepairAgent
import ast
from cve_bench.cve_database import CVEDatabase
from cve_bench.cve_pipeline import CVEBenchPipeline
import json

# Example usage
if __name__ == '__main__':
    cve_database = CVEDatabase()
    cve_id_map = json.load(open("cves/cve_list.json", "r"))
    for cve_id in cve_id_map["Java"]+cve_id_map["Javascript"]+cve_id_map["PHP"]+cve_id_map["Python"]:
        cve_pipeline = CVEBenchPipeline(
            cve_database=cve_database,
            cve_id=cve_id
        )
        cve_info_dict = cve_pipeline.extract_info()
        for info_level in ["blackbox", "midbox", "whitebox"]:
            cve_pipeline.repair_cve(
                cve_info_dict=cve_info_dict, 
                info_level=info_level, 
                model_choice="openai", 
                model_name="gpt-4o-mini", 
                openai_api_key=None, 
                ollama_base_url=None, 
                tools_allowed=['ls','cat','git','bandit'], 
                patch_folder="cves", 
                patch_filename=cve_id+"-"+info_level
            )