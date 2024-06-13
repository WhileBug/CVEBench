import pandas as pd
from lib.cve_database import get_conn, ConnSearcher
from lib.codebase_manager import codebaseManager

class PromptGenerator:
    def __init__(
            self,
            conn_searcher:ConnSearcher
    ):
        self.conn_searcher=conn_searcher

    def prompt_load(
            self,
            prompt_path
    ):
        with open(prompt_path, "r") as f:
            prompt=f.read()
        return prompt

    def fix_issue_prompt_generate(
        self,
        cve_id,
        fix_level=1,
        fix_tool:str=None
    ):
        cve_description = self.conn_searcher.get_cve_desc(cve_id=cve_id)
        cve_changes_df = self.conn_searcher.get_changes(cve_id=cve_id)
        cve_file_changes_desc = ""
        cve_method_changes_desc = ""
        for cve_change_item in cve_changes_df.itertuples():
            change_old_path = getattr(cve_change_item, "old_path")
            change_method = getattr(cve_change_item, "name")
            cve_file_changes_desc += change_old_path+";"
            cve_method_changes_desc += change_old_path+":"+change_method+"();"
        if fix_level==1:
            prompt = '''
            Now there is a CVE in this repo:{cve_description}.
            Please try to fix the CVE.
            '''.format(cve_description=cve_description)
        elif fix_level==2:
            prompt = f'''
            Now there is a CVE in this repo:{cve_description}.
            Now the following scripts is the cause for the CVE:{cve_file_changes_desc}
            '''.format(cve_description=cve_description, cve_file_changes_desc=cve_file_changes_desc)
        elif fix_level==3:
            prompt = f'''
            Now there is a CVE in this repo:{cve_description}.
            Now the following functions is the cause for the CVE:{cve_method_changes_desc}
            '''.format(cve_description=cve_description, cve_method_changes_desc=cve_method_changes_desc)
        else:
            raise Exception

        tool_prompt = ""
        if fix_tool is None:
            tool_prompt = ""
        elif fix_tool == "prospector":
            tool_prompt = "You need to implement the static analysis tool: prospector to assist your fix process." \
                          "You can run ``pip install prospector'' to install the tool first." \
                          "And then you must use the tool during your fix process"
        elif fix_tool == "bandit":
            tool_prompt = "You need to implement the static analysis tool: bandit to assist your fix process." \
                          "You can run ``pip install bandit'' to install the tool first." \
                          "And then you must use the tool during your fix process"
        elif fix_tool == "pylint":
            tool_prompt = "You need to implement the static analysis tool: pylint to assist your fix process." \
                          "You can run ``pip install pylint'' to install the tool first." \
                          "And then you must use the tool during your fix process"
        elif fix_tool == "mypy":
            tool_prompt = "You need to implement the static analysis tool: mypy to assist your fix process." \
                          "You can run ``pip install mypy'' to install the tool first." \
                          "And then you must use the tool during your fix process"
        else:
            tool_prompt = ""

        return prompt