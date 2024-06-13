import pandas as pd
from lib.commit import commit
from lib.fix import fix
from lib.gpt_agent import GPT3Client
import configparser

class fix_judger:
    def __init__(
            self,
            gpt_config_filename="config.ini",
            prompt_config_filename="prompts.ini"
    ):
        self.gpt_config_filename = gpt_config_filename
        self.gpt_agent = GPT3Client(config_filename=gpt_config_filename)

        self.prompt_config_filename=prompt_config_filename
        self.judge_prompt = self.load_prompt()

        self.fix = None
        self.commit = None

    def load_prompt(self):
        config = configparser.ConfigParser()  # 读取配置文件
        config.read(self.prompt_config_filename)  # 获取特定的配置信息
        judge_prompt = config.get('DEFAULT', 'judge_prompt')
        return judge_prompt

    def load_fix_and_commit(
            self,
            fix:fix,
            commit:commit
    ):
        self.fix=fix
        self.commit=commit

    def judge_gpt_by_filename(
            self,
            filename
    ):
        commit_row = self.commit.file_changes[self.commit.file_changes["filename"] == filename]
        fix_row = self.fix.file_changes[self.fix.file_changes["filename"] == filename]

        original_code = commit_row["code_before"][0]
        fix_code_1 = commit_row["code_after"][0]
        fix_code_2 = fix_row["code_after"][0]
        prompt = self.judge_prompt.format(
            original_code=original_code,
            fix_code_1=fix_code_1,
            fix_code_2=fix_code_2
        )
        system_prompt = "You are a agent for software engineering." \
                        "Now I will give you "
        messages= {}
        response=self.gpt_agent.generate_text(
            prompt=prompt
        )
        return self.judge_gpt_response(response=response)

    def judge_gpt_response(self, response:str):
        if "True" in response:
            return True
        else:
            return False

    def judge_asr_by_filename(self, filename):
        pass

    def judge_gpt(self):
        true_count = 0
        false_count = 0
        for filename in self.fix.file_changes["filename"]:
            judge_response = self.judge_gpt_by_filename(filename=filename)
            if judge_response:
                true_count +=1
            else:
                false_count += 1
        return true_count/(true_count+false_count)