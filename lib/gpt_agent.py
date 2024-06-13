import os
from openai import AzureOpenAI
import configparser
import copy

class GPT3Client:
    def __init__(self, config_filename):

        self.config_filename = config_filename
        self.api_key, self.end_point, self.proxy, self.engine = self.load_config()

        #openai.api_type = "azure"
        #openai.api_base = self.end_point
        #openai.api_key = self.api_key
        #openai.api_version = "2024-02-01"

        os.environ["HTTP_PROXY"] = self.proxy
        os.environ["HTTPS_PROXY"] = self.proxy

        self.client = AzureOpenAI(
            azure_endpoint=self.end_point,
            api_key=self.api_key,
            api_version="2024-02-01"
        )

    def load_config(self):
        config = configparser.ConfigParser()  # 读取配置文件
        config.read(self.config_filename)  # 获取特定的配置信息
        api_key = config.get('DEFAULT', 'api_key')
        end_point = config.get('DEFAULT', 'end_point')
        proxy = config.get('DEFAULT', 'proxy')
        engine = config.get('DEFAULT', 'engine')
        return api_key, end_point, proxy, engine
    def generate_text(self, messages:[dict]):
        response = self.client.completions.create(
            model=self.engine,
            prompt=messages
        )
        generated_text = response.choices[0].message.content
        return generated_text

    def generate_messages(
            self,
            system_prompt: str = None,
            previous_messages: [dict]=None,
            input_prompt: str=None
    ):
        if previous_messages is None:
            if system_prompt is None:
                return [
                    {"role": "user", "content": input_prompt}
                ]
            else:
                return [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": input_prompt}
                ]
        else:
            current_messages = copy.deepcopy(previous_messages)