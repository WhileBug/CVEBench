import os
import subprocess
import time
import json
from typing import List, Tuple, Optional, Dict, Any

# Abstract tool base class
class Tool:
    """
    Abstract base class for tools available within the security agent.
    """
    name: str

    def run(self, *args: str) -> str:
        """
        Execute the tool with provided arguments and return combined stdout and stderr.
        """
        raise NotImplementedError

# Concrete tool implementations
class LsTool(Tool):
    name = 'ls'
    def run(self, path: str, options: str = '') -> str:
        cmd = f"ls {options} {path}"
        result = subprocess.run(['docker', 'exec', self.container, 'bash', '-lc', cmd], capture_output=True, text=True)
        return result.stdout + result.stderr

class CatTool(Tool):
    name = 'cat'
    def run(self, filepath: str) -> str:
        cmd = f"cat {filepath}"
        result = subprocess.run(['docker', 'exec', self.container, 'bash', '-lc', cmd], capture_output=True, text=True)
        return result.stdout + result.stderr

class GitTool(Tool):
    name = 'git'
    def run(self, *args: str) -> str:
        cmd = ' '.join(['git'] + list(args))
        result = subprocess.run(['docker', 'exec', self.container, 'bash', '-lc', cmd], capture_output=True, text=True)
        return result.stdout + result.stderr

class BanditTool(Tool):
    name = 'bandit'
    def run(self, target: str) -> str:
        cmd = f"bandit -r {target} -f json --quiet"
        result = subprocess.run(['docker', 'exec', self.container, 'bash', '-lc', cmd], capture_output=True, text=True)
        return result.stdout + result.stderr

class PylintTool(Tool):
    name = 'pylint'
    def run(self, target: str) -> str:
        cmd = f"pylint {target} --exit-zero --output-format=text"
        result = subprocess.run(['docker', 'exec', self.container, 'bash', '-lc', cmd], capture_output=True, text=True)
        return result.stdout + result.stderr

class MypyTool(Tool):
    name = 'mypy'
    def run(self, target: str) -> str:
        cmd = f"mypy {target} --ignore-missing-imports"
        result = subprocess.run(['docker', 'exec', self.container, 'bash', '-lc', cmd], capture_output=True, text=True)
        return result.stdout + result.stderr

class ProspectorTool(Tool):
    name = 'prospector'
    def run(self, target: str) -> str:
        cmd = f"prospector {target} --output-format=json"
        result = subprocess.run(['docker', 'exec', self.container, 'bash', '-lc', cmd], capture_output=True, text=True)
        return result.stdout + result.stderr

# Main agent class
class RepairAgent:
    """
    A ReAct-based agent for automated vulnerability patching inside a Docker container.

    Attributes:
        vuln_path (str): Absolute host path to the vulnerable code directory.
        info_level (str): One of 'blackbox', 'midbox', 'whitebox'.
        info_content (str): Detailed input corresponding to info_level.
        tools_allowed (List[str]): Keys of allowed tools.
        model_choice (str): 'openai' or 'ollama'.
        openai_api_key, ollama_base_url, ollama_model: optional config.
        container (str): Docker container name.
        tool_instances (Dict[str, Tool]): Instantiated tool objects.
    """

    PROMPT_TEMPLATE = (
        "You are a security-fix agent running within a Docker container.\n"
        "Your mission is to locate and fix a software vulnerability by iteratively executing only the allowed tools.\n"
        "Follow the ReACT paradigm: generate your reasoning in <THOUGHT> tags and your commands in <ACTION> tags.\n"
        "Strictly enforce the following format for every LLM response (without deviation):\n"
        "^<THOUGHT>[\s\S]*?</THOUGHT>\\s*<ACTION>[\s\S]*?</ACTION>(?:\\s*<DONE/>)?$\n"
        "If the format is incorrect, reply: 'Output format incorrect, please follow the specified format.' and then emit only the tags.\n"
        "Only these tools are available (arguments must match examples):\n"
        "  - ls: list files. Example: <ACTION>ls -la /workspace/vuln</ACTION>\n"
        "  - cat: show file. Example: <ACTION>cat /workspace/vuln/src/app.c</ACTION>\n"
        "  - git: version control. Examples: <ACTION>git status</ACTION>, <ACTION>git diff</ACTION>, <ACTION>git apply /patch.patch</ACTION>\n"
        "  - bandit: Python security scan. Example: <ACTION>bandit -r /workspace/vuln -f json --quiet</ACTION>\n"
        "  - pylint: Python code analysis. Example: <ACTION>pylint /workspace/vuln --exit-zero --output-format=text</ACTION>\n"
        "  - mypy: Python type check. Example: <ACTION>mypy /workspace/vuln --ignore-missing-imports</ACTION>\n"
        "  - prospector: Meta-linter. Example: <ACTION>prospector /workspace/vuln --output-format=json</ACTION>\n"
        "<INPUT>\n"
        "vuln_path: {vuln_path}\n"
        "info_level: {info_level}\n"
        "info_content: {info_content}\n"
        "tools_allowed: {tools_allowed}\n"
        "</INPUT>\n"
        "<GOAL>\n"
        "Based on info_level and provided info_content, locate the vulnerable code segments, apply the minimal patch via git commands, and validate the fix.\n"
        "</GOAL>\n"
        "<FORMAT>\n"
        "Each cycle: one <THOUGHT> with reasoning, one <ACTION> with the command(s) to run.\n"
        "After executing <ACTION>, await the output before next thought.\n"
        "When the vulnerability is fixed and tests pass, append <DONE/> immediately after the final <ACTION>.\n"
        "</FORMAT>"
    )

    def __init__(
        self,
        vuln_path: str,
        info_level: str,
        info_content: str,
        tools_allowed: List[str],
        model_choice: str = 'openai',
        openai_api_key: Optional[str] = None,
        ollama_base_url: Optional[str] = None,
        ollama_model: Optional[str] = None,
    ):
        self.vuln_path = vuln_path
        self.info_level = info_level
        self.info_content = info_content
        self.tools_allowed = tools_allowed
        self.model_choice = model_choice
        self.openai_api_key = openai_api_key
        self.ollama_base_url = ollama_base_url
        self.ollama_model = ollama_model
        self.container = f"agent_env_{int(time.time())}"
        # instantiate allowed tools
        self.tool_instances: Dict[str, Tool] = {}
        for key in tools_allowed:
            if key == 'ls': self.tool_instances['ls'] = LsTool()
            if key == 'cat': self.tool_instances['cat'] = CatTool()
            if key == 'git': self.tool_instances['git'] = GitTool()
            if key == 'bandit': self.tool_instances['bandit'] = BanditTool()
            if key == 'pylint': self.tool_instances['pylint'] = PylintTool()
            if key == 'mypy': self.tool_instances['mypy'] = MypyTool()
            if key == 'prospector': self.tool_instances['prospector'] = ProspectorTool()
        # bind container to each tool
        for t in self.tool_instances.values(): setattr(t, 'container', self.container)
        # init model client
        if model_choice == 'openai':
            import openai
            openai.api_key = openai_api_key
            self.client = openai.ChatCompletion
        elif model_choice == 'ollama':
            from ollama import Ollama
            self.client = Ollama(base_url=ollama_base_url)
        else:
            raise ValueError("model_choice must be 'openai' or 'ollama'")

    def _build_prompt(self) -> str:
        return self.PROMPT_TEMPLATE.format(
            vuln_path=self.vuln_path,
            info_level=self.info_level,
            info_content=self.info_content,
            tools_allowed=json.dumps(self.tools_allowed)
        )

    def call_model(self, messages: List[dict]) -> dict:
        if self.model_choice == 'openai':
            resp = self.client.create(model='gpt-4o-mini', messages=messages)
            return resp.choices[0].message
        else:
            prompt = "".join([m['content'] for m in messages])
            out = self.client.generate(model=self.ollama_model, prompt=prompt)
            return {'role': 'assistant', 'content': out['choices'][0]['message']}

    def parse_response(self, content: str) -> Tuple[str, str, bool]:
        thought, action, done = '', '', False
        if '<THOUGHT>' in content and '</THOUGHT>' in content:
            thought = content.split('<THOUGHT>')[1].split('</THOUGHT>')[0].strip()
        if '<ACTION>' in content and '</ACTION>' in content:
            action = content.split('<ACTION>')[1].split('</ACTION>')[0].strip()
        if '<DONE/>' in content: done = True
        return thought, action, done

    def setup_environment(self):
        subprocess.run(['docker','run','-dit','--name',self.container,'python:3.11-slim'], check=True)
        cmds=['apt-get update && apt-get install -y git']
        for key in self.tools_allowed:
            if key in ['bandit','pylint','mypy','prospector']: cmds.append(f'pip install {key}')
        for c in cmds: subprocess.run(['docker','exec',self.container,'bash','-lc',c], check=True)
        subprocess.run(['docker','cp',self.vuln_path,f'{self.container}:/workspace/vuln'], check=True)

    def run_tool(self, action: str) -> str:
        parts=action.split(); tool_key=parts[0]; args=parts[1:]
        if tool_key not in self.tool_instances:
            return f"Error: tool '{tool_key}' not allowed."
        return self.tool_instances[tool_key].run(*args)

    def run_react_loop(self):
        system={'role':'system','content':self._build_prompt()}
        messages=[system]
        while True:
            resp=self.call_model(messages)
            content=resp['content']; thought,action,done=self.parse_response(content)
            messages.append({'role':'assistant','content':content})
            if not thought or not action:
                messages.append({'role':'assistant','content':'Output format incorrect, please follow the specified format.'})
                continue
            print(f'[THOUGHT] {thought}')
            print(f'[ACTION] {action}')
            obs=self.run_tool(action)
            print(f'[OBSERVATION] {obs}')
            messages.append({'role':'user','content':obs})
            if done: break

    def extract_patch(self, patch_name: str, host_dest: str):
        self.run_tool('git add .')
        self.run_tool('git commit -m agent_patch')
        path=f'/workspace/{patch_name}.patch'
        self.run_tool(f'git format-patch -1 HEAD --stdout > {path}')
        subprocess.run(['docker','cp',f'{self.container}:{path}',os.path.join(host_dest,f'{patch_name}.patch')], check=True)

    def cleanup(self):
        subprocess.run(['docker','rm','-f',self.container], check=True)