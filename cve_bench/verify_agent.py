import os, json, re, shlex, subprocess
from typing import Any, Dict, List, Optional

# —— 1. TerminalTool: expose arbitrary shell commands to the LLM —— #
from langchain_core.tools import tool  # LangChain @tool decorator :contentReference[oaicite:8]{index=8}

@tool("run")
def run_cmd(cmd: str, cwd: Optional[str] = None, timeout: int = 300) -> Dict[str, Any]:
    """
    Executes `cmd` in shell or list form.
    Args:
      cmd: Command string or JSON-encoded list of strings.
      cwd: Working directory.
      timeout: Seconds before killing the process.
    Returns:
      { "stdout": str, "stderr": str, "exit_code": int }
    """
    if cmd.startswith("[") or cmd.startswith("\""):
        cmd_list = json.loads(cmd)
    else:
        cmd_list = shlex.split(cmd)
    result = subprocess.run(
        cmd_list, cwd=cwd, capture_output=True, text=True, timeout=timeout
    )
    return {
        "stdout": result.stdout,
        "stderr": result.stderr,
        "exit_code": result.returncode
    }

# —— 2. Language-specific TestTools —— #
@tool("junit_test")
def junit_test(repo_dir: str, test_path: str, code: str, script: str) -> Dict[str, Any]:
    """
    Writes Java test to `repo_dir/test_path`, then runs Maven script.
    """
    full_path = os.path.join(repo_dir, test_path)
    os.makedirs(os.path.dirname(full_path), exist_ok=True)
    with open(full_path, "w") as f:
        f.write(code)
    return run_cmd(f"docker exec verify_env bash -lc \"cd {repo_dir} && {script}\"")

@tool("jest_test")
def jest_test(repo_dir: str, test_path: str, code: str, script: str) -> Dict[str, Any]:
    """
    Writes JS test to `repo_dir/test_path`, then runs npm script.
    """
    full_path = os.path.join(repo_dir, test_path)
    os.makedirs(os.path.dirname(full_path), exist_ok=True)
    with open(full_path, "w") as f:
        f.write(code)
    return run_cmd(f"docker exec verify_env bash -lc \"cd {repo_dir} && {script}\"")

@tool("phpunit_test")
def phpunit_test(repo_dir: str, test_path: str, code: str, script: str) -> Dict[str, Any]:
    """
    Writes PHP test to `repo_dir/test_path`, then runs PHPUnit.
    """
    full_path = os.path.join(repo_dir, test_path)
    os.makedirs(os.path.dirname(full_path), exist_ok=True)
    with open(full_path, "w") as f:
        f.write(code)
    return run_cmd(f"docker exec verify_env bash -lc \"cd {repo_dir} && {script}\"")

@tool("pytest_test")
def pytest_test(repo_dir: str, test_path: str, code: str, script: str) -> Dict[str, Any]:
    """
    Writes Python test to `repo_dir/test_path`, then runs pytest.
    """
    full_path = os.path.join(repo_dir, test_path)
    os.makedirs(os.path.dirname(full_path), exist_ok=True)
    with open(full_path, "w") as f:
        f.write(code)
    return run_cmd(f"docker exec verify_env bash -lc \"cd {repo_dir} && {script}\"")

# —— 3. LLMBasedVerifyAgent —— #
class VerifyAgent:
    """
    LLM-based agent using ReAct:
    1. Builds Docker image and starts container.
    2. Applies local .patch.
    3. Writes and runs unit tests in Java/JS/PHP/Python.
    """
    ACTION_RE = re.compile(r"<THOUGHT>(.*?)</THOUGHT>\s*<ACTION>(.*?)</ACTION>", re.S)

    def __init__(
        self,
        backend: str,
        model_name: str,
        openai_api_key: Optional[str] = None
    ):
        self.backend = backend.lower()
        self.model = model_name
        if self.backend == "openai":
            import openai
            openai.api_key = openai_api_key
            self.client = openai.ChatCompletion
        else:
            import ollama
            self.client = ollama

    def _call_llm(self, prompt: str) -> str:
        if self.backend == "openai":
            resp = self.client.create(model=self.model, messages=[{"role":"system","content":prompt}])
            return resp.choices[0].message.content
        else:
            resp = self.client.chat(model=self.model, messages=[{"role":"user","content":prompt}])
            return resp['choices'][0]['message']['content']

    def _parse(self, text: str):
        m = self.ACTION_RE.search(text)
        if not m:
            raise RuntimeError("Invalid ReAct format")
        return m.group(1).strip(), m.group(2).strip()

    def verify(self, patch_path: str, repo_path: str, unit: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Drives the ReAct loop:
        - Input placeholders: {patch_path}, {repo_path}, {unit_test_path}, {unit_test}, {shell_script}
        - Tools available: run, junit_test, jest_test, phpunit_test, pytest_test
        """
        prompt = f"""
You are a CVE Verify Agent using ReAct. Available tools:
1. run(cmd: str, cwd?: str, timeout?: int)
2. junit_test(repo_dir: str, test_path: str, code: str, script: str)
3. jest_test(repo_dir: str, test_path: str, code: str, script: str)
4. phpunit_test(repo_dir: str, test_path: str, code: str, script: str)
5. pytest_test(repo_dir: str, test_path: str, code: str, script: str)

Inputs:
- patch_path = "{patch_path}"
- repo_path = "{repo_path}"
- unit_test = {json.dumps(unit)}

Format Rules:
Every response MUST exactly match:
<THOUGHT>...reasoning...</THOUGHT>
<ACTION>tool_name(arg1=..., arg2=..., ...)</ACTION>
If output deviates, retry.

Begin:
<THOUGHT>Build Docker image with repo and patch</THOUGHT>
<ACTION>run("docker build -t verify_image -f - .", cwd="{repo_path}", timeout=600)</ACTION>
<THOUGHT>Start container named verify_env</THOUGHT>
<ACTION>run("docker run -d --name verify_env verify_image tail -f /dev/null")</ACTION>
"""
        history = []
        for _ in range(15):
            resp = self._call_llm(prompt)  # invoke LLM :contentReference[oaicite:9]{index=9}
            thought, action = self._parse(resp)
            result = self._execute_action(action)
            history.append({"thought": thought, "action": action, "result": result})
            prompt += f"\n{resp}\n<OBSERVATION>{result}</OBSERVATION>"
            if "Complete" in thought:
                break
        return history

    def _execute_action(self, action: str) -> Any:
        # Dispatch to the right tool by parsing action string
        name, args = action.split("(", 1)
        args = args.rstrip(")")
        # Safely evaluate args as Python kwargs
        kwargs = eval(f"dict({args})")
        return globals()[name](**kwargs)
