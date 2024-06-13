# CVE-Bench: Benchmarking LLM-based Software Engineering Agent’s Ability to Repair Real-World CVE Vulnerabilities

## Introduction

Automated vulnerability repair is a crucial field within software engineering and security research. Large Language Models (LLMs) and LLM agents have demonstrated significant potential in this domain by understanding descriptions in natural language and generating corresponding formal code. Although the coding capabilities of LLMs have advanced rapidly, evaluation benchmarks for real-world programming setups are still lagging, preventing the development of LLM and LLM agents in real-world vulnerability repair. To this end, we introduce CVE-bench, an evaluation framework consisting of 509 Common Vulnerabilities and Exposures (CVEs) from four programming languages and 120 popular open-source repositories. Unlike previous vulnerability repair benchmarks, which only involve the code input and output, we provide LLM agents with a test environment that simulates the real-world vulnerability repair process. This environment provides multiple levels of CVE information modeling, such as black-box testing and white-box testing. It enables the agents to use static analysis tools to assist their repair process. Our evaluation reveals that the SWE-agent can only repair 21% of vulnerabilities at its best. Furthermore, they lack expert knowledge about how to use the analysis tool to assist in vulnerability repair.

## Usage

### Initialize

- Please first follow [CVEFixes](https://github.com/secureIT-project/CVEfixes)'s setup process to set up a CVEFixed Database first.
- Then clone our repo use the git clone command
- Run ``pip install -r requirements.txt``
- Run ``python 1-repo_clone.py``
- Run ``python 2-fix.py``

### Fix 

### Validate

## Still in update...