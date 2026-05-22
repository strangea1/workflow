import argparse
import json
import logging
import os
import re
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

import pandas as pd
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from generate_vfind_tasks import generate_tasks
from nvd_api import fetch_and_save_cve_list
from run_codewiki_pipline import clone_repo, prepare_and_run_codewiki

WORKSPACE_ROOT = Path(__file__).resolve().parent
EVAL_DIR = WORKSPACE_ROOT / "eval"
if str(EVAL_DIR) not in sys.path:
    sys.path.insert(0, str(EVAL_DIR))

from main import build_risk_payload, run_component_summarizer, run_module_locator, run_risk_assessment


logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
LOGGER = logging.getLogger(__name__)

REQUEST_TIMEOUT = 60
RAW_BASE = "https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}"
TAGS_API = "https://api.github.com/repos/{owner}/{repo}/tags"
HEADERS = {
    "Accept": "application/vnd.github+json, text/plain",
    "User-Agent": "component-version-cve-workflow",
}
MAVEN_NAMESPACE = "http://maven.apache.org/POM/4.0.0"
DEFAULT_OUTPUT = "result.xlsx"
DEFAULT_TOP_N_TAGS = 10
SLEEP_BETWEEN_REQUESTS = 0.2
TREE_API = "https://api.github.com/repos/{owner}/{repo}/git/trees/{ref}?recursive=1"
DEFAULT_DEBUG_DIR = "debug_output"
DEFAULT_NVD_OUTPUT_DIR = "workflow_output/nvd"
DEFAULT_EVAL_OUTPUT_DIR = "workflow_output/eval_runs"
RETRY_STATUS_CODES = [429, 500, 502, 503, 504]
BACKOFF_FACTOR = 1
RETRY_TOTAL = 5
GITHUB_RAW_CACHE_DIR = WORKSPACE_ROOT / "workflow_cache" / "github_raw"
GITHUB_RAW_CACHE_DIR.mkdir(parents=True, exist_ok=True)
SESSION = requests.Session()
SESSION.mount(
    "https://",
    HTTPAdapter(
        max_retries=Retry(
            total=RETRY_TOTAL,
            backoff_factor=BACKOFF_FACTOR,
            status_forcelist=RETRY_STATUS_CODES,
            allowed_methods=frozenset(["GET"]),
        )
    ),
)

# CISA KEV 目录缓存（None = 未加载，set() = 加载失败或空）
_KEV_CATALOG: Optional[Set[str]] = None


PYTHON_TARGET_COMPONENTS = [
    "urllib3",
    "transformers",
    "pandas",
    "langchain",
    "torch",
    "tensorflow",
    "PyYAML",
    "scikit-learn",
    "numpy",
    "scipy",
    "joblib",
    "pickle",
    "fastapi",
    "mlflow",
    "opencv-python",
    "Pillow",
]

JAVA_TARGET_COMPONENTS: Dict[str, List[Tuple[str, str]]] = {
    "Spring Framework": [("org.springframework", "spring-core")],
    "Spring Boot": [("org.springframework.boot", "spring-boot")],
    "jackson": [("com.fasterxml.jackson.core", "jackson-databind")],
    "Apache Tomcat": [("org.apache.tomcat", "tomcat-embed-core")],
    "Apache Kafka": [("org.apache.kafka", "kafka-clients")],
    "log4j": [("org.apache.logging.log4j", "log4j-core")],
    "XStream": [("com.thoughtworks.xstream", "xstream")],
    "Apache ActiveMQ": [("org.apache.activemq", "activemq-client")],
    "Netty": [("io.netty", "netty-all")],
    "fastjson2": [("com.alibaba.fastjson2", "fastjson2")],
    "Apache Solr": [("org.apache.solr", "solr-core")],
    "Apache Struts2": [("org.apache.struts", "struts2-core")],
    "Apache FileUpload": [("commons-fileupload", "commons-fileupload")],
    "Apache Shiro": [("org.apache.shiro", "shiro-core")],
    "Dom4j": [("org.dom4j", "dom4j")],
    "Apache Commons IO": [("commons-io", "commons-io")],
    "myBatis": [("org.mybatis", "mybatis")],
    "Apache Commons Text": [("org.apache.commons", "commons-text")],
    "Apache XMLBeans": [("org.apache.xmlbeans", "xmlbeans")],
    "Apache Commons BeanUtils": [("commons-beanutils", "commons-beanutils")],
    "Apache Commons Collections": [("org.apache.commons", "commons-collections4")],
    "Logback": [("ch.qos.logback", "logback-classic")],
    "Groovy": [("org.apache.groovy", "groovy")],
    "Jetty": [("org.eclipse.jetty", "jetty-server")],
}

COMPONENT_DESCRIPTION_ALIASES: Dict[str, Tuple[str, ...]] = {
    "jackson": ("jackson", "jackson-core", "jackson-databind", "jackson-dataformats"),
    "torch": ("torch", "pytorch"),
    "groovy": ("groovy",),
    "apachegroovy": ("groovy",),
    "log4j": ("log4j",),
    "apachelog4j": ("log4j",),
    "apacheshiro": ("shiro",),
    "shiro": ("shiro",),
    "apachetomcat": ("tomcat",),
    "tomcat": ("tomcat",),
    "springboot": ("spring boot", "spring-boot"),
    "apachecommonsbeanutils": ("commons-beanutils", "beanutils"),
    "jetty": ("jetty",),
    "logback": ("logback",),
}

# 描述首句中必须出现这些关键词，才认为 CVE 的漏洞主体是该组件（而非使用了该组件的上层应用）
# 若某组件名不在此表，则不做主体过滤
COMPONENT_SUBJECT_KEYWORDS: Dict[str, Tuple[str, ...]] = {
    "groovy": ("groovy",),
    "apachegroovy": ("groovy",),
    "log4j": ("log4j",),
    "apachelog4j": ("log4j",),
}

PYTHON_CANDIDATE_FILES = [
    "pyproject.toml",
    "requirements.txt",
    "requirements/base.txt",
    "requirements/dev.txt",
    "requirements/all.txt",
    "setup.cfg",
    "setup.py",
    "environment.yml",
]

JAVA_CANDIDATE_FILES = ["pom.xml", "build.gradle", "build.gradle.kts", "gradle.properties"]

PYTHON_FILE_PATTERNS = (
    "requirements",
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "environment.yml",
    "environment.yaml",
    "pdm.lock",
    "poetry.lock",
    "Pipfile",
    "Pipfile.lock",
    "tox.ini",
)

JAVA_FILE_PATTERNS = (
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "settings.gradle",
    "settings.gradle.kts",
    "gradle.properties",
    "build.xml",
    "ivy.xml",
    "mvnw",
    "gradlew",
)

REQ_LINE_REGEXES = [
    re.compile(r"^(?P<pkg>[A-Za-z0-9_.\-]+)(?:\[.*\])?\s*(?P<op>==|>=|<=|~=|>|<)\s*(?P<ver>[A-Za-z0-9_.\-+]+)"),
]

TOML_DEP_SECTION_REGEXES = [
    re.compile(r'^\s*([A-Za-z0-9_.\-]+)\s*=\s*"(?P<spec>[^"]+)"'),
    re.compile(r'^\s*([A-Za-z0-9_.\-]+)\s*=\s*\{[^}]*version\s*=\s*"(?P<spec>[^"]+)"[^}]*\}'),
]

GRADLE_DEP_REGEX = re.compile(
    r"(?:implementation|api|compileOnly|runtimeOnly|testImplementation|classpath)?\s*[\(\s\"]*([A-Za-z0-9_.\-]+):([A-Za-z0-9_.\-]+):([A-Za-z0-9_.\-$\{\}]+)"
)

SETUP_PY_REGEX = re.compile(
    r"([A-Za-z0-9_.\-]+)(?:\[[^\]]+\])?\s*(?:==|>=|<=|~=|>|<)\s*([A-Za-z0-9_.\-+]+)"
)

PIPFILE_REGEX = re.compile(
    r'^\s*"?([A-Za-z0-9_.\-]+)"?\s*=\s*(?:\{[^}]*version\s*=\s*"([^"]+)"[^}]*\}|"([^"]+)")'
)

POETRY_LOCK_NAME_REGEX = re.compile(r'^name\s*=\s*"([^"]+)"\s*$')
POETRY_LOCK_VERSION_REGEX = re.compile(r'^version\s*=\s*"([^"]+)"\s*$')
PDM_LOCK_NAME_REGEX = re.compile(r'^name\s*=\s*"([^"]+)"\s*$')
PDM_LOCK_VERSION_REGEX = re.compile(r'^version\s*=\s*"([^"]+)"\s*$')

MAVEN_COORD_REGEX = re.compile(
    r"<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*<version>([^<]+)</version>",
    re.DOTALL,
)

ANT_IVY_REGEX = re.compile(
    r'(?:org|group)\s*=\s*"([^"]+)"[^\n>]*(?:name)\s*=\s*"([^"]+)"[^\n>]*(?:rev|version)\s*=\s*"([^"]+)"',
    re.IGNORECASE,
)

VERSION_TEXT_REGEX = re.compile(r"\d+\.\d+(?:\.\d+){0,3}")
EXPLICIT_RANGE_HINTS = ("before", "prior to", "through", "up to", "upto", "starting in version", "from ")
START_BEFORE_RANGE_REGEX = re.compile(
    r"starting in version\s+(?P<lower>\d+\.\d+(?:\.\d+){0,3})\s+and\s+(?P<mode>prior to|before)\s+version\s+(?P<upper>\d+\.\d+(?:\.\d+){0,3})",
    re.IGNORECASE,
)
GENERIC_BOUNDED_RANGE_REGEX = re.compile(
    r"(?:from\s+)?(?P<lower>\d+\.\d+(?:\.\d+){0,3})\s+through\s+(?P<upper>\d+\.\d+(?:\.\d+){0,3})",
    re.IGNORECASE,
)
BRANCH_BEFORE_REGEX = re.compile(
    r"(?P<branch>\d+(?:\.\d+)*)\.x\s+before\s+(?P<upper>\d+\.\d+(?:\.\d+){0,3})",
    re.IGNORECASE,
)
GENERIC_UPPER_BOUND_REGEX = re.compile(
    r"(?P<mode>before|prior to|through|up to|upto)\s+(?:versions?\s+)?(?P<upper>\d+\.\d+(?:\.\d+){0,3})",
    re.IGNORECASE,
)
LLM_JUDGE_CACHE: Dict[Tuple[str, str, str], Optional[bool]] = {}


@dataclass
class RepoInfo:
    project: str
    url: str
    language: str
    owner: str
    repo: str


@dataclass
class AnalysisTask:
    project: str
    repo_url: str
    repo_name: str
    language: str
    tag: str
    component: str
    version: str
    cve: str
    repo_dir: Optional[str]
    docs_dir: Optional[str]
    vfind_json_path: Optional[str]

from collections import Counter, defaultdict
import statistics

def aggregate_votes(vote_results: List[Dict[str, object]]) -> Dict[str, object]:
    valid_votes = [
        v for v in vote_results
        if isinstance(v, dict) and "final_result" in v
    ]
    if not valid_votes:
        return {}

    # -----------------------------
    # 工具函数：多数 or 平均
    # -----------------------------
    def majority_or_average(values: List[float]):
        if not values:
            return None

        # 👉 防止浮点抖动（非常关键）
        rounded_vals = [round(v, 2) for v in values]

        counter = Counter(rounded_vals)
        top_value, top_count = counter.most_common(1)[0]

        if top_count > len(rounded_vals) / 2:
            return top_value
        else:
            return round(statistics.mean(rounded_vals), 2)

    # -----------------------------
    # 提取 score
    # -----------------------------
    def extract_scores(key: str):
        vals = []
        for v in valid_votes:
            try:
                score = v.get("scoring_factors", {}).get(key, {}).get("score")
                if score is not None:
                    vals.append(float(score))
            except Exception:
                continue
        return vals

    # -----------------------------
    # 聚合 sub_factors（核心新增）
    # -----------------------------
    def aggregate_sub_factors(factor_key: str):
        sub_factor_values = defaultdict(list)
        sub_factor_labels = {}

        for v in valid_votes:
            sub = v.get("scoring_factors", {}).get(factor_key, {}).get("sub_factors", {})
            for name, item in sub.items():
                try:
                    score = item.get("score")
                    if score is not None:
                        sub_factor_values[name].append(float(score))
                        sub_factor_labels[name] = item.get("label", name)
                except Exception:
                    continue

        result = {}
        for name, values in sub_factor_values.items():
            result[name] = {
                "label": sub_factor_labels.get(name, name),
                "score": majority_or_average(values)
            }

        return result

    # -----------------------------
    # 1. 主 factors（多数 or 平均）
    # -----------------------------
    f_vuln_scores = extract_scores("f_vuln")
    f_threat_scores = extract_scores("f_threat")
    f_business_scores = extract_scores("f_business")

    final_f_vuln = majority_or_average(f_vuln_scores)
    final_f_threat = majority_or_average(f_threat_scores)
    final_f_business = majority_or_average(f_business_scores)

    # -----------------------------
    # 2. sub_factors 聚合
    # -----------------------------
    sub_vuln = aggregate_sub_factors("f_vuln")
    sub_threat = aggregate_sub_factors("f_threat")
    sub_business = aggregate_sub_factors("f_business")

    # -----------------------------
    # 3. risk_level（多数 or 未达成一致）
    # -----------------------------
    risk_levels = [
        v.get("final_result", {}).get("risk_level")
        for v in valid_votes
        if v.get("final_result", {}).get("risk_level")
    ]

    counter = Counter(risk_levels)

    final_risk = "未取得共识"
    if counter:
        top_label, top_count = counter.most_common(1)[0]
        if top_count > len(risk_levels) / 2:
            final_risk = top_label

    # -----------------------------
    # 4. 构造最终结构
    # -----------------------------
    base = valid_votes[0]

    aggregated = {
        "project_name": base.get("project_name"),
        "project_description": base.get("project_description"),
        "vulnerability": base.get("vulnerability"),

        "scoring_factors": {
            "f_vuln": {
                "score": final_f_vuln,
                "sub_factors": sub_vuln
            },
            "f_threat": {
                "score": final_f_threat,
                "sub_factors": sub_threat
            },
            "f_business": {
                "score": final_f_business,
                "sub_factors": sub_business
            }
        },

        "final_result": {
            "risk_level": final_risk,
            "assessment_process": (
                f"基于{len(valid_votes)}次投票结果聚合："
                f"所有分数（含子因子）采用多数优先否则平均；"
                f"风险等级采用多数，否则标记为未取得共识"
            )
        },

        "aggregation": {
            "vote_count": len(valid_votes),
            "risk_distribution": dict(counter),
            "method": {
                "score": "majority_or_average",
                "risk_level": "majority_or_unresolved"
            }
        }
    }

    return aggregated


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Crawl recent component versions and match CVEs into Excel.")
    parser.add_argument("--projects-excel", required=True, help="输入项目 Excel，包含 Project、URL、language 三列")
    parser.add_argument("--cve-excel", required=True, help="漏洞库 Excel，包含 软件名、CVE编号、描述 三列")
    parser.add_argument("--output-excel", default=DEFAULT_OUTPUT, help="输出结果 Excel 路径")
    parser.add_argument("--debug-dir", default=DEFAULT_DEBUG_DIR, help="调试输出目录，会保存中间结果和日志汇总")
    parser.add_argument("--top-tags", type=int, default=DEFAULT_TOP_N_TAGS, help="每个项目爬取最近多少个 tag，默认 10")
    parser.add_argument("--github-token", default="", help="可选 GitHub Token，用于提升 API 额度")
    parser.add_argument("--openai-base-url", default="", help="OpenAI 格式接口 base_url，留空则不调用 LLM")
    parser.add_argument("--openai-api-key", default="", help="OpenAI 格式接口 api_key，留空则不调用 LLM")
    parser.add_argument("--openai-model", default="", help="OpenAI 模型名，例如 gpt-4o-mini")
    parser.add_argument("--run-codewiki", action="store_true", help="对项目先 clone 到 target_repo/[目标库] 并运行 codewiki")
    parser.add_argument("--run-vfind", action="store_true", help="根据 result.xlsx 运行 recon/vfind 流程")
    parser.add_argument("--run-nvd", action="store_true", help="对 vfind 输出的 cvelist 抓取 NVD 信息")
    parser.add_argument("--run-eval", action="store_true", help="基于 vfind + CodeWiki docs + eval 后半流程执行模块定位、业务摘要和风险评估")
    parser.add_argument("--nvd-output-dir", default=DEFAULT_NVD_OUTPUT_DIR, help="NVD 输出目录")
    parser.add_argument("--eval-output-dir", default=DEFAULT_EVAL_OUTPUT_DIR, help="eval 阶段输出目录")
    parser.add_argument("--eval-prompt-dir", default=str(Path("eval") / "final_result_system_prompt"), help="风险评估 prompt 目录")
    parser.add_argument("--eval-prompt-filename", default="prompt2.md", help="风险评估 prompt 文件名")
    parser.add_argument("--eval-excel-path", default=str(Path("eval") / "data_sort.xlsx"), help="风险评估辅助 Excel")
    parser.add_argument("--eval-risk-verbose", action="store_true", help="输出风险评估阶段调试信息")
    parser.add_argument("--vote", type=int, default=1, metavar="N", help="评估阶段向 LLM 发起 N 次请求并保存全部结果，默认 1（单次，保持原有行为）")
    parser.add_argument("--skip-matching", action="store_true", help="若存在 output Excel，则跳过爬取/匹配，直接使用已有结果")
    return parser.parse_args()


def build_headers(github_token: str = "") -> Dict[str, str]:
    headers = dict(HEADERS)
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"
    return headers


def normalize_version(version: str) -> str:
    version = str(version).strip()
    match = re.search(r"(\d+(?:\.\d+){0,4})", version)
    return match.group(1) if match else version


def parse_github_repo_url(repo_url: str) -> Tuple[str, str]:
    match = re.match(
        r"https?://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/#?]+?)(?:\.git)?/?(?:[#?].*)?$",
        repo_url.strip(),
    )
    if not match:
        raise ValueError(f"无效的 GitHub 仓库地址: {repo_url}")
    return match.group("owner"), match.group("repo")


def normalize_language(value: str) -> str:
    language = str(value).strip().lower()
    mapping = {
        "py": "python",
        "python": "python",
        "python3": "python",
        "java": "java",
        "java8": "java",
        "java11": "java",
        "java17": "java",
        "jvm": "java",
    }
    if language not in mapping:
        raise ValueError(f"不支持的 language 值: {value}，当前仅支持 python/java")
    return mapping[language]


def get_raw_cache_path(owner: str, repo: str, tag: str, path: str) -> Path:
    path_obj = PurePosixPath(path)
    safe_parts = [sanitize_filename(owner), sanitize_filename(repo), sanitize_filename(tag)]
    for part in path_obj.parts:
        safe_parts.append(sanitize_filename(part))
    return GITHUB_RAW_CACHE_DIR.joinpath(*safe_parts)


def http_get(url: str, headers: Optional[Dict[str, str]] = None) -> Tuple[int, str]:
    merged_headers = dict(HEADERS)
    if headers:
        merged_headers.update(headers)
    try:
        resp = SESSION.get(url, headers=merged_headers, timeout=REQUEST_TIMEOUT)
        LOGGER.debug("HTTP GET %s -> %s", url, resp.status_code)
        return resp.status_code, resp.text
    except requests.RequestException as exc:
        LOGGER.warning("HTTP GET 失败 %s: %s", url, exc)
        return 0, str(exc)


def ensure_debug_dir(path: str) -> Path:
    debug_dir = Path(path)
    debug_dir.mkdir(parents=True, exist_ok=True)
    return debug_dir


def sanitize_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("_") or "unknown"


def write_debug_dataframe(df: pd.DataFrame, path: Path, description: str) -> None:
    if df.empty:
        LOGGER.info("调试输出 %s 为空，仍写出空文件: %s", description, path)
    else:
        LOGGER.info("写出调试输出 %s: %s (%s rows)", description, path, len(df))
    if path.suffix.lower() == ".xlsx":
        df.to_excel(path, index=False)
    else:
        df.to_csv(path, index=False, encoding="utf-8-sig")


def append_debug_log(debug_dir: Path, message: str) -> None:
    with (debug_dir / "debug.log").open("a", encoding="utf-8") as fh:
        fh.write(message.rstrip() + "\n")


def list_repository_files(owner: str, repo: str, ref: str, headers: Dict[str, str]) -> List[str]:
    url = TREE_API.format(owner=owner, repo=repo, ref=ref)
    code, text = http_get(url, headers=headers)
    if code != 200:
        LOGGER.warning("获取仓库文件树失败 %s/%s@%s: %s", owner, repo, ref, text[:200])
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    paths: List[str] = []
    for item in data.get("tree", []):
        if item.get("type") == "blob" and item.get("path"):
            paths.append(item["path"])
    LOGGER.info("仓库 %s/%s @ %s 获取到 %s 个文件", owner, repo, ref, len(paths))
    return paths


def filter_candidate_files(paths: Iterable[str], patterns: Sequence[str]) -> List[str]:
    result: List[str] = []
    for path in paths:
        lower_path = path.lower()
        filename = os.path.basename(lower_path)
        if any(token.lower() in lower_path or token.lower() == filename for token in patterns):
            result.append(path)
    return result


def fetch_raw_file(owner: str, repo: str, tag: str, path: str, headers: Dict[str, str]) -> Optional[str]:
    cache_path = get_raw_cache_path(owner, repo, tag, path)
    if cache_path.exists():
        LOGGER.debug("来自缓存读取 %s", cache_path)
        try:
            return cache_path.read_text(encoding="utf-8")
        except Exception as exc:
            LOGGER.warning("读取缓存失败 %s: %s，尝试重新请求", cache_path, exc)
    raw_url = RAW_BASE.format(owner=owner, repo=repo, ref=tag, path=path)
    code, content = http_get(raw_url, headers=headers)
    if code == 200 and content:
        LOGGER.debug("成功读取文件 %s", raw_url)
        try:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(content, encoding="utf-8")
            LOGGER.debug("缓存 %s", cache_path)
        except Exception as exc:
            LOGGER.warning("缓存文件失败 %s: %s", cache_path, exc)
        return content
    LOGGER.debug("读取文件失败 %s -> %s", raw_url, code)
    return None


def normalize_package_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", str(name).strip().lower())


def list_recent_tags(owner: str, repo: str, top_n: int, headers: Dict[str, str]) -> List[str]:
    tags: List[str] = []
    page = 1
    while len(tags) < top_n:
        api = TAGS_API.format(owner=owner, repo=repo)
        url = f"{api}?per_page=100&page={page}"
        code, text = http_get(url, headers=headers)
        if code != 200:
            LOGGER.warning("获取 tags 失败 %s/%s: %s", owner, repo, text[:200])
            break
        data = json.loads(text)
        if not data:
            break
        for item in data:
            name = item.get("name") if isinstance(item, dict) else None
            # 跳过不含数字的 tag（如 "zookeeper-"），这类 tag 通常是无意义的占位符
            if name and re.search(r"\d", name):
                tags.append(name)
                if len(tags) >= top_n:
                    break
        page += 1
        time.sleep(SLEEP_BETWEEN_REQUESTS)
    LOGGER.info("项目 %s/%s 获取到 %s 个 tags: %s", owner, repo, len(tags), tags)
    return tags


def parse_python_versions_from_content(pkg: str, content: str) -> List[str]:
    results: List[str] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for rgx in REQ_LINE_REGEXES:
            matched = rgx.match(line)
            if matched and matched.group("pkg").lower() == pkg.lower():
                results.append(normalize_version(matched.group("ver")))
                break
    for line in content.splitlines():
        line = line.strip()
        for rgx in TOML_DEP_SECTION_REGEXES:
            matched = rgx.match(line)
            if matched and matched.group(1).lower() == pkg.lower():
                results.append(normalize_version(matched.group("spec")))
    return list(dict.fromkeys(results))


def parse_setup_py_versions(pkg: str, content: str) -> List[str]:
    target = normalize_package_name(pkg)
    versions: List[str] = []
    for dep_name, dep_version in SETUP_PY_REGEX.findall(content):
        if normalize_package_name(dep_name) == target:
            versions.append(normalize_version(dep_version))
    return list(dict.fromkeys(versions))


def parse_pipfile_versions(pkg: str, content: str) -> List[str]:
    target = normalize_package_name(pkg)
    versions: List[str] = []
    for name, version1, version2 in PIPFILE_REGEX.findall(content):
        if normalize_package_name(name) == target:
            versions.append(normalize_version(version1 or version2))
    return list(dict.fromkeys(versions))


def parse_poetry_or_pdm_lock_versions(pkg: str, content: str) -> List[str]:
    target = normalize_package_name(pkg)
    current_name = ""
    versions: List[str] = []
    for line in content.splitlines():
        stripped = line.strip()
        name_match = POETRY_LOCK_NAME_REGEX.match(stripped) or PDM_LOCK_NAME_REGEX.match(stripped)
        if name_match:
            current_name = name_match.group(1)
            continue
        version_match = POETRY_LOCK_VERSION_REGEX.match(stripped) or PDM_LOCK_VERSION_REGEX.match(stripped)
        if version_match and normalize_package_name(current_name) == target:
            versions.append(normalize_version(version_match.group(1)))
            current_name = ""
    return list(dict.fromkeys(versions))


def parse_python_file_for_package(path: str, pkg: str, content: str) -> List[str]:
    lower_path = path.lower()
    versions: List[str] = []
    versions.extend(parse_python_versions_from_content(pkg, content))
    if lower_path.endswith("setup.py"):
        versions.extend(parse_setup_py_versions(pkg, content))
    if lower_path.endswith("pipfile") or lower_path.endswith("pipfile.lock"):
        versions.extend(parse_pipfile_versions(pkg, content))
    if lower_path.endswith("poetry.lock") or lower_path.endswith("pdm.lock"):
        versions.extend(parse_poetry_or_pdm_lock_versions(pkg, content))
    return list(dict.fromkeys([v for v in versions if v]))


def crawl_python_tag(owner: str, repo: str, tag: str, headers: Dict[str, str]) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    repo_files = list_repository_files(owner, repo, tag, headers)
    candidate_paths = list(dict.fromkeys(PYTHON_CANDIDATE_FILES + filter_candidate_files(repo_files, PYTHON_FILE_PATTERNS)))
    LOGGER.info("[Python] %s/%s@%s 候选依赖文件数: %s", owner, repo, tag, len(candidate_paths))
    for path in candidate_paths:
        content = fetch_raw_file(owner, repo, tag, path, headers)
        if content is None:
            continue
        for pkg in PYTHON_TARGET_COMPONENTS:
            versions = parse_python_file_for_package(path, pkg, content)
            for version in versions:
                rows.append({"Tag": tag, "Component": pkg, "Version": version})
                LOGGER.info("[Python] 命中组件: repo=%s/%s tag=%s file=%s component=%s version=%s", owner, repo, tag, path, pkg, version)
        time.sleep(SLEEP_BETWEEN_REQUESTS)
    if not rows:
        LOGGER.warning("[Python] %s/%s@%s 未提取到任何目标组件版本", owner, repo, tag)
    return deduplicate_rows(rows)


def match_java_component(group: str, artifact: str) -> Optional[str]:
    for name, patterns in JAVA_TARGET_COMPONENTS.items():
        for target_group, artifact_keyword in patterns:
            group_match = group == target_group or group.startswith(target_group) or target_group in group
            if group_match and artifact_keyword in artifact:
                return name
    return None


def parse_maven_properties(content: str) -> Dict[str, str]:
    properties: Dict[str, str] = {}
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return properties
    ns = {"pom": MAVEN_NAMESPACE}
    props_element = root.find("pom:properties", ns)
    if props_element is not None:
        for prop in props_element:
            tag = prop.tag.replace("{" + MAVEN_NAMESPACE + "}", "")
            text = prop.text.strip() if prop.text else ""
            if text:
                properties[f"${{{tag}}}"] = text
    return properties


def parse_pom_dependencies(content: str, inherited_properties: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    versions: Dict[str, str] = {}
    properties = dict(inherited_properties or {})
    properties.update(parse_maven_properties(content))
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return versions
    ns = {"pom": MAVEN_NAMESPACE}
    dependencies = root.findall(".//pom:dependency", ns)
    for dep in dependencies:
        gid = dep.findtext("pom:groupId", default="", namespaces=ns).strip()
        aid = dep.findtext("pom:artifactId", default="", namespaces=ns).strip()
        ver = dep.findtext("pom:version", default="", namespaces=ns).strip()
        if not gid or not aid or not ver:
            continue
        if ver.startswith("${"):
            ver = properties.get(ver, ver)
        component = match_java_component(gid, aid)
        if component:
            versions.setdefault(component, normalize_version(ver))
    return versions


def parse_gradle_properties(content: str) -> Dict[str, str]:
    properties: Dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        properties[key.strip()] = value.strip()
    return properties


def resolve_gradle_placeholders(version: str, properties: Dict[str, str]) -> str:
    version = version.strip().strip("\"'")
    placeholder_match = re.fullmatch(r"\$\{?([A-Za-z0-9_.\-]+)\}?", version)
    if placeholder_match:
        key = placeholder_match.group(1)
        return properties.get(key, version)
    return version


def parse_gradle_dependencies(content: str, properties: Dict[str, str]) -> Dict[str, str]:
    versions: Dict[str, str] = {}
    for group, artifact, version in GRADLE_DEP_REGEX.findall(content):
        component = match_java_component(group, artifact)
        if component:
            resolved = resolve_gradle_placeholders(version, properties)
            versions.setdefault(component, normalize_version(resolved))
    return versions


def parse_ant_or_ivy_dependencies(content: str) -> Dict[str, str]:
    versions: Dict[str, str] = {}
    for group, artifact, version in ANT_IVY_REGEX.findall(content):
        component = match_java_component(group, artifact)
        if component:
            versions.setdefault(component, normalize_version(version))
    return versions


def parse_maven_coordinates_from_text(content: str) -> Dict[str, str]:
    versions: Dict[str, str] = {}
    for group, artifact, version in MAVEN_COORD_REGEX.findall(content):
        component = match_java_component(group.strip(), artifact.strip())
        if component:
            versions.setdefault(component, normalize_version(version.strip()))
    return versions


def crawl_java_tag(owner: str, repo: str, tag: str, headers: Dict[str, str]) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    collected_properties: Dict[str, str] = {}
    contents: Dict[str, str] = {}
    repo_files = list_repository_files(owner, repo, tag, headers)
    candidate_paths = list(dict.fromkeys(JAVA_CANDIDATE_FILES + filter_candidate_files(repo_files, JAVA_FILE_PATTERNS)))
    LOGGER.info("[Java] %s/%s@%s 候选依赖文件数: %s", owner, repo, tag, len(candidate_paths))
    for path in candidate_paths:
        content = fetch_raw_file(owner, repo, tag, path, headers)
        if content is not None:
            contents[path] = content
            if path.endswith("gradle.properties"):
                collected_properties.update(parse_gradle_properties(content))
            elif path.endswith("pom.xml"):
                # 先收集所有 pom 的 properties，供后续子模块 pom 解析时使用
                collected_properties.update(parse_maven_properties(content))
    for path, content in contents.items():
        if path.endswith("pom.xml"):
            versions = parse_pom_dependencies(content, collected_properties)
        elif path.endswith("build.gradle") or path.endswith("build.gradle.kts"):
            versions = parse_gradle_dependencies(content, collected_properties)
        elif path.endswith("build.xml") or path.endswith("ivy.xml"):
            versions = parse_ant_or_ivy_dependencies(content)
        else:
            versions = parse_maven_coordinates_from_text(content)
        for component, version in versions.items():
            rows.append({"Tag": tag, "Component": component, "Version": version})
            LOGGER.info("[Java] 命中组件: repo=%s/%s tag=%s file=%s component=%s version=%s", owner, repo, tag, path, component, version)
    if not rows:
        LOGGER.warning("[Java] %s/%s@%s 未提取到任何目标组件版本", owner, repo, tag)
    return deduplicate_rows(rows)


def deduplicate_rows(rows: Sequence[Dict[str, str]]) -> List[Dict[str, str]]:
    seen = set()
    result = []
    for row in rows:
        key = (row.get("Tag"), row.get("Component"), row.get("Version"))
        if key in seen:
            continue
        seen.add(key)
        result.append(dict(row))
    return result


def load_projects(excel_path: str) -> List[RepoInfo]:
    df = pd.read_excel(excel_path)
    required_columns = {"Project", "URL", "language"}
    missing = required_columns - set(df.columns)
    if missing:
        raise ValueError(f"项目 Excel 缺少列: {', '.join(sorted(missing))}")
    repos: List[RepoInfo] = []
    for _, row in df.iterrows():
        project = str(row["Project"]).strip()
        url = str(row["URL"]).strip()
        language = normalize_language(row["language"])
        if not project or not url or url.lower() == "nan":
            continue
        owner, repo = parse_github_repo_url(url)
        repos.append(
            RepoInfo(
                project=project,
                url=url,
                language=language,
                owner=owner,
                repo=repo,
            )
        )
    LOGGER.info("读取项目 Excel 完成，共 %s 个有效项目", len(repos))
    return repos


def load_cve_database(excel_path: str) -> pd.DataFrame:
    df = pd.read_excel(excel_path)
    required_columns = {"软件名", "CVE编号", "描述"}
    missing = required_columns - set(df.columns)
    if missing:
        raise ValueError(f"CVE Excel 缺少列: {', '.join(sorted(missing))}")
    result = df[["软件名", "CVE编号", "描述"]].copy()
    LOGGER.info("读取 CVE Excel 完成，共 %s 条记录", len(result))
    return result


def normalize_component_name(name: str) -> str:
    return re.sub(r"\s+", "", str(name).strip().lower())


def component_description_aliases(component: str) -> Tuple[str, ...]:
    return COMPONENT_DESCRIPTION_ALIASES.get(normalize_component_name(component), ())


def _component_subject_keywords(component: str) -> Tuple[str, ...]:
    return COMPONENT_SUBJECT_KEYWORDS.get(normalize_component_name(component), ())


def description_mentions_component(component: str, description: str) -> bool:
    desc = str(description).strip().lower()
    aliases = component_description_aliases(component)
    # 无别名配置时，用组件规范名本身做关键词，不再直接放行
    if not aliases:
        norm = normalize_component_name(component)
        return norm in desc
    if not any(alias in desc for alias in aliases):
        return False
    # 对于容易产生"上层应用误匹配"的组件（Groovy/log4j等），
    # 额外要求描述的首句中就出现组件关键词，过滤掉"使用了该技术的上层应用漏洞"
    subject_keywords = _component_subject_keywords(component)
    if subject_keywords:
        first_sentence = re.split(r"(?<=[.!?])\s+|\n+", desc)[0]
        if not any(kw in first_sentence for kw in subject_keywords):
            return False
    return True


def extract_component_context(component: str, description: str) -> str:
    desc = str(description).strip()
    aliases = component_description_aliases(component)
    if not desc:
        return desc
    if not aliases:
        return desc
    sentences = re.split(r"(?<=[.!?])\s+|\n+", desc)
    matched = [sentence for sentence in sentences if any(alias in sentence.lower() for alias in aliases)]
    return " ".join(matched) if matched else desc


def parse_version_parts(version: str) -> Tuple[int, ...]:
    normalized = normalize_version(version)
    if not normalized:
        return ()
    try:
        return tuple(int(part) for part in normalized.split("."))
    except ValueError:
        return ()


def compare_versions(left: str, right: str) -> int:
    left_parts = parse_version_parts(left)
    right_parts = parse_version_parts(right)
    if not left_parts or not right_parts:
        left_norm = normalize_version(left)
        right_norm = normalize_version(right)
        if left_norm == right_norm:
            return 0
        return -1 if left_norm < right_norm else 1
    max_len = max(len(left_parts), len(right_parts))
    padded_left = left_parts + (0,) * (max_len - len(left_parts))
    padded_right = right_parts + (0,) * (max_len - len(right_parts))
    if padded_left == padded_right:
        return 0
    return -1 if padded_left < padded_right else 1


def version_matches_branch(version: str, branch: str) -> bool:
    version_parts = parse_version_parts(version)
    branch_parts = parse_version_parts(branch)
    if not version_parts or not branch_parts or len(version_parts) < len(branch_parts):
        return False
    return version_parts[: len(branch_parts)] == branch_parts


def simple_version_matches(description: str, version: str) -> Optional[bool]:
    desc = description.lower()
    version = normalize_version(version)
    if not version:
        return None
    patterns = [
        re.escape(version),
        re.escape(version).replace("\\.", r"[._-]?"),
    ]
    if any(re.search(pattern, desc) for pattern in patterns):
        return True

    saw_explicit_constraint = False

    for match in START_BEFORE_RANGE_REGEX.finditer(desc):
        saw_explicit_constraint = True
        lower = match.group("lower")
        upper = match.group("upper")
        if compare_versions(version, lower) >= 0 and compare_versions(version, upper) < 0:
            return True

    for match in GENERIC_BOUNDED_RANGE_REGEX.finditer(desc):
        saw_explicit_constraint = True
        lower = match.group("lower")
        upper = match.group("upper")
        if compare_versions(version, lower) >= 0 and compare_versions(version, upper) <= 0:
            return True

    for match in BRANCH_BEFORE_REGEX.finditer(desc):
        saw_explicit_constraint = True
        branch = match.group("branch")
        upper = match.group("upper")
        if version_matches_branch(version, branch):
            return compare_versions(version, upper) < 0

    for match in GENERIC_UPPER_BOUND_REGEX.finditer(desc):
        saw_explicit_constraint = True
        upper = match.group("upper")
        mode = match.group("mode").lower()
        if mode in {"through", "up to", "upto"}:
            if compare_versions(version, upper) <= 0:
                return True
        else:
            if compare_versions(version, upper) < 0:
                return True

    mentioned_versions = [normalize_version(item) for item in VERSION_TEXT_REGEX.findall(desc)]
    mentioned_versions = [item for item in mentioned_versions if item]
    if mentioned_versions and any(hint in desc for hint in EXPLICIT_RANGE_HINTS):
        highest_mentioned = mentioned_versions[0]
        for candidate in mentioned_versions[1:]:
            if compare_versions(candidate, highest_mentioned) > 0:
                highest_mentioned = candidate
        if compare_versions(version, highest_mentioned) > 0:
            return False

    if saw_explicit_constraint:
        return False
    return None


def call_openai_judge(base_url: str, api_key: str, model: str, component: str, version: str, cve: str, description: str) -> Optional[bool]:
    if not (base_url and api_key and model):
        return None
    cache_key = (normalize_component_name(component), normalize_version(version), str(cve).strip())
    if cache_key in LLM_JUDGE_CACHE:
        return LLM_JUDGE_CACHE[cache_key]
    url = base_url.rstrip("/") + "/chat/completions"
    prompt = (
        '你是漏洞分析助手。请只回答 JSON，格式为 {"affected": true/false, "is_direct": true/false, "reason": "..."}。\n'
        f"组件名: {component}\n"
        f"组件版本: {version}\n"
        f"CVE: {cve}\n"
        f"描述: {description}\n"
        "请判断两个问题：\n"
        f"1. affected：该版本的 {component} 本身（作为漏洞直接主体）是否受该 CVE 影响？"
        f"注意：若该 CVE 的受影响软件是使用了 {component} 的上层应用（如 XWiki、Jenkins、OFBiz 等），"
        f"而非 {component} 库本身，则 affected 应为 false。\n"
        f"2. is_direct：该 CVE 的漏洞主体是否就是 {component} 本身（而非依赖它的上层应用）？\n"
        "若描述不足以判断，请保守返回 false。"
    )

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a precise vulnerability triage assistant."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0,
    }
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}
    response_text = ""
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=REQUEST_TIMEOUT)
        response_text = response.text or ""
        LOGGER.debug("LLM 原始响应 [%s]: %s", response.status_code, response_text[:1000])
        response.raise_for_status()
        data = response.json()
        content = data["choices"][0]["message"]["content"]
        stripped_content = re.sub(r"^```(?:json)?\s*", "", content.strip(), flags=re.IGNORECASE)
        stripped_content = re.sub(r"\s*```$", "", stripped_content)
        parsed = json.loads(stripped_content)
        # affected 且是直接主体（is_direct），才算命中；is_direct 缺失时保守视为 True（兼容旧格式）
        is_direct = parsed.get("is_direct", True)
        result = bool(parsed.get("affected")) and bool(is_direct)
        LLM_JUDGE_CACHE[cache_key] = result
        return result
    except Exception as exc:
        details = f" response_text={response_text[:1000]}" if response_text else ""
        LOGGER.warning("LLM 判断失败，已跳过：%s%s", exc, details)
        LLM_JUDGE_CACHE[cache_key] = None
        return None


def match_cves_for_component(
    component: str,
    version: str,
    cve_df: pd.DataFrame,
    openai_base_url: str,
    openai_api_key: str,
    openai_model: str,
) -> List[str]:
    normalized_component = normalize_component_name(component)
    matched_cves: List[str] = []
    candidate_count = 0
    for _, row in cve_df.iterrows():
        software_name = str(row["软件名"])
        cve_id = str(row["CVE编号"])
        description = str(row["描述"])
        software_norm = normalize_component_name(software_name)
        if normalized_component not in software_norm and software_norm not in normalized_component:
            continue
        if not description_mentions_component(component, description):
            continue
        candidate_count += 1
        relevant_description = extract_component_context(component, description)
        heuristic_match = simple_version_matches(relevant_description, version)
        llm_match = None
        if heuristic_match is None:
            llm_match = call_openai_judge(
                openai_base_url,
                openai_api_key,
                openai_model,
                component,
                version,
                cve_id,
                relevant_description,
            )
        if heuristic_match or llm_match is True:
            matched_cves.append(cve_id)
    LOGGER.info("CVE 匹配完成: component=%s version=%s 候选=%s 命中=%s", component, version, candidate_count, len(set(matched_cves)))
    return sorted(set(matched_cves))


def crawl_project_versions(repo: RepoInfo, top_tags: int, headers: Dict[str, str]) -> List[Dict[str, str]]:
    LOGGER.info("开始处理项目 %s (%s)", repo.project, repo.language)
    tags = list_recent_tags(repo.owner, repo.repo, top_tags, headers)
    all_rows: List[Dict[str, str]] = []
    for tag in tags:
        try:
            if repo.language == "java":
                rows = crawl_java_tag(repo.owner, repo.repo, tag, headers)
            else:
                rows = crawl_python_tag(repo.owner, repo.repo, tag, headers)
            for row in rows:
                row["Project"] = repo.project
            all_rows.extend(rows)
            LOGGER.info("项目 %s tag %s 提取到 %s 条记录", repo.project, tag, len(rows))
        except Exception as exc:
            LOGGER.warning("处理 %s tag %s 失败: %s", repo.project, tag, exc)
    deduped = deduplicate_rows(all_rows)
    LOGGER.info("项目 %s 汇总后共 %s 条唯一组件记录", repo.project, len(deduped))
    return deduped


def build_result_dataframe(
    crawled_rows: List[Dict[str, str]],
    cve_df: pd.DataFrame,
    openai_base_url: str,
    openai_api_key: str,
    openai_model: str,
) -> pd.DataFrame:
    result_rows: List[Dict[str, str]] = []
    for row in crawled_rows:
        matched_cves = match_cves_for_component(
            component=row["Component"],
            version=row["Version"],
            cve_df=cve_df,
            openai_base_url=openai_base_url,
            openai_api_key=openai_api_key,
            openai_model=openai_model,
        )
        result_rows.append(
            {
                "Project": row["Project"],
                "Tag": row["Tag"],
                "Component": row["Component"],
                "Version": row["Version"],
                "CVE": ", ".join(matched_cves),
            }
        )
    result_df = pd.DataFrame(result_rows, columns=["Project", "Tag", "Component", "Version", "CVE"])
    LOGGER.info("最终结果构建完成，共 %s 条", len(result_df))
    return result_df


def ensure_dependencies() -> None:
    missing = []
    for package in ["pandas", "openpyxl", "requests"]:
        try:
            __import__(package)
        except ImportError:
            missing.append(package)
    if missing:
        raise RuntimeError(f"缺少依赖，请先安装: pip install {' '.join(missing)}")


def run_codewiki_for_projects(projects: List[RepoInfo], debug_dir: Path, selected_tags: Optional[Dict[str, str]] = None) -> List[Dict[str, str]]:
    codewiki_rows: List[Dict[str, str]] = []
    for repo in projects:
        if selected_tags is not None and repo.project not in selected_tags:
            continue
        ref = selected_tags.get(repo.project) if selected_tags is not None else None
        try:
            LOGGER.info("开始执行 CodeWiki: %s", repo.project)
            repo_dir = prepare_and_run_codewiki(repo.url, ref=ref)
            LOGGER.info("CodeWiki 执行完成: %s -> %s", repo.project, repo_dir)
            codewiki_rows.append(
                {
                    "Project": repo.project,
                    "RepoURL": repo.url,
                    "Tag": ref or "",
                    "RepoDir": str(repo_dir),
                    "Status": "success",
                }
            )
        except Exception as exc:
            LOGGER.warning("CodeWiki 处理失败 %s: %s", repo.project, exc)
            codewiki_rows.append(
                {
                    "Project": repo.project,
                    "RepoURL": repo.url,
                    "Tag": ref or "",
                    "RepoDir": "",
                    "Status": f"failed: {exc}",
                }
            )
            append_debug_log(debug_dir, f"CodeWiki failed for {repo.project}: {exc}")
    return codewiki_rows


def run_post_processing_pipeline(args: argparse.Namespace, debug_dir: Path) -> List[Dict[str, str]]:
    cve_list: List[Dict[str, str]] = []
    if args.run_vfind:
        cve_list = generate_tasks(result_file=args.output_excel, data_file="DATA.xlsx")
        write_debug_dataframe(pd.DataFrame(cve_list), debug_dir / "vfind_cvelist.xlsx", "vfind 输出 cvelist")

    if args.run_nvd:
        if not cve_list:
            LOGGER.warning("run-nvd 已启用，但没有可用 cvelist，跳过 NVD 抓取")
            append_debug_log(debug_dir, "WARNING: run-nvd enabled but cvelist is empty")
            return cve_list
        nvd_result = fetch_and_save_cve_list(cve_list, args.nvd_output_dir)
        write_debug_dataframe(pd.DataFrame(nvd_result.get("results", [])), debug_dir / "nvd_results.xlsx", "NVD 抓取结果")
        write_debug_dataframe(pd.DataFrame(nvd_result.get("failed", [])), debug_dir / "nvd_failed.xlsx", "NVD 抓取失败结果")
        append_debug_log(debug_dir, f"NVD summary written to {nvd_result.get('summary_path', '')}")
    return cve_list


def safe_read_json(path: Path) -> Optional[Dict[str, object]]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        LOGGER.warning("读取 JSON 失败 %s: %s", path, exc)
        return None


def find_repo_dir_for_project(project: str, repo_name: str) -> Optional[Path]:
    candidates = [Path("target_repo") / project, Path("target_repo") / repo_name]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def resolve_docs_dir(repo_dir: Optional[Path]) -> Optional[Path]:
    if not repo_dir:
        return None
    docs_dir = repo_dir / "docs"
    if docs_dir.exists() and (docs_dir / "module_tree.json").exists():
        return docs_dir
    return None


def find_vfind_result(project: str, cve: str) -> Optional[Path]:
    base = Path("workflow_output") / "vfind" / project
    if not base.exists():
        return None
    preferred = base / f"{project}_{cve}.json"
    if preferred.exists():
        return preferred
    matches = sorted(base.glob(f"*{cve}*.json"))
    return matches[0] if matches else None


def parse_vfind_payload(vfind_path: Path) -> Dict[str, object]:
    payload = safe_read_json(vfind_path) or {}
    sinks = payload.get("sinks") or []
    first_sink = sinks[0] if isinstance(sinks, list) and sinks else {}
    trigger = ""
    if isinstance(first_sink, dict):
        file_path = str(first_sink.get("file") or "")
        function_name = str(first_sink.get("function") or "")
        code_snippet = str(first_sink.get("code_snippet") or "")
        trigger = f"{function_name}: {code_snippet}".strip(": ")
    else:
        file_path = ""
        function_name = ""
        code_snippet = ""
    return {
        "reachable": bool(sinks),
        "trigger": trigger,
        "target": function_name,
        "filepath": file_path,
        "code_snippet": code_snippet,
        "sink_count": payload.get("total_sinks_found", len(sinks) if isinstance(sinks, list) else 0),
        "raw": payload,
    }


def load_nvd_vulnerability_info(cve: str, nvd_output_dir: str) -> Optional[Dict[str, object]]:
    base = Path(nvd_output_dir)
    matches = sorted(base.glob(f"*{cve}*_nvd.json")) if base.exists() else []
    if not matches:
        return None
    payload = safe_read_json(matches[0]) or {}
    # NVD API v2.0 格式：顶层是 vulnerabilities 列表，每项含 cve 对象
    vulnerabilities = payload.get("vulnerabilities") or []
    if vulnerabilities and isinstance(vulnerabilities[0], dict):
        cve_item = vulnerabilities[0].get("cve") or {}
    else:
        # 兼容旧格式（直接是 cve 对象）
        cve_item = payload.get("cve") if isinstance(payload.get("cve"), dict) else payload
    if not isinstance(cve_item, dict):
        cve_item = {}
    descriptions = cve_item.get("descriptions") or []
    description_text = ""
    if isinstance(descriptions, list):
        for item in descriptions:
            if isinstance(item, dict) and item.get("lang") == "en":
                description_text = str(item.get("value") or "")
                break
        if not description_text and descriptions and isinstance(descriptions[0], dict):
            description_text = str(descriptions[0].get("value") or "")
    metrics = cve_item.get("metrics") or {}
    cvss_score = ""
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        values = metrics.get(key)
        if not isinstance(values, list) or not values:
            continue
        # 优先取 type==Primary 或 source==nvd@nist.gov 的官方评分，避免 Secondary 评分被默认取到
        primary = next(
            (m for m in values if m.get("type") == "Primary" or m.get("source") == "nvd@nist.gov"),
            None,
        )
        metric = primary if primary else values[0]
        if isinstance(metric, dict):
            cvss_data = metric.get("cvssData") or {}
            base_score = cvss_data.get("baseScore")
            if base_score is not None:
                cvss_score = str(base_score)
                break
    # 遍历所有 weaknesses 条目，去重后合并，例如 "CWE-502, CWE-918"
    weaknesses = cve_item.get("weaknesses") or []
    vul_type = ""
    if isinstance(weaknesses, list) and weaknesses:
        seen_cwes: list = []
        for w in weaknesses:
            if isinstance(w, dict):
                for d in (w.get("description") or []):
                    val = str(d.get("value") or "") if isinstance(d, dict) else str(d)
                    if val and val not in seen_cwes:
                        seen_cwes.append(val)
        vul_type = ", ".join(seen_cwes)
    # 从 references 中检测补丁可用性：
    # 1) NVD 明确打了 "Patch" tag
    # 2) "Vendor Advisory"（厂商公告）通常意味着已发布修复版本
    references = cve_item.get("references") or []
    patch_tag_found = any(
        "Patch" in (ref.get("tags") or [])
        for ref in references
        if isinstance(ref, dict)
    )
    vendor_advisory_found = any(
        "Vendor Advisory" in (ref.get("tags") or [])
        for ref in references
        if isinstance(ref, dict)
    )
    vul_patch_available = patch_tag_found or vendor_advisory_found
    # 兜底：vulnStatus=Analyzed/Modified 且发布超过 365 天，视为已有修复
    if not vul_patch_available:
        vuln_status = cve_item.get("vulnStatus", "")
        pub_date_str = cve_item.get("published", "")
        if pub_date_str and vuln_status in ("Analyzed", "Modified"):
            try:
                from datetime import datetime
                # 截取到秒，忽略毫秒和时区，统一做朴素日期比较
                pub_plain = pub_date_str.split(".")[0].replace("Z", "").split("+")[0]
                pub = datetime.strptime(pub_plain, "%Y-%m-%dT%H:%M:%S")
                if (datetime.now() - pub).days > 365:
                    vul_patch_available = True
            except Exception:
                pass
    # 从 references 中检测是否存在 PoC/Exploit 相关标签
    poc_tags = {"Exploit", "Proof of Concept", "Mitigation"}
    vul_poc_available = any(
        bool(poc_tags & set(ref.get("tags") or []))
        for ref in references
        if isinstance(ref, dict)
    )
    # CISA KEV 收录状态
    kev_catalog = _load_kev_catalog()
    vul_kev_in_catalog = cve in kev_catalog
    # CVE 发布年龄（天数）
    vul_cve_age_days = 0
    pub_date_str_raw = cve_item.get("published", "")
    if pub_date_str_raw:
        try:
            from datetime import datetime as _dt
            pub_plain = str(pub_date_str_raw).split(".")[0].replace("Z", "").split("+")[0]
            pub = _dt.strptime(pub_plain, "%Y-%m-%dT%H:%M:%S")
            vul_cve_age_days = (_dt.now() - pub).days
        except Exception:
            pass
    return {
        "vul_name": cve,
        "vul_id": cve,
        "vul_cvss_score": cvss_score,
        "vul_type": vul_type,
        "vul_cwe_type": vul_type,
        "vul_risk": description_text,
        "vul_fix_suggestion": "参考官方补丁、升级版本或规避方案。",
        "vul_reason": description_text,
        "vul_trigger_condition": description_text,
        "vul_patch_available": vul_patch_available,
        "vul_poc_available": vul_poc_available,
        "vul_kev_in_catalog": vul_kev_in_catalog,
        "vul_cve_age_days": vul_cve_age_days,
    }


def split_cve_values(value: object) -> List[str]:
    text = str(value) if value is not None else ""
    parts = [item.strip() for item in text.split(",")]
    return [item for item in parts if item]


def load_triggered_cves_from_existing_vfind() -> Dict[str, Set[str]]:
    cvelist_path = Path("workflow_output") / "cvelist" / "non_empty_sinks.json"
    if not cvelist_path.is_file():
        return {}
    try:
        text = cvelist_path.read_text(encoding="utf-8")
        data = json.loads(text)
    except Exception as exc:
        LOGGER.warning("failed to load existing vfind cvelist from %s: %s", cvelist_path, exc)
        return {}
    triggered: Dict[str, Set[str]] = {}
    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            project_name = str(item.get("repo_name") or "").strip()
            cve_id = str(item.get("cve_id") or "").strip()
            if not project_name or not cve_id:
                continue
            project_set = triggered.setdefault(project_name, set())
            project_set.add(cve_id)
    return triggered


def select_top_tags_by_triggered_cves(
    result_df: pd.DataFrame,
    triggered_cves_by_project: Dict[str, Set[str]],
) -> Dict[str, str]:
    project_tag_cves: Dict[str, Dict[str, Set[str]]] = {}
    for _, row in result_df.iterrows():
        project = str(row.get("Project", "")).strip()
        tag = str(row.get("Tag", "")).strip()
        if not project or not tag:
            continue
        triggered_set = triggered_cves_by_project.get(project)
        if not triggered_set:
            continue
        cves = split_cve_values(row.get("CVE", ""))
        matched = [cve for cve in cves if cve in triggered_set]
        if not matched:
            continue
        tag_map = project_tag_cves.setdefault(project, {})
        tag_set = tag_map.setdefault(tag, set())
        for cve in matched:
            tag_set.add(cve)
    selected: Dict[str, str] = {}
    for project, tag_map in project_tag_cves.items():
        best_tag = ""
        best_count = 0
        for tag, cves in tag_map.items():
            count = len(cves)
            if count > best_count:
                best_tag = tag
                best_count = count
        if best_tag and best_count > 0:
            selected[project] = best_tag
    return selected


def build_analysis_tasks(
    projects: List[RepoInfo],
    result_df: pd.DataFrame,
    selected_tags: Optional[Dict[str, str]] = None,
    triggered_cves_by_project: Optional[Dict[str, Set[str]]] = None,
) -> List[AnalysisTask]:
    repo_map = {repo.project: repo for repo in projects}
    tasks: List[AnalysisTask] = []
    # 按 (project, tag, cve) 去重：同一CVE在同一tag下可能因多个版本文件产生重复行
    seen: Set[tuple] = set()
    for _, row in result_df.iterrows():
        cves = split_cve_values(row.get("CVE", ""))
        if not cves:
            continue
        project = str(row.get("Project", "")).strip()
        tag = str(row.get("Tag", "")).strip()
        if selected_tags is not None:
            expected_tag = selected_tags.get(project)
            if not expected_tag or tag != expected_tag:
                continue
        repo = repo_map.get(project)
        if not repo:
            continue
        repo_dir = find_repo_dir_for_project(repo.project, repo.repo)
        docs_dir = resolve_docs_dir(repo_dir)
        for cve in cves:
            vfind_json = find_vfind_result(project, cve)
            if triggered_cves_by_project is not None:
                triggered_set = triggered_cves_by_project.get(project)
                in_triggered = bool(triggered_set and cve in triggered_set)
                # 不可达 CVE（有 vfind 结果但 sinks=0）也纳入任务，后续打零分而非丢弃
                if not in_triggered and not vfind_json:
                    continue
            dedup_key = (project, tag, cve)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            tasks.append(
                AnalysisTask(
                    project=project,
                    repo_url=repo.url,
                    repo_name=repo.repo,
                    language=repo.language,
                    tag=tag,
                    component=str(row.get("Component", "")).strip(),
                    version=str(row.get("Version", "")).strip(),
                    cve=cve,
                    repo_dir=str(repo_dir) if repo_dir else None,
                    docs_dir=str(docs_dir) if docs_dir else None,
                    vfind_json_path=str(vfind_json) if vfind_json else None,
                )
            )
    LOGGER.info("构建 analysis tasks 完成，共 %s 条（已按 project+tag+cve 去重）", len(tasks))
    return tasks


def _load_kev_catalog() -> Set[str]:
    """下载并缓存 CISA KEV 目录，返回 CVE ID 集合。失败时返回空集合。"""
    global _KEV_CATALOG
    if _KEV_CATALOG is not None:
        return _KEV_CATALOG
    local_cache = Path("workflow_output") / "kev_catalog.json"
    try:
        if local_cache.is_file():
            data = safe_read_json(local_cache) or {}
        else:
            import urllib.request
            kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            with urllib.request.urlopen(kev_url, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            local_cache.parent.mkdir(parents=True, exist_ok=True)
            local_cache.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        vulns = data.get("vulnerabilities") or []
        _KEV_CATALOG = {str(v.get("cveID") or "").strip() for v in vulns if v.get("cveID")}
        LOGGER.info("CISA KEV 目录已加载，共 %d 条", len(_KEV_CATALOG))
    except Exception as exc:
        LOGGER.warning("CISA KEV 加载失败，已禁用 KEV 信号: %s", exc)
        _KEV_CATALOG = set()
    return _KEV_CATALOG


def _cap_fvuln_by_cvss(payload: dict, cvss_str: str) -> dict:
    """根据 CVSS 基础分对 f_vuln 施加后置上限，等比压缩子因子，保持内部权重不变。"""
    try:
        cvss = float(cvss_str)
    except (TypeError, ValueError):
        return payload
    if cvss >= 9.0:
        return payload
    cap = 3.5 if cvss >= 7.0 else (2.5 if cvss >= 4.0 else 1.5)
    sf = (payload.get("scoring_factors") or {}).get("f_vuln")
    if not isinstance(sf, dict):
        return payload
    current_score = sf.get("score")
    if current_score is None:
        return payload
    try:
        current_score = float(current_score)
    except (TypeError, ValueError):
        return payload
    if current_score <= cap:
        return payload
    ratio = cap / current_score
    sf["score"] = round(cap, 4)
    for sub in (sf.get("sub_factors") or {}).values():
        if isinstance(sub, dict) and sub.get("score") is not None:
            try:
                sub["score"] = round(float(sub["score"]) * ratio, 4)
            except (TypeError, ValueError):
                pass
    return payload


def _zero_fbusiness(payload: dict) -> dict:
    """将 f_business 所有子因子及总分强制置零，用于不可达 CVE。"""
    fb = (payload.get("scoring_factors") or {}).get("f_business")
    if not isinstance(fb, dict):
        return payload
    fb["score"] = 0.0
    fb["details"] = "漏洞不可达，业务影响为零"
    for sf in (fb.get("sub_factors") or {}).values():
        if isinstance(sf, dict):
            sf["score"] = 0.0
    return payload


def run_eval_pipeline(tasks: List[AnalysisTask], args: argparse.Namespace, debug_dir: Path) -> pd.DataFrame:
    result_rows: List[Dict[str, object]] = []
    shared_api_key = args.openai_api_key or os.environ.get("OPENAI_API_KEY") or ""
    shared_base_url = args.openai_base_url or os.environ.get("OPENAI_BASE_URL") or ""
    model = args.openai_model or os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
    output_base = Path(args.eval_output_dir)
    output_base.mkdir(parents=True, exist_ok=True)

    for task in tasks:
        task_dir = output_base / sanitize_filename(task.project) / sanitize_filename(task.tag or "unknown_tag") / sanitize_filename(task.cve)
        task_dir.mkdir(parents=True, exist_ok=True)
        row: Dict[str, object] = {
            "Project": task.project,
            "Tag": task.tag,
            "Component": task.component,
            "Version": task.version,
            "CVE": task.cve,
            "CVSS": "",
            "Reachable": False,
            "Trigger": "",
            "FilePath": "",
            "Module": "",
            "LocatedComponent": "",
            "RiskLevel": "",
            "FVuln": "",
            "FThreat": "",
            "FBusiness": "",
            "OutputDir": str(task_dir),
            "Status": "pending",
            "Error": "",
        }
        try:
            if not task.docs_dir:
                row["Status"] = "skipped"
                row["Error"] = "docs_dir not found"
                result_rows.append(row)
                continue
            if not task.vfind_json_path:
                row["Status"] = "skipped"
                row["Error"] = "vfind result not found"
                result_rows.append(row)
                continue

            vfind_info = parse_vfind_payload(Path(task.vfind_json_path))
            row["Reachable"] = bool(vfind_info["reachable"])
            row["Trigger"] = str(vfind_info["trigger"])
            row["FilePath"] = str(vfind_info["filepath"])

            vulnerability_info = load_nvd_vulnerability_info(task.cve, args.nvd_output_dir)
            row["CVSS"] = vulnerability_info.get("vul_cvss_score", "") if vulnerability_info else ""
            vote_n: int = max(1, int(getattr(args, "vote", 1) or 1))

            if not vfind_info["reachable"]:
                (task_dir / "trigger_analysis.json").write_text(
                    json.dumps(vfind_info, ensure_ascii=False, indent=2), encoding="utf-8"
                )
                unreachable_business_factors = {
                    "project": {
                        "name": task.project,
                        "description": "不可达，业务影响为零",
                        "overall_role": "",
                        "business_importance_analysis": "",
                        "data_sensitivity_analysis": "",
                        "exposure_analysis": "",
                    },
                    "component": {
                        "name": task.component,
                        "role_in_project": "",
                        "importance_analysis": "",
                        "data_sensitivity_analysis": "",
                        "attack_surface_analysis": "",
                        "impact_analysis": {
                            "service_availability": "",
                            "data_security": "",
                            "compliance_impact": "",
                        },
                    },
                }
                # NVD 数据缺失时跳过 LLM，直接产出确定性低危记录，避免回落读本地文件失败
                if vulnerability_info is None:
                    LOGGER.info("不可达且无 NVD 数据，使用确定性低危记录: %s %s", task.project, task.cve)
                    risk_payload = {
                        "scoring_factors": {
                            "f_vuln":     {"score": 0.0, "details": "缺少 NVD 数据，无法评估", "sub_factors": {}},
                            "f_threat":   {"score": 0.0, "details": "缺少 NVD 数据，无法评估", "sub_factors": {}},
                            "f_business": {"score": 0.0, "details": "漏洞不可达，业务影响为零", "sub_factors": {}},
                        },
                        "final_result": {
                            "risk_level": "非高危",
                            "assessment_process": "漏洞触发点不可达且无 NVD 数据，三因子均为零，判定为非高危",
                        },
                    }
                    vote_results: List[Dict[str, object]] = [risk_payload]
                    (task_dir / "risk_assessment.json").write_text(
                        json.dumps(risk_payload, ensure_ascii=False, indent=2), encoding="utf-8"
                    )
                else:
                    vote_results = []
                    for vote_idx in range(vote_n):
                        LOGGER.info("不可达投票 %d/%d: %s %s", vote_idx + 1, vote_n, task.project, task.cve)
                        try:
                            risk_result_i = run_risk_assessment(
                                prompt_filename=args.eval_prompt_filename,
                                cve_id=task.cve,
                                prompt_dir=Path(args.eval_prompt_dir),
                                vulnerability_dir=Path("eval") / "cve_data",
                                vulnerability_info=vulnerability_info,
                                business_dir=Path("eval") / "cve_data",
                                business_factors=unreachable_business_factors,
                                excel_path=Path(args.eval_excel_path),
                                reachability={"reachability": "不可达"},
                                model=model,
                                api_key=shared_api_key,
                                api_base=shared_base_url,
                                verbose=args.eval_risk_verbose,
                            )
                            risk_payload_i = _zero_fbusiness(build_risk_payload(risk_result_i))
                        except Exception as vote_exc:
                            LOGGER.warning(
                                "不可达 vote %d/%d failed for %s %s: %s",
                                vote_idx + 1, vote_n, task.project, task.cve, vote_exc,
                            )
                            risk_payload_i = {"error": str(vote_exc)}
                        vote_results.append(risk_payload_i)
                        suffix = f"_vote{vote_idx + 1}" if vote_n > 1 else ""
                        (task_dir / f"risk_assessment{suffix}.json").write_text(
                            json.dumps(risk_payload_i, ensure_ascii=False, indent=2), encoding="utf-8"
                        )
                        LOGGER.info("不可达 vote %d/%d done: %s %s", vote_idx + 1, vote_n, task.project, task.cve)
                    if vote_n > 1:
                        (task_dir / "risk_assessment_all_votes.json").write_text(
                            json.dumps(vote_results, ensure_ascii=False, indent=2), encoding="utf-8"
                        )
                    risk_payload = _zero_fbusiness(aggregate_votes(vote_results))
                final_record = {
                    "task": task.__dict__,
                    "vfind": vfind_info,
                    "module_locator": {},
                    "component_summary": {},
                    "risk_assessment": risk_payload,
                    "vote_n": vote_n,
                    "vote_results": vote_results,
                }
                (task_dir / "final_record.json").write_text(
                    json.dumps(final_record, ensure_ascii=False, indent=2), encoding="utf-8"
                )
                row["RiskLevel"] = risk_payload.get("final_result", {}).get("risk_level", "")
                row["FVuln"] = risk_payload.get("scoring_factors", {}).get("f_vuln", {}).get("score", "")
                row["FThreat"] = risk_payload.get("scoring_factors", {}).get("f_threat", {}).get("score", "")
                row["FBusiness"] = 0.0
                row["VoteN"] = vote_n
                row["Status"] = "success"
                result_rows.append(row)
                continue

            module_locator_result = run_module_locator(
                module_tree_path=Path(task.docs_dir) / "module_tree.json",
                docs_path=Path(task.docs_dir),
                trigger=str(vfind_info["trigger"]),
                target=str(vfind_info["target"]),
                repo=task.project,
                cve=task.cve,
                filepath=str(vfind_info["filepath"]),
                snippet_size=10,
                model=model,
                api_key=shared_api_key,
                base_url=shared_base_url,
            )
            (task_dir / "trigger_analysis.json").write_text(json.dumps(vfind_info, ensure_ascii=False, indent=2), encoding="utf-8")
            (task_dir / "module_locator_result.json").write_text(json.dumps(module_locator_result, ensure_ascii=False, indent=2), encoding="utf-8")
            row["Module"] = module_locator_result.get("module", "")
            row["LocatedComponent"] = module_locator_result.get("component", "")

            located_component = str(module_locator_result.get("component") or "").strip()
            component_summary = None
            if not located_component:
                # 回退一：用依赖名（task.component）搜索最近似模块文档
                fallback_comp = (task.component or "").strip()
                if fallback_comp:
                    try:
                        component_summary = run_component_summarizer(
                            component=fallback_comp,
                            docs_dir=Path(task.docs_dir),
                            model=model,
                            api_key=shared_api_key,
                            base_url=shared_base_url,
                            language="zh",
                        )
                        row["LocatedComponent"] = fallback_comp
                        row["Module"] = "fallback_component"
                        LOGGER.info("module locator 回退一成功 %s %s，使用依赖名: %s", task.project, task.cve, fallback_comp)
                    except Exception as _fb1:
                        LOGGER.info("module locator 回退一失败 %s %s: %s", task.project, task.cve, _fb1)
                # 回退二：读取 overview.md 构造最小业务上下文
                if component_summary is None:
                    _overview = Path(task.docs_dir) / "overview.md"
                    if _overview.is_file():
                        try:
                            _overview_text = _overview.read_text(encoding="utf-8")[:3000]
                            component_summary = [{
                                "project": {
                                    "name": task.project,
                                    "description": _overview_text,
                                    "overall_role": "",
                                    "business_importance_analysis": "",
                                    "data_sensitivity_analysis": "",
                                    "exposure_analysis": "",
                                },
                                "component": {
                                    "name": task.component,
                                    "role_in_project": "",
                                    "importance_analysis": "（由 overview.md 兜底，无具体模块文档）",
                                    "data_sensitivity_analysis": "",
                                    "attack_surface_analysis": "",
                                    "impact_analysis": {
                                        "service_availability": "",
                                        "data_security": "",
                                        "compliance_impact": "",
                                    },
                                },
                            }]
                            row["LocatedComponent"] = task.component
                            row["Module"] = "fallback_overview"
                            LOGGER.info("module locator 回退二成功 %s %s，使用 overview.md", task.project, task.cve)
                        except Exception as _fb2:
                            LOGGER.info("module locator 回退二失败 %s %s: %s", task.project, task.cve, _fb2)
                if component_summary is None:
                    row["Status"] = "skipped"
                    row["Error"] = "module locator returned empty component, all fallbacks failed"
                    result_rows.append(row)
                    continue
            else:
                component_summary = run_component_summarizer(
                    component=located_component,
                    docs_dir=Path(task.docs_dir),
                    model=model,
                    api_key=shared_api_key,
                    base_url=shared_base_url,
                    language="zh",
                )
            (task_dir / "component_summary.json").write_text(json.dumps(component_summary, ensure_ascii=False, indent=2), encoding="utf-8")

            # --- vote: run risk assessment vote_n times, save all results ---
            vote_results: List[Dict[str, object]] = []
            business_factors = (
                component_summary[0]
                if isinstance(component_summary, list) and component_summary
                else component_summary
            )
            for vote_idx in range(vote_n):
                logging.info("开始投票 %d/%d: %s %s", vote_idx + 1, vote_n, task.project, task.cve)
                try:
                    risk_result_i = run_risk_assessment(
                        prompt_filename=args.eval_prompt_filename,
                        cve_id=task.cve,
                        prompt_dir=Path(args.eval_prompt_dir),
                        vulnerability_dir=Path("eval") / "cve_data",
                        vulnerability_info=vulnerability_info,
                        business_dir=Path("eval") / "cve_data",
                        business_factors=business_factors,
                        excel_path=Path(args.eval_excel_path),
                        reachability={"reachability": "可达"},
                        model=model,
                        api_key=shared_api_key,
                        api_base=shared_base_url,
                        verbose=args.eval_risk_verbose,
                    )
                    risk_payload_i = build_risk_payload(risk_result_i)
                except Exception as vote_exc:
                    LOGGER.warning(
                        "vote %d/%d failed for %s %s: %s",
                        vote_idx + 1, vote_n, task.project, task.cve, vote_exc,
                    )
                    risk_payload_i = {"error": str(vote_exc)}
                vote_results.append(risk_payload_i)
                # save each vote result individually
                suffix = f"_vote{vote_idx + 1}" if vote_n > 1 else ""
                (task_dir / f"risk_assessment{suffix}.json").write_text(
                    json.dumps(risk_payload_i, ensure_ascii=False, indent=2), encoding="utf-8"
                )
                LOGGER.info(
                    "vote %d/%d done: %s %s",
                    vote_idx + 1, vote_n, task.project, task.cve,
                )

            # when vote_n > 1, additionally save a summary file of all votes
            if vote_n > 1:
                (task_dir / "risk_assessment_all_votes.json").write_text(
                    json.dumps(vote_results, ensure_ascii=False, indent=2), encoding="utf-8"
                )

            # use the first result as the representative value (single-run behaviour unchanged)
            
            risk_payload = aggregate_votes(vote_results)
            # 施加 CVSS 分段 FVuln 上限，修正系统性虚高
            _cvss_str = str(vulnerability_info.get("vul_cvss_score", "") if vulnerability_info else "")
            risk_payload = _cap_fvuln_by_cvss(risk_payload, _cvss_str)
            # -------------------------------------------------------------------

            final_record = {
                "task": task.__dict__,
                "vfind": vfind_info,
                "module_locator": module_locator_result,
                "component_summary": component_summary,
                "risk_assessment": risk_payload,
                "vote_n": vote_n,
                "vote_results": vote_results,
            }
            (task_dir / "final_record.json").write_text(json.dumps(final_record, ensure_ascii=False, indent=2), encoding="utf-8")

            row["RiskLevel"] = risk_payload.get("final_result", {}).get("risk_level", "")
            row["FVuln"] = risk_payload.get("scoring_factors", {}).get("f_vuln", {}).get("score", "")
            row["FThreat"] = risk_payload.get("scoring_factors", {}).get("f_threat", {}).get("score", "")
            row["FBusiness"] = risk_payload.get("scoring_factors", {}).get("f_business", {}).get("score", "")
            row["VoteN"] = vote_n
            row["Status"] = "success"
        except Exception as exc:
            LOGGER.warning("eval pipeline failed for %s %s %s: %s", task.project, task.tag, task.cve, exc)
            append_debug_log(debug_dir, f"eval pipeline failed for {task.project}/{task.tag}/{task.cve}: {exc}")
            row["Status"] = "failed"
            row["Error"] = str(exc)
        result_rows.append(row)

    return pd.DataFrame(result_rows)


def main() -> None:
    LOGGER.info("workflow_unified main() start")
    args = parse_args()
    ensure_dependencies()
    debug_dir = ensure_debug_dir(args.debug_dir)
    append_debug_log(debug_dir, f"==== run started at {time.strftime('%Y-%m-%d %H:%M:%S')} ====")
    append_debug_log(debug_dir, f"argv: {' '.join(sys.argv)}")
    headers = build_headers(args.github_token)
    projects = load_projects(args.projects_excel)
    cve_df = load_cve_database(args.cve_excel)

    write_debug_dataframe(pd.DataFrame([vars(repo) for repo in projects]), debug_dir / "projects_loaded.xlsx", "已加载项目")
    write_debug_dataframe(cve_df, debug_dir / "cve_loaded.xlsx", "已加载CVE数据")

    if args.run_codewiki and not args.run_eval:
        codewiki_rows = run_codewiki_for_projects(projects, debug_dir)
        write_debug_dataframe(pd.DataFrame(codewiki_rows), debug_dir / "codewiki_runs.xlsx", "CodeWiki 执行结果")
        LOGGER.info("CodeWiki 阶段完成，继续执行版本爬取与后处理流程")

    crawled_rows: List[Dict[str, str]] = []

    # 如果用户请求跳过匹配并且已有 output Excel，则直接加载并跳过爬取/匹配阶段
    if getattr(args, "skip_matching", False) and Path(args.output_excel).is_file():
        LOGGER.info("--skip-matching 启用：从已存在的输出文件加载结果: %s", args.output_excel)
        result_df = pd.read_excel(args.output_excel)
        crawled_df = pd.DataFrame([], columns=["Project", "Tag", "Component", "Version"])  # 占位，保持后续逻辑兼容
    else:
        for repo in projects:
            repo_rows = crawl_project_versions(repo, args.top_tags, headers)
            crawled_rows.extend(repo_rows)
            repo_debug_name = sanitize_filename(f"{repo.project}_{repo.language}_crawl")
            write_debug_dataframe(pd.DataFrame(repo_rows), debug_dir / f"{repo_debug_name}.xlsx", f"项目 {repo.project} 爬取结果")

        crawled_df = pd.DataFrame(crawled_rows, columns=["Project", "Tag", "Component", "Version"])
        write_debug_dataframe(crawled_df, debug_dir / "all_crawled_rows.xlsx", "全部爬取结果")

        result_df = build_result_dataframe(
            crawled_rows,
            cve_df,
            args.openai_base_url,
            args.openai_api_key,
            args.openai_model,
        )
        write_debug_dataframe(result_df, debug_dir / "final_result_debug.xlsx", "最终结果")

    if crawled_df.empty:
        LOGGER.warning("本次运行未爬取到任何组件记录，请优先检查 debug_output 下各项目 crawl 文件和 debug.log")
        append_debug_log(debug_dir, "WARNING: no crawled rows were produced")
    if result_df.empty:
        LOGGER.warning("本次运行最终结果为空，请检查组件版本提取和 CVE 匹配逻辑")
        append_debug_log(debug_dir, "WARNING: final result is empty")

    result_df.to_excel(args.output_excel, index=False)
    append_debug_log(debug_dir, f"result written to {args.output_excel}, rows={len(result_df)}")

    triggered_cves_by_project: Dict[str, Set[str]] = {}
    if args.run_vfind:
        for repo in projects:
            try:
                clone_repo(repo.url)
            except Exception as exc:
                LOGGER.warning("clone repo failed for %s: %s", repo.project, exc)

    vfind_cve_list: List[Dict[str, str]] = []
    if args.run_vfind or args.run_nvd:
        LOGGER.info("开始 vfind/nvd 阶段")
        vfind_cve_list = run_post_processing_pipeline(args, debug_dir)
        for item in vfind_cve_list or []:
            project_name = str(item.get("repo_name") or "").strip()
            cve_id = str(item.get("cve_id") or "").strip()
            if not project_name or not cve_id:
                continue
            project_set = triggered_cves_by_project.setdefault(project_name, set())
            project_set.add(cve_id)

    if args.run_eval and not args.run_vfind and not triggered_cves_by_project:
        resumed_triggered = load_triggered_cves_from_existing_vfind()
        if resumed_triggered:
            triggered_cves_by_project = resumed_triggered
            append_debug_log(
                debug_dir,
                "Resumed triggered CVEs from existing workflow_output/cvelist/non_empty_sinks.json",
            )

    selected_tags: Dict[str, str] = {}
    if args.run_eval:
        LOGGER.info("开始 eval 分析阶段")
        if triggered_cves_by_project:
            selected_tags = select_top_tags_by_triggered_cves(result_df, triggered_cves_by_project)
        if args.run_codewiki and selected_tags:
            filtered_projects = [repo for repo in projects if repo.project in selected_tags]
            codewiki_rows = run_codewiki_for_projects(filtered_projects, debug_dir, selected_tags)
            write_debug_dataframe(pd.DataFrame(codewiki_rows), debug_dir / "codewiki_runs.xlsx", "CodeWiki 执行结果")
        if selected_tags:
            tasks = build_analysis_tasks(projects, result_df, selected_tags=selected_tags, triggered_cves_by_project=triggered_cves_by_project)
            tasks_df = pd.DataFrame([task.__dict__ for task in tasks])
            write_debug_dataframe(tasks_df, debug_dir / "eval_tasks.xlsx", "eval 分析任务")
            eval_df = run_eval_pipeline(tasks, args, debug_dir)
            write_debug_dataframe(eval_df, debug_dir / "eval_results.xlsx", "eval 阶段结果")
            final_assessment_path = Path("workflow_output") / "final_assessment.xlsx"
            final_assessment_path.parent.mkdir(parents=True, exist_ok=True)
            eval_df.to_excel(final_assessment_path, index=False)
            append_debug_log(debug_dir, f"final assessment written to {final_assessment_path}, rows={len(eval_df)}")

    LOGGER.info("完成，结果已写入 %s；调试文件目录：%s", args.output_excel, debug_dir)


if __name__ == "__main__":
    main()
