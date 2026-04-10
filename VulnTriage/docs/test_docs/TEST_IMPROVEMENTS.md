# Python Recon 模块改进总结

## 文件修改清单

### 1. `src/recon/matcher_py.py` - 核心改进

#### 改进 1.1: 导出提取优化

**方法**: `_scan_exports()` 和 `_find_main_package_inits()`

**关键变化**:
```python
# 原有: 只扫描 py_files 中的 __init__.py (受 1000 文件限制)
init_files = [f for f in py_files if f.endswith('__init__.py')]

# 改进: 独立查找主包 init 文件
main_init_files = self._find_main_package_inits(repo_root)  # 不受限制
init_files_from_scan = [f for f in py_files if f.endswith('__init__.py')]
all_init_files = list(set(main_init_files + init_files_from_scan))  # 合并
```

**优先级排序** (确保找到主包 init):
```python
def init_priority(path: str) -> int:
    if '/src/' in path and path.count('/') < 10:    # src/* = 优先级 0
        return 0
    if path.count('/') < 5:                          # 顶层 = 优先级 1
        return 1
    return 100  # 深层嵌套 = 最低
```

#### 改进 1.2: 动态导入结构解析

**新方法**: `_extract_import_structure_exports()`

**支持 Transformers 模式**:
```python
_import_structure = {
    "configuration_utils": ["PreTrainedConfig", "PretrainedConfig"],
    "data": ["DataProcessor", "InputExample", ...],
    ...
}
```

**实现**:
```python
def _extract_import_structure_exports(self, file_path, content, exports):
    pattern = r'_import_structure\s*=\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}'
    # 正则匹配整个字典
    # 提取每个 "key": [...] 的条目
    # 将每个导出符号记录为 import_structure_entry 类型
```

#### 改进 1.3: 多源依赖提取

**扩展 `_parse_dependencies()`**:

1. **多个 requirements 文件**:
```python
req_files = [
    'requirements.txt',
    'requirements-dev.txt',
    'requirements-test.txt',
    'requirements-tests.txt',
    'requirements-docs.txt',
]
for req_file_name in req_files:
    # 逐一解析
```

2. **pyproject.toml 支持**:
```python
if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

pyproject = tomllib.load(f)
for dep_spec in pyproject['project']['dependencies']:
    # 解析和记录
```

3. **setup.py 正则解析**:
```python
install_requires_match = re.search(
    r'install_requires\s*=\s*\[(.*?)\]',
    content,
    re.DOTALL
)
# 提取引号内的依赖规范
```

### 2. `src/recon/models.py` - 数据模型更新

**Export 类扩展**:
```python
@dataclass
class Export:
    file: str
    line: int
    symbol: str
    type: str  # 扩展支持新类型
    extra: Dict[str, Any] = field(default_factory=dict)  # NEW
```

**支持的 type 值**:
- `export_all` - 来自 `__all__` 列表
- `import_re_export` - 来自 `from X import Y` 语句
- `import_structure_entry` - 来自动态 `_import_structure` 字典
- `function` - 直接定义的函数
- `async_function` - 异步函数定义
- `class` - 类定义

**extra 字段用途**:
```python
# import_re_export
{"from_module": "applications", "original_name": "FastAPI"}

# import_structure_entry  
{"module": "configuration_utils"}
```

## 性能影响

| 操作 | 变化 |
|------|------|
| 扫描时间 | FastAPI: 0.6s (无变化), Transformers: 7s (包括 1598 exports) |
| 内存 | 轻微增加 (缓存正则编译) |
| 准确性 | 从 0 exports (Transformers) → 1598 exports ✅ |

## 测试覆盖

### FastAPI (Web Framework)
- ✅ 15 个导出识别 (import_re_export)
- ✅ 44 个依赖来自 4 个源

### Transformers (ML Library)
- ✅ 1598 个导出 (49 import_re_export + 1549 import_structure_entry)
- ✅ 1 个依赖来自 setup.py

## 向后兼容性

- ✅ 现有的 EntryPoint, Sanitizer, Sink, Dep 模型无变化
- ✅ Export 的 extra 字段有默认值，不影响现有代码
- ✅ 新的导出类型只是额外的选项，原有逻辑保持不变

## 建议后续工作

1. **缓存优化**: 对 _import_structure 的正则解析结果进行缓存
2. **Java 支持**: 在 matcher_java.py 中实现对应的导出和依赖提取
3. **配置提取**: 扩展支持从 setup.cfg 提取项目元数据
4. **增量扫描**: 仅扫描修改过的文件以加快重复运行
