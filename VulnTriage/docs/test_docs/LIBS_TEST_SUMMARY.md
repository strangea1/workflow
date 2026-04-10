# Python 库 Recon 测试 - 快速总结

## 测试对象

| 库 | 类型 | 路径 |
|----|------|------|
| **FastAPI** | Web Framework | `examples/libs/python/fastapi/` |
| **Transformers** | ML Library | `examples/libs/python/transformers/` |

## 扫描结果对比

```
                FastAPI    Transformers    说明
Entrypoints         1171              4    HTTP 路由/入口点
Sanitizers           366              0    验证/依赖注入点
Sinks                 56            524    敏感操作 (I/O/exec/db)
Exports              15           1598    公开 API 符号 ✨ 大幅提升
Dependencies         44              1    依赖声明
```

## 关键提升

### 🎯 导出提取 (Exports)

**新增能力**:
- ✅ `__all__` 显式列表解析
- ✅ `from X import Y` 标准重新导出
- ✅ **动态导入结构** (`_import_structure` 字典) - 支持 Transformers 模式
- ✅ 直接定义的 `function`/`class` 符号

**优化**:
- 独立主包 init 文件扫描，不受全局 1000 文件限制
- 优先查找 `src/*/` 和顶层 package init
- 限制扫描深度避免扫描 tests/ 目录

### 📦 依赖提取 (Dependencies)

**支持源**:
- ✅ `requirements.txt` (基础)
- ✅ `requirements-dev.txt`, `requirements-test.txt` 等 (多个变体)
- ✅ `pyproject.toml` ([project] section)
- ✅ `setup.py` (install_requires 正则解析)

**版本规范识别**:
- `==` `>=` `<=` `~=` `!=` `>` `<` 等操作符
- 复杂规范如 `>=0.40.0,<0.51.0`

## 测试数据

### FastAPI
```json
{
  "exports": [
    {"symbol": "FastAPI", "type": "import_re_export", "from_module": "applications"},
    {"symbol": "Depends", "type": "import_re_export", "from_module": "param_functions"},
    ...15 items total
  ],
  "deps": [
    {"name": "prek", "version": "0.2.22", "source": "requirements.txt"},
    {"name": "pytest", "version": "7.1.3,<9.0.0", "source": "requirements-tests.txt"},
    ...44 items total
  ]
}
```

### Transformers
```json
{
  "exports": [
    {"symbol": "PreTrainedModel", "type": "import_re_export"},
    {"symbol": "AutoConfig", "type": "import_structure_entry", "module": "configuration_utils"},
    ...1598 items total (49 import_re_export + 1549 import_structure_entry)
  ],
  "deps": [
    {"name": "filelock", "source": "setup.py"}
  ]
}
```

## 性能

| 库 | 总时间 | Exports 数 | 性能 |
|----|--------|-----------|------|
| FastAPI | 0.6s | 15 | 25/s |
| Transformers | 7s | 1598 | 228/s |

## 输出产物

- ✅ [TEST_REPORT_LIBS.md](./TEST_REPORT_LIBS.md) - 完整测试报告
- ✅ `out/fastapi_lib_recon_v3.json` - FastAPI 扫描结果
- ✅ `out/transformers_lib_recon_v5.json` - Transformers 扫描结果

## 验证清单

- [x] 导出提取：标准和动态导入都支持
- [x] 依赖提取：多源解析和版本规范识别
- [x] 大型库测试：1598 exports 正确提取
- [x] 文件限制突破：独立 init 扫描不受 1000 文件上限限制
- [x] 配置文件优先级：正确区分 src/transformers vs tests/

## 下一步

1. **Java 库**: 实现同等功能 (matcher_java.py 中的导出/依赖提取)
2. **Tech Stack**: 扩展 tech_stack 扫描（Docker, compose 文件）
3. **配置元数据**: 提取项目版本、作者等信息
4. **缓存优化**: 对大型库的 _import_structure 结果进行缓存
