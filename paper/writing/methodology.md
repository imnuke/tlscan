# Methodology

本章详细阐述本文提出的SSL/TLS客户端安全分析方法。我们首先在§IV-A中给出系统整体架构概览，随后在§IV-B中介绍分层安全模型的构建方法，§IV-C中阐述多智能体协同分析框架的设计，§IV-D中描述跨边界条件追踪技术，最后在§IV-E中说明静态分析引擎的实现。

---

## A. 系统概览 (System Overview)

### A.1 设计目标

本系统旨在实现固件级SSL/TLS客户端安全配置的自动化分析。区别于现有工具仅支持单一程序的静态检查，本系统具备以下核心能力：(1) 支持多种程序类型的分析，包括编译型二进制程序、PHP脚本、Shell脚本等；(2) 识别依赖运行时条件的安全配置；(3) 跨越程序边界追踪配置变量的实际取值。

### A.2 整体架构

系统采用两阶段设计，如图1所示。

**离线阶段 (Offline Phase)。** 本阶段从RFC协议规范中提取与实现无关的安全要求，并将其映射为针对特定SSL/TLS库的检测规则。该过程利用大语言模型的语义理解能力，自动生成覆盖OpenSSL、libcurl、GnuTLS、mbedTLS等主流库的规则集。

**在线阶段 (Online Phase)。** 给定待分析的固件镜像，系统首先执行目标发现，识别固件中使用SSL/TLS的客户端程序。随后，多智能体分析框架对每个目标程序执行安全规则检查、数据流追踪和跨边界分析，最终生成包含完整追踪路径的安全评估报告。

```
┌────────────────────────────────────────────────────────────────────────┐
│                           Offline Phase                                 │
├────────────────────────────────────────────────────────────────────────┤
│  RFC Documents ──▶ LLM ──▶ Abstract Security Rules                     │
│                            (Implementation-Agnostic)                    │
│                                    │                                    │
│                                    ▼                                    │
│                    ┌──────────────────────────────┐                    │
│                    │  LLM + Library Documentation  │                    │
│                    └──────────────────────────────┘                    │
│                                    │                                    │
│                                    ▼                                    │
│        ┌────────────┬────────────┬────────────┬────────────┐          │
│        │  OpenSSL   │  libcurl   │   GnuTLS   │  mbedTLS   │ ...      │
│        │  Rules     │  Rules     │   Rules    │  Rules     │          │
│        └────────────┴────────────┴────────────┴────────────┘          │
└────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                           Online Phase                                  │
├────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐   ┌──────────────────────────────────────────┐   │
│  │ Target Discovery │──▶│      Multi-Agent Analysis Framework      │   │
│  │ (Heuristic Scan) │   │                                          │   │
│  └─────────────────┘   │  SSL Agent ──▶ Dataflow Agent ──▶ ...    │   │
│                         │         ↓              ↓                  │   │
│                         │    ┌────────────────────────┐            │   │
│                         │    │   Shared State Store   │            │   │
│                         │    └────────────────────────┘            │   │
│                         │                    ↓                      │   │
│                         │           Security Report                 │   │
│                         └──────────────────────────────────────────┘   │
│                                                                          │
└────────────────────────────────────────────────────────────────────────┘
```
**图1.** 系统整体架构

### A.3 分析目标识别

在执行安全分析之前，首先需要从固件中识别使用SSL/TLS的客户端程序。固件通常包含大量程序文件，但仅有一部分实际进行SSL/TLS通信。本系统支持分析多种类型的目标程序：

**编译型二进制程序。** 对于ELF格式的可执行文件和共享库，我们通过分析符号表（`.dynsym`, `.symtab`）中的导入符号，匹配预定义的SSL/TLS客户端特征函数集。表I列出了主要SSL/TLS库的特征函数。

| 库 | 强特征函数 | 弱特征函数 |
|---|-----------|-----------|
| OpenSSL | `SSL_connect`, `BIO_new_ssl_connect` | `SSL_set_verify`, `SSL_set_fd` |
| libcurl | `curl_easy_perform`, `curl_multi_perform` | `curl_easy_init`, `curl_easy_setopt` |
| GnuTLS | `gnutls_handshake`, `gnutls_record_send` | `gnutls_init`, `gnutls_credentials_set` |
| mbedTLS | `mbedtls_ssl_handshake`, `mbedtls_ssl_write` | `mbedtls_ssl_init`, `mbedtls_ssl_setup` |

**表I.** SSL/TLS客户端特征函数集

**脚本程序。** 本系统同样支持分析Shell脚本和PHP脚本中的SSL/TLS使用情况。对于Shell脚本，我们检测`curl`、`wget`等命令的调用及其SSL相关参数（如`--insecure`、`-k`）。对于PHP脚本，我们分析cURL扩展函数的调用模式（如`curl_setopt`设置`CURLOPT_SSL_VERIFYPEER`）。这种多语言支持能力源于我们方法的设计：安全规则在抽象层面定义，可自然映射到不同编程语言的SSL/TLS使用模式。

**置信度评分。** 仅凭符号引用不足以确定程序是否为SSL客户端：OpenSSL库也可能仅用于加密操作而非建立SSL连接，程序可能是服务端而非客户端。因此，我们根据符号组合计算置信度分数：

- **高置信度**：存在强特征函数（如`SSL_connect`）
- **中置信度**：存在客户端方法函数（如`TLS_client_method`）
- **低置信度**：仅存在多个弱特征函数

Algorithm 1给出了目标发现的完整流程。

```latex
\begin{algorithm}[t]
\caption{Analysis Target Discovery with Confidence Scoring}
\label{alg:discover-targets}
\KwIn{$firmware\_path$ -- Root path of extracted firmware}
\KwOut{List of $(program\_path, type, library, confidence)$ tuples}
\BlankLine
$candidates \gets []$\;
\BlankLine
\tcp{Phase 1: Binary program discovery}
$binaries \gets \textsc{FindAllELFFiles}(firmware\_path)$\;
\ForEach{$binary \in binaries$}{
    \lIf{$\textsc{IsSSLLibrary}(binary)$}{\Continue}
    $imports \gets \textsc{ExtractImportedSymbols}(binary)$\;
    \ForEach{$library \in \mathcal{L}$}{
        $confidence \gets \textsc{ComputeConfidence}(imports, library)$\;
        \lIf{$confidence \neq \textsc{None}$}{
            $candidates.\textsc{Append}((binary, \textsc{Binary}, library, confidence))$
        }
    }
}
\BlankLine
\tcp{Phase 2: Script program discovery}
$scripts \gets \textsc{FindScriptFiles}(firmware\_path)$\;
\ForEach{$script \in scripts$}{
    $content \gets \textsc{ReadFile}(script)$\;
    \If{$\textsc{ContainsSSLCommands}(content)$}{
        $library \gets \textsc{DetectSSLLibrary}(content)$\;
        $candidates.\textsc{Append}((script, \textsc{Script}, library, \textsc{High}))$\;
    }
}
\BlankLine
\Return{$\textsc{SortByConfidence}(candidates)$}\;
\end{algorithm}
```

---

## B. 分层安全模型 (Hierarchical Security Model)

本节阐述分层安全模型的构建方法。该模型从协议规范出发定义与实现无关的安全要求，再利用LLM映射到具体库的检测规则，从而实现对多种SSL/TLS库的统一支持。图X展示了分层演绎模型的整体结构。

### B.1 设计理念：从归纳到演绎的范式转变

**问题分析。** 现有SSL/TLS安全分析工具采用**归纳式**方法：观察具体API的误用模式，将其泛化为检测规则。这种自底向上的方法论存在根本局限——它只能检测已见过的模式，扩展到新库需要大量人工工作。

**本文方法。** 我们提出一种根本不同的范式：**演绎式**安全分析。我们不是问"什么API模式表示不安全"，而是问"协议**要求**什么才能保证安全"。这一转变类似于数学中从经验观察到公理化推理的演进，或物理学中从唯象模型到第一性原理计算的跨越。

**方法论对比。** 表X对比了传统方法与本文方法的核心差异：

| 维度 | 传统方法 | 本文方法 |
|------|---------|---------|
| **认识论** | 归纳（从实例到规则） | 演绎（从规范到检测） |
| **知识来源** | API文档 + 漏洞案例 | RFC协议规范 |
| **规则性质** | 经验模式 | 形式化语义约束 |
| **正确性保证** | 测试覆盖 | 规范溯源 |
| **扩展机制** | 人工编写 | 自动语义映射 |

**类比：公理化方法。** 我们的方法与数学中的**公理化方法**异曲同工。正如欧几里得几何从五条公理演绎出全部定理，我们的安全模型从协议规范演绎出全部检测规则。传统工具类似于经验几何——测量具体三角形并归纳规律；我们实践的是公理几何——建立公理（RFC规范），推导定理（抽象规则），证明推论（库特定检测）。

**层次分离。** 分层架构实现了关注点分离：

1. **协议规范层**回答"TLS应该做什么"——这是安全性的**定义**，独立于任何实现
2. **抽象规则层**回答"必须满足什么约束"——这是安全性的**要求**，与实现无关
3. **库检测层**回答"如何验证约束"——这是安全性的**检测**，针对具体API

这种分离带来两个关键优势：

**语义等价识别。** 传统模式匹配只能识别预定义的API调用序列。我们的语义翻译理解**意图**而非语法——它知道"设置一个总是返回1的验证回调"和"将CURLOPT_SSL_VERIFYPEER设为0"代表**相同的安全违规**：绕过证书验证。

**跨库/跨语言泛化。** 抽象规则在语义层面定义，自然支持多种SSL/TLS库（OpenSSL、libcurl、GnuTLS、mbedTLS）和多种编程语言（C二进制、PHP脚本、Shell脚本）。新增库支持仅需LLM执行一次语义映射，无需人工规则工程。

### B.2 与实现无关的安全要求

**设计动机。** 现有工具如SAMBA~\cite{samba}和SSLint~\cite{sslint}针对特定库（主要是OpenSSL）硬编码检测规则。这种方法存在两个根本局限：(1) 扩展到其他库需要大量人工工作；(2) 无法识别语义等价但模式不同的安全实现（如自定义证书验证逻辑）。

**方法设计。** 我们提出从协议层面定义安全约束的方法。具体而言，我们利用LLM从RFC文档（RFC 5246、RFC 8446、RFC 6125等）中自动提取与实现无关的安全要求。LLM能够：(1) 理解RFC中的规范性语言（MUST、SHOULD、MAY等）；(2) 识别与客户端安全相关的条款；(3) 将散落在多个RFC中的相关要求整合为统一规则集。

表II展示了提取得到的核心安全规则。

| 安全要求 | 来源 | 优先级 |
|---------|------|--------|
| SSL/TLS 使用检测 | RFC 5246 §7.4.4 | MUST |
| 证书链与有效期验证 | RFC 5280 §6 | MUST |
| 主机名验证 | RFC 6125 §6 | MUST |
| 协议版本强制 | RFC 8446, RFC 7525 | MUST |
| 密码套件选择 | RFC 7525 §4.2 | MUST |
| 证书吊销检查 | RFC 5280 §6.3 | RECOMMENDED |
| 证书签名算法强度 | RFC 7525 §4.3 | RECOMMENDED |
| 证书固定 | RFC 7469 | OPTIONAL |

**表II.** 从RFC提取的核心安全规则

每条规则以结构化格式描述协议层面的安全要求，不涉及任何具体API。例如，证书链验证规则定义为：

```
规则：证书链验证

安全要求：
- 客户端必须验证服务器证书链至受信任的根CA
- 必须验证链中每个证书的签名有效性
- 必须检查每个证书的有效期
- 根CA必须存在于客户端的信任存储中

违规行为：
- 跳过证书链验证
- 忽略证书有效期检查
- 验证失败后继续建立连接
```

### B.3 库特定规则生成

**映射机制。** 给定抽象安全规则和目标SSL/TLS库，LLM将安全要求映射为具体的检测规则。映射依赖两类知识来源：

1. **LLM预训练知识**：对主流库的API语义理解，包括正确使用模式和常见错误模式
2. **文档增强**：对于不常见的库或最新API，通过提供man pages或官方文档辅助映射

**映射示例。** 以证书链验证规则为例，其在不同库中的映射如表III所示。

| 库 | 检测规则 |
|----|---------|
| OpenSSL | 调用`SSL_CTX_set_verify()`或`SSL_set_verify()`设置`SSL_VERIFY_PEER`标志；若使用自定义回调，回调必须正确处理`preverify_ok`参数 |
| libcurl | `CURLOPT_SSL_VERIFYPEER`保持默认值1或显式设置为1；不能设置为0 |
| mbedTLS | 调用`mbedtls_ssl_set_authmode()`设置`MBEDTLS_SSL_VERIFY_REQUIRED` |
| curl CLI | 不使用`--insecure`或`-k`参数 |
| PHP cURL | `curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true)` |

**表III.** 证书链验证规则的库映射

**多语言支持。** 值得注意的是，本方法天然支持多种编程语言。由于安全规则在抽象层面定义，LLM可将其映射到任意使用对应SSL/TLS库的编程语言，包括C/C++编译的二进制程序、PHP脚本中的cURL扩展调用、Shell脚本中的curl/wget命令等。

### B.4 三态分析模型

**问题定义。** 传统工具仅提供二元判定（安全/不安全），无法处理嵌入式设备中普遍存在的条件依赖场景。实际系统中，安全配置往往不是静态固定的，而是由配置文件、命令行参数或环境变量动态控制。例如：

```c
if (config.verify_cert) {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
}
```

现有工具会报告「使用了SSL_VERIFY_PEER」，但无法判断`config.verify_cert`的实际取值。

**三态模型。** 为解决这一问题，我们提出三态分析结果模型：

设$\mathcal{R} = \{r_1, r_2, ..., r_n\}$为安全规则集合，对于每条规则$r_i$，定义其分析结果$\mathcal{S}(r_i) \in \{\textsc{Pass}, \textsc{Fail}, \textsc{Conditional}\}$：

- **PASS**：安全措施正确实现，无条件启用
- **FAIL**：安全措施缺失或被显式禁用
- **CONDITIONAL**：安全措施的启用依赖于运行时可变条件

**CONDITIONAL状态处理。** 当规则$r_i$的判定结果为CONDITIONAL时，系统提取影响该规则的条件变量集合$V_i = \{v_1, v_2, ..., v_k\}$，并为每个变量附加安全语义映射$M_i: \mathcal{D}(v_j) \rightarrow \{\textsc{Pass}, \textsc{Fail}\}$。后续的数据流分析阶段将追踪这些变量的实际取值，以确定最终安全状态。

---

## C. 多智能体协同分析框架 (Multi-Agent Collaborative Analysis Framework)

本节阐述多智能体分析框架的设计。该框架通过专门化智能体的协作，实现从规则检查到跨边界追踪的完整分析流程。

### C.1 框架架构

**设计原则。** SSL/TLS安全分析涉及多种异构能力：规则语义理解、程序反编译、数据流分析、文件系统搜索等。我们采用专门化智能体架构，每个智能体专注于单一职责，通过共享状态协调工作。

形式化地，定义智能体集合$\mathcal{A} = \{\mathcal{A}_{ssl}, \mathcal{A}_{df}, \mathcal{A}_{fw}, \mathcal{A}_{syn}\}$，其中：
- $\mathcal{A}_{ssl}$：SSL安全分析智能体，执行规则检查
- $\mathcal{A}_{df}$：数据流追踪智能体，追踪变量来源
- $\mathcal{A}_{fw}$：固件探索智能体，搜索跨边界资源
- $\mathcal{A}_{syn}$：综合报告智能体，汇总生成最终报告

**工作流程。** Algorithm 2给出了工作流执行的形式化描述。

```latex
\begin{algorithm}[t]
\caption{Multi-Agent Workflow Execution}
\label{alg:multi-agent-workflow}
\KwIn{$P$ -- Target program, $\mathcal{R}$ -- Security rule set, $F$ -- Firmware path}
\KwOut{$Report$ -- Security analysis report}
\BlankLine
\tcp{Initialize shared state}
$\Sigma \gets \textsc{InitState}(P, \mathcal{R}, F)$\;
\BlankLine
\tcp{Phase 1: SSL security analysis}
$\Sigma.results \gets \mathcal{A}_{ssl}.\textsc{Analyze}(P, \mathcal{R})$\;
\ForEach{$r \in \Sigma.results$}{
    \lIf{$r.status = \textsc{Conditional}$}{
        $\Sigma.df\_tasks.\textsc{Extend}(r.conditions)$
    }
}
\BlankLine
\tcp{Phase 2-3: Iterative tracing loop}
\While{$\Sigma.df\_tasks \neq \emptyset \vee \Sigma.fw\_tasks \neq \emptyset$}{
    \tcp{Dataflow analysis}
    \While{$\Sigma.df\_tasks \neq \emptyset$}{
        $task \gets \Sigma.df\_tasks.\textsc{Pop}()$\;
        $trace \gets \mathcal{A}_{df}.\textsc{Trace}(task)$\;
        $\textsc{AddToGraph}(\Sigma.traces, trace)$\;
        $\textsc{GenerateFollowupTasks}(\Sigma, trace)$\;
    }
    \tcp{Firmware exploration}
    \While{$\Sigma.fw\_tasks \neq \emptyset$}{
        $task \gets \Sigma.fw\_tasks.\textsc{Pop}()$\;
        $result \gets \mathcal{A}_{fw}.\textsc{Execute}(task)$\;
        $\textsc{ProcessFirmwareResult}(\Sigma, result)$\;
    }
}
\BlankLine
\tcp{Phase 4: Synthesis}
\Return{$\mathcal{A}_{syn}.\textsc{GenerateReport}(\Sigma)$}\;
\end{algorithm}
```

**迭代追踪机制。** 数据流分析和固件探索形成迭代循环。当数据流追踪发现变量来源为外部调用时，生成跨程序分析任务；当发现来源为配置文件时，生成配置读取任务。固件探索执行后可能产生新的数据流任务（如发现新的调用者程序）。循环持续直至所有任务处理完毕。

### C.2 状态驱动的上下文管理

**问题分析。** 多智能体系统面临上下文传递的挑战。传统方法在智能体间传递自然语言形式的历史上下文，导致：(1) 上下文长度膨胀，每次分析调用累积大量冗余信息；(2) LLM注意力分散，长上下文降低分析准确性；(3) token消耗剧增，影响系统成本和效率。

**状态驱动架构。** 我们设计了结构化共享状态$\Sigma$替代自然语言上下文传递：

$$\Sigma = \langle \mathcal{C}, \mathcal{R}_{result}, \mathcal{T}, \mathcal{Q}_{df}, \mathcal{Q}_{fw} \rangle$$

其中：
- $\mathcal{C}$：分析上下文（目标程序路径、规则集、固件路径）
- $\mathcal{R}_{result}$：规则检查结果映射
- $\mathcal{T}$：统一追踪图（详见§C.5）
- $\mathcal{Q}_{df}$：待处理数据流任务队列
- $\mathcal{Q}_{fw}$：待处理固件探索任务队列

**设计原则。**

1. **单一职责**：每个智能体仅执行单一任务，无需了解完整分析历史。例如，$\mathcal{A}_{df}$仅需知道追踪哪个函数的哪个变量，无需理解SSL安全语义。

2. **按需注入**：调用智能体时，仅从$\Sigma$中提取该智能体必需的最小信息集。

3. **结果解析与丢弃**：智能体执行完毕后，将结果解析为结构化数据存入$\Sigma$，丢弃智能体的完整对话历史。

### C.3 SSL安全分析智能体

$\mathcal{A}_{ssl}$负责基于安全规则对目标程序执行全面检查。

**输入**：目标程序$P$、库特定规则集$\mathcal{R}$

**输出**：规则检查结果$\{(r_i, status_i, evidence_i, conditions_i)\}$

对于二进制程序，$\mathcal{A}_{ssl}$通过静态分析引擎获取反编译代码，分析SSL/TLS API的调用模式。对于脚本程序，直接分析源代码中的SSL相关函数调用或命令行参数。

当发现安全配置依赖运行时变量时，$\mathcal{A}_{ssl}$将规则标记为CONDITIONAL，并提取条件变量及其安全语义映射：

$$conditions_i = \{(func, var, mapping)\}$$

其中$mapping: value \rightarrow \{\textsc{Pass}, \textsc{Fail}\}$定义变量取值的安全含义。

### C.4 数据流追踪智能体

$\mathcal{A}_{df}$负责追踪条件变量的数据来源。

**后向切片方法。** 我们采用后向切片（Backward Slicing）作为核心追踪方法。给定切片标准$(function, variable)$，从目标变量出发沿数据流逆向追溯所有影响该变量的语句。

后向切片的优势在于：(1) 目标导向，仅分析与目标变量相关的代码路径；(2) 天然支持跨函数、跨程序的追踪。

**来源分类。** 追踪终止于以下六类来源之一：

| 来源类型 | 描述 | 后续处理 |
|---------|------|----------|
| CONSTANT | 硬编码常量值 | 直接解析 |
| CONFIG_FILE | 配置文件读取 | 生成配置读取任务 |
| ENV_VAR | 环境变量 | 标记为外部控制 |
| CLI_ARG | 命令行参数 | 生成脚本发现任务 |
| EXTERNAL_CALL | 外部函数参数 | 生成跨程序分析任务 |
| UNKNOWN | 无法确定 | 标记为未解析 |

Algorithm 3给出了数据流追踪的完整流程。

```latex
\begin{algorithm}[t]
\caption{Backward Slicing based Dataflow Tracing}
\label{alg:backward-slicing}
\KwIn{$func$ -- Target function, $var$ -- Target variable, $P$ -- Program}
\KwOut{$VariableTrace$ with $source\_kind$ and $trace\_path$}
\BlankLine
$path \gets [\textsc{TraceStep}(\textsc{Start}, func, var)]$\;
$curr\_func \gets func$; $curr\_var \gets var$\;
\BlankLine
\While{\True}{
    $code \gets \textsc{GetCode}(P, curr\_func)$\;
    $source \gets \textsc{LLM.AnalyzeOrigin}(code, curr\_var)$\;
    \BlankLine
    \Switch{$source.type$}{
        \Case{\textsc{Constant}}{
            $path.\textsc{Append}(\textsc{TraceEnd}(source))$\;
            \Return{$\textsc{Trace}(path, value\!=\!source.value)$}\;
        }
        \Case{\textsc{ConfigFile}}{
            $path.\textsc{Append}(\textsc{TraceEnd}(source))$\;
            \Return{$\textsc{Trace}(path, task\!=\!\textsc{ConfigFetch})$}\;
        }
        \Case{\textsc{FunctionParam}}{
            \uIf{$\textsc{IsExported}(curr\_func)$}{
                $path.\textsc{Append}(\textsc{TraceEnd}(source))$\;
                \Return{$\textsc{Trace}(path, task\!=\!\textsc{CallerDiscovery})$}\;
            }
            \Else{
                $callers \gets \textsc{GetCallers}(P, curr\_func)$\;
                $path.\textsc{Append}(\textsc{CallSite}(callers[0]))$\;
                $curr\_func \gets callers[0]$\;
                $curr\_var \gets source.arg$\;
            }
        }
        \Case{\textsc{EnvVar} $\vee$ \textsc{CliArg} $\vee$ \textsc{Unknown}}{
            $path.\textsc{Append}(\textsc{TraceEnd}(source))$\;
            \Return{$\textsc{Trace}(path, source)$}\;
        }
    }
}
\end{algorithm}
```

### C.5 统一追踪图

**设计动机。** 跨边界追踪中，变量来源可能跨越多个程序和配置源。传统的线性追踪列表难以表达复杂的追踪关系：一个变量可能同时受多个源影响，一个导出函数可能被多个程序调用形成追踪分支。

**图结构定义。** 我们设计统一追踪图$G = (V, E)$存储所有追踪数据：

- $V$：追踪节点集合，每个节点$v \in V$表示一次追踪结果
- $E$：有向边集合，$e = (v_i, v_j)$表示$v_j$由$v_i$触发

每个追踪节点$v$包含：

$$v = (id, type, source\_path, func, var, value, path, status, children)$$

其中$type \in \{\textsc{MainBinary}, \textsc{CrossBinary}, \textsc{Config}, \textsc{Script}, \textsc{Env}\}$标识追踪类型。

**规则-追踪链接。** 为连接规则条件与追踪图，定义链接结构：

$$Link = (condition\_key, root\_ids, mapping, outcomes)$$

其中$condition\_key = func:var$标识规则条件，$root\_ids$为该条件对应的根追踪节点集合。

### C.6 固件探索智能体

$\mathcal{A}_{fw}$负责在固件文件系统中搜索跨边界资源，支持三类任务：

1. **调用者发现（Caller Discovery）**：搜索固件中调用指定导出函数的所有程序
2. **配置读取（Config Fetch）**：定位配置文件并提取指定配置项的值
3. **脚本发现（Script Discovery）**：查找调用目标程序的启动脚本，提取命令行参数

---

## D. 跨边界条件追踪 (Cross-Boundary Condition Tracing)

本节详细阐述跨边界追踪的技术细节，这是本方法区别于现有工作的核心创新。

### D.1 问题定义

**现有工作局限。** SAMBA~\cite{samba}考虑了跨程序调用，但其跨程序调用图仅记录调用关系，不包含数据流信息。它只能判断「程序A调用了程序B的函数F」，但无法确定传入的参数值。

**示例。** 考虑以下代码：

```c
// libupsclient.so
void upscli_connect(conn_t *conn, int flags) {
    if (flags & VERIFY_CERT) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    }
}
```

仅有调用图时，可知`/usr/bin/upsmon`调用了`upscli_connect()`，但无法确定`flags`参数的实际值，因而无法判断证书验证是否启用。

**本文方法。** 我们追踪`flags`参数在调用方程序中的取值来源，最终追溯到配置文件中的`CERTVERIFY`选项。

### D.2 多层追踪模型

变量的最终值可能需要多级追踪才能确定。我们设计支持递归嵌套的追踪模型：

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 1: Main Binary Trace                                  │
│  libupsclient.so: SSL_CTX_set_verify(ctx, mode=?)           │
│       └─ mode ← upscli_sslinit() 参数 a2                     │
│              └─ a2 ← upscli_connect() 参数 flags             │
│                      └─ source: EXTERNAL_CALL               │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼ 触发跨程序分析
┌─────────────────────────────────────────────────────────────┐
│  Layer 2: Cross-Binary Trace                                 │
│  /usr/bin/upsmon: upscli_connect(..., flags)                │
│       └─ flags ← parse_config("CERTVERIFY")                 │
│              └─ source: CONFIG_FILE (upsmon.conf)           │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼ 触发配置读取
┌─────────────────────────────────────────────────────────────┐
│  Layer 3: Config Resolution                                  │
│  /etc/nut/upsmon.conf: CERTVERIFY = 1                       │
│  resolved_value: "1" → mapping["1"] = PASS                  │
└─────────────────────────────────────────────────────────────┘
```

### D.3 多入口点检测

**问题。** 共享库的导出函数可能被多个程序调用，每个调用方可能传递不同的参数值：

```
libupsclient.so:upscli_connect(flags)
     ↑                    ↑                    ↑
  /usr/bin/upsmon      /usr/bin/upsc      /usr/sbin/upsd
  flags = 0x11         flags = 0x01        flags = 0x00
  (验证启用)            (验证启用)           (验证禁用)
```

**解决方案。** Algorithm 4给出了多入口点检测与跨边界追踪的完整流程。

```latex
\begin{algorithm}[t]
\caption{Multi-Entry-Point Cross-Boundary Tracing}
\label{alg:cross-boundary}
\KwIn{$trace_0$ -- Initial trace (ending with EXTERNAL\_CALL), $F$ -- Firmware path}
\KwOut{List of resolved traces}
\BlankLine
$results \gets []$\;
$queue \gets [(trace_0, trace_0.program)]$\;
\BlankLine
\While{$queue \neq \emptyset$}{
    $(trace, prog) \gets queue.\textsc{Pop}()$\;
    $func \gets trace.path.\textsc{Last}().external\_function$\;
    $param \gets trace.path.\textsc{Last}().parameter\_index$\;
    \BlankLine
    $callers \gets \textsc{SearchFirmware}(F, func)$\;
    \ForEach{$caller \in callers$}{
        $cont \gets \mathcal{A}_{df}.\textsc{Trace}(caller, func, param)$\;
        $extended \gets trace.\textsc{Extend}(cont)$\;
        \BlankLine
        \Switch{$cont.source\_kind$}{
            \Case{\textsc{Constant} $\vee$ \textsc{ConfigFile}}{
                $extended.value \gets \textsc{Resolve}(cont)$\;
                $results.\textsc{Append}(extended)$\;
            }
            \Case{\textsc{ExternalCall}}{
                $queue.\textsc{Append}((extended, caller))$\;
            }
            \lCase{\textsc{EnvVar} $\vee$ \textsc{CliArg}}{
                $results.\textsc{Append}(extended)$
            }
        }
    }
}
\Return{$results$}\;
\end{algorithm}
```

**结果聚合。** 给定所有追踪路径的解析结果，按以下规则聚合最终安全状态：

$$
\mathcal{S}_{final} =
\begin{cases}
\textsc{Fail} & \exists\, path: \mathcal{S}(path) = \textsc{Fail} \\
\textsc{Pass} & \forall\, path: \mathcal{S}(path) = \textsc{Pass} \\
\textsc{Conditional} & otherwise
\end{cases}
$$

---

## E. 静态分析引擎 (Static Analysis Engine)

本节简述为多智能体系统提供静态分析能力的基础设施。

### E.1 程序分析能力

**二进制程序分析。** 基于IDA Pro MCP Server实现，为智能体提供以下工具：

| 工具 | 功能 |
|-----|------|
| `decompile_function` | 获取函数反编译代码 |
| `get_callers` | 查找函数调用者 |
| `get_xrefs_to` | 获取地址交叉引用 |
| `is_entry_point` | 判断是否为导出函数 |
| `list_functions_filter` | 按模式搜索函数 |

**脚本程序分析。** 对于PHP和Shell脚本，直接解析源代码。智能体利用LLM的代码理解能力分析SSL/TLS相关的函数调用和命令行参数使用。

### E.2 固件文件系统分析

基于高性能文件搜索工具（fd、ripgrep）和ELF解析库（pyelftools）实现：

| 工具 | 功能 |
|-----|------|
| `search_files_by_name` | 按文件名模式搜索 |
| `search_files_by_content` | 按内容正则搜索 |
| `read_file` | 读取文件内容 |
| `find_function_references` | 查找导入函数的程序 |

### E.3 多程序会话管理

跨程序分析需要同时分析多个二进制程序。我们采用会话池设计，为每个被分析的二进制维护独立的IDA Pro会话，使用端口管理器动态分配通信端口，通过会话缓存避免重复初始化开销。

---

# 附录：非Methodology内容

以下内容不属于Methodology章节，但在设计过程中有所涉及，供后续章节参考。

## Motivation相关内容

### 研究问题与Challenges

| Challenge | 描述 | 对应解决方案 |
|-----------|------|-------------|
| C1: 安全模型的准确性与完备性 | 如何建立准确且完备的安全模型，涵盖各种SSL证书验证的规范和最佳实践 | 分层安全模型：从RFC自动提取与实现无关的规则 |
| C2: 检测的通用性与准确性 | 如何正确识别各种自定义算法以及配置依赖，判断SSL客户端在不同配置下的行为 | 三态分析模型 + 跨边界条件追踪 |
| C3: 自动化与可扩展性 | 如何全面自动化分析过程，减少人工干预，提高分析效率 | 多智能体协同框架 + 状态驱动架构 |

## 与现有工作对比

| 特性 | SAMBA | SSLint | 本文方法 |
|------|-------|--------|----------|
| 语义理解 | 模式匹配 | 图查询 | LLM语义推理 |
| 自定义验证逻辑 | ✗ | ✗ | ✓ |
| 条件依赖分析 | ✗ | ✗ | ✓ (三态模型) |
| 跨程序追踪 | 调用图 | ✗ | 数据流追踪 |
| 配置文件分析 | ✗ | ✗ | ✓ |
| 多语言支持 | ✗ | ✗ | ✓ |
| 多库支持 | OpenSSL | OpenSSL | 8种库 |

## LaTeX算法汇总

本Methodology章节包含以下核心算法：

| Algorithm | Section | Caption |
|-----------|---------|---------|
| Algorithm 1 | §A.3 | Analysis Target Discovery with Confidence Scoring |
| Algorithm 2 | §C.1 | Multi-Agent Workflow Execution |
| Algorithm 3 | §C.4 | Backward Slicing based Dataflow Tracing |
| Algorithm 4 | §D.3 | Multi-Entry-Point Cross-Boundary Tracing |

**LaTeX依赖**：
```latex
\usepackage[ruled,vlined,linesnumbered]{algorithm2e}
```
