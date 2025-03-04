# Container_runtime_scanner

**Container Runtime Scanner** 是一个使用 Go 语言编写的容器运行时扫描工具，旨在对容器环境进行漏洞扫描、渗透测试与安全检测，并提供可视化的前端进行操作。

本项目采用了常见的 Go 目录组织方式，将可执行入口放在 `cmd/` 下，将核心业务逻辑放在 `internal/` 下，并单独维护前端代码。

```
csharp复制编辑Container_runtime_scanner/
├── cmd/
│   └── scanner/
│       └── main.go           # 主程序入口
├── frontend/                 # 前端项目 (Node.js/React/Vue等)
│   ├── package.json
│   ├── package-lock.json
│   └── node_modules/
├── internal/
│   ├── data/
│   │   ├── exp/
│   │   ├── data_utils.go
│   │   └── vul_database.go   # 漏洞数据库相关
│   ├── docker/
│   │   ├── controller.go     # Docker 相关操作
│   │   └── utils.go
│   ├── pentest/
│   │   └── main_part.go      # 渗透测试相关逻辑
│   └── web/
│       └── route.go          # 路由与接口定义
├── vendor/                   # (可选) 依赖的vendor目录
├── go.mod                    # Go Modules 配置文件
├── main.go                   # (可选) 也可以放在 cmd/scanner/main.go
└── README.md
```

## 功能特性

- **漏洞扫描**：基于内置漏洞数据库，对容器镜像或运行时环境进行扫描。
- **Web 接口**：通过前端与服务相交互
