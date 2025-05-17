Secure User System
一个基于 Flask 的安全用户管理系统，支持用户认证、登录日志记录、数据脱敏、接口健康检查等功能，适合用于学习和展示 Web 安全开发实践。

功能列表
用户注册与登录（JWT 认证）
登录日志记录与统计（成功/失败）
登录趋势可视化（Chart.js 折线图）
CSV 导出登录日志
接口健康检查（/api/status）
字段脱敏展示（用户名、邮箱）
ZAP 安全扫描支持

安全特性
JWT Token 身份验证，存储于 HttpOnly Cookie
接口探针 /api/status，用于健康检查和安全扫描
字段脱敏装饰器 @sensitive_output()，支持 JSON 配置控制
支持 OWASP ZAP 自动化安全测试

安装与运行
克隆项目：
git clone https://github.com/peepeew/secure-user-system.git
cd secure-user-system

项目结构
secure-user-system/
├── app.py
├── models.py
├── templates/
│   ├── login.html
│   ├── dashboard.html
│   └── ...
├── static/
│   └── ...
├── login.log
├── requirements.txt
└── README.md
