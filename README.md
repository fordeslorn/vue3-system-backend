# vue3-system-backend
The backend system supporting the vue3-system.

## Deployment
To deploy the backend system, follow these steps:

1. **Dependencies**
   The backend system needs a database like `postgresql` and a `redis` instance running. 
   Use Docker to quickly set them up.
   Example:
   ```bash
    docker run --name pg_sys_backend -e POSTGRES_PASSWORD=pass -e POSTGRES_USER=user -e POSTGRES_DB=db -v pgdata:/var/lib/postgresql/data -p 5432:5432 -d postgres:18
    docker run --name redis_sys_backend -v redis_data:/data -p 6379:6379 -d redis:8
   ```

   Then, you need to create a table named `users` in the database. You can use the following SQL command:
   ```sql
   CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now());
    ```

2. **Environment Variables**
    Create a `.env` file in the root directory of the project and set the following environment variables:
    ```env
    # The postgres db connection url
    DATABASE_URL=postgres://user:pass@localhost:5432/db?sslmode=disable
    
    # The redis addr
    REDIS_ADDR=localhost:6379
    
    # The cookie domain
    COOKIE_DOMAIN=localhost

    # The allowed origins for CORS(The frontend address)
    CORS_ALLOWED_ORIGINS=http://localhost:5173

    # SMTP Configuration  
    SMTP_HOST=your_smtp_server.com
    SMTP_PORT=587
    SMTP_USER=your_email@example.com
    # Notice: This should be an app-specific password if you are using services like Gmail
    SMTP_PASS=your_app_specific_password
    ```
3. **Deploy the Backend**
    Run:
    cd to the project directory and execute:
    ```bash
    go run ./cmd/main
    ```
    The backend server should now be running and accessible at `http://localhost:8080`. <br/> 
    
    Build:
    ```bash
    go build -o ./dist/vue3-system-backend.exe ./cmd/main
    ./dist/vue3-system-backend.exe
    ```

    For production build:
    ```bash
    go build -ldflags="-s -w" -o ./dist/vue3-system-backend-slim.exe ./cmd/main 
    ./dist/vue3-system-backend-slim.exe
    ```

## Project Structure
<details>
<summary>Tree</summary>
<pre><code>
management-system-backend/
├── cmd/                  # 项目的可执行文件入口
│   └── main/             # 主应用程序
│       └── main.go       # 程序启动、依赖注入和服务器初始化
├── config/               # 配置管理
│   └── config.go         # 加载环境变量、配置文件和数据库连接
├── internal/             # 私有应用和库代码 (项目内部使用)
│   ├── api/              # API 层，处理 HTTP 请求
│   │   ├── auth_handlers.go    # 认证相关的处理器
│   │   ├── captcha_handlers.go # 验证码处理器
│   │   ├── handlers.go         # 处理器的主结构体和依赖
│   │   ├── routes.go           # 定义所有 API 路由
│   │   └── user_handlers.go    # 用户信息相关的处理器
│   ├── auth/             # 认证和授权逻辑
│   │   ├── captcha.go          # 验证码生成和验证逻辑
│   │   ├── middleware.go       # Gin 中间件 
│   │   └── session.go          # Session 管理 (基于 Redis)
│   ├── core/             # 核心业务模型/领域对象
│   │   └── models.go           # 定义数据结构 (如 User)
│   └── store/            # 数据存储层 (数据库交互)
│       └── user_store.go       # 用户数据的增删改查操作
├── assets/               # 静态资源
│   └── captcha_images/   # 验证码图片资源
│       ├── other/
│       └── white/
├── go.mod                # Go 模块依赖定义
├── go.sum                # 依赖项的校验和
├── LICENSE               # 项目许可证
└── README.md             # 项目说明文档
</code></pre>
</details>