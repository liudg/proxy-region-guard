# 代理地区卫士 (Proxy Region Guard)

Windows 桌面端代理出口地区实时防漂移监控、进程安全熔断、系统时区/区域一键同步，以及 **Claude / Antigravity 跨订阅专属节点独立代理启动器**。

## 核心特性

1. **三通道相互解耦架构**
   - **Antigravity 启动器专栏（纯代理指定）**：支持从任意已激活或未激活的 Clash Verge Rev 订阅组中挑选指定节点，动态在 Mihomo 内核注入专属本地端口（默认 `127.0.0.1:27898`）与 `PROCESS-NAME` 规则（覆盖 `Antigravity.exe` 及 `language_server_windows_x64.exe`），并通过命令行 `--proxy-server` 与环境变量全链路绑定代理；纯分流启动，不触发强杀或弹窗拦截。
   - **Claude 专栏（三重强校验 + 唯一安全启动入口）**：独立绑定专属本地端口（默认 `127.0.0.1:27897`），强制校验 `[Claude 选定节点真实出口地区] == [Windows 系统区域] == [Windows 系统时区]` 及目标服务（Google / Claude）地区一致性；支持拦截外部未授权直接启动的 Claude Desktop，运行期一旦出现节点地区漂移、断连或系统时区不一致即毫秒级熔断进程树（含 `cowork-svc.exe` 等关联后台服务）。
   - **实时监控与进程守护专栏**：监控系统代理或主代理通道的实时落地出口，偏离默认保护地区或断连时自动终止自定义受保护进程列表。

2. **真实落地出口穿透检测 + 目标服务地区真伪核验**
   - 经由对应代理隧道并发请求全球回显端点（Cloudflare Connectivity Trace / AWS CheckIP 等），100% 获取远端真实落地出口公网 IP。
   - 内置 `GeoLite2-Country` 离线 `.mmdb` 数据库（支持 IPv4 与 IPv6），毫秒级纯本地解析国家/地区代码与中文名。
   - 针对部分机场“分流伪装节点”（测速网站走 A 国、Google/Claude 实际分流走 B 国），主动对 `www.google.com/generate_204`、`claude.ai/cdn-cgi/trace` 发起实测核验并拦截地区不符节点。

3. **Windows 系统时区与区域一键同步 & 安全还原**
   - 内置全球国家/地区到 Windows 标准时区 ID 的映射表，针对美、加、澳、俄、巴等多时区国家自动通过出口 IP 精准识别城市级 IANA 时区。
   - 支持一键将 Windows 系统时区与系统国家/地区（GeoID / Locale）同步至目标代理地区，或一键安全还原为中国默认时区（`China Standard Time` / `CN`），切换前自动检测并清理冲突进程以防暴露。

4. **双擎变更捕获与置顶强提醒**
   - **本地事件实时驱动 + 轻量心跳兜底**：自动连接本机 Clash 系列客户端（同時支持 Windows Named Pipe 与本地 HTTP 控制端口），监听订阅重载、节点切换、系统代理注册表与虚拟网卡变动。
   - **系统托盘状态变色 + 独立置顶警告弹窗**：屏幕右下角 `screen-saver` 级置顶弹窗，不抢占当前输入焦点，支持快捷处置。

## 启动与打包命令

### 方式一：双击快捷启动（日常使用推荐）
直接双击项目根目录下的 **[`启动应用.bat`](./启动应用.bat)** 即可启动桌面程序。

### 方式二：命令行启动与打包
```powershell
# 构建并启动正式桌面窗口
npm start

# 开发调试模式（支持前端热更新）
npm run dev

# 仅编译前后端生产代码
npm run build

# 打包 Windows x64 绿色免安装发行版（输出至 release/代理地区卫士-win32-x64）
npm run package
```
