# 代理地区卫士

Windows 桌面代理出口监控工具，提供 Claude 与 Antigravity 专属代理启动、地区检查、进程守护和系统时区同步。

## 专属代理

- Claude 和 Antigravity 分别使用独立的私有 Mihomo 进程，默认端口为 `127.0.0.1:27897`、`127.0.0.1:27898`。
- 从 Clash Verge 本地订阅及扩展配置读取节点。选择后保存节点、链式代理、DNS 代理依赖和证书文件的独立副本。
- Clash Verge 更新或删除源节点时，界面提示变化，运行中的专属通道继续使用副本。点击“应用节点更新”才会应用源节点的新配置。
- 节点 DNS 引用本机 Clash DNS 时，保存其明确的独立上游。无法确定上游、存在循环或依赖动态分流时拒绝应用，并提示在订阅中明确配置 `proxy-server-nameserver`。
- 私有内核意外退出后，在 60 秒内最多自动恢复三次，等待时间依次为 1、3、10 秒。失败后显示故障原因，可手动重新启动内核。
- 关闭管理窗口后，后台守护、私有内核和应用继续运行。再次启动卫士会打开管理窗口。
- 托盘菜单中的“退出代理地区卫士”会结束管理程序及 Claude 守护会话并移除托盘图标，Antigravity 和私有代理内核继续运行。
- 开发启动和打包程序默认共用 `%APPDATA%\代理地区卫士`，同时只运行一个管理实例。
- 当前专属通道适用于关闭 TUN 的环境。检测到 Clash Verge 开启 TUN 时，在屏幕右下角显示警告。同一次开启期间不会重复提醒；检测不到运行状态时显示未知状态。

## 应用守护

Claude 启动前检查专属出口、Claude 服务识别地区、Windows 区域和时区。默认启用会话出口 IP 锁定及唯一启动入口保护。确认内核退出、出口 IP 漂移、地区或系统设置冲突时终止 Claude 关联进程；校验请求失败进入每隔 5 秒执行的后台复核，恢复后自动清除异常提示。

切换 Claude 节点、端口、应用节点更新或重启私有内核前，先确认 Claude 关联进程已经终止。校验完成后需要手动启动 Claude。

Antigravity 使用其专属代理启动，启动前终止旧实例并确认退出。运行期间不执行地区限制或断线强制终止；私有内核恢复后由应用重新连接。

普通监控支持系统代理、手动代理和直接连接，使用离线 GeoLite2 Country 数据库判断出口地区，可配置受保护进程。普通监控、Claude 和系统警告分别处理恢复及关闭事件。

## 安装与运行

需要 Windows x64 和 Node.js。首次安装依赖后运行：

```powershell
npm ci
npm start
```

也可以双击 [启动应用.bat](./启动应用.bat)。构建、开发、启动、测试和打包入口会准备固定版本的 Mihomo；首次准备需要下载官方压缩包并验证 SHA-256，后续运行检查已有文件。下载或校验失败会终止操作。

```powershell
npm run prepare:core  # 单独准备内核
npm run dev           # 开发运行
npm run build         # 构建
npm run launch        # 运行已有构建
npm test              # 独立目录回归
npm run package       # 输出 Windows 发行包到 release/
```

内核版本和官方压缩包摘要记录在 [resources/mihomo-release.json](./resources/mihomo-release.json)。内核文件保存在 `resources/mihomo/`，打包时同时包含程序及完整性清单。

## 验证

默认回归使用临时目录、真实 Mihomo 进程、真实 HTTP/SOCKS 连接和密码学签名，检查持续连接隔离、恢复任务交错、订阅更新与删除、进程接管、控制接口失联重启、端口冲突、保存失败、节点协议配置及独立 DNS 副本。

真实订阅集成测试：

```powershell
$env:GUARD_TEST_NODE_NAME = '本地订阅中的节点名称'
npm test -- tests/privateKernelIntegration.ts
```

该测试读取本地订阅，通过两个私有内核执行真实 HTTPS 请求。不会修改 Clash Verge 配置。

桌面验收入口 `npm test -- tests/desktopAcceptance.ts` 必须从管理员终端运行。它使用临时配置和独立端口；普通权限启动会直接报错，不自动提权。桌面验收会开启实际守护逻辑，应在验收环境中运行。

## 发布与更新

发布流程执行类型检查、回归和打包，生成完整 ZIP、ASAR 压缩包、离线数据库和 Ed25519 签名的 `latest.json`。签名私钥由 `UPDATE_SIGNING_PRIVATE_KEY` 提供。

更新清单包含 Mihomo 版本及二进制摘要。Electron 基座与私有内核符合要求时使用 ASAR 更新，否则使用完整包。应用更新前停止守护和私有内核；更新助手无法启动时恢复后台服务。更新替换失败时由更新助手恢复文件。

本地生成签名密钥可使用 `npm run keygen`。发布私钥应与应用内置公钥配对，并保存在 GitHub Actions Secret 或本地忽略目录中。
