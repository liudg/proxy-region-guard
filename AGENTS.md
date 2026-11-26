# AGENTS.md

## 红线

- **宿主与进程隔离**：禁误杀宿主机在用的 `Antigravity`、`claude*.exe`、`guard-mihomo.exe`（禁擅传 `--allow-kill-claude`）或抢占运行中卫士；接管内核与更新停机须核验 PID 完整路径及命令行，禁按裸名强杀或连带终止外部子进程。
- **外部零侵入**：只读解析 Clash Verge 订阅，禁写回外部 Clash 文件或控制接口；专属通道仅跑保存的独立快照（含展开后的明确外部 DNS，遇循环或动态分流须拒用），源节点变更待手动更新。
- **差异化熔断**：**Claude** 须出口与 `claude.ai/cdn-cgi/trace` 经离线 `.mmdb` 匹配系统区域/时区，确认违规、IP 漂移或内核退出立杀，探测不可达则 5 秒后台复核并保留会话；**Antigravity** 须保留回环 `NO_PROXY`，运行期禁强杀，托盘退出保留其与私有内核。

## 交付标准

- **全真实回归**：须过 `npx tsc --noEmit` 与 `npm test`（禁 `node` 直跑及常规跑 `desktopAcceptance.ts`）；用独立 `GUARD_TEST_DATA`、动态端口、真实 `guard-mihomo.exe`、本地转发与真实签名构造异常，禁 Mock / 假桩 / 后门。
- **Fail-Closed**：内核或 `.mmdb` 摘要不符、端口归属不明、清单非法或目标进程未杀净须显式报错阻断，禁空 `catch`、默认回退或放宽校验。
- **底层取消零残留**：`AbortSignal` 须贯穿代理 Socket 与子进程销毁（SOCKS 统一 `socks5h://`），探测与自愈须校验世代（`probeSeq` / `recoveryEpoch` / `generation`），禁 `Promise.race` 伪超时与退出残留。
- **手写打包同步**：读写 `.asar` 用 `original-fs`；改依赖、`resources/` 或更新清单须同步 `build-electron.mjs`、`package-release.mjs` 与 `updateManifest.ts`（验证打包加 `--out-dir <临时目录> --no-kill-running --no-relaunch`，禁交私钥）。
- **Windows 细节**：拉起 Electron 须 `delete env.ELECTRON_RUN_AS_NODE`；PowerShell 经环境变量 + `-LiteralPath` 兼容中文、空格与 `[]` 路径；MSIX 别名重解析点用 `fs.lstatSync` 判存。
- **用户视角界面**：界面只呈现终端用户操作与决策所必需的信息，不带入开发者视角。
