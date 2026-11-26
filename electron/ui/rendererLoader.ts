import { BrowserWindow } from 'electron';
import * as path from 'node:path';

export function getPreloadPath(): string {
  // esbuild 将主进程入口打包至 dist-electron/main.js，运行时 __dirname 即为 dist-electron
  return path.join(__dirname, 'preload.js');
}

export function loadRendererRoute(win: BrowserWindow, hash?: string): void {
  const handleLoadError = (err: unknown) => {
    const code = (err as { code?: string })?.code || '';
    const msg = err instanceof Error ? err.message : String(err);
    if (code === 'ERR_ABORTED' || msg.includes('ERR_ABORTED') || msg.includes('(-3)')) {
      return;
    }
    console.error('[Renderer Load Error]', err);
  };
  const devUrl = process.env.VITE_DEV_SERVER_URL;
  if (devUrl) {
    const fullUrl = hash ? `${devUrl}#${hash}` : devUrl;
    void win.loadURL(fullUrl).catch(handleLoadError);
  } else {
    const htmlPath = path.join(__dirname, '../dist/index.html');
    void win.loadFile(htmlPath, hash ? { hash } : undefined).catch(handleLoadError);
  }
}

export function waitForPostUpdateRendererReady(
  win: BrowserWindow,
  timeoutMs = 4500
): Promise<void> {
  if (win.isDestroyed()) return Promise.resolve();
  const wc = win.webContents;
  if (!wc.isLoading() && wc.getURL() !== '') {
    return Promise.resolve();
  }

  return new Promise<void>((resolve, reject) => {
    let settled = false;
    const cleanup = () => {
      clearTimeout(timer);
      if (!win.isDestroyed()) {
        win.removeListener('closed', onClosed);
        wc.removeListener('did-finish-load', onFinish);
        wc.removeListener('did-fail-load', onFail);
        wc.removeListener('render-process-gone', onGone);
      }
    };
    const onFinish = () => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve();
    };
    const onClosed = () => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve();
    };
    const onFail = (
      _event: Electron.Event,
      errorCode: number,
      errorDescription: string,
      _validatedURL: string,
      isMainFrame: boolean
    ) => {
      if (!isMainFrame || errorCode === -3 || settled) return;
      settled = true;
      cleanup();
      reject(new Error(`主窗口页面加载失败 (${errorCode}): ${errorDescription}`));
    };
    const onGone = (
      _event: Electron.Event,
      details: Electron.RenderProcessGoneDetails
    ) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(new Error(`渲染进程启动异常退出 (${details.reason})`));
    };
    const timer = setTimeout(onFinish, timeoutMs);
    timer.unref?.();

    win.once('closed', onClosed);
    wc.once('did-finish-load', onFinish);
    wc.on('did-fail-load', onFail);
    wc.once('render-process-gone', onGone);
  });
}
