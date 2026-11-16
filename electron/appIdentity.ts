import { app } from 'electron';
import * as path from 'node:path';

export function configureAppUserData(): void {
  const defaultDirectory = path.join(app.getPath('appData'), app.getName());
  // 显式指定的数据目录用于独立运行；默认启动统一使用产品目录。
  if (path.resolve(app.getPath('userData')) === path.resolve(defaultDirectory)) {
    app.setPath('userData', path.join(app.getPath('appData'), '代理地区卫士'));
  }
}
