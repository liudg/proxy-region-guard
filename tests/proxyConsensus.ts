import { app } from 'electron';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { verifyClaudeIpv4Enforcement } from './consensus/claudeIpv4Enforcement';
import { verifyMultiSourceConsensus } from './consensus/multiSourceConsensus';
import { verifyLocalNetClientAndKernelRecovery } from './consensus/netClientAndKernelRecovery';
import { root, shutdownAllServices } from './consensus/testHarness';
import { verifyTransportHostsAndPureSafety } from './consensus/transportAndPureSafety';

async function run(): Promise<void> {
  const coreDir = path.join(root, 'core');
  fs.cpSync(path.resolve('resources/mihomo'), coreDir, { recursive: true });
  verifyTransportHostsAndPureSafety();
  await verifyLocalNetClientAndKernelRecovery(coreDir);
  await verifyMultiSourceConsensus(coreDir);
  await verifyClaudeIpv4Enforcement(coreDir);
}

let fatalExiting = false;
const handleFatalExit = () => {
  if (fatalExiting) return;
  fatalExiting = true;
  void shutdownAllServices().finally(() => app.exit(1));
};
process.on('uncaughtException', handleFatalExit);
process.on('unhandledRejection', handleFatalExit);

app.whenReady()
  .then(run)
  .then(() => shutdownAllServices())
  .then(() => app.exit(0))
  .catch(async (error) => {
    console.error(error);
    await shutdownAllServices();
    app.exit(1);
  });
