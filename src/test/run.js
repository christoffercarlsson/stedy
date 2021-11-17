import createReport from './create-report.js';
import loadTests from './load-tests.js';
import runTests from './run-tests.js';

const run = async (moduleNames, { concurrency, onProgress, cwd } = {}) => {
  const start = new Date();
  const [tests, results] = await loadTests(moduleNames, cwd);
  await runTests(tests, concurrency, onProgress);
  return createReport(cwd, results, start);
};

export default run;
