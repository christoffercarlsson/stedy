import { DEFAULT_CONCURRENCY } from './constants.js';
import { ensureFunc } from './utils.js';

const splitWorkload = (tests, concurrency) => {
  const size =
    concurrency > 0 && concurrency <= Number.MAX_VALUE
      ? concurrency
      : DEFAULT_CONCURRENCY;
  if (tests.length <= size) {
    return [tests];
  }
  const length = Math.ceil(tests.length / size);
  return Array.from({ length }, (_, index) => {
    const begin = index * size;
    return tests.slice(begin, begin + size);
  });
};

const createReportProgress = (onProgress, totalNumberOfTests) => {
  let numberOfCompletedTests = 0;
  return async () => {
    numberOfCompletedTests += 1;
    await onProgress(
      Math.floor((numberOfCompletedTests / totalNumberOfTests) * 100),
      numberOfCompletedTests,
      totalNumberOfTests
    );
  };
};

const sequentially = (funcs) =>
  funcs.reduce(async (previousPromise, func) => {
    await previousPromise;
    await func();
  }, Promise.resolve());

const runBatch = (batch, reportProgress) =>
  Promise.all(
    batch.map(async (test) => {
      await test();
      await reportProgress();
    })
  );

const runTests = (tests, concurrency, onProgress) => {
  const batches = splitWorkload(tests, concurrency);
  const reportProgress = createReportProgress(
    ensureFunc(onProgress),
    tests.length
  );
  return sequentially(
    batches.map((batch) => () => runBatch(batch, reportProgress))
  );
};

export default runTests;
