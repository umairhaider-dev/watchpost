import '@testing-library/jest-dom/vitest';
import { cleanup, configure } from '@testing-library/react';
import { afterEach } from 'vitest';

// Pages wait for the session check before loading their own data. With every
// test file running in parallel (and on slower CI machines) that can take more
// than the default second, so findBy* queries wait up to five.
configure({ asyncUtilTimeout: 5000 });

afterEach(() => {
  cleanup();
});
