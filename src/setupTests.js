import '@testing-library/jest-dom';

const { TextEncoder, TextDecoder } = require('util');
global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder;

if (typeof window !== 'undefined' && typeof window.scrollTo !== 'function') {
  window.scrollTo = () => {};
}

jest.mock('jspdf', () => ({
  __esModule: true,
  default: jest.fn().mockImplementation(() => ({
    addImage: jest.fn(),
    save: jest.fn(),
  })),
}));

jest.mock('jspdf-autotable', () => ({
  __esModule: true,
  default: jest.fn(),
}));

jest.mock('sweetalert2', () => ({
  __esModule: true,
  default: { fire: jest.fn() },
  fire: jest.fn(),
}));

jest.mock('datatables.net-dt', () => jest.fn().mockImplementation(() => ({
  destroy: jest.fn(),
})));
