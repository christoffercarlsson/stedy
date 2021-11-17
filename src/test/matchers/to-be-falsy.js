import toBeTruthy from './to-be-truthy.js';

const toBeFalsy = (received) => !toBeTruthy(received);

export default toBeFalsy;
