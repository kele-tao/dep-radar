// Synthetic bundler stub: the fixture exists to be audited, not executed.
require('dotenv').config();
const fs = require('node:fs');

for (const file of fs.readdirSync('src')) {
  console.log('build', file);
}
