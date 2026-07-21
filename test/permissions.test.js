const test = require('node:test');
const assert = require('node:assert/strict');
const { canAccessFile } = require('../permissions');

test('public file is viewable by anyone', () => {
  assert.equal(canAccessFile({ visibility: 'public' }, null, []), true);
});

test('private file is only visible to owner, admin, or explicitly shared users', () => {
  const file = { visibility: 'private', owner_id: 1 };
  assert.equal(canAccessFile(file, { id: 1, role: 'member' }, []), true);
  assert.equal(canAccessFile(file, { id: 2, role: 'member' }, []), false);
  assert.equal(canAccessFile(file, { id: 2, role: 'member' }, [2]), true);
  assert.equal(canAccessFile(file, { id: 3, role: 'admin' }, []), true);
});
