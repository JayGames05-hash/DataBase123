function canAccessFile(file, user, sharedUserIds = []) {
  if (!user) {
    return file.visibility === 'public';
  }

  if (file.owner_id === user.id || user.role === 'admin') {
    return true;
  }

  return file.visibility === 'public' || sharedUserIds.includes(user.id);
}

module.exports = { canAccessFile };
