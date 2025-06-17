import { AccessControl } from 'accesscontrol';

const ac = new AccessControl();

// Définissez vos permissions ici
ac.grant('guest').readAny('profile');

ac.grant('user')
  .extend('guest')
  .readOwn('profile')
  .createOwn('data')
  .updateOwn('data')
  .deleteOwn('data');

ac.grant('admin')
  .extend(['user', 'guest'])
  .createAny('data')
  .updateAny('data')
  .deleteAny('data');

export { ac };
