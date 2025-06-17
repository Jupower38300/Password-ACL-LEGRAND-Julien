import { beforeAll, describe, expect, test } from 'vitest'

import App from '../src/index.js'

/////////////////////////////
// Exemple de divers tests que vous pouvre réaliser pour s'assurer que votre api fonctionne correctement dans un environnement isolé
/////////////////////////
//
describe('Users functionnal test', async () => {

  describe('Register Correct', async () => {
    const res = await App.request('/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        username: 'admin1',
        password: 'Password123',
        role: 'admin',
        email: 'hello@work.com'
      }),
    })
    const resJson = await res.json();

    test('Register should return a 201 when using with correct parameters', async () => {
      expect(res.status).toBe(201)
    })

    test('Register should return Access token and Refresh token when using with correct parameters', async () => {
      expect(resJson.accessToken).not.toBeNull()
      expect(resJson.refreshToken).not.toBeNull();
    })

  })

  describe('Register Incorrect', async () => {
    test('Register should send 400 error if sent information is not correct', async () => {
      const res = await App.request('/register', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          username: 'adm1',
        })
      })

      expect(res.status).toBe(400)
    })

    test('Register should send 400 error if sent username that already exist', async () => {
      const res = await App.request('/register', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          username: 'admin1',
          password: 'Password123',
          role: 'admin',
          email: 'hello@work.com'
        }),
      })
      const resJson = await res.json();

      expect(res.status).toBe(400)
      expect(resJson.error).toBe('Nom d\'utilisateur déjà pris')

    })

    test('Register should send 400 error if at least one value does not correspond to the defined schema', async () => {
      const res = await App.request('/register', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          username: 'admin1',
          password: ['Password123'],
          role: 'admin',
          email: 'hello@work.com'
        }),
      })
      const resJson = await res.json();

      expect(res.status).toBe(400)
      expect(resJson.error.name).toBe('ZodError');
    })

    test('Register should send 400 error if email has not a valid format', async () => {
      const res = await App.request('/register', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          username: 'admin1',
          password: 'Password123',
          role: 'admin',
          email: 'hello@work'
        }),
      })
      const resJson = await res.json();

      expect(res.status).toBe(400)
      expect(resJson.error.name).toBe('ZodError');
    })

    test('Register should send 400 error if role is not in the defined list', async () => {
      const res = await App.request('/register', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          username: 'admin1',
          password: 'Password123',
          role: 'hackerman',
          email: 'hello@work.com'
        }),
      })
      const resJson = await res.json();

      expect(res.status).toBe(400)
      expect(resJson.error.name).toBe('ZodError');
    })

  })

})
