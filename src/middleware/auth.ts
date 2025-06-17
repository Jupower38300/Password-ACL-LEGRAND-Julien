import { verifyAccessToken } from '../services/JWT.js';
import { createMiddleware } from 'hono/factory';

import { users } from '../fake/data.js';

export const authMiddleware = createMiddleware(async (c, next) => {
  try {
    const authHeader = c.req.header('Authorization');

    if (!authHeader?.startsWith('Bearer ')) {
      return c.json({ error: 'Token manquant' }, 401);
    }

    const token = authHeader.split(' ')[1];
    const decoded = verifyAccessToken(token);

    // Récupérer l'utilisateur depuis la "base de données"
    const user = users.get(decoded.username);

    if (!user) {
      return c.json({ error: 'Utilisateur non trouvé' }, 404);
    }

    // Stocker les informations de l'utilisateur dans le contexte
    c.set('user', {
      ...user,
      id: decoded.userId
    });

    await next();
  } catch (error) {
    return c.json({ error: 'Token invalide ou expiré' }, 401);
  }
});  
