import { Hono } from 'hono'; // Import de votre configuration ACL existante
import { authMiddleware } from '../middleware/auth.js';
import type { User } from '../models/User.js';
import { ac } from '../services/accessControl.js';

const api = new Hono();

// Déclaration de l'extension de contexte
declare module 'hono' {
  interface ContextVariableMap {
    user: User & { id: string };
  }
}

// Middleware d'authentification global
api.use('*', authMiddleware);

// Route: Consultation d'un profil
api.get('/api/profile/:id', (c) => {
  const { id } = c.req.param();
  const user = c.get('user');

  // Déterminer le type de permission nécessaire
  const isOwn = id === user.id;
  const permissionType = isOwn ? 'readOwn' : 'readAny';

  // Vérifier la permission avec votre système ACL existant
  const permission = ac.can(user.role)[permissionType]('profile');

  if (!permission.granted) {
    return c.text(`Accès refusé au profil ${id}`, 403);
  }

  return c.text(`Profil ${id} consulté par ${user.username} (${user.role})`);
});

// Route: Création de données
api.post('/api/data', (c) => {
  const user = c.get('user');

  // Utiliser votre système ACL existant pour vérifier la permission
  const permission = ac.can(user.role).createOwn('data');

  if (!permission.granted) {
    return c.text('Accès refusé pour la création de données', 403);
  }

  return c.text(`Donnée créée par ${user.username} (${user.role})`);
});

// Route: Modification de données
api.put('/api/data/:id', (c) => {
  const { id } = c.req.param();
  const user = c.get('user');

  // Déterminer le type de permission nécessaire
  const isOwn = id.startsWith(`${user.id}-`); // Adaptez à votre logique métier
  const permissionType = isOwn ? 'updateOwn' : 'updateAny';

  // Utiliser votre système ACL existant
  const permission = ac.can(user.role)[permissionType]('data');

  if (!permission.granted) {
    return c.text(`Accès refusé pour modifier la donnée ${id}`, 403);
  }

  return c.text(`Donnée ${id} modifiée par ${user.username} (${user.role})`);
});

// Route: Suppression de données
api.delete('/api/data/:id', (c) => {
  const { id } = c.req.param();
  const user = c.get('user');

  // Déterminer le type de permission nécessaire
  const isOwn = id.startsWith(`${user.id}-`); // Adaptez à votre logique métier
  const permissionType = isOwn ? 'deleteOwn' : 'deleteAny';

  // Utiliser votre système ACL existant
  const permission = ac.can(user.role)[permissionType]('data');

  if (!permission.granted) {
    return c.text(`Accès refusé pour supprimer la donnée ${id}`, 403);
  }

  return c.text(`Donnée ${id} supprimée par ${user.username} (${user.role})`);
});

export default api;
