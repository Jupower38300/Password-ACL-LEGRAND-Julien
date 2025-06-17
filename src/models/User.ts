
import { z } from 'zod';
import { users } from '../fake/data.js';

export const UserSchema = z.object({
  username: z.string().min(3).max(20),
  password: z.string().min(8).regex(/^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/),
  role: z.enum(['admin', 'user', 'guest']),
  email: z.string().email()
});

export const LoginSchema = z.object({
  username: z.string(),
  password: z.string()
});

export type User = z.infer<typeof UserSchema>;

export function getUser(id: string) {
  return users.get(id);
}

export function setUser(user: User) {
  users.set(user.username, user);
}

export function userExist(id: string) {
  return users.has(id);
}
