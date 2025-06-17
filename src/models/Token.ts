import { z } from 'zod';

export const TokenSchema = z.object({
  refreshToken: z.string()
});

const refreshTokens = new Set<string>();

export const createRefreshToken = (token: string) => {
  refreshTokens.add(token);
};

export const readRefreshTokens = () => {
  return Array.from(refreshTokens);
};

export const updateRefreshToken = (oldToken: string, newToken: string) => {
  if (refreshTokens.has(oldToken)) {
    refreshTokens.delete(oldToken);
    refreshTokens.add(newToken);
  }
};

export const deleteRefreshToken = (token: string) => {
  refreshTokens.delete(token);
};

export const existsRefreshToken = (token: string) => {
  return refreshTokens.has(token);
};
