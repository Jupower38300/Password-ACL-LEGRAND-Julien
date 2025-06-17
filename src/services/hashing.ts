// Ici dénissez les fonctions qui vont vous permettre de vérifier et générer des mots de passes sécurisés

export const hashPassword = async (password: string): Promise<{ password: string, salt: string }> => {

};

export const verifyPassword = async (
  password: string,
  salt: string,
  hashedPassword: string
): Promise<boolean> => {
};
