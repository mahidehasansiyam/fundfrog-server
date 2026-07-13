function createAuth(db, betterAuth, mongodbAdapter) {
  return betterAuth({
    database: mongodbAdapter(db),
    baseURL: process.env.BETTER_AUTH_URL,
    emailAndPassword: {
      enabled: true,
    },
    socialProviders: {
      google: {
        clientId: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      },
    },
    user: {
      modelName: 'users',
      additionalFields: {
        role: {
          type: 'string',
          required: true,
          defaultValue: 'supporter',
          input: true,
        },
        credits: {
          type: 'number',
          required: true,
          defaultValue: 0,
          input: false,
        },
        photoURL: {
          type: 'string',
          required: false,
          defaultValue: '',
          input: true,
        },
      },
    },
    databaseHooks: {
      user: {
        create: {
          before: async (user) => {
            const credits = user.role === 'creator' ? 20 : 50;
            return { data: { ...user, credits } };
          },
        },
      },
    },
  });
}

module.exports = { createAuth };
