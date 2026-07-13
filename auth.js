function createAuth(db, betterAuth, mongodbAdapter) {
  const baseURL = process.env.BETTER_AUTH_URL;

  // On Vercel (or any deploy behind a proxy), trust x-forwarded-* headers so
  // Better Auth auto-detects the correct origin from the proxied request.
  // When baseURL is unset, Better Auth falls through to per-request detection
  // which reads x-forwarded-host/proto (if trustedProxyHeaders is set) or the
  // request URL – both of which give the correct origin in production.
  const isDeployed = !!(process.env.VERCEL || process.env.NODE_ENV === 'production');
  const useLocalhostBase = baseURL && baseURL.includes('localhost');
  const resolvedBase = isDeployed && useLocalhostBase ? undefined : baseURL;

  return betterAuth({
    database: mongodbAdapter(db),
    baseURL: resolvedBase,
    advanced: {
      trustedProxyHeaders: isDeployed,
    },
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
