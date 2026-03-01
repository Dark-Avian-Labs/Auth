process.env.NODE_ENV ??= 'test';
process.env.BASE_PROTOCOL ??= 'https';
process.env.BASE_DOMAIN ??= 'example.test';
process.env.AUTH_SUBDOMAIN ??= 'auth';
process.env.APP_LIST ??= 'parametric,corpus';

// Backward compatibility for branches/config variants that read this directly.
process.env.APP_PUBLIC_BASE_URL ??= 'https://auth.example.test';
