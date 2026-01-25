import swaggerJsdoc from 'swagger-jsdoc';

const options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Secure Auth API',
      version: '1.0.0',
      description: 'Production-ready authentication service with JWT, refresh tokens, email verification, and password reset',
    },
    servers: [
      { url: 'http://localhost:5000', description: 'Backend (local)' },
      { url: "", description: 'Frontend proxy (optional)' },
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
        },
      },
    },
  },
  apis: ['./src/routes/*.ts', './src/controllers/*.ts'], // Where your JSDoc comments live
};

export const specs = swaggerJsdoc(options);