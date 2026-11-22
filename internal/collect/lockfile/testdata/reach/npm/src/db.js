// Knex loads the driver by name: no import of pg anywhere.
module.exports = { client: 'pg', connection: process.env.DATABASE_URL };
