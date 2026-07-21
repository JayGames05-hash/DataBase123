# Railway PostgreSQL Storage App

A simple cloud-style file storage app with PostgreSQL, user accounts, and private/public file visibility.

## Features
- User registration and login
- Upload files and basic media assets
- Store file metadata and content in PostgreSQL
- Set file visibility to public or private
- Restrict download access to the owner/admin or public files

## Local development
1. Copy `.env.example` to `.env` and set your values.
2. Install dependencies:
   ```bash
   npm install
   ```
3. Start the app:
   ```bash
   npm start
   ```
4. Open http://localhost:3000

## Railway deployment
1. Create a new Railway project.
2. Add a PostgreSQL database.
3. Link the app service to the database.
4. Set environment variables:
   - `DATABASE_URL` (Railway will provide this)
   - `SESSION_SECRET` (any strong random string)
5. Deploy the app.

## Notes
- The app uses PostgreSQL and stores uploaded file bytes in the database.
- For a production deployment, consider object storage such as S3 or Cloudflare R2 for large files.
