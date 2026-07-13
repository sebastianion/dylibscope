# DylibScope UI

Minimal Vite + React interface for the deployed DylibScope API.

## Setup

```bash
cd ui
npm install
cp .env.example .env
```

Edit `.env` and set the deployed API URL:

```bash
VITE_API_BASE_URL=https://your-render-api-service.onrender.com
```

Run locally:

```bash
npm run dev
```

Build:

```bash
npm run build
```

## Render Static Site settings

Create a new Render Static Site with:

```text
Root Directory: ui
Build Command: npm install && npm run build
Publish Directory: dist
```

Environment variable:

```text
VITE_API_BASE_URL=https://your-render-api-service.onrender.com
```

The API must allow CORS requests from the UI origin.
