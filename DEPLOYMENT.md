# Deploying LogWarden to Vercel

This guide explains how to deploy the **LogWarden Dashboard** (frontend) to Vercel.

## Prerequisites
- A Vercel account (free tier works): https://vercel.com
- Git repository with your code (GitHub, GitLab, or Bitbucket)

## Architecture Overview
- **Frontend (Dashboard)**: Next.js app → Deploy to **Vercel**
- **Backend (Core API)**: FastAPI app → Deploy to **Railway** or **Render** (separate from Vercel)
- **Database**: PostgreSQL → Use **Vercel Postgres** or **Supabase**

---

## Step 1: Prepare Your Repository

### Push to GitHub
```bash
cd /Users/prashant/Documents/Security

# Initialize git if not already done
git init
git add .
git commit -m "Initial commit - LogWarden Dashboard"

# Add your GitHub remote
git remote add origin https://github.com/Prashantstrugglestocode/LogWarden.git
git branch -M main
git push -u origin main
```

---

## Step 2: Deploy Frontend to Vercel

### Option A: Deploy via Vercel Dashboard (Recommended)
1. Go to https://vercel.com/new
2. Import your GitHub repository
3. **Configure Project**:
   - **Framework Preset**: Next.js
   - **Root Directory**: `dashboard`
   - **Build Command**: `npm run build`
   - **Output Directory**: `.next`

4. **Environment Variables** (Add these in Vercel):
   ```
   NEXT_PUBLIC_API_URL=https://your-backend.railway.app
   ```

5. Click **Deploy**

### Option B: Deploy via CLI
```bash
# Install Vercel CLI
npm install -g vercel

# Navigate to dashboard
cd dashboard

# Deploy
vercel

# Follow prompts:
# - Link to existing project? No
# - Project name? logwarden-dashboard
# - Directory? ./ (current)
```

---

## Step 3: Deploy Backend (FastAPI)

Since Vercel is optimized for frontend, deploy your backend to **Railway** or **Render**.

### Railway (Recommended for Python)
1. Go to https://railway.app
2. Click "New Project" → "Deploy from GitHub"
3. Select your repo
4. **Configure**:
   - **Root Directory**: `core-api`
   - **Start Command**: `uvicorn main:app --host 0.0.0.0 --port $PORT`
5. **Environment Variables**:
   ```
   DATABASE_URL=postgresql://...
   OLLAMA_HOST=http://your-ollama-instance:11434
   ```
6. Deploy

### Get Backend URL
After deployment, Railway gives you a URL like: `https://logwarden-api.railway.app`

---

## Step 4: Update Frontend Environment Variables

In Vercel:
1. Go to your project → **Settings** → **Environment Variables**
2. Add:
   ```
   NEXT_PUBLIC_API_URL=https://logwarden-api.railway.app
   ```
3. **Redeploy** the frontend

---

## Step 5: Setup Database

### Option A: Vercel Postgres
1. In your Vercel project → **Storage** → **Create Database**
2. Select **Postgres**
3. Copy the connection string
4. Add to Railway backend env vars

### Option B: Supabase (Free Tier)
1. Create project at https://supabase.com
2. Get connection string from Settings → Database
3. Add to Railway backend env vars

---

## Step 6: Configure CORS

Update `core-api/main.py` CORS to allow Vercel domain:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "https://logwarden-dashboard.vercel.app",  # Your Vercel domain
        "https://*.vercel.app"  # All Vercel preview deployments
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

Commit and push changes.

---

## Step 7: Update API Calls in Frontend

Update all `fetch` calls in `dashboard/app/dashboard/page.tsx` and other files:

```typescript
// Before
const res = await fetch('http://localhost:8000/ingest/logs');

// After
const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
const res = await fetch(`${API_URL}/ingest/logs`);
```

---

## Vercel Deployment Checklist

- [ ] Frontend deployed to Vercel
- [ ] Backend deployed to Railway/Render
- [ ] Database setup (Vercel Postgres or Supabase)
- [ ] Environment variables configured
- [ ] CORS updated in backend
- [ ] API URLs updated in frontend
- [ ] Custom domain configured (optional)

---

## Useful Commands

```bash
# Redeploy to Vercel (from dashboard directory)
vercel --prod

# View logs
vercel logs

# Check deployment status
vercel list
```

---

## Production Checklist

Before going live:
- [ ] Enable authentication (currently bypassed)
- [ ] Setup SSL/TLS certificates (automatic on Vercel)
- [ ] Configure rate limiting
- [ ] Setup monitoring (Vercel Analytics)
- [ ] Add Privacy Policy link to footer
- [ ] Test all features in production

---

## Troubleshooting

**Issue**: "Cannot connect to backend"
- Check `NEXT_PUBLIC_API_URL` is set correctly in Vercel
- Verify backend is running on Railway
- Check CORS settings in backend

**Issue**: "Database connection failed"
- Verify `DATABASE_URL` in Railway env vars
- Check database is accessible from Railway's IP

**Issue**: "Build failed on Vercel"
- Check `package.json` has all dependencies
- Ensure `next.config.js` is correct
- Review build logs in Vercel dashboard

---

## Next Steps
- Setup custom domain in Vercel (e.g., `app.logwarden.io`)
- Configure environment-specific settings (staging, production)
- Setup CI/CD for automatic deployments
