# Open-Source Deepstash Alternative: Complete Development Guide

## Table of Contents
1. [Project Overview](#project-overview)
2. [Development Methodology](#development-methodology)
3. [Technology Stack](#technology-stack)
4. [Security Best Practices](#security-best-practices)
5. [Open Source Guidelines](#open-source-guidelines)
6. [Development Environment Setup](#development-environment-setup)
7. [Database Design](#database-design)
8. [API Design](#api-design)
9. [Frontend Architecture](#frontend-architecture)
10. [Testing Strategy](#testing-strategy)
11. [Deployment Strategy](#deployment-strategy)
12. [Community Management](#community-management)
13. [Maintenance and Updates](#maintenance-and-updates)

## Project Overview

### Mission Statement
Create a free, open-source alternative to Deepstash that provides microlearning capabilities, knowledge management, and community-driven content curation while maintaining the highest standards of security and privacy.

### Core Features
- **Bite-sized Learning**: Curated idea cards for quick consumption
- **Personal Knowledge Management**: Save, organize, and retrieve insights
- **Offline Access**: Local storage and synchronization capabilities
- **Community Features**: Share insights and collaborate with others
- **Personalization**: AI-driven content recommendations
- **Multi-platform**: Web, mobile-responsive design

### Success Metrics
- User engagement and retention rates
- Community contribution levels
- Code quality and security metrics
- Performance benchmarks
- Open source adoption metrics

## Development Methodology

### Agile/Scrum Framework
- **Sprint Duration**: 2 weeks
- **Sprint Planning**: Every 2 weeks (4 hours)
- **Daily Standups**: 15 minutes daily
- **Sprint Review**: 2 hours at sprint end
- **Sprint Retrospective**: 1 hour after review

### Development Principles
1. **Security by Design**: Integrate security from day one
2. **Test-Driven Development**: Write tests before implementation
3. **Code First Documentation**: Maintain living documentation
4. **Community-Driven**: Regular feedback and contributions
5. **Performance Focus**: Optimize for speed and scalability

### Quality Gates
- **Code Coverage**: Minimum 80% test coverage
- **Security Scans**: Pass all SAST/DAST checks
- **Performance**: Load time under 3 seconds
- **Accessibility**: WCAG 2.1 AA compliance
- **Code Review**: Minimum 2 approvers required

## Technology Stack

### Backend Stack (Recommended: Node.js/Express)
```javascript
// Core Technologies
- Runtime: Node.js 18+ LTS
- Framework: Express.js 4.18+
- Database: PostgreSQL 14+ (primary), Redis (cache)
- ORM: Prisma or TypeORM
- Authentication: JWT + Passport.js
- File Storage: MinIO (self-hosted S3 alternative)

// Supporting Tools
- API Documentation: Swagger/OpenAPI
- Process Manager: PM2
- Logging: Winston + Morgan
- Monitoring: Prometheus + Grafana
```

### Frontend Stack (React.js)
```javascript
// Core Technologies
- Framework: React 18+
- Routing: React Router v6
- State Management: Zustand or Redux Toolkit
- Styling: TailwindCSS + Headless UI
- Forms: React Hook Form + Zod
- HTTP Client: Axios with interceptors

// Development Tools
- Build Tool: Vite
- Testing: Jest + React Testing Library
- Linting: ESLint + Prettier
- Type Checking: TypeScript 4.9+
```

### Alternative Stack (Python/Django)
```python
# Core Technologies
- Framework: Django 4.2 LTS
- API: Django REST Framework
- Database: PostgreSQL + Redis
- Authentication: Django Allauth
- Task Queue: Celery + Redis

# Supporting Tools
- API Documentation: drf-spectacular
- Testing: pytest + factory_boy
- Deployment: Gunicorn + Nginx
```

### DevOps & Infrastructure
```yaml
# Containerization
- Docker & Docker Compose
- Multi-stage builds for optimization

# CI/CD Pipeline
- GitHub Actions or GitLab CI
- Automated testing and deployment
- Security scanning integration

# Monitoring & Logging
- Application: Sentry for error tracking
- Infrastructure: Prometheus + Grafana
- Logs: ELK Stack (Elasticsearch, Logstash, Kibana)

# Hosting Options
- Self-hosted: Docker Swarm or Kubernetes
- Cloud: DigitalOcean, AWS, or Google Cloud
- Database: Managed PostgreSQL service
```

## Security Best Practices

### Application Security

#### Authentication & Authorization
```javascript
// JWT Implementation with Refresh Tokens
const authConfig = {
  accessTokenExpiry: '15m',
  refreshTokenExpiry: '7d',
  requireMFA: process.env.NODE_ENV === 'production',
  passwordPolicy: {
    minLength: 12,
    requireSpecialChars: true,
    requireNumbers: true,
    requireUppercase: true
  }
};

// Role-based Access Control
const roles = {
  ADMIN: ['read', 'write', 'delete', 'admin'],
  MODERATOR: ['read', 'write', 'moderate'],
  USER: ['read', 'write:own'],
  GUEST: ['read:public']
};
```

#### Input Validation & Sanitization
```javascript
// Use validation libraries
import { z } from 'zod';
import DOMPurify from 'dompurify';

const ideaSchema = z.object({
  title: z.string().min(5).max(200).trim(),
  content: z.string().min(10).max(5000),
  tags: z.array(z.string()).max(10),
  category: z.enum(['productivity', 'learning', 'health', 'technology'])
});

// Sanitize HTML content
const sanitizeContent = (content) => {
  return DOMPurify.sanitize(content, {
    ALLOWED_TAGS: ['p', 'br', 'strong', 'em', 'ul', 'ol', 'li'],
    ALLOWED_ATTR: []
  });
};
```

#### API Security
```javascript
// Rate Limiting
const rateLimit = require('express-rate-limit');

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP'
});

// CORS Configuration
const corsOptions = {
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
};
```

### Infrastructure Security

#### Docker Security
```dockerfile
# Use specific, minimal base images
FROM node:18-alpine

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nextjs -u 1001

# Set proper file permissions
COPY --chown=nextjs:nodejs . .

# Run as non-root user
USER nextjs

# Use read-only root filesystem
VOLUME ["/tmp"]
READONLY_ROOTFS=true
```

#### Database Security
```sql
-- Create application-specific database user
CREATE USER app_user WITH PASSWORD 'strong_random_password';

-- Grant minimal required permissions
GRANT CONNECT ON DATABASE deepstash_db TO app_user;
GRANT USAGE ON SCHEMA public TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_user;

-- Enable SSL connections
ALTER SYSTEM SET ssl = on;
ALTER SYSTEM SET ssl_cert_file = '/path/to/server.crt';
ALTER SYSTEM SET ssl_key_file = '/path/to/server.key';
```

### Security Scanning & Monitoring

#### Automated Security Checks
```yaml
# GitHub Actions Security Workflow
name: Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      # Dependency vulnerability scanning
      - name: Run npm audit
        run: npm audit --audit-level moderate
        
      # Static Application Security Testing (SAST)
      - name: Run CodeQL Analysis
        uses: github/codeql-action/analyze@v2
        with:
          languages: javascript, typescript
          
      # Container security scanning
      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'my-app:latest'
          format: 'sarif'
          output: 'trivy-results.sarif'
```

#### Secret Management
```bash
# Use environment variables for secrets
export DATABASE_URL="postgresql://user:pass@localhost/db"
export JWT_SECRET="your-256-bit-secret"
export REDIS_URL="redis://localhost:6379"

# Use tools like sops or sealed-secrets for production
sops -e -i secrets.yaml
```

## Open Source Guidelines

### Repository Structure
```
deepstash-oss/
├── .github/
│   ├── ISSUE_TEMPLATE/
│   ├── workflows/
│   └── PULL_REQUEST_TEMPLATE.md
├── docs/
│   ├── API.md
│   ├── CONTRIBUTING.md
│   ├── DEPLOYMENT.md
│   └── SECURITY.md
├── src/
│   ├── backend/
│   ├── frontend/
│   └── shared/
├── tests/
├── docker/
├── scripts/
├── LICENSE
├── README.md
├── CODE_OF_CONDUCT.md
└── SECURITY.md
```

### License Selection
**Recommended: MIT License**
- Permissive and business-friendly
- Allows commercial use and modification
- Simple and well-understood
- Encourages adoption and contributions

### Contributing Guidelines
```markdown
# Contributing to Deepstash OSS

## Development Setup
1. Fork the repository
2. Clone your fork: `git clone https://github.com/yourusername/deepstash-oss.git`
3. Install dependencies: `npm install`
4. Copy `.env.example` to `.env` and configure
5. Run tests: `npm test`
6. Start development server: `npm run dev`

## Pull Request Process
1. Create a feature branch from `develop`
2. Make your changes with appropriate tests
3. Ensure all tests pass and linting is clean
4. Update documentation if needed
5. Submit PR with clear description

## Code Style
- Use Prettier for formatting
- Follow ESLint rules
- Write descriptive commit messages
- Add JSDoc comments for public APIs

## Security Policy
- Never commit secrets or credentials
- Run security scans before submitting
- Report security issues privately to security@project.com
```

### Community Building
```markdown
# Community Guidelines

## Communication Channels
- GitHub Discussions for general questions
- Issues for bug reports and feature requests
- Discord server for real-time chat
- Monthly community calls

## Recognition System
- Contributor of the month program
- GitHub badges and recognition
- Feature author credits
- Conference speaking opportunities

## Governance Model
- Core maintainer team (3-5 people)
- Technical steering committee
- Community representatives
- Clear escalation process
```

## Development Environment Setup

### Local Development with Docker
```yaml
# docker-compose.dev.yml
version: '3.8'
services:
  postgres:
    image: postgres:14-alpine
    environment:
      POSTGRES_USER: deepstash
      POSTGRES_PASSWORD: password
      POSTGRES_DB: deepstash_dev
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    command: redis-server --appendonly yes
    volumes:
      - redis_data:/data

  backend:
    build: 
      context: .
      dockerfile: Dockerfile.dev
    ports:
      - "3001:3001"
    volumes:
      - ./src/backend:/app/src
      - /app/node_modules
    environment:
      - NODE_ENV=development
      - DATABASE_URL=postgresql://deepstash:password@postgres:5432/deepstash_dev
      - REDIS_URL=redis://redis:6379
    depends_on:
      - postgres
      - redis

  frontend:
    build:
      context: .
      dockerfile: Dockerfile.frontend.dev
    ports:
      - "3000:3000"
    volumes:
      - ./src/frontend:/app/src
      - /app/node_modules
    environment:
      - REACT_APP_API_URL=http://localhost:3001
    depends_on:
      - backend

volumes:
  postgres_data:
  redis_data:
```

### Development Scripts
```json
{
  "scripts": {
    "dev": "concurrently \"npm run dev:backend\" \"npm run dev:frontend\"",
    "dev:backend": "cd src/backend && npm run dev",
    "dev:frontend": "cd src/frontend && npm start",
    "test": "npm run test:backend && npm run test:frontend",
    "test:watch": "npm run test -- --watch",
    "lint": "eslint src/ --ext .js,.jsx,.ts,.tsx",
    "lint:fix": "npm run lint -- --fix",
    "typecheck": "tsc --noEmit",
    "build": "npm run build:backend && npm run build:frontend",
    "docker:dev": "docker-compose -f docker-compose.dev.yml up --build",
    "docker:prod": "docker-compose -f docker-compose.prod.yml up --build",
    "db:migrate": "cd src/backend && npx prisma migrate dev",
    "db:seed": "cd src/backend && npx prisma db seed",
    "security:audit": "npm audit && npm run security:scan",
    "security:scan": "snyk test"
  }
}
```

## Database Design

### Core Entities
```sql
-- Users table
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email VARCHAR(255) UNIQUE NOT NULL,
  username VARCHAR(50) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  first_name VARCHAR(100),
  last_name VARCHAR(100),
  avatar_url TEXT,
  email_verified BOOLEAN DEFAULT false,
  is_active BOOLEAN DEFAULT true,
  role VARCHAR(20) DEFAULT 'user',
  preferences JSONB DEFAULT '{}',
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- Ideas table
CREATE TABLE ideas (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title VARCHAR(500) NOT NULL,
  content TEXT NOT NULL,
  summary VARCHAR(1000),
  source_url TEXT,
  source_title VARCHAR(500),
  author_id UUID REFERENCES users(id),
  category_id UUID REFERENCES categories(id),
  is_public BOOLEAN DEFAULT true,
  is_featured BOOLEAN DEFAULT false,
  view_count INTEGER DEFAULT 0,
  like_count INTEGER DEFAULT 0,
  save_count INTEGER DEFAULT 0,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW(),
  
  -- Full-text search
  search_vector tsvector GENERATED ALWAYS AS (
    setweight(to_tsvector('english', title), 'A') ||
    setweight(to_tsvector('english', content), 'B')
  ) STORED
);

-- Categories table
CREATE TABLE categories (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(100) UNIQUE NOT NULL,
  slug VARCHAR(100) UNIQUE NOT NULL,
  description TEXT,
  color VARCHAR(7), -- hex color
  icon VARCHAR(50),
  parent_id UUID REFERENCES categories(id),
  sort_order INTEGER DEFAULT 0,
  is_active BOOLEAN DEFAULT true,
  created_at TIMESTAMP DEFAULT NOW()
);

-- Tags table
CREATE TABLE tags (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(100) UNIQUE NOT NULL,
  slug VARCHAR(100) UNIQUE NOT NULL,
  color VARCHAR(7),
  usage_count INTEGER DEFAULT 0,
  created_at TIMESTAMP DEFAULT NOW()
);

-- Idea tags many-to-many
CREATE TABLE idea_tags (
  idea_id UUID REFERENCES ideas(id) ON DELETE CASCADE,
  tag_id UUID REFERENCES tags(id) ON DELETE CASCADE,
  created_at TIMESTAMP DEFAULT NOW(),
  PRIMARY KEY (idea_id, tag_id)
);

-- User saved ideas
CREATE TABLE user_saved_ideas (
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  idea_id UUID REFERENCES ideas(id) ON DELETE CASCADE,
  notes TEXT,
  is_favorite BOOLEAN DEFAULT false,
  saved_at TIMESTAMP DEFAULT NOW(),
  PRIMARY KEY (user_id, idea_id)
);

-- User interactions (views, likes, shares)
CREATE TABLE user_interactions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  idea_id UUID REFERENCES ideas(id) ON DELETE CASCADE,
  interaction_type VARCHAR(20) NOT NULL, -- 'view', 'like', 'share', 'comment'
  metadata JSONB DEFAULT '{}',
  created_at TIMESTAMP DEFAULT NOW(),
  
  UNIQUE(user_id, idea_id, interaction_type)
);

-- Indexes for performance
CREATE INDEX idx_ideas_search ON ideas USING GIN (search_vector);
CREATE INDEX idx_ideas_category ON ideas(category_id);
CREATE INDEX idx_ideas_author ON ideas(author_id);
CREATE INDEX idx_ideas_created_at ON ideas(created_at DESC);
CREATE INDEX idx_ideas_public_featured ON ideas(is_public, is_featured);
CREATE INDEX idx_user_interactions_user ON user_interactions(user_id);
CREATE INDEX idx_user_interactions_idea ON user_interactions(idea_id);
CREATE INDEX idx_user_saved_ideas_user ON user_saved_ideas(user_id);
```

### Data Migration Strategy
```javascript
// Prisma migration example
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

model User {
  id            String   @id @default(cuid())
  email         String   @unique
  username      String   @unique
  passwordHash  String
  firstName     String?
  lastName      String?
  avatarUrl     String?
  emailVerified Boolean  @default(false)
  isActive      Boolean  @default(true)
  role          Role     @default(USER)
  preferences   Json     @default("{}")
  createdAt     DateTime @default(now())
  updatedAt     DateTime @updatedAt

  ideas         Idea[]
  savedIdeas    UserSavedIdea[]
  interactions  UserInteraction[]

  @@map("users")
}

model Idea {
  id          String   @id @default(cuid())
  title       String
  content     String
  summary     String?
  sourceUrl   String?
  sourceTitle String?
  authorId    String
  categoryId  String
  isPublic    Boolean  @default(true)
  isFeatured  Boolean  @default(false)
  viewCount   Int      @default(0)
  likeCount   Int      @default(0)
  saveCount   Int      @default(0)
  createdAt   DateTime @default(now())
  updatedAt   DateTime @updatedAt

  author      User              @relation(fields: [authorId], references: [id])
  category    Category          @relation(fields: [categoryId], references: [id])
  tags        IdeaTag[]
  savedBy     UserSavedIdea[]
  interactions UserInteraction[]

  @@map("ideas")
}
```

## API Design

### RESTful API Structure
```javascript
// API Routes Structure
/api/v1/
├── auth/
│   ├── POST /login
│   ├── POST /register
│   ├── POST /logout
│   ├── POST /refresh
│   └── POST /forgot-password
├── users/
│   ├── GET /me
│   ├── PUT /me
│   ├── GET /:id/profile
│   └── GET /:id/ideas
├── ideas/
│   ├── GET / (with pagination, filters)
│   ├── POST /
│   ├── GET /:id
│   ├── PUT /:id
│   ├── DELETE /:id
│   ├── POST /:id/like
│   ├── POST /:id/save
│   └── DELETE /:id/save
├── categories/
│   ├── GET /
│   ├── GET /:id/ideas
│   └── GET /tree
├── tags/
│   ├── GET /
│   ├── GET /:id/ideas
│   └── GET /popular
├── search/
│   ├── GET /ideas?q=query
│   └── GET /suggest?q=query
└── admin/
    ├── GET /stats
    ├── GET /users
    └── GET /reports
```

### API Implementation Example
```javascript
// ideas.controller.js
const IdeaController = {
  // GET /api/v1/ideas
  async getIdeas(req, res) {
    try {
      const {
        page = 1,
        limit = 20,
        category,
        tags,
        author,
        sort = 'created_at',
        order = 'desc',
        search
      } = req.query;

      const filters = {
        isPublic: true,
        ...(category && { categoryId: category }),
        ...(author && { authorId: author }),
        ...(tags && { tags: { some: { tagId: { in: tags.split(',') } } } })
      };

      if (search) {
        filters.OR = [
          { title: { contains: search, mode: 'insensitive' } },
          { content: { contains: search, mode: 'insensitive' } }
        ];
      }

      const ideas = await prisma.idea.findMany({
        where: filters,
        include: {
          author: { select: { id: true, username: true, avatarUrl: true } },
          category: { select: { id: true, name: true, slug: true, color: true } },
          tags: { include: { tag: true } },
          _count: { select: { savedBy: true, interactions: true } }
        },
        orderBy: { [sort]: order },
        skip: (page - 1) * limit,
        take: parseInt(limit)
      });

      const total = await prisma.idea.count({ where: filters });

      res.json({
        ideas,
        pagination: {
          page: parseInt(page),
          limit: parseInt(limit),
          total,
          pages: Math.ceil(total / limit)
        }
      });
    } catch (error) {
      res.status(500).json({ error: 'Failed to fetch ideas' });
    }
  },

  // POST /api/v1/ideas
  async createIdea(req, res) {
    try {
      const { title, content, summary, sourceUrl, sourceTitle, categoryId, tags } = req.body;
      const authorId = req.user.id;

      // Validate input
      const validation = ideaSchema.safeParse(req.body);
      if (!validation.success) {
        return res.status(400).json({ errors: validation.error.errors });
      }

      // Create idea
      const idea = await prisma.idea.create({
        data: {
          title,
          content: sanitizeContent(content),
          summary,
          sourceUrl,
          sourceTitle,
          authorId,
          categoryId,
          tags: {
            create: tags?.map(tagId => ({ tagId })) || []
          }
        },
        include: {
          author: { select: { id: true, username: true, avatarUrl: true } },
          category: true,
          tags: { include: { tag: true } }
        }
      });

      // Update tag usage counts
      if (tags?.length) {
        await prisma.tag.updateMany({
          where: { id: { in: tags } },
          data: { usageCount: { increment: 1 } }
        });
      }

      res.status(201).json(idea);
    } catch (error) {
      res.status(500).json({ error: 'Failed to create idea' });
    }
  }
};
```

### API Security Middleware
```javascript
// auth.middleware.js
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

const authorizeRoles = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
};

// Usage
app.get('/api/v1/admin/stats', 
  authenticateToken, 
  authorizeRoles('admin', 'moderator'), 
  AdminController.getStats
);
```

## Frontend Architecture

### Component Structure
```
src/
├── components/
│   ├── common/
│   │   ├── Button/
│   │   ├── Input/
│   │   ├── Modal/
│   │   └── Layout/
│   ├── features/
│   │   ├── Auth/
│   │   ├── Ideas/
│   │   ├── Profile/
│   │   └── Search/
│   └── ui/
├── hooks/
├── services/
├── stores/
├── utils/
├── types/
└── pages/
```

### State Management with Zustand
```javascript
// stores/authStore.js
import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { authAPI } from '../services/auth';

export const useAuthStore = create(
  persist(
    (set, get) => ({
      user: null,
      token: null,
      isAuthenticated: false,
      isLoading: false,

      login: async (email, password) => {
        set({ isLoading: true });
        try {
          const { user, token } = await authAPI.login(email, password);
          set({ user, token, isAuthenticated: true, isLoading: false });
          return { success: true };
        } catch (error) {
          set({ isLoading: false });
          return { success: false, error: error.message };
        }
      },

      logout: () => {
        set({ user: null, token: null, isAuthenticated: false });
        authAPI.logout();
      },

      updateProfile: async (data) => {
        try {
          const user = await authAPI.updateProfile(data);
          set({ user });
          return { success: true };
        } catch (error) {
          return { success: false, error: error.message };
        }
      }
    }),
    {
      name: 'auth-storage',
      partialize: (state) => ({ 
        user: state.user, 
        token: state.token, 
        isAuthenticated: state.isAuthenticated 
      })
    }
  )
);

// stores/ideasStore.js
export const useIdeasStore = create((set, get) => ({
  ideas: [],
  currentIdea: null,
  filters: {
    category: null,
    tags: [],
    search: '',
    sort: 'created_at',
    order: 'desc'
  },
  pagination: {
    page: 1,
    limit: 20,
    total: 0,
    pages: 0
  },
  isLoading: false,

  fetchIdeas: async (resetPagination = false) => {
    set({ isLoading: true });
    try {
      const { filters, pagination } = get();
      const params = {
        ...filters,
        page: resetPagination ? 1 : pagination.page,
        limit: pagination.limit
      };

      const response = await ideasAPI.getIdeas(params);
      
      set({
        ideas: resetPagination ? response.ideas : [...get().ideas, ...response.ideas],
        pagination: response.pagination,
        isLoading: false
      });
    } catch (error) {
      set({ isLoading: false });
      throw error;
    }
  },

  setFilters: (newFilters) => {
    set({ filters: { ...get().filters, ...newFilters } });
    get().fetchIdeas(true);
  },

  likeIdea: async (ideaId) => {
    try {
      await ideasAPI.likeIdea(ideaId);
      set({
        ideas: get().ideas.map(idea => 
          idea.id === ideaId 
            ? { ...idea, likeCount: idea.likeCount + 1, isLiked: true }
            : idea
        )
      });
    } catch (error) {
      throw error;
    }
  }
}));
```

### Custom Hooks
```javascript
// hooks/useInfiniteScroll.js
import { useEffect, useCallback } from 'react';

export const useInfiniteScroll = (callback, hasNextPage, isLoading) => {
  const handleScroll = useCallback(() => {
    if (isLoading || !hasNextPage) return;
    
    if (window.innerHeight + window.scrollY >= document.body.offsetHeight - 1000) {
      callback();
    }
  }, [callback, hasNextPage, isLoading]);

  useEffect(() => {
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, [handleScroll]);
};

// hooks/useDebounce.js
import { useState, useEffect } from 'react';

export const useDebounce = (value, delay) => {
  const [debouncedValue, setDebouncedValue] = useState(value);

  useEffect(() => {
    const handler = setTimeout(() => {
      setDebouncedValue(value);
    }, delay);

    return () => {
      clearTimeout(handler);
    };
  }, [value, delay]);

  return debouncedValue;
};

// hooks/useLocalStorage.js
import { useState, useEffect } from 'react';

export const useLocalStorage = (key, initialValue) => {
  const [storedValue, setStoredValue] = useState(() => {
    try {
      const item = window.localStorage.getItem(key);
      return item ? JSON.parse(item) : initialValue;
    } catch (error) {
      return initialValue;
    }
  });

  const setValue = (value) => {
    try {
      setStoredValue(value);
      window.localStorage.setItem(key, JSON.stringify(value));
    } catch (error) {
      console.error(`Error setting localStorage key "${key}":`, error);
    }
  };

  return [storedValue, setValue];
};
```

### Component Examples
```jsx
// components/features/Ideas/IdeaCard.jsx
import React from 'react';
import { BookmarkIcon, HeartIcon, ShareIcon } from '@heroicons/react/24/outline';
import { useAuthStore } from '../../../stores/authStore';
import { useIdeasStore } from '../../../stores/ideasStore';

export const IdeaCard = ({ idea }) => {
  const { isAuthenticated } = useAuthStore();
  const { likeIdea, saveIdea } = useIdeasStore();

  const handleLike = async () => {
    if (!isAuthenticated) return;
    try {
      await likeIdea(idea.id);
    } catch (error) {
      // Show error toast
    }
  };

  const handleSave = async () => {
    if (!isAuthenticated) return;
    try {
      await saveIdea(idea.id);
    } catch (error) {
      // Show error toast
    }
  };

  return (
    <div className="bg-white rounded-lg shadow-md p-6 hover:shadow-lg transition-shadow">
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center space-x-3">
          <img
            src={idea.author.avatarUrl || '/default-avatar.png'}
            alt={idea.author.username}
            className="w-8 h-8 rounded-full"
          />
          <div>
            <p className="text-sm font-medium text-gray-900">
              {idea.author.username}
            </p>
            <p className="text-xs text-gray-500">
              {new Date(idea.createdAt).toLocaleDateString()}
            </p>
          </div>
        </div>
        <div className="flex items-center space-x-1">
          <span 
            className="px-2 py-1 rounded-full text-xs font-medium"
            style={{ 
              backgroundColor: `${idea.category.color}20`,
              color: idea.category.color 
            }}
          >
            {idea.category.name}
          </span>
        </div>
      </div>

      <h3 className="text-lg font-semibold text-gray-900 mb-2">
        {idea.title}
      </h3>
      
      <p className="text-gray-600 text-sm mb-4 line-clamp-3">
        {idea.summary || idea.content.substring(0, 150) + '...'}
      </p>

      {idea.tags.length > 0 && (
        <div className="flex flex-wrap gap-2 mb-4">
          {idea.tags.slice(0, 3).map((tagRelation) => (
            <span
              key={tagRelation.tag.id}
              className="px-2 py-1 bg-gray-100 text-gray-600 text-xs rounded-md"
            >
              #{tagRelation.tag.name}
            </span>
          ))}
          {idea.tags.length > 3 && (
            <span className="px-2 py-1 bg-gray-100 text-gray-500 text-xs rounded-md">
              +{idea.tags.length - 3} more
            </span>
          )}
        </div>
      )}

      <div className="flex items-center justify-between pt-4 border-t border-gray-100">
        <div className="flex items-center space-x-4">
          <button
            onClick={handleLike}
            className={`flex items-center space-x-1 text-sm ${
              idea.isLiked ? 'text-red-500' : 'text-gray-500 hover:text-red-500'
            }`}
          >
            <HeartIcon className={`w-5 h-5 ${idea.isLiked ? 'fill-current' : ''}`} />
            <span>{idea.likeCount}</span>
          </button>
          
          <button
            onClick={handleSave}
            className={`flex items-center space-x-1 text-sm ${
              idea.isSaved ? 'text-blue-500' : 'text-gray-500 hover:text-blue-500'
            }`}
          >
            <BookmarkIcon className={`w-5 h-5 ${idea.isSaved ? 'fill-current' : ''}`} />
            <span>{idea.saveCount}</span>
          </button>
        </div>

        <button className="text-gray-500 hover:text-gray-700">
          <ShareIcon className="w-5 h-5" />
        </button>
      </div>
    </div>
  );
};
```

## Testing Strategy

### Testing Pyramid

#### Unit Tests (70% of tests)
```javascript
// tests/utils/sanitize.test.js
import { sanitizeContent } from '../../src/utils/sanitize';

describe('sanitizeContent', () => {
  it('should remove script tags', () => {
    const input = '<p>Hello</p><script>alert("xss")</script>';
    const expected = '<p>Hello</p>';
    expect(sanitizeContent(input)).toBe(expected);
  });

  it('should allow safe HTML tags', () => {
    const input = '<p><strong>Bold</strong> and <em>italic</em></p>';
    expect(sanitizeContent(input)).toBe(input);
  });

  it('should remove dangerous attributes', () => {
    const input = '<p onclick="alert()">Click me</p>';
    const expected = '<p>Click me</p>';
    expect(sanitizeContent(input)).toBe(expected);
  });
});

// tests/stores/authStore.test.js
import { useAuthStore } from '../../src/stores/authStore';
import { authAPI } from '../../src/services/auth';

jest.mock('../../src/services/auth');

describe('authStore', () => {
  beforeEach(() => {
    useAuthStore.setState({ 
      user: null, 
      token: null, 
      isAuthenticated: false 
    });
  });

  it('should login successfully', async () => {
    const mockUser = { id: '1', username: 'testuser' };
    const mockToken = 'mock-jwt-token';
    
    authAPI.login.mockResolvedValue({ user: mockUser, token: mockToken });

    const result = await useAuthStore.getState().login('test@example.com', 'password');

    expect(result.success).toBe(true);
    expect(useAuthStore.getState().user).toEqual(mockUser);
    expect(useAuthStore.getState().token).toBe(mockToken);
    expect(useAuthStore.getState().isAuthenticated).toBe(true);
  });
});
```

#### Integration Tests (20% of tests)
```javascript
// tests/api/ideas.test.js
import request from 'supertest';
import app from '../../src/app';
import { prisma } from '../../src/lib/prisma';

describe('Ideas API', () => {
  let authToken;
  let testUser;

  beforeAll(async () => {
    // Create test user
    testUser = await prisma.user.create({
      data: {
        email: 'test@example.com',
        username: 'testuser',
        passwordHash: 'hashed-password'
      }
    });

    // Get auth token
    const response = await request(app)
      .post('/api/v1/auth/login')
      .send({
        email: 'test@example.com',
        password: 'password'
      });

    authToken = response.body.token;
  });

  afterAll(async () => {
    await prisma.user.delete({ where: { id: testUser.id } });
    await prisma.$disconnect();
  });

  describe('GET /api/v1/ideas', () => {
    it('should return paginated ideas', async () => {
      const response = await request(app)
        .get('/api/v1/ideas')
        .query({ page: 1, limit: 10 });

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('ideas');
      expect(response.body).toHaveProperty('pagination');
      expect(Array.isArray(response.body.ideas)).toBe(true);
    });

    it('should filter ideas by category', async () => {
      const category = await prisma.category.findFirst();
      
      const response = await request(app)
        .get('/api/v1/ideas')
        .query({ category: category.id });

      expect(response.status).toBe(200);
      response.body.ideas.forEach(idea => {
        expect(idea.categoryId).toBe(category.id);
      });
    });
  });

  describe('POST /api/v1/ideas', () => {
    it('should create a new idea', async () => {
      const category = await prisma.category.findFirst();
      
      const ideaData = {
        title: 'Test Idea',
        content: 'This is a test idea content.',
        categoryId: category.id
      };

      const response = await request(app)
        .post('/api/v1/ideas')
        .set('Authorization', `Bearer ${authToken}`)
        .send(ideaData);

      expect(response.status).toBe(201);
      expect(response.body.title).toBe(ideaData.title);
      expect(response.body.authorId).toBe(testUser.id);
    });

    it('should require authentication', async () => {
      const response = await request(app)
        .post('/api/v1/ideas')
        .send({
          title: 'Test Idea',
          content: 'This is a test idea content.'
        });

      expect(response.status).toBe(401);
    });
  });
});
```

#### End-to-End Tests (10% of tests)
```javascript
// tests/e2e/user-journey.test.js
import { test, expect } from '@playwright/test';

test.describe('User Journey', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('user can browse ideas without authentication', async ({ page }) => {
    // Check that ideas are visible
    await expect(page.locator('[data-testid=idea-card]')).toHaveCount({ min: 1 });
    
    // Check pagination
    await expect(page.locator('[data-testid=load-more-button]')).toBeVisible();
    
    // Test search
    await page.fill('[data-testid=search-input]', 'productivity');
    await page.press('[data-testid=search-input]', 'Enter');
    await expect(page.url()).toContain('search=productivity');
  });

  test('user can register and login', async ({ page }) => {
    // Go to register
    await page.click('[data-testid=register-button]');
    
    // Fill registration form
    await page.fill('[data-testid=email-input]', 'test@example.com');
    await page.fill('[data-testid=username-input]', 'testuser');
    await page.fill('[data-testid=password-input]', 'StrongPassword123!');
    await page.fill('[data-testid=confirm-password-input]', 'StrongPassword123!');
    
    // Submit form
    await page.click('[data-testid=register-submit]');
    
    // Should redirect to dashboard
    await expect(page.url()).toContain('/dashboard');
    await expect(page.locator('[data-testid=user-menu]')).toBeVisible();
  });

  test('authenticated user can save and like ideas', async ({ page }) => {
    // Login first
    await loginUser(page, 'test@example.com', 'StrongPassword123!');
    
    // Find first idea
    const firstIdea = page.locator('[data-testid=idea-card]').first();
    
    // Like the idea
    await firstIdea.locator('[data-testid=like-button]').click();
    await expect(firstIdea.locator('[data-testid=like-button]')).toHaveClass(/text-red-500/);
    
    // Save the idea
    await firstIdea.locator('[data-testid=save-button]').click();
    await expect(firstIdea.locator('[data-testid=save-button]')).toHaveClass(/text-blue-500/);
    
    // Check saved ideas page
    await page.click('[data-testid=saved-ideas-link]');
    await expect(page.locator('[data-testid=idea-card]')).toHaveCount({ min: 1 });
  });
});

async function loginUser(page, email, password) {
  await page.click('[data-testid=login-button]');
  await page.fill('[data-testid=email-input]', email);
  await page.fill('[data-testid=password-input]', password);
  await page.click('[data-testid=login-submit]');
  await expect(page.locator('[data-testid=user-menu]')).toBeVisible();
}
```

### Performance Testing
```javascript
// tests/performance/load.test.js
import http from 'k6/http';
import { check, sleep } from 'k6';

export let options = {
  stages: [
    { duration: '2m', target: 100 }, // Ramp up
    { duration: '5m', target: 100 }, // Stay at 100 users
    { duration: '2m', target: 200 }, // Ramp up to 200 users
    { duration: '5m', target: 200 }, // Stay at 200 users
    { duration: '2m', target: 0 },   // Ramp down
  ],
  thresholds: {
    http_req_duration: ['p(99)<1500'], // 99% of requests under 1.5s
    http_req_failed: ['rate<0.1'],     // Error rate under 10%
  },
};

export default function () {
  // Test ideas endpoint
  let response = http.get(`${__ENV.API_URL}/api/v1/ideas`);
  check(response, {
    'status is 200': (r) => r.status === 200,
    'response time < 1000ms': (r) => r.timings.duration < 1000,
  });

  sleep(1);

  // Test search endpoint
  response = http.get(`${__ENV.API_URL}/api/v1/search/ideas?q=productivity`);
  check(response, {
    'search status is 200': (r) => r.status === 200,
    'search response time < 2000ms': (r) => r.timings.duration < 2000,
  });

  sleep(1);
}
```

## Deployment Strategy

### Docker Configuration

#### Production Dockerfile
```dockerfile
# Multi-stage build for backend
FROM node:18-alpine AS backend-deps
WORKDIR /app
COPY src/backend/package*.json ./
RUN npm ci --only=production && npm cache clean --force

FROM node:18-alpine AS backend-build
WORKDIR /app
COPY src/backend/package*.json ./
RUN npm ci
COPY src/backend ./
RUN npm run build

# Frontend build
FROM node:18-alpine AS frontend-build
WORKDIR /app
COPY src/frontend/package*.json ./
RUN npm ci
COPY src/frontend ./
ARG REACT_APP_API_URL
ENV REACT_APP_API_URL=$REACT_APP_API_URL
RUN npm run build

# Production image
FROM node:18-alpine AS production

# Create app directory and non-root user
WORKDIR /app
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodeapp -u 1001

# Copy backend dependencies and built code
COPY --from=backend-deps --chown=nodeapp:nodejs /app/node_modules ./node_modules
COPY --from=backend-build --chown=nodeapp:nodejs /app/dist ./dist
COPY --from=backend-build --chown=nodeapp:nodejs /app/package*.json ./

# Copy frontend build
COPY --from=frontend-build --chown=nodeapp:nodejs /app/build ./public

# Security hardening
RUN apk add --no-cache dumb-init && \
    rm -rf /var/cache/apk/* /tmp/*

# Switch to non-root user
USER nodeapp

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node dist/healthcheck.js

# Start application
EXPOSE 3000
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "dist/server.js"]
```

#### Docker Compose Production
```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  postgres:
    image: postgres:14-alpine
    restart: unless-stopped
    environment:
      POSTGRES_USER: ${DB_USER}
      POSTGRES_PASSWORD: ${DB_PASSWORD}
      POSTGRES_DB: ${DB_NAME}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./scripts/postgres-init.sql:/docker-entrypoint-initdb.d/init.sql
    networks:
      - backend
    deploy:
      resources:
        limits:
          cpus: '1'
          memory: 1G

  redis:
    image: redis:7-alpine
    restart: unless-stopped
    command: redis-server --appendonly yes --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis_data:/data
    networks:
      - backend
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 256M

  app:
    build:
      context: .
      dockerfile: Dockerfile
      args:
        REACT_APP_API_URL: ${API_URL}
    restart: unless-stopped
    depends_on:
      - postgres
      - redis
    environment:
      - NODE_ENV=production
      - DATABASE_URL=postgresql://${DB_USER}:${DB_PASSWORD}@postgres:5432/${DB_NAME}
      - REDIS_URL=redis://redis:6379
      - JWT_SECRET=${JWT_SECRET}
      - PORT=3000
    networks:
      - backend
      - frontend
    deploy:
      replicas: 2
      resources:
        limits:
          cpus: '1'
          memory: 512M

  nginx:
    image: nginx:alpine
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/ssl:/etc/nginx/ssl:ro
      - static_files:/var/www/static:ro
    depends_on:
      - app
    networks:
      - frontend
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 128M

  prometheus:
    image: prom/prometheus:latest
    restart: unless-stopped
    ports:
      - "9090:9090"
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
    networks:
      - monitoring

  grafana:
    image: grafana/grafana:latest
    restart: unless-stopped
    ports:
      - "3001:3000"
    volumes:
      - grafana_data:/var/lib/grafana
      - ./monitoring/grafana/dashboards:/var/lib/grafana/dashboards
      - ./monitoring/grafana/provisioning:/etc/grafana/provisioning
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD}
    networks:
      - monitoring

networks:
  backend:
    driver: bridge
  frontend:
    driver: bridge
  monitoring:
    driver: bridge

volumes:
  postgres_data:
  redis_data:
  static_files:
  prometheus_data:
  grafana_data:
```

### CI/CD Pipeline

#### GitHub Actions Workflow
```yaml
# .github/workflows/ci-cd.yml
name: CI/CD Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

env:
  NODE_VERSION: '18'
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:14
        env:
          POSTGRES_PASSWORD: postgres
          POSTGRES_DB: test_db
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432

      redis:
        image: redis:7
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 6379:6379

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: ${{ env.NODE_VERSION }}
          cache: 'npm'

      - name: Install dependencies
        run: |
          npm ci
          cd src/backend && npm ci
          cd ../frontend && npm ci

      - name: Run linting
        run: npm run lint

      - name: Run type checking
        run: npm run typecheck

      - name: Run unit tests
        run: npm run test:unit
        env:
          DATABASE_URL: postgresql://postgres:postgres@localhost:5432/test_db
          REDIS_URL: redis://localhost:6379

      - name: Run integration tests
        run: npm run test:integration
        env:
          DATABASE_URL: postgresql://postgres:postgres@localhost:5432/test_db
          REDIS_URL: redis://localhost:6379

      - name: Upload test coverage
        uses: codecov/codecov-action@v3
        with:
          files: ./coverage/lcov.info
          fail_ci_if_error: true

  security:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Run dependency vulnerability scan
        run: npm audit --audit-level moderate

      - name: Run Snyk security scan
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        with:
          args: --severity-threshold=high

      - name: Run CodeQL Analysis
        uses: github/codeql-action/analyze@v2
        with:
          languages: javascript, typescript

  build:
    needs: [test, security]
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    
    permissions:
      contents: read
      packages: write

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Log in to Container Registry
        uses: docker/login-action@v2
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Extract metadata
        id: meta
        uses: docker/metadata-action@v4
        with:
          images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
          tags: |
            type=ref,event=branch
            type=ref,event=pr
            type=sha
            type=raw,value=latest,enable={{is_default_branch}}

      - name: Build and push Docker image
        uses: docker/build-push-action@v4
        with:
          context: .
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          build-args: |
            REACT_APP_API_URL=${{ secrets.API_URL }}

  deploy:
    needs: build
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    environment: production

    steps:
      - name: Deploy to production
        uses: appleboy/ssh-action@v0.1.5
        with:
          host: ${{ secrets.HOST }}
          username: ${{ secrets.USERNAME }}
          key: ${{ secrets.SSH_KEY }}
          script: |
            cd /opt/deepstash-oss
            docker-compose -f docker-compose.prod.yml pull
            docker-compose -f docker-compose.prod.yml up -d
            docker system prune -f

      - name: Run post-deployment tests
        run: |
          sleep 30
          curl -f ${{ secrets.API_URL }}/health || exit 1

      - name: Notify deployment
        uses: 8398a7/action-slack@v3
        if: always()
        with:
          status: ${{ job.status }}
          text: Deployment to production completed
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK }}
```

### Monitoring and Observability

#### Application Monitoring
```javascript
// src/backend/middleware/monitoring.js
const prometheus = require('prom-client');

// Create a Registry
const register = new prometheus.Registry();

// Add default metrics
prometheus.collectDefaultMetrics({ register });

// Custom metrics
const httpDuration = new prometheus.Histogram({
  name: 'http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'route', 'status_code'],
  buckets: [0.1, 0.3, 0.5, 0.7, 1, 3, 5, 7, 10]
});

const httpRequests = new prometheus.Counter({
  name: 'http_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'route', 'status_code']
});

const activeUsers = new prometheus.Gauge({
  name: 'active_users_total',
  help: 'Total number of active users',
});

const dbConnectionPool = new prometheus.Gauge({
  name: 'database_connections_active',
  help: 'Number of active database connections',
});

register.registerMetric(httpDuration);
register.registerMetric(httpRequests);
register.registerMetric(activeUsers);
register.registerMetric(dbConnectionPool);

// Middleware to track HTTP requests
const trackHttpRequests = (req, res, next) => {
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = (Date.now() - start) / 1000;
    const labels = {
      method: req.method,
      route: req.route?.path || req.path,
      status_code: res.statusCode
    };
    
    httpDuration.observe(labels, duration);
    httpRequests.inc(labels);
  });
  
  next();
};

// Metrics endpoint
const metricsEndpoint = (req, res) => {
  res.set('Content-Type', register.contentType);
  res.end(register.metrics());
};

module.exports = {
  trackHttpRequests,
  metricsEndpoint,
  register,
  metrics: {
    httpDuration,
    httpRequests,
    activeUsers,
    dbConnectionPool
  }
};
```

#### Health Check Implementation
```javascript
// src/backend/routes/health.js
const express = require('express');
const { PrismaClient } = require('@prisma/client');
const Redis = require('ioredis');

const router = express.Router();
const prisma = new PrismaClient();
const redis = new Redis(process.env.REDIS_URL);

router.get('/health', async (req, res) => {
  const checks = {
    timestamp: new Date().toISOString(),
    status: 'healthy',
    version: process.env.npm_package_version || '1.0.0',
    environment: process.env.NODE_ENV,
    checks: {}
  };

  try {
    // Database check
    await prisma.$queryRaw`SELECT 1`;
    checks.checks.database = { status: 'healthy', responseTime: 0 };
  } catch (error) {
    checks.checks.database = { 
      status: 'unhealthy', 
      error: error.message 
    };
    checks.status = 'unhealthy';
  }

  try {
    // Redis check
    const start = Date.now();
    await redis.ping();
    checks.checks.redis = { 
      status: 'healthy', 
      responseTime: Date.now() - start 
    };
  } catch (error) {
    checks.checks.redis = { 
      status: 'unhealthy', 
      error: error.message 
    };
    checks.status = 'unhealthy';
  }

  // Memory usage
  const memUsage = process.memoryUsage();
  checks.checks.memory = {
    status: memUsage.heapUsed > 500 * 1024 * 1024 ? 'warning' : 'healthy',
    heapUsed: `${Math.round(memUsage.heapUsed / 1024 / 1024)}MB`,
    heapTotal: `${Math.round(memUsage.heapTotal / 1024 / 1024)}MB`
  };

  const statusCode = checks.status === 'healthy' ? 200 : 503;
  res.status(statusCode).json(checks);
});

router.get('/ready', async (req, res) => {
  // Readiness check - more thorough than health check
  try {
    await prisma.user.findFirst();
    res.status(200).json({ status: 'ready' });
  } catch (error) {
    res.status(503).json({ status: 'not ready', error: error.message });
  }
});

module.exports = router;
```

## Community Management

### Open Source Project Structure

#### Governance Model
```markdown
# Project Governance

## Core Team
- **Project Lead**: Overall vision and direction
- **Technical Lead**: Architecture and code quality
- **Community Manager**: User engagement and support
- **Security Lead**: Security reviews and incident response

## Contribution Levels
1. **Users**: Report issues, provide feedback
2. **Contributors**: Submit code, documentation, translations
3. **Maintainers**: Review PRs, manage releases
4. **Core Team**: Strategic decisions, governance

## Decision Making
- Technical decisions: Consensus among maintainers
- Strategic decisions: Core team vote
- Community input: Regular surveys and RFC process
- Dispute resolution: Escalation to project lead
```

#### Contributing Guidelines
```markdown
# Contributing Guide

## Getting Started
1. Read our Code of Conduct
2. Check existing issues and discussions
3. Set up development environment
4. Make small, focused contributions initially

## Types of Contributions
- **Bug Reports**: Use issue templates
- **Feature Requests**: Submit RFC for large changes
- **Code**: Follow our coding standards
- **Documentation**: Improve clarity and completeness
- **Translations**: Help localize the application
- **Design**: UI/UX improvements and assets

## Development Process
1. Fork repository and create feature branch
2. Write code with tests and documentation
3. Run full test suite and linting
4. Submit PR with clear description
5. Respond to review feedback
6. Celebrate when merged! 🎉

## Code Review Process
- All changes require review from core team member
- Focus on code quality, security, and maintainability
- Be constructive and respectful in feedback
- Learn from each other

## Recognition
- Contributors listed in README and releases
- Special recognition for significant contributions
- Invitation to join maintainer team for outstanding contributors
```

#### Issue and PR Templates
```markdown
# Bug Report Template
---
name: Bug report
about: Create a report to help us improve
title: ''
labels: 'bug'
assignees: ''
---

## Bug Description
A clear and concise description of what the bug is.

## Steps to Reproduce
1. Go to '...'
2. Click on '....'
3. Scroll down to '....'
4. See error

## Expected Behavior
A clear and concise description of what you expected to happen.

## Screenshots
If applicable, add screenshots to help explain your problem.

## Environment
- OS: [e.g. iOS, Windows, Ubuntu]
- Browser: [e.g. Chrome, Safari, Firefox]
- Version: [e.g. 22]
- Device: [e.g. iPhone6, Desktop]

## Additional Context
Add any other context about the problem here.

---

# Feature Request Template
---
name: Feature request
about: Suggest an idea for this project
title: ''
labels: 'enhancement'
assignees: ''
---

## Feature Description
A clear and concise description of what you want to happen.

## Problem/Motivation
Is your feature request related to a problem? Please describe.
A clear and concise description of what the problem is.

## Proposed Solution
Describe the solution you'd like.

## Alternatives Considered
Describe any alternative solutions or features you've considered.

## Additional Context
Add any other context or screenshots about the feature request here.

## Implementation Notes
- [ ] Requires database changes
- [ ] Affects API
- [ ] Needs UI changes
- [ ] Security considerations
- [ ] Breaking change
```

### Community Engagement

#### Communication Channels
```yaml
# Community Channels Setup
GitHub:
  - Issues: Bug reports and feature requests
  - Discussions: General questions and community chat
  - Projects: Roadmap and sprint planning
  - Wiki: Documentation and guides

Discord Server:
  channels:
    - general: General discussion
    - help: User support
    - development: Technical discussions
    - showcase: Community projects
    - off-topic: Non-project chat
  
  roles:
    - Core Team: Full permissions
    - Maintainers: Moderation permissions
    - Contributors: Special badge
    - Users: Default permissions

Email:
  - security@project.com: Security reports
  - community@project.com: General inquiries
  - media@project.com: Press inquiries

Social Media:
  - Twitter: Updates and community highlights
  - LinkedIn: Professional updates
  - Reddit: Community discussions
```

#### Community Events
```markdown
# Community Calendar

## Regular Events
- **Weekly Dev Sync**: Fridays 15:00 UTC
- **Monthly Community Call**: First Tuesday 18:00 UTC
- **Quarterly Roadmap Review**: Every 3 months
- **Annual Community Conference**: Summer

## Special Events
- **Hacktoberfest**: October contribution drive
- **Spring Cleaning**: March technical debt reduction
- **Summer of Code**: Mentoring program
- **Winter Release**: Major release preparation

## Recognition Programs
- **Contributor of the Month**: Monthly recognition
- **Annual Awards**: Outstanding contribution recognition
- **Conference Speakers**: Support speaking opportunities
- **Mentorship Program**: Pair experienced with new contributors
```

## Maintenance and Updates

### Release Management

#### Semantic Versioning
```markdown
# Version Strategy

## Versioning Scheme: MAJOR.MINOR.PATCH

### MAJOR (1.0.0 → 2.0.0)
- Breaking API changes
- Major architectural changes
- Significant feature overhauls
- Database schema breaking changes

### MINOR (1.0.0 → 1.1.0)  
- New features
- Non-breaking API additions
- Performance improvements
- New endpoints or capabilities

### PATCH (1.0.0 → 1.0.1)
- Bug fixes
- Security patches
- Documentation updates
- Minor improvements

## Pre-release Versions
- Alpha: 1.1.0-alpha.1 (early development)
- Beta: 1.1.0-beta.1 (feature complete, testing)
- RC: 1.1.0-rc.1 (release candidate)
```

#### Release Process
```bash
#!/bin/bash
# scripts/release.sh

set -e

VERSION=$1
if [ -z "$VERSION" ]; then
  echo "Usage: ./release.sh <version>"
  exit 1
fi

echo "🚀 Starting release process for version $VERSION"

# 1. Run full test suite
echo "📋 Running tests..."
npm run test:full

# 2. Run security audit
echo "🔒 Running security audit..."
npm audit --audit-level moderate

# 3. Update version in package.json
echo "📝 Updating version..."
npm version $VERSION --no-git-tag-version

# 4. Build production assets
echo "🏗️ Building production assets..."
npm run build

# 5. Run final checks
echo "✅ Running final checks..."
npm run typecheck
npm run lint

# 6. Update CHANGELOG
echo "📋 Updating CHANGELOG..."
conventional-changelog -p angular -i CHANGELOG.md -s

# 7. Commit and tag
echo "💾 Creating git tag..."
git add .
git commit -m "chore: release v$VERSION"
git tag -a "v$VERSION" -m "Release v$VERSION"

# 8. Push to repository
echo "📤 Pushing to repository..."
git push origin main --tags

# 9. Create GitHub release
echo "🎉 Creating GitHub release..."
gh release create "v$VERSION" --auto --notes-file CHANGELOG.md

echo "✨ Release v$VERSION completed successfully!"
```

### Security Updates

#### Security Patch Process
```markdown
# Security Update Process

## Immediate Response (Critical - 24 hours)
1. **Assessment**: Evaluate severity and impact
2. **Fix Development**: Implement minimal viable fix
3. **Testing**: Security-focused testing
4. **Release**: Emergency patch release
5. **Communication**: Security advisory publication

## Standard Response (High/Medium - 7 days)
1. **Triage**: Classify and prioritize
2. **Investigation**: Root cause analysis
3. **Fix Development**: Comprehensive solution
4. **Review**: Security team review
5. **Testing**: Full regression testing
6. **Release**: Standard release process
7. **Disclosure**: Coordinated disclosure

## Security Advisory Template
```markdown
# Security Advisory: [CVE-ID] - [Title]

## Summary
Brief description of the vulnerability.

## Impact
Description of potential impact and affected versions.

## Affected Versions
- Version range affected
- Fixed in version X.Y.Z

## Workarounds
Temporary mitigation steps if available.

## Fix
Description of the fix and upgrade instructions.

## Credits
Recognition of security researchers.

## Timeline
- Discovery date
- Fix development
- Release date
- Public disclosure
```

### Dependency Management

#### Automated Updates
```yaml
# .github/dependabot.yml
version: 2
updates:
  # NPM dependencies
  - package-ecosystem: "npm"
    directory: "/src/backend"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
    reviewers:
      - "@core-team"
    commit-message:
      prefix: "deps"
      prefix-development: "deps-dev"

  - package-ecosystem: "npm"
    directory: "/src/frontend"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
    reviewers:
      - "@core-team"

  # Docker dependencies
  - package-ecosystem: "docker"
    directory: "/"
    schedule:
      interval: "weekly"
    reviewers:
      - "@core-team"

  # GitHub Actions
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
```

#### Dependency Security Monitoring
```javascript
// scripts/security-check.js
const { execSync } = require('child_process');
const fs = require('fs');

async function runSecurityChecks() {
  const results = {
    timestamp: new Date().toISOString(),
    checks: []
  };

  try {
    // NPM Audit
    console.log('🔍 Running npm audit...');
    const auditResult = execSync('npm audit --json', { encoding: 'utf8' });
    const audit = JSON.parse(auditResult);
    
    results.checks.push({
      type: 'npm-audit',
      status: audit.metadata.vulnerabilities.total === 0 ? 'pass' : 'fail',
      vulnerabilities: audit.metadata.vulnerabilities,
      advisories: Object.keys(audit.advisories).length
    });

  } catch (error) {
    results.checks.push({
      type: 'npm-audit',
      status: 'error',
      error: error.message
    });
  }

  try {
    // Snyk test
    console.log('🔍 Running Snyk security test...');
    execSync('snyk test --severity-threshold=medium', { stdio: 'pipe' });
    results.checks.push({
      type: 'snyk',
      status: 'pass'
    });
  } catch (error) {
    results.checks.push({
      type: 'snyk',
      status: 'fail',
      error: error.message
    });
  }

  // Save results
  fs.writeFileSync('security-report.json', JSON.stringify(results, null, 2));
  
  // Exit with error if any checks failed
  const hasFailures = results.checks.some(check => check.status === 'fail');
  if (hasFailures) {
    console.error('❌ Security checks failed!');
    process.exit(1);
  } else {
    console.log('✅ All security checks passed!');
  }
}

runSecurityChecks().catch(console.error);
```

### Performance Monitoring

#### Key Metrics
```javascript
// monitoring/metrics.js
const metrics = {
  // Application Performance
  responseTime: {
    target: 'p95 < 500ms',
    critical: 'p95 > 1000ms'
  },
  
  throughput: {
    target: '> 1000 req/min',
    critical: '< 100 req/min'
  },
  
  errorRate: {
    target: '< 1%',
    critical: '> 5%'
  },
  
  // System Resources
  cpuUsage: {
    target: '< 70%',
    critical: '> 90%'
  },
  
  memoryUsage: {
    target: '< 80%',
    critical: '> 95%'
  },
  
  diskUsage: {
    target: '< 80%',
    critical: '> 95%'
  },
  
  // Database Performance
  dbConnectionPool: {
    target: '< 80% utilized',
    critical: '> 95% utilized'
  },
  
  dbQueryTime: {
    target: 'p95 < 100ms',
    critical: 'p95 > 500ms'
  },
  
  // Business Metrics
  activeUsers: {
    target: 'Growing MoM',
    monitor: 'DAU, MAU'
  },
  
  userEngagement: {
    target: 'Session duration > 5min',
    monitor: 'Page views, interactions'
  }
};

module.exports = metrics;
```

## Conclusion

This comprehensive development guide provides the foundation for building a secure, scalable, and community-driven open-source alternative to Deepstash. The guide emphasizes:

### Key Success Factors
1. **Security First**: Implement security at every layer
2. **Community Driven**: Build for and with the community
3. **Quality Focus**: Maintain high code quality and test coverage
4. **Performance Optimized**: Deliver fast, responsive user experience
5. **Scalable Architecture**: Design for growth and sustainability

### Next Steps
1. **Phase 1**: Set up development environment and team structure
2. **Phase 2**: Implement core features with security focus
3. **Phase 3**: Build advanced features and community tools
4. **Phase 4**: Launch and iterate based on user feedback
5. **Phase 5**: Scale and maintain the platform

### Long-term Vision
Create a thriving open-source ecosystem that empowers knowledge sharing and microlearning while maintaining the highest standards of security, performance, and user experience.

Remember: Building successful open-source software is a marathon, not a sprint. Focus on building a strong foundation, fostering community, and iterating based on real user needs.

---

*This guide is a living document. Please contribute improvements and updates as the project evolves.*