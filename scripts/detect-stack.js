'use strict';

// Reconnaissance engine. Reads a target repository and produces a structured
// picture of the stack so the audit plan adapts to what is actually present.
// Deterministic and offline: file-name and content heuristics only. The AI
// recon agent (Phase 2 of SKILL.md) extends this with semantic analysis and
// writes threat-model.json on top of it.

const fs = require('fs');
const path = require('path');
const { walkFiles, toRel } = require('../lib/util');

function readIfSmall(absPath, maxBytes) {
  const limit = maxBytes || 512 * 1024;
  try {
    const stat = fs.statSync(absPath);
    if (stat.size > limit) return null;
    return fs.readFileSync(absPath, 'utf8');
  } catch (_e) {
    return null;
  }
}

function exists(root, rel) {
  try {
    return fs.existsSync(path.join(root, rel));
  } catch (_e) {
    return false;
  }
}

function anyExists(root, rels) {
  return rels.some((r) => exists(root, r));
}

// ---------------------------------------------------------------------------
// Language detection by extension + marker files
// ---------------------------------------------------------------------------

const LANG_BY_EXT = {
  '.js': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript', '.jsx': 'javascript',
  '.ts': 'typescript', '.tsx': 'typescript', '.mts': 'typescript', '.cts': 'typescript',
  '.py': 'python', '.rb': 'ruby', '.go': 'go', '.rs': 'rust', '.java': 'java',
  '.kt': 'kotlin', '.swift': 'swift', '.php': 'php', '.cs': 'csharp', '.c': 'c',
  '.h': 'c', '.cpp': 'cpp', '.cc': 'cpp', '.hpp': 'cpp', '.scala': 'scala',
  '.sh': 'shell', '.bash': 'shell', '.ps1': 'powershell', '.sql': 'sql',
  '.dart': 'dart', '.lua': 'lua', '.ex': 'elixir', '.erl': 'erlang',
  '.hs': 'haskell', '.zig': 'zig', '.vue': 'vue', '.svelte': 'svelte',
};

function detectLanguages(root, files) {
  const counts = {};
  for (const f of files) {
    const ext = path.extname(f).toLowerCase();
    const lang = LANG_BY_EXT[ext];
    if (lang) counts[lang] = (counts[lang] || 0) + 1;
  }
  return Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .map(([lang, count]) => ({ lang, files: count }));
}

// ---------------------------------------------------------------------------
// Package manifest parsing (Node, Python, Go, Rust, PHP, Ruby, Java)
// ---------------------------------------------------------------------------

function safeParseJson(text) {
  try {
    return JSON.parse(text);
  } catch (_e) {
    return null;
  }
}

function parseDependenciesSection(depsObj, out, source) {
  if (!depsObj || typeof depsObj !== 'object') return;
  for (const [name, spec] of Object.entries(depsObj)) {
    out.push({ name, spec: String(spec), source });
  }
}

function detectNodeStack(root, files, manifestFiles) {
  const stack = { languages: [], frameworks: [], packages: [], tooling: [] };
  const pkgJsonPath = manifestFiles.find((f) => f.endsWith('package.json'));
  if (!pkgJsonPath) return stack;

  const pkg = safeParseJson(readIfSmall(path.join(root, pkgJsonPath)) || '');
  if (!pkg) return stack;

  const deps = [];
  parseDependenciesSection(pkg.dependencies, deps, 'dependencies');
  parseDependenciesSection(pkg.devDependencies, deps, 'devDependencies');

  const FRAMEWORK_HINTS = [
    { match: /^next$/, framework: 'Next.js', kind: 'fullstack' },
    { match: /^nuxt$/, framework: 'Nuxt', kind: 'fullstack' },
    { match: /^remix$/, framework: 'Remix', kind: 'fullstack' },
    { match: /^@nestjs\/core$/, framework: 'NestJS', kind: 'backend' },
    { match: /^express$/, framework: 'Express', kind: 'backend' },
    { match: /^@fastify\/express$|^fastify$/, framework: 'Fastify', kind: 'backend' },
    { match: /^koa$/, framework: 'Koa', kind: 'backend' },
    { match: /^hapi|^@hapi\/hapi$/, framework: 'Hapi', kind: 'backend' },
    { match: /^@hono\/hono$|^hono$/, framework: 'Hono', kind: 'backend' },
    { match: /^react$|^react-dom$/, framework: 'React', kind: 'frontend' },
    { match: /^vue$|^vue-router$/, framework: 'Vue', kind: 'frontend' },
    { match: /^svelte|^@sveltejs/, framework: 'Svelte', kind: 'frontend' },
    { match: /^@angular\/core$/, framework: 'Angular', kind: 'frontend' },
    { match: /^astro$/, framework: 'Astro', kind: 'fullstack' },
    { match: /^gatsby$/, framework: 'Gatsby', kind: 'fullstack' },
    { match: /^graphql|^@apollo\/server$|^apollo-server/, framework: 'GraphQL', kind: 'api' },
    { match: /^@trpc\/server$/, framework: 'tRPC', kind: 'api' },
    { match: /^socket\.io$|^ws$/, framework: 'WebSockets', kind: 'realtime' },
    { match: /^prisma$|^@prisma\/client$/, framework: 'Prisma', kind: 'orm' },
    { match: /^typeorm$/, framework: 'TypeORM', kind: 'orm' },
    { match: /^sequelize$/, framework: 'Sequelize', kind: 'orm' },
    { match: /^knex$/, framework: 'Knex', kind: 'orm' },
    { match: /^drizzle-orm$/, framework: 'Drizzle', kind: 'orm' },
    { match: /^mongoose$/, framework: 'Mongoose', kind: 'orm' },
    { match: /^redis$|^ioredis$/, framework: 'Redis', kind: 'cache' },
    { match: /^bullmq$|^bull$|^kafkajs$|^amqplib$/, framework: 'Job Queue', kind: 'queue' },
    { match: /^aws-sdk|^@aws-sdk\//, framework: 'AWS SDK', kind: 'cloud' },
    { match: /^firebase$|^@firebase\//, framework: 'Firebase', kind: 'cloud' },
    { match: /^stripe$|^@stripe\/|^braintree|^paypal/, framework: 'Payments', kind: 'payments' },
    { match: /^openai$|^@anthropic-ai\/|^@google\/generativeai$|^langchain$|^@langchain\//, framework: 'AI/LLM', kind: 'ai' },
    { match: /^passport$|^passport-/, framework: 'Passport', kind: 'auth' },
    { match: /^jsonwebtoken$|^jose$|^@auth0\//, framework: 'JWT', kind: 'auth' },
    { match: /^next-auth$|^@auth\/core$|^auth0$|^@auth0\/nextjs/, framework: 'Auth Platform', kind: 'auth' },
    { match: /^bcrypt$|^bcryptjs$|^argon2$/, framework: 'Password Hashing', kind: 'auth' },
    { match: /^multer$|^formidable$|^busboy$/, framework: 'File Upload', kind: 'upload' },
    { match: /^sharp$|^imagekit$|^cloudinary/, framework: 'Image Processing', kind: 'media' },
    { match: /^puppeteer$|^playwright$|^cheerio$/, framework: 'HTML Parsing/Browser', kind: 'client' },
    { match: /^nodemailer$|^sendgrid$|^@aws-sdk\/client-ses$/, framework: 'Email', kind: 'email' },
  ];

  for (const dep of deps) {
    for (const hint of FRAMEWORK_HINTS) {
      if (hint.match.test(dep.name)) {
        stack.frameworks.push({ name: hint.framework, kind: hint.kind, evidence: `${pkgJsonPath}: ${dep.name}` });
        break;
      }
    }
    stack.packages.push({ name: dep.name, spec: dep.spec, section: dep.source });
  }

  // Test runners and tooling
  const TOOL_HINTS = [
    { match: /^jest$|^vitest$|^mocha$|^@playwright\/test$|^cypress$/, tool: 'test-runner' },
    { match: /^eslint$|^prettier$/, tool: 'linter' },
    { match: /^typescript$/, tool: 'typescript' },
    { match: /^webpack$|^vite$|^esbuild$|^rollup$|^turbo$/, tool: 'bundler' },
    { match: /^husky$|^lint-staged$/, tool: 'git-hooks' },
  ];
  for (const dep of deps) {
    for (const hint of TOOL_HINTS) {
      if (hint.match.test(dep.name)) stack.tooling.push(hint.tool);
    }
  }
  stack.tooling = [...new Set(stack.tooling)];

  return stack;
}

function detectPythonStack(root, files) {
  const stack = { frameworks: [], packages: [] };
  const candidates = ['requirements.txt', 'Pipfile', 'pyproject.toml', 'setup.py', 'setup.cfg'];
  let text = '';
  let source = null;
  for (const c of candidates) {
    if (exists(root, c)) {
      text = readIfSmall(path.join(root, c)) || '';
      source = c;
      break;
    }
  }
  if (!source) return stack;

  const FRAMEWORK_HINTS = [
    { re: /^django(?:[\[=<>.! ]|$)/im, framework: 'Django', kind: 'backend' },
    { re: /^flask(?:[\[=<>.! ]|$)/im, framework: 'Flask', kind: 'backend' },
    { re: /^fastapi(?:[\[=<>.! ]|$)/im, framework: 'FastAPI', kind: 'backend' },
    { re: /^starlette(?:[\[=<>.! ]|$)/im, framework: 'Starlette', kind: 'backend' },
    { re: /^tornado(?:[\[=<>.! ]|$)/im, framework: 'Tornado', kind: 'backend' },
    { re: /^aiohttp(?:[\[=<>.! ]|$)/im, framework: 'aiohttp', kind: 'backend' },
    { re: /^sanic(?:[\[=<>.! ]|$)/im, framework: 'Sanic', kind: 'backend' },
    { re: /^sqlalchemy(?:[\[=<>.! ]|$)/im, framework: 'SQLAlchemy', kind: 'orm' },
    { re: /^django-rest-framework|^djangorestframework/im, framework: 'DRF', kind: 'api' },
    { re: /^celery(?:[\[=<>.! ]|$)/im, framework: 'Celery', kind: 'queue' },
    { re: /^redis(?:[\[=<>.! ]|$)/im, framework: 'Redis', kind: 'cache' },
    { re: /^boto3|^botocore/im, framework: 'AWS SDK', kind: 'cloud' },
    { re: /^openai|^anthropic|^langchain/im, framework: 'AI/LLM', kind: 'ai' },
    { re: /^authlib|^pyjwt|^python-jose/im, framework: 'JWT/Auth', kind: 'auth' },
    { re: /^flask-login|^django-allauth|^python-ldap/im, framework: 'Auth', kind: 'auth' },
    { re: /^gunicorn|^uvicorn|^daphne/im, framework: 'WSGI/ASGI Server', kind: 'server' },
  ];

  for (const hint of FRAMEWORK_HINTS) {
    if (hint.re.test(text)) {
      stack.frameworks.push({ name: hint.framework, kind: hint.kind, evidence: source });
    }
  }
  return stack;
}

// ---------------------------------------------------------------------------
// Main detection entry point
// ---------------------------------------------------------------------------

function detectStack(root, options) {
  const opts = options || {};
  const files = walkFiles(root, opts.extraIgnores, opts.maxFiles);

  const relFiles = files.map((f) => toRel(root, f));
  const languages = detectLanguages(root, relFiles);

  const manifestFiles = relFiles.filter((f) =>
    ['package.json', 'requirements.txt', 'Pipfile', 'pyproject.toml', 'go.mod', 'Cargo.toml', 'composer.json', 'Gemfile', 'pom.xml', 'build.gradle'].includes(f)
  );

  const node = detectNodeStack(root, relFiles, manifestFiles);
  const python = detectPythonStack(root, relFiles);

  const frameworks = [...node.frameworks, ...python.frameworks];
  const packages = [...node.packages, ...python.packages];

  // Package managers
  const packageManagers = [];
  if (anyExists(root, ['package-lock.json'])) packageManagers.push('npm');
  if (anyExists(root, ['yarn.lock'])) packageManagers.push('yarn');
  if (anyExists(root, ['pnpm-lock.yaml'])) packageManagers.push('pnpm');
  if (anyExists(root, ['bun.lockb', 'bun.lock'])) packageManagers.push('bun');
  if (anyExists(root, ['poetry.lock'])) packageManagers.push('poetry');
  if (anyExists(root, ['Pipfile.lock'])) packageManagers.push('pipenv');
  if (anyExists(root, ['uv.lock'])) packageManagers.push('uv');
  if (anyExists(root, ['go.sum'])) packageManagers.push('go-modules');
  if (anyExists(root, ['Cargo.lock'])) packageManagers.push('cargo');
  if (anyExists(root, ['composer.lock'])) packageManagers.push('composer');
  if (anyExists(root, ['Gemfile.lock'])) packageManagers.push('bundler');
  if (anyExists(root, ['pom.xml'])) packageManagers.push('maven');
  if (anyExists(root, ['build.gradle', 'build.gradle.kts'])) packageManagers.push('gradle');

  // Databases / storage
  const databases = [];
  const DB_HINTS = [
    { re: /postgres|pg|psql/i, name: 'PostgreSQL', patterns: ['postgres://', 'postgresql://', 'pg', 'psql', 'prisma/schema.prisma provider = "postgresql"', 'DATABASE_URL'] },
    { re: /mysql|mariadb/i, name: 'MySQL', patterns: ['mysql://', 'mariadb'] },
    { re: /mongo/i, name: 'MongoDB', patterns: ['mongodb://', 'mongodb+srv://', 'mongoose'] },
    { re: /redis/i, name: 'Redis', patterns: ['redis://', 'ioredis', 'redis'] },
    { re: /sqlite/i, name: 'SQLite', patterns: ['sqlite', '.sqlite', '.db'] },
    { re: /dynamo/i, name: 'DynamoDB', patterns: ['dynamodb', 'DynamoDB'] },
    { re: /elasticsearch|opensearch/i, name: 'Elasticsearch', patterns: ['elasticsearch', 'opensearch'] },
    { re: /s3|bucket|object.?storage/i, name: 'Object Storage', patterns: ['s3', 'bucket', 'GCS', 'Azure Blob'] },
    { re: /pinecone|weaviate|qdrant|milvus|pgvector|chroma/i, name: 'Vector DB', patterns: ['pinecone', 'weaviate', 'qdrant', 'milvus', 'pgvector', 'chroma'] },
  ];
  const allText = [];
  for (const f of files) {
    const rel = toRel(root, f);
    if (/\.(json|ya?ml|toml|env|txt|md|lock)$/.test(rel) || /package\.json$/.test(rel)) {
      const t = readIfSmall(f, 200 * 1024);
      if (t) allText.push({ file: rel, text: t });
    }
  }
  for (const hint of DB_HINTS) {
    for (const { file, text } of allText) {
      if (hint.re.test(text)) {
        databases.push({ name: hint.name, evidence: file });
        break;
      }
    }
  }

  // Auth detection
  const auth = { mechanisms: [], providers: [] };
  for (const fw of frameworks) {
    if (fw.kind === 'auth') auth.mechanisms.push(fw.name);
  }
  const AUTH_PATTERNS = [
    { re: /oauth|oidc/i, name: 'OAuth/OIDC' },
    { re: /saml/i, name: 'SAML' },
    { re: /jwt/i, name: 'JWT' },
    { re: /session/i, name: 'Server Sessions' },
    { re: /magic.?link/i, name: 'Magic Links' },
    { re: /mfa|two.?factor|totp|2fa/i, name: 'MFA' },
    { re: /ldap/i, name: 'LDAP' },
  ];
  for (const { file, text } of allText) {
    for (const p of AUTH_PATTERNS) {
      if (p.re.test(text) && !auth.providers.includes(p.name)) {
        auth.providers.push(p.name);
      }
    }
  }

  // Containers / CI / IaC / serverless
  const infra = { containers: [], cicd: [], iac: [], serverless: [], deployment: [] };
  if (anyExists(root, ['Dockerfile', 'Dockerfile.dev', 'docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml'])) infra.containers.push('Docker');
  if (anyExists(root, ['.github/workflows'])) infra.cicd.push('GitHub Actions');
  if (anyExists(root, ['.gitlab-ci.yml'])) infra.cicd.push('GitLab CI');
  if (anyExists(root, ['Jenkinsfile'])) infra.cicd.push('Jenkins');
  if (anyExists(root, ['.circleci/config.yml'])) infra.cicd.push('CircleCI');
  if (anyExists(root, ['.drone.yml'])) infra.cicd.push('Drone');
  if (anyExists(root, ['azure-pipelines.yml'])) infra.cicd.push('Azure Pipelines');
  if (anyExists(root, ['bitbucket-pipelines.yml'])) infra.cicd.push('Bitbucket Pipelines');
  if (anyExists(root, ['terraform', 'main.tf', 'variables.tf'])) infra.iac.push('Terraform');
  if (anyExists(root, ['pulumi'])) infra.iac.push('Pulumi');
  if (anyExists(root, ['serverless.yml'])) { infra.serverless.push('Serverless Framework'); infra.deployment.push('AWS Lambda'); }
  if (anyExists(root, ['vercel.json'])) infra.deployment.push('Vercel');
  if (anyExists(root, ['netlify.toml'])) infra.deployment.push('Netlify');
  if (anyExists(root, ['fly.toml'])) infra.deployment.push('Fly.io');
  if (anyExists(root, ['railway.json', 'railway.toml'])) infra.deployment.push('Railway');
  if (anyExists(root, ['render.yaml'])) infra.deployment.push('Render');
  if (anyExists(root, ['heroku.yml', 'Procfile'])) infra.deployment.push('Heroku');
  if (anyExists(root, ['samtemplate.yaml', 'template.yaml']) || anyExists(root, ['sam'])) infra.serverless.push('AWS SAM');
  if (anyExists(root, ['knative.yml'])) infra.serverless.push('Knative');
  if (anyExists(root, ['k8s', 'kubernetes', 'helm', 'Chart.yaml'])) infra.deployment.push('Kubernetes/Helm');

  // Env / config files
  const config = { envFiles: [], configFiles: [] };
  for (const rel of relFiles) {
    if (/^\.env/.test(path.basename(rel)) && !rel.endsWith('.example') && !rel.endsWith('.sample')) {
      config.envFiles.push(rel);
    }
    if (/^(config|settings|appsettings|application)\.(json|ya?ml|toml|properties)$/.test(path.basename(rel))) {
      config.configFiles.push(rel);
    }
  }

  // API surface heuristics
  const api = { rest: false, graphql: false, grpc: false, websocket: false, openapiSpec: null };
  api.rest = frameworks.some((f) => f.kind === 'backend');
  api.graphql = frameworks.some((f) => f.name === 'GraphQL');
  if (anyExists(root, ['openapi.json', 'openapi.yaml', 'swagger.json', 'swagger.yaml'])) {
    api.openapiSpec = relFiles.find((f) => /^(openapi|swagger)\.(json|ya?ml)$/.test(path.basename(f)));
  }
  const codeFiles = relFiles.filter((f) => /\.(js|mjs|cjs|ts|tsx|py|go|rb|java|kt|php|cs)$/.test(f));
  let wsHits = 0;
  let grpcHits = 0;
  for (const f of files) {
    const rel = toRel(root, f);
    if (!codeFiles.includes(rel)) continue;
    const t = readIfSmall(f, 200 * 1024);
    if (!t) continue;
    if (/WebSocket|socket\.io|Upgrade.*websocket/i.test(t)) wsHits++;
    if (/grpc|\.proto\b/.test(t)) grpcHits++;
  }
  api.websocket = wsHits > 0;
  api.grpc = grpcHits > 0 || anyExists(root, ['proto', 'protos', 'pb.go', '_pb2.py']);

  // Webhooks: look for known providers + generic webhook route patterns
  const webhooks = { detected: false, providers: [], genericRoutes: [] };
  const WEBHOOK_PROVIDERS = ['stripe', 'github', 'gitlab', 'slack', 'twilio', 'shopify', 'razorpay', 'paypal', 'square', 'clerk', 'supabase', 'sentry', 'linear', 'notion', 'discord'];
  for (const { file, text } of allText) {
    const lower = text.toLowerCase();
    for (const p of WEBHOOK_PROVIDERS) {
      if (lower.includes(`${p}`) && lower.includes('webhook') && !webhooks.providers.includes(p)) {
        webhooks.providers.push(p);
      }
    }
  }
  for (const f of files) {
    const rel = toRel(root, f);
    if (!codeFiles.includes(rel)) continue;
    const t = readIfSmall(f, 200 * 1024);
    if (!t) continue;
    const m = t.match(/['"`]\/(?:api\/)?webhooks?\/([^'"`\s]*)['"`]/gi);
    if (m) webhooks.genericRoutes.push(...m.slice(0, 10).map((x) => `${rel}: ${x}`));
  }
  webhooks.detected = webhooks.providers.length > 0 || webhooks.genericRoutes.length > 0;

  // AI/LLM
  const ai = { detected: frameworks.some((f) => f.kind === 'ai'), providers: [], agentFrameworks: [] };
  for (const { file, text } of allText) {
    if (/openai/i.test(text)) ai.providers.push('OpenAI');
    if (/anthropic/i.test(text)) ai.providers.push('Anthropic');
    if (/gemini|google.?ai/i.test(text)) ai.providers.push('Google AI');
    if (/langchain|llamaindex|autogen|crewai|haystack/i.test(text)) ai.agentFrameworks.push('LangChain-family');
  }
  ai.providers = [...new Set(ai.providers)];
  ai.agentFrameworks = [...new Set(ai.agentFrameworks)];

  // Mobile / desktop
  const mobile = { ios: anyExists(root, ['ios', '*.xcodeproj']), android: anyExists(root, ['android', 'AndroidManifest.xml']), reactNative: frameworks.some((f) => f.name === 'React Native') };
  if (packages.some((p) => p.name === 'react-native')) mobile.reactNative = true;

  const summary = {
    primaryLanguages: languages.slice(0, 3).map((l) => l.lang),
    isWebApp: api.rest || frameworks.some((f) => f.kind === 'frontend' || f.kind === 'fullstack'),
    hasBackend: api.rest || api.graphql || api.grpc,
    hasFrontend: frameworks.some((f) => f.kind === 'frontend'),
    hasAuth: auth.mechanisms.length > 0 || auth.providers.length > 0,
    hasDatabase: databases.length > 0,
    hasCloud: infra.deployment.length > 0 || frameworks.some((f) => f.kind === 'cloud'),
    hasContainer: infra.containers.length > 0,
    hasCI: infra.cicd.length > 0,
    hasAI: ai.detected,
    hasWebhooks: webhooks.detected,
    hasPayments: frameworks.some((f) => f.kind === 'payments'),
    fileCount: files.length,
  };

  return {
    generated_at: new Date().toISOString(),
    root: path.resolve(root),
    languages,
    frameworks,
    packages: packages.slice(0, 500),
    packageManagers,
    databases,
    auth,
    infra,
    config,
    api,
    webhooks,
    ai,
    mobile,
    summary,
    manifestFiles,
    _fileListSample: relFiles.slice(0, 200),
  };
}

module.exports = { detectStack, readIfSmall };
