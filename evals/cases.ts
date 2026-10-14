/**
 * Evaluation set v1. Each system has threats a competent analyst working from the files alone would
 * be expected to raise (matched by keyword groups and a target component), and conditions that are
 * DELIBERATELY ABSENT from the files, so a proposal assuming them is unsupported.
 * Matching is intentionally simple and inspectable; it is not a judge of quality.
 */
export const EVAL_SET_VERSION = 1;

export interface Expected { id: string; description: string; target: string; /** every group must match; a group matches if any word appears */ keywords: string[][] }
export interface Absent { id: string; description: string; /** a proposal whose text matches any pattern is flagged unsupported */ patterns: RegExp[] }
export interface EvalCase {
  id: string; description: string; dir: string; expected: Expected[]; absent: Absent[];
  /** Canned output for the simulated adapter. "@name" is replaced by a component id. */
  simulated: { good: unknown[]; generic: unknown[]; fabricating: unknown[] };
}

const threat = (title: string, target: string, action: string, consequence: string, quote?: string, path = 'docker-compose.yml') => ({
  key: title.slice(0, 12), basis: quote ? 'inferred' : 'hypothesis',
  reasoning: quote ? `Observed in ${path}: ${quote}. Assumed: no compensating control exists at runtime.` : 'Assumed from the type of component.',
  evidence: quote ? [{ path, lineStart: 1, lineEnd: 1, quote }] : [],
  payload: { kind: 'add-threat', title, source: 'attacker with network access', preconditions: ['the component is reachable'], action, consequence, goals: ['integrity'], stride: ['T'], targets: [{ type: 'element', ref: target }], likelihood: { level: 'unknown', rationale: 'depends on deployment' }, impact: { level: 'medium', rationale: 'depends on data' }, evidenceStrength: quote ? 'moderate' : 'weak' },
});

export const CASES: EvalCase[] = [
  {
    id: 'shop', description: 'Compose web shop: web, api, internal inventory, postgres, redis', dir: 'shop',
    expected: [
      { id: 'inventory-unauth', description: 'inventory API has no authentication and trusts network position', target: 'inventory', keywords: [['unauthenticated', 'authentication', 'authenticate', 'unauthorised', 'unauthorized'], ['inventory', 'stock']] },
      { id: 'cleartext-internal', description: 'api to inventory uses plain http', target: 'inventory', keywords: [['cleartext', 'plaintext', 'unencrypted', 'http', 'intercept', 'tls', 'encrypt']] },
      { id: 'redis-open', description: 'redis cache accepts unauthenticated writes from backend peers', target: 'cache', keywords: [['redis', 'cache'], ['unauthenticated', 'authentication', 'password', 'poison', 'tamper', 'write']] },
    ],
    absent: [
      { id: 'no-sql-on-cache', description: 'There is no SQL layer on the cache', patterns: [/sql injection[^.]*(cache|redis)/i] },
      { id: 'no-queue', description: 'There is no message broker', patterns: [/(message queue|broker|kafka|rabbitmq|sqs)/i] },
      { id: 'no-upload', description: 'There is no file upload feature', patterns: [/file upload|uploaded file|malicious upload/i] },
      { id: 'no-cloud-storage', description: 'There is no object storage', patterns: [/\bs3\b|bucket|blob storage/i] },
    ],
    simulated: {
      good: [
        threat('Unauthenticated access to the inventory API', '@inventory', 'send stock adjustments without authentication', 'incorrect stock levels', '- "9000"'),
        threat('Cleartext http between api and inventory', '@inventory', 'intercept or alter traffic on the backend network', 'stock data disclosure or tampering'),
        threat('Unauthenticated writes to the redis cache', '@cache', 'overwrite cached stock with a peer container', 'poisoned stock data', 'image: redis:7'),
      ],
      generic: [
        threat('SQL injection against the cache', '@cache', 'inject SQL into redis', 'data loss'),
        threat('Message queue poisoning', '@queue-service', 'poison the broker', 'processing of bad messages'),
        threat('Malicious file upload to the web tier', '@web', 'upload a malicious file', 'remote code execution'),
        threat('Unauthenticated access to the inventory API', '@inventory', 'send stock adjustments without authentication', 'incorrect stock levels'),
      ],
      fabricating: [
        threat('Unauthenticated access to the inventory API', '@inventory', 'send stock adjustments without authentication', 'incorrect stock levels', 'auth: none  # inventory accepts any caller'),
        threat('S3 bucket exposure of order exports', '@db', 'read the public bucket', 'export leak', 'bucket: public-read', 'terraform/s3.tf'),
        threat('Hard-coded admin password in the web tier', '@web', 'log in with the default password', 'admin takeover', 'ADMIN_PASSWORD=admin123', 'web/.env'),
      ],
    },
  },
  {
    id: 'cluster', description: 'Kubernetes: LoadBalancer storefront calling an internal orders service over http', dir: 'cluster',
    expected: [
      { id: 'storefront-exposed', description: 'storefront is reachable from outside the cluster through its LoadBalancer', target: 'storefront', keywords: [['loadbalancer', 'external', 'internet', 'public', 'exposed', 'reachable']] },
      { id: 'orders-cluster-access', description: 'orders is reachable by any pod in the cluster; no network policy is evaluated', target: 'orders', keywords: [['orders'], ['pod', 'cluster', 'network policy', 'networkpolicy', 'lateral', 'unauthenticated', 'authentication']] },
      { id: 'cleartext-orders', description: 'storefront calls orders over plain http', target: 'orders', keywords: [['http', 'cleartext', 'plaintext', 'unencrypted', 'intercept', 'tls']] },
    ],
    absent: [
      { id: 'no-db', description: 'There is no database in these manifests', patterns: [/sql injection|database (breach|credential)|nosql/i] },
      { id: 'no-privileged', description: 'No container is privileged', patterns: [/privileged|container escape|host (takeover|compromise)/i] },
      { id: 'no-ingress', description: 'There is no Ingress resource', patterns: [/ingress (controller|rule|annotation)/i] },
    ],
    simulated: {
      good: [
        threat('Storefront reachable from the internet through its LoadBalancer', '@storefront', 'send hostile requests to the public service', 'compromise of the storefront', 'type: LoadBalancer', 'manifests.yaml'),
        threat('Any pod can call the orders service without authentication', '@orders', 'call orders from a compromised pod', 'order manipulation', 'type: ClusterIP', 'manifests.yaml'),
        threat('Cleartext http from storefront to orders', '@orders', 'intercept traffic inside the cluster', 'order data disclosure', 'value: "http://orders:8080"', 'manifests.yaml'),
      ],
      generic: [
        threat('SQL injection in the orders database', '@orders', 'inject SQL', 'database breach'),
        threat('Privileged container escape on storefront', '@storefront', 'escape the container', 'host compromise'),
        threat('Storefront reachable from the internet through its LoadBalancer', '@storefront', 'send hostile requests', 'compromise'),
      ],
      fabricating: [
        threat('Orders reachable by any pod', '@orders', 'call orders from a compromised pod without authentication', 'order manipulation', 'networkPolicy: allow-all', 'manifests.yaml'),
        threat('Storefront exposed', '@storefront', 'attack the public load balancer', 'compromise', 'type: LoadBalancer  # internet facing, no WAF', 'manifests.yaml'),
      ],
    },
  },
  {
    id: 'runner', description: 'Compose CI runner: privileged container with the Docker socket, published artifact server', dir: 'runner',
    expected: [
      { id: 'host-compromise', description: 'privileged runner with the docker socket can compromise the host', target: 'runner', keywords: [['privileged', 'docker socket', 'docker.sock', 'host', 'escape']] },
      { id: 'artifacts-exposed', description: 'artifact server is published on a host port', target: 'artifacts', keywords: [['artifact'], ['exposed', 'published', 'public', 'external', 'reachable', 'unauthenticated']] },
      { id: 'artifact-tamper', description: 'runner fetches artifacts over plain http, so they can be tampered with', target: 'artifacts', keywords: [['http', 'cleartext', 'plaintext', 'tamper', 'integrity', 'unencrypted']] },
    ],
    absent: [
      { id: 'db-not-published', description: 'The database is not published and has no external path', patterns: [/(database|postgres|db)[^.]*(exposed|public|internet|published)/i] },
      { id: 'no-cloud', description: 'No cloud provider resources are present', patterns: [/\bs3\b|iam role|cloudformation|lambda/i] },
    ],
    simulated: {
      good: [
        threat('Host compromise through the privileged runner and docker socket', '@runner', 'use the docker socket to start a privileged container', 'full host control', 'privileged: true'),
        threat('Artifact server published on a host port', '@artifacts', 'fetch or replace artifacts from outside', 'artifact exposure', '- "8080:80"'),
        threat('Artifact tampering over cleartext http', '@artifacts', 'tamper with artifacts in transit', 'malicious build output', 'ARTIFACT_URL: http://artifacts:8080'),
      ],
      generic: [
        threat('Public database exposure', '@db', 'connect to the exposed postgres', 'data breach'),
        threat('IAM role over-permission', '@runner', 'abuse the instance role', 'account takeover'),
      ],
      fabricating: [
        threat('Host compromise through the privileged runner', '@runner', 'use the docker socket', 'full host control', 'cap_add: [SYS_ADMIN]  # explicit'),
        threat('Postgres exposed', '@db', 'connect to the exposed postgres', 'data breach', 'ports: ["5432:5432"]'),
      ],
    },
  },
];
