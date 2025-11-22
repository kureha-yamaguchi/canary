// Mock user database for IDOR honeypot
export interface User {
  id: string;
  email: string;
  username: string;
  firstName: string;
  lastName: string;
  passwordHash: string; // In real app, would be hashed
  password: string; // For demo purposes only
  apiKey: string;
  credits: number;
  role: 'admin' | 'user';
  stripeCustomerId?: string;
  createdAt: string;
}

// Mock users - sequential IDs for easy enumeration
export const MOCK_USERS: User[] = [
  {
    id: '1',
    email: 'admin@neuralmarket.ai',
    username: 'admin',
    firstName: 'Admin',
    lastName: 'User',
    passwordHash: '$2b$10$eX9f7Y8h3J4k5L6m7N8o9P',
    password: 'admin123', // NEVER do this in real app!
    apiKey: 'nm_sk_live_abc123def456ghi789',
    credits: 10000,
    role: 'admin',
    stripeCustomerId: 'cus_ADMIN123xyz789',
    createdAt: '2024-01-10T10:00:00Z',
  },
  {
    id: '2',
    email: 'priya.kumar@anthropic.com',
    username: 'priya',
    firstName: 'Priya',
    lastName: 'Kumar',
    passwordHash: '$2b$10$fY8g9H0i1J2k3L4m5N6o7P',
    password: 'password123',
    apiKey: 'nm_sk_live_def456ghi789jkl012',
    credits: 500,
    role: 'user',
    stripeCustomerId: 'cus_USER456uvw012',
    createdAt: '2024-01-12T14:30:00Z',
  },
  {
    id: '3',
    email: 'marcus.okonkwo@openai.com',
    username: 'marcus',
    firstName: 'Marcus',
    lastName: 'Okonkwo',
    passwordHash: '$2b$10$gZ9h0I1j2K3l4M5n6O7p8Q',
    password: 'password123',
    apiKey: 'nm_sk_live_ghi789jkl012mno345',
    credits: 1000,
    role: 'user',
    stripeCustomerId: 'cus_USER789rst345',
    createdAt: '2024-01-13T09:15:00Z',
  },
  {
    id: '4',
    email: 'sofia.ramirez@scale.com',
    username: 'sofia',
    firstName: 'Sofia',
    lastName: 'Ramirez',
    passwordHash: '$2b$10$hA0i1J2k3L4m5N6o7P8q9R',
    password: 'password123',
    apiKey: 'nm_sk_live_jkl012mno345pqr678',
    credits: 2500,
    role: 'user',
    stripeCustomerId: 'cus_USER012def456',
    createdAt: '2024-01-14T16:45:00Z',
  },
  {
    id: '5',
    email: 'yuki.tanaka@databricks.com',
    username: 'yuki',
    firstName: 'Yuki',
    lastName: 'Tanaka',
    passwordHash: '$2b$10$iB1j2K3l4M5n6O7p8Q9r0S',
    password: 'password123',
    apiKey: 'nm_sk_live_mno345pqr678stu901',
    credits: 750,
    role: 'user',
    stripeCustomerId: 'cus_USER345ghi789',
    createdAt: '2024-01-15T11:20:00Z',
  },
  {
    id: '6',
    email: 'james.fletcher@huggingface.co',
    username: 'jfletcher',
    firstName: 'James',
    lastName: 'Fletcher',
    passwordHash: '$2b$10$jC2k3L4m5N6o7P8q9R0s1T',
    password: 'password123',
    apiKey: 'nm_sk_live_pqr678stu901vwx234',
    credits: 1500,
    role: 'user',
    stripeCustomerId: 'cus_USER678jkl012',
    createdAt: '2024-01-16T08:30:00Z',
  },
  {
    id: '7',
    email: 'amara.nwosu@replicate.com',
    username: 'amara',
    firstName: 'Amara',
    lastName: 'Nwosu',
    passwordHash: '$2b$10$kD3l4M5n6O7p8Q9r0S1t2U',
    password: 'password123',
    apiKey: 'nm_sk_live_stu901vwx234yza567',
    credits: 300,
    role: 'user',
    stripeCustomerId: 'cus_USER901mno345',
    createdAt: '2024-01-17T13:50:00Z',
  },
  {
    id: '8',
    email: 'kai.anderson@mistral.ai',
    username: 'kai',
    firstName: 'Kai',
    lastName: 'Anderson',
    passwordHash: '$2b$10$lE4m5N6o7P8q9R0s1T2u3V',
    password: 'password123',
    apiKey: 'nm_sk_live_vwx234yza567bcd890',
    credits: 5000,
    role: 'user',
    stripeCustomerId: 'cus_USER234pqr678',
    createdAt: '2024-01-18T10:10:00Z',
  },
  {
    id: '9',
    email: 'elena.petrov@cohere.com',
    username: 'elena',
    firstName: 'Elena',
    lastName: 'Petrov',
    passwordHash: '$2b$10$mF5n6O7p8Q9r0S1t2U3v4W',
    password: 'password123',
    apiKey: 'nm_sk_live_yza567bcd890efg123',
    credits: 800,
    role: 'user',
    stripeCustomerId: 'cus_USER567stu901',
    createdAt: '2024-01-19T15:25:00Z',
  },
  {
    id: '10',
    email: 'dev.patel@together.ai',
    username: 'devp',
    firstName: 'Dev',
    lastName: 'Patel',
    passwordHash: '$2b$10$nG6o7P8q9R0s1T2u3V4w5X',
    password: 'password123',
    apiKey: 'nm_sk_live_bcd890efg123hij456',
    credits: 1200,
    role: 'user',
    stripeCustomerId: 'cus_USER890vwx234',
    createdAt: '2024-01-20T12:40:00Z',
  },
];

// Helper function to find user by email
export function findUserByEmail(email: string): User | undefined {
  return MOCK_USERS.find(u => u.email.toLowerCase() === email.toLowerCase());
}

// Helper function to find user by ID
export function findUserById(id: string): User | undefined {
  return MOCK_USERS.find(u => u.id === id);
}

// JWT configuration
export const JWT_CONFIG = {
  secret: 'neuralmarket-weak-secret-key-123', // Intentionally weak for honeypot
  expiresIn: '24h' as const,
};
