const express = require('express');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
const PORT = 3000;
const SECRET_KEY = 'your_jwt_secret_key';

app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// Mock users with roles
const users = [
  { email: 'admin@example.com', password: 'admin123', role: 'admin' },
  { email: 'user@example.com', password: 'user123', role: 'user' },
];

// Login route
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email && u.password === password);

  if (user) {
    const token = jwt.sign({ email: user.email, role: user.role }, SECRET_KEY, { expiresIn: '1h' });
    return res.json({ token });
  }

  res.status(401).json({ message: 'Invalid credentials' });
});

// Middleware to verify JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Middleware to check role
function authorizeRoles(roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ message: 'Access denied: insufficient permissions' });
    }
    next();
  };
}

// Routes
app.get('/api/user-data', authenticateToken, authorizeRoles(['user', 'admin']), (req, res) => {
  res.json({ message: `Hello ${req.user.email}, this is user data.` });
});

app.get('/api/admin-data', authenticateToken, authorizeRoles(['admin']), (req, res) => {
  res.json({ message: `Hello ${req.user.email}, this is admin data.` });
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});

