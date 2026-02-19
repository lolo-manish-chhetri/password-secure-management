const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(bodyParser.json());

// In-memory demo stores
const users = {}; // userId -> { salt, publicKey, note }
const vaultItems = {}; // itemId -> { householdId, ownerId, encryptedData }
const wrappedDEKs = {}; // itemId -> { userId: wrappedDEK }

// Simple ID helpers (demo only)
let userCounter = 1;
let itemCounter = 1;

// Register user
app.post('/register', (req, res) => {
  const { username, salt, publicKey } = req.body || {};
  if (!username || !salt) {
    return res.status(400).json({ error: 'username and salt are required' });
  }

  const userId = `u${userCounter++}`;
  users[userId] = {
    username,
    salt,
    publicKey: publicKey || null,
  };

  res.json({ userId });
});

// Create vault item
app.post('/vault/create', (req, res) => {
  const { householdId, ownerId, encryptedData, wrappedDEK } = req.body || {};
  if (!householdId || !ownerId || !encryptedData || !wrappedDEK) {
    return res.status(400).json({ error: 'householdId, ownerId, encryptedData, wrappedDEK are required' });
  }
  if (!users[ownerId]) {
    return res.status(400).json({ error: 'ownerId not found' });
  }

  const itemId = `i${itemCounter++}`;
  vaultItems[itemId] = {
    householdId,
    ownerId,
    encryptedData,
  };

  wrappedDEKs[itemId] = {
    [ownerId]: wrappedDEK,
  };

  res.json({ itemId });
});

// Share vault item with another user
app.post('/vault/share', (req, res) => {
  const { itemId, recipientId, wrappedDEKForRecipient } = req.body || {};
  if (!itemId || !recipientId || !wrappedDEKForRecipient) {
    return res.status(400).json({ error: 'itemId, recipientId, wrappedDEKForRecipient are required' });
  }
  if (!vaultItems[itemId]) {
    return res.status(404).json({ error: 'item not found' });
  }
  if (!users[recipientId]) {
    return res.status(400).json({ error: 'recipientId not found' });
  }

  if (!wrappedDEKs[itemId]) {
    wrappedDEKs[itemId] = {};
  }
  wrappedDEKs[itemId][recipientId] = wrappedDEKForRecipient;

  res.json({ success: true });
});

// Access vault item: return encryptedData + wrappedDEK for this user
app.post('/vault/access', (req, res) => {
  const { itemId, userId } = req.body || {};
  if (!itemId || !userId) {
    return res.status(400).json({ error: 'itemId and userId are required' });
  }
  const item = vaultItems[itemId];
  if (!item) {
    return res.status(404).json({ error: 'item not found' });
  }
  const itemWrapped = wrappedDEKs[itemId] || {};
  const wrappedDEK = itemWrapped[userId];
  if (!wrappedDEK) {
    return res.status(403).json({ error: 'no access for this user to item DEK' });
  }

  res.json({
    itemId,
    householdId: item.householdId,
    encryptedData: item.encryptedData,
    wrappedDEK,
  });
});

// Simple debugging endpoint to inspect in-memory state (do not use in real systems)
app.get('/debug/state', (req, res) => {
  res.json({ users, vaultItems, wrappedDEKs });
});

// Serve static frontend
app.use(express.static(path.join(__dirname)));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Zero-knowledge vault demo server running on http://localhost:${PORT}`);
});


