const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(bodyParser.json());

// In-memory demo stores
const users = {}; // userId -> { username, salt, publicKey }
const vaultItems = {}; // itemId -> { householdId, ownerId, secretData, schemaType }
const wrappedDEKs = {}; // itemId -> { userId: wrappedDEK }

// Helper: Check if string is valid base64
function isBase64(str) {
  if (!str || typeof str !== 'string') return false;
  try {
    return btoa(atob(str)) === str;
  } catch (err) {
    return false;
  }
}

// Validate incoming secret against schema
function validateSecretAgainstSchema(secretData, schemaType) {
  const schema = schemas[schemaType];
  if (!schema) {
    throw new Error(`Schema ${schemaType} not found`);
  }

  console.log(`\n🔍 Backend: Validating secret against schema: ${schemaType}`);

  // Validation 1: All schema fields exist
  const schemaFields = Object.keys(schema.properties).sort();
  const dataFields = Object.keys(secretData).sort();
  
  if (JSON.stringify(schemaFields) !== JSON.stringify(dataFields)) {
    throw new Error(
      `Fields mismatch. Expected: [${schemaFields.join(', ')}], Got: [${dataFields.join(', ')}]`
    );
  }
  console.log(`✅ All fields present: [${schemaFields.join(', ')}]`);

  // Validation 2: Verify encrypted fields are base64 (not plaintext)
  const encryptedFields = Object.keys(schema.properties)
    .filter(f => schema.properties[f]['x-ui-encrypted']);
  
  for (const encField of encryptedFields) {
    const value = secretData[encField];
    // Encrypted fields must be valid base64
    if (!isBase64(value)) {
      throw new Error(`Encrypted field "${encField}" is not valid base64 encoding`);
    }
    console.log(`✅ Encrypted field "${encField}" is base64 encoded`);
  }

  // Validation 3: Verify plaintext fields have correct type
  const plaintextFields = Object.keys(schema.properties)
    .filter(f => !schema.properties[f]['x-ui-encrypted']);
  
  for (const plaintextField of plaintextFields) {
    const fieldDef = schema.properties[plaintextField];
    const value = secretData[plaintextField];
    const expectedType = fieldDef.type;

    if (expectedType === 'string' && typeof value !== 'string') {
      throw new Error(`Field "${plaintextField}" should be string, got ${typeof value}`);
    }
  }
  console.log(`✅ All plaintext field types match schema`);

  // Validation 4: Verify enum constraints (for select fields)
  for (const [fieldName, fieldDef] of Object.entries(schema.properties)) {
    if (fieldDef.enum && !fieldDef['x-ui-encrypted']) {
      const value = secretData[fieldName];
      if (!fieldDef.enum.includes(value)) {
        throw new Error(
          `Field "${fieldName}" value "${value}" not in allowed enum: [${fieldDef.enum.join(', ')}]`
        );
      }
    }
  }
  console.log(`✅ All enum constraints valid`);

  // Validation 5: No extra fields
  const extraFields = dataFields.filter(f => !schema.properties[f]);
  if (extraFields.length > 0) {
    throw new Error(`Extra fields not in schema: [${extraFields.join(', ')}]`);
  }
  console.log(`✅ No extra fields`);

  console.log(`✅ Schema validation PASSED\n`);
  return true;
}

// Schema definitions for different secret types
const schemas = {
  loginCredentials: {
    type: 'object',
    label: 'Login Credentials',
    properties: {
      ProviderName: {
        type: 'string',
        label: 'Provider name',
        'x-ui-order': 0,
        'x-ui-span': 6,
        'x-ui-type': 'select',
        enum: ['Gmail', 'Gmail (Google)', 'Outlook.com', 'iCloud Mail', 'Other'],
      },
      Website: {
        type: 'string',
        label: 'Website',
        'x-ui-order': 1,
        'x-ui-span': 6,
      },
      Username: {
        type: 'string',
        label: 'Username',
        'x-ui-order': 2,
        'x-ui-span': 12,
      },
      Password: {
        type: 'string',
        label: 'Password',
        'x-ui-order': 3,
        'x-ui-span': 12,
        'x-ui-sensitive': true,
        'x-ui-encrypted': true,
      },
      '2FAMethod': {
        type: 'string',
        label: '2FA Method',
        'x-ui-order': 4,
        'x-ui-span': 12,
        enum: ['None', 'Authenticator App', 'SMS', 'Email'],
        'x-ui-type': 'select',
      },
      '2FADetails': {
        type: 'string',
        label: '2FA Details',
        'x-ui-order': 5,
        'x-ui-span': 12,
        'x-ui-sensitive': true,
        'x-ui-encrypted': true,
      },
      Notes: {
        type: 'string',
        label: 'Notes',
        'x-ui-order': 6,
        'x-ui-span': 12,
        'x-ui-type': 'textarea',
      },
    },
  },
  bankAccount: {
    type: 'object',
    label: 'Bank Account',
    properties: {
      BankName: {
        type: 'string',
        label: 'Bank Name',
        'x-ui-order': 0,
        'x-ui-span': 6,
      },
      AccountHolder: {
        type: 'string',
        label: 'Account Holder',
        'x-ui-order': 1,
        'x-ui-span': 6,
      },
      AccountNumber: {
        type: 'string',
        label: 'Account Number',
        'x-ui-order': 2,
        'x-ui-span': 12,
        'x-ui-sensitive': true,
        'x-ui-encrypted': true,
      },
      PIN: {
        type: 'string',
        label: 'PIN',
        'x-ui-order': 3,
        'x-ui-span': 6,
        'x-ui-sensitive': true,
        'x-ui-encrypted': true,
      },
      Notes: {
        type: 'string',
        label: 'Notes',
        'x-ui-order': 4,
        'x-ui-span': 12,
        'x-ui-type': 'textarea',
      },
    },
  },
};

// Simple ID helpers (demo only)
let userCounter = 1;
let itemCounter = 1;

// Register user - FLOW 1: Onboarding (Master Password Setup)
app.post('/register', (req, res) => {
  try {
    const { username, salt, publicKey, wrappedPrivateKey } = req.body || {};
    
    if (!username || !salt || !publicKey || !wrappedPrivateKey) {
      return res.status(400).json({ 
        error: 'username, salt, publicKey, and wrappedPrivateKey are all required' 
      });
    }

    // Validate salt is base64
    if (!isBase64(salt)) {
      return res.status(400).json({ error: 'salt must be valid base64' });
    }

    // Validate wrappedPrivateKey is base64
    if (!isBase64(wrappedPrivateKey)) {
      return res.status(400).json({ error: 'wrappedPrivateKey must be valid base64' });
    }

    const userId = `u${userCounter++}`;
    users[userId] = {
      username,
      salt,                    // kek_salt - used to re-derive KEK on login
      publicKey,               // ECDH public key (JWK) - used to verify signatures
      wrappedPrivateKey,       // ECDH private key wrapped with KEK - proof of password ownership
      createdAt: new Date().toISOString(),
    };

    console.log(`\n═══════════════════════════════════════`);
    console.log(`✅ USER REGISTERED: ${userId}`);
    console.log(`═══════════════════════════════════════`);
    console.log(`   Username: ${username}`);
    console.log(`   Salt (kek_salt): ${salt.substring(0, 30)}...`);
    console.log(`   Public Key (JWK): ${JSON.stringify(publicKey).substring(0, 60)}...`);
    console.log(`   Wrapped Private Key: ${wrappedPrivateKey.substring(0, 30)}...`);
    console.log(`   Created At: ${users[userId].createdAt}`);
    console.log(`═══════════════════════════════════════\n`);

    res.json({ 
      userId,
      success: true,
      message: 'User registered with ECDH keypair and wrapped private key'
    });
  } catch (err) {
    console.error('❌ Registration error:', err.message);
    return res.status(400).json({ error: err.message });
  }
});

// Get schema by type
app.get('/schemas/:schemaType', (req, res) => {
  const { schemaType } = req.params;
  const schema = schemas[schemaType];
  if (!schema) {
    return res.status(404).json({ error: 'schema not found' });
  }
  res.json(schema);
});

// List all available schemas
app.get('/schemas', (req, res) => {
  const schemaList = Object.keys(schemas).map((key) => ({
    id: key,
    label: schemas[key].label,
  }));
  res.json(schemaList);
});

// Create vault item with schema validation
app.post('/vault/create', (req, res) => {
  try {
    const { householdId, ownerId, secretData, wrappedDEK, schemaType } = req.body;
    
    if (!householdId || !ownerId || !secretData || !wrappedDEK || !schemaType) {
      return res.status(400).json({ 
        error: 'Missing required fields: householdId, ownerId, secretData, wrappedDEK, schemaType' 
      });
    }
    
    if (!users[ownerId]) {
      return res.status(400).json({ error: 'ownerId not found' });
    }

    // Backend validates schema on PLAINTEXT data
    validateSecretAgainstSchema(secretData, schemaType);

    // Only store if validation passes
    const itemId = `i${itemCounter++}`;
    vaultItems[itemId] = {
      householdId,
      ownerId,
      secretData, // Mix of plaintext + encrypted fields
      schemaType,
      createdAt: new Date().toISOString(),
    };

    wrappedDEKs[itemId] = {
      [ownerId]: wrappedDEK,
    };

    res.json({ 
      itemId,
      success: true,
      message: `Secret created and validated against ${schemaType}`
    });
  } catch (err) {
    console.error('❌ Validation error:', err.message);
    return res.status(400).json({ error: err.message });
  }
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

// Access vault item: return secretData (plaintext + encrypted fields) + wrappedDEK + schema
app.post('/vault/access', (req, res) => {
  try {
    const { itemId, userId } = req.body;
    
    if (!itemId || !userId) {
      return res.status(400).json({ error: 'itemId and userId required' });
    }

    const item = vaultItems[itemId];
    if (!item) {
      return res.status(404).json({ error: 'Item not found' });
    }

    const dek = wrappedDEKs[itemId]?.[userId];
    if (!dek) {
      return res.status(401).json({ error: 'No access to this secret' });
    }

    const schema = schemas[item.schemaType];
    const ownerPublicKey = users[item.ownerId].publicKey;

    res.json({
      secretData: item.secretData, // Plaintext + encrypted fields as-is
      schema: schema,
      ownerPublicKey: ownerPublicKey,
      // NOTE: wrappedDEK is NOT sent here - fetched on-demand via /vault/get-wrapped-dek after password verification
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Get wrapped DEK for a specific item (called ONLY after password verified)
app.post('/vault/get-wrapped-dek', (req, res) => {
  try {
    const { itemId, userId } = req.body;
    
    if (!itemId || !userId) {
      return res.status(400).json({ error: 'itemId and userId required' });
    }

    const item = vaultItems[itemId];
    if (!item) {
      return res.status(404).json({ error: 'Item not found' });
    }

    const wrappedDEK = wrappedDEKs[itemId]?.[userId];
    if (!wrappedDEK) {
      return res.status(401).json({ error: 'No access to this secret' });
    }

    res.json({
      itemId,
      userId,
      wrappedDEK,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
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
