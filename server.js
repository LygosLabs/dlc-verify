const express = require('express');
const path = require('path');
const { verifyDlc } = require('./verify');

const app = express();
const PORT = 3456;

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

app.post('/api/verify', async (req, res) => {
  const { offer, accept, expectedOraclePubkey } = req.body;

  if (!offer || !accept) {
    return res.status(400).json({ error: 'Missing offer or accept hex' });
  }

  try {
    const result = await verifyDlc(offer, accept, { expectedOraclePubkey });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`DLC Verify server running at http://localhost:${PORT}`);
});
