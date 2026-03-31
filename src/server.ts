import * as path from 'node:path';
import express, { Request, Response } from 'express';
import { verifyDlc } from './verify';

const app = express();
const PORT = process.env.PORT || 3456;

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, '../public')));

interface VerifyRequestBody {
  offer?: string;
  accept?: string;
  expectedOraclePubkey?: string;
}

app.post('/api/verify', async (req: Request<object, object, VerifyRequestBody>, res: Response): Promise<void> => {
  const { offer, accept, expectedOraclePubkey } = req.body;

  if (!offer || !accept) {
    res.status(400).json({ error: 'Missing offer or accept hex' });
    return;
  }

  try {
    const result = await verifyDlc(offer, accept, { expectedOraclePubkey });
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

app.get('/', (_req: Request, res: Response): void => {
  res.sendFile(path.join(__dirname, '../public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`DLC Verify server running at http://localhost:${PORT}`);
});
