import * as path from 'node:path';
import express, { Request, Response } from 'express';
import { executeCet, verifyDlc } from './verify';

const app = express();
const PORT = process.env.PORT || 3456;

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, '../public')));

interface VerifyRequestBody {
  offer?: string;
  accept?: string;
  expectedOraclePubkey?: string;
  signHex?: string;
}

app.post('/api/verify', async (req: Request<object, object, VerifyRequestBody>, res: Response): Promise<void> => {
  const { offer, accept, expectedOraclePubkey, signHex } = req.body;
  const reqId = Math.random().toString(36).slice(2, 8);
  const t0 = Date.now();

  console.log(
    `[verify:${reqId}] incoming offer=${offer?.length ?? 0} accept=${accept?.length ?? 0} sign=${signHex?.length ?? 0} expectedOraclePubkey=${expectedOraclePubkey ?? 'none'}`,
  );

  if (!offer || !accept) {
    console.warn(`[verify:${reqId}] rejected: missing offer or accept hex`);
    res.status(400).json({ error: 'Missing offer or accept hex' });
    return;
  }

  try {
    const result = await verifyDlc(offer, accept, { expectedOraclePubkey, signHex, logPrefix: `verify:${reqId}` });
    console.log(
      `[verify:${reqId}] done in ${Date.now() - t0}ms error=${result.error ?? 'null'} ` +
        `contractType=${result.contractType} contractId=${result.contractId ?? 'null'} ` +
        `oracleSigValid=${result.oracleSigValid} ` +
        `adaptorAvailable=${result.adaptorSigVerificationAvailable} adaptorValid=${result.adaptorValid} ` +
        `adaptorValidCount=${result.adaptorValidCount}/${result.adaptorTotalCount} ` +
        `adaptorError=${result.adaptorError ?? 'null'} ` +
        `signAvailable=${result.signAvailable} signAdaptorValid=${result.signAdaptorValid} ` +
        `signContractIdMatches=${result.signContractIdMatches} signAdaptorError=${result.signAdaptorError ?? 'null'}`,
    );
    res.json(result);
  } catch (err) {
    console.error(`[verify:${reqId}] threw after ${Date.now() - t0}ms:`, err);
    res.status(500).json({ error: (err as Error).message });
  }
});

interface ExecuteRequestBody {
  offer?: string;
  accept?: string;
  signHex?: string;
  attestationHex?: string;
}

app.post('/api/execute', async (req: Request<object, object, ExecuteRequestBody>, res: Response): Promise<void> => {
  const { offer, accept, signHex, attestationHex } = req.body;
  const reqId = Math.random().toString(36).slice(2, 8);
  const t0 = Date.now();

  console.log(
    `[execute:${reqId}] incoming offer=${offer?.length ?? 0} accept=${accept?.length ?? 0} sign=${signHex?.length ?? 0} attestation=${attestationHex?.length ?? 0}`,
  );

  if (!offer || !accept || !signHex || !attestationHex) {
    console.warn(`[execute:${reqId}] rejected: missing required fields`);
    res.status(400).json({ error: 'Missing required fields: offer, accept, signHex, attestationHex' });
    return;
  }

  try {
    const result = await executeCet(offer, accept, signHex, attestationHex);
    console.log(
      `[execute:${reqId}] done in ${Date.now() - t0}ms outcome=${result.outcome} outcomeIndex=${result.outcomeIndex} cetTxid=${result.cetTxid}`,
    );
    res.json(result);
  } catch (err) {
    console.error(`[execute:${reqId}] threw after ${Date.now() - t0}ms:`, err);
    res.status(500).json({ error: (err as Error).message });
  }
});

app.get('/', (_req: Request, res: Response): void => {
  res.sendFile(path.join(__dirname, '../public', 'index.html'));
});

app.listen(Number(PORT), '0.0.0.0', () => {
  console.log(`DLC Verify server running at http://0.0.0.0:${PORT}`);
});
