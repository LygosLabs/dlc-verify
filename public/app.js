// Sample data
const SAMPLE_OFFER = "a71a000000010006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f75e8f015ca87424c5fd51da4c15ba8e49d0626c64e27f9a55d0c42a94285216b000000000000004e200004086e6f742d706169640000000000004e20067265706169640000000000004e201d6c6971756964617465642d62792d6d617475726174696f6e2d6461746500000000000000001d6c6971756964617465642d62792d70726963652d7468726573686f6c64000000000000000000fdd824fd012a18c141dd421bb8c54e2965f964b9c53c30e2f8c288e84684d2da313fb314a16b3a739b951ab043c9a9b012c972c542ec4533cbab53ae597ff7b1cbd2b57e26dd8731249d979def2d5d76c61795969e953807d37ff36ef8dbab60d57ae08bb004fdd822c60001aaf6f439e22ebc287b0b72e45d62c2a6fc10392bd6e67b0fed7a5c0623cd909869ca9e00fdd8064e0004086e6f742d70616964067265706169641d6c6971756964617465642d62792d6d617475726174696f6e2d646174651d6c6971756964617465642d62792d70726963652d7468726573686f6c644d6c6f616e2d6d6174757265642d37393332653463326635313336636133643833653530373938373662643139333131626236316462336534306533323865346531386333386362316433343532036eb76057911e044f21ff936e44d559e50e8205115b398873663062978d59ca5300160014c4c19bd65e8e01887b4233d3d00aeba814e32e700000000000002e6c0000000000004e2001000000000000f93beb02000000000101e39ded02db3a29b96516add32332f14a90564b5003c69b019007127caa0984780100000000ffffffff026c5000000000000022002094dc89c4908b2b6e77240a7aef9bf348305ef5747eb9295e72dd9f84b61ce030c6d2120000000000160014a1ce41748ea25502e2b8a96b9f355d9f127d6650024830450221008adea390dbe7eed07f75e658c09796bce58a20d055613a012fcf52bacf38f2f90220708568036845fff6dac50103141b64dfa1fa5d9d399861f18ff4357e1fb4419001210384c27feb59925d4fab7a109e819359593a4024805a8aaddb2e36eefbe50f2a2b0000000000000001ffffffff006c000000001600140aaf7cb8008f5ad8869e13f47f490d4cc1e2870a00000000004f3700000000000005069e00000000000000036954661469d3d880";
const SAMPLE_ACCEPT = "a71c0000000175e8f015ca87424c5fd51da4c15ba8e49d0626c64e27f9a55d0c42a94285216b000000000000000003903300005c2442e25c16cc27491e27cac1f694873c66f3754290be363909378c001600146ca95318f13155e107ecaee89be880f614885154f9ba97c4a58d90c200001600146ca95318f13155e107ecaee89be880f61488515420ce87964a55e5520402d6976bff43f6db838aee8b7fe8bd3fa9e2c4d1c93cd713ba3f17a13230c6067403175812ef0fcf9577c3ded949c35269c2fb1d366708e03c4edd2e2bb3943e40b26048bf4f26e6cae095802ae112b1296ec9a13831f445b37081c362c4aa3542dbdfa78a978a17d7b8bd183ec83220d9714d584ce2d4a2cff316bfdc49681781e00b1cee98438bd63ecc6f225fcd7c9cfabe0ba98af13609112547f6d67ab30c4e02966e83473db580ddbabc8fda1d62074b08d823aee5e3013430449e2ebf3dd48903929a9152dec88ff9c1cd459554255c0d7f6862f8060c40520b74555afaedeb9a6567a37882ac4f5f3ed6ef194e74ceda88fde0e2d90423115b77459a880b6615004b50141972be52af0a569afe8014d87efdf26b03af8044fb349e48ec10f6afdd2fac90ab762ba82c28f0f1a35b753d5e72650e93b78281d0c7f27df2c3960d03602d3114d3c3d9cd672aa2730806545ee376afa8cb9a5e6cd150d9d952e5da6002552536cec0b25ee6338f6a261d43777f21993c356da47d048a3271d1936be3e5bb92908f150d1b29f0b6e4eb090f4b9c608d9aa32c3b9c96b9b247cbf0982abfffc62bcec688b7599d84e897694c4623d53aeecd4dc72b95c1a0916961d52abdf43e22b1ad91e665db410416b4f20a1d5a16e6a778b3c81e67c1944bd9db988f0383ba2802beda6a21f64a4356c61252491ded76986ae50177d35971b18adaf008029b63359f180780ecb6f34183e50482d2eb7bcc4ad4c266d3cd33e8668bcdb29284080ab6a48301d5bd5eafbf80de2092dd26f809ea5ee9caf869f4acb6ac5ac47b8742bed7ab95e82a3dbb91e82436cdd8f42b5ea2c449bf353090bec7e95cfc0b8f54d611373ea9e3e7824cf64d864c4890d994d0e9caa592ba68ebf56b55ef70889ae3043986cdfff2051c1c6521225583ca6a5b3c6ed81c02a32b81d98e5424fef0ab2b94ddc01da104a53e04074c864f4f3d2364a1fadee0620d4d9923f100";
const KNOWN_ORACLES = [
    { label: 'Mainnet Magnolia Pubkey', pubkey: '8731249d979def2d5d76c61795969e953807d37ff36ef8dbab60d57ae08bb004' },
    { label: 'Testnet Magnolia Pubkey', pubkey: 'dde465c101a1aaa5a88c0d35d21744eb5352c62b7c7665d62d5f20c770ddfd8f' },
];

document.getElementById('offerHex').value = SAMPLE_OFFER;
document.getElementById('acceptHex').value = SAMPLE_ACCEPT;

function formatSats(sats) {
    const num = BigInt(sats);
    const btc = Number(num) / 1e8;
    return `${btc.toFixed(8)} BTC (${num.toLocaleString()} sats)`;
}


function formatLocktimeToDate(locktime) {
    const LOCKTIME_THRESHOLD = 500000000;
    if (locktime >= LOCKTIME_THRESHOLD) {
        return new Date(locktime * 1000).toISOString().replace('T', ' ').replace(/\.\d+Z/, ' UTC');
    }
    return `block ${Number(locktime).toLocaleString()}`;
}

function truncateHex(hex, startLen = 8, endLen = 8) {
    if (!hex || hex.length <= startLen + endLen + 3) return hex;
    return `${hex.slice(0, startLen)}...${hex.slice(-endLen)}`;
}

function normalizeOraclePubkeyInput(value) {
    const normalized = String(value || '').trim().toLowerCase().replace(/^0x/, '').replace(/\s+/g, '');
    if (!normalized) return '';
    if (!/^[0-9a-f]+$/.test(normalized)) {
        throw new Error('Oracle pubkey must be hex');
    }
    if (normalized.length !== 64) {
        throw new Error('Oracle pubkey must be a 32-byte x-only pubkey (64 hex chars)');
    }
    return normalized;
}

function populateOraclePresetOptions() {
    const select = document.getElementById('oraclePreset');
    if (!select) return;
    select.innerHTML = '';

    const customOption = document.createElement('option');
    customOption.value = '';
    customOption.textContent = 'Custom / none';
    select.appendChild(customOption);

    for (const oracle of KNOWN_ORACLES) {
        const option = document.createElement('option');
        option.value = oracle.pubkey;
        option.textContent = oracle.label;
        select.appendChild(option);
    }
}

function syncOracleInputFromPreset() {
    const select = document.getElementById('oraclePreset');
    const input = document.getElementById('oraclePubkeyInput');
    if (!select || !input) return;
    if (!select.value) return;
    input.value = select.value;
}

function syncOraclePresetFromInput() {
    const select = document.getElementById('oraclePreset');
    const input = document.getElementById('oraclePubkeyInput');
    if (!select || !input) return;
    const raw = input.value.trim().toLowerCase().replace(/^0x/, '').replace(/\s+/g, '');
    if (!raw) {
        select.value = '';
        return;
    }
    const match = KNOWN_ORACLES.find((oracle) => oracle.pubkey === raw);
    select.value = match ? match.pubkey : '';
}

function getOracleSelectionContext() {
    const expectedPubkey = normalizeOraclePubkeyInput(document.getElementById('oraclePubkeyInput').value);
    const knownOracle = KNOWN_ORACLES.find((oracle) => oracle.pubkey === expectedPubkey) || null;
    return {
        expectedPubkey: expectedPubkey || null,
        expectedLabel: knownOracle ? knownOracle.label : 'provided oracle pubkey',
    };
}

function getOracleTrustState(result, oracleContext) {
    const extractedOraclePubkey = (result.extractedOraclePubkey || '').toLowerCase();
    const expectedPubkey = oracleContext.expectedPubkey || '';
    const knownMatch = extractedOraclePubkey
        ? KNOWN_ORACLES.find((oracle) => oracle.pubkey === extractedOraclePubkey)
        : null;

    if (expectedPubkey) {
        if (expectedPubkey === extractedOraclePubkey) {
            return {
                badgeTone: 'green',
                badgeIcon: 'ph-fill ph-check-circle text-green-600',
                badgeText: `Matches ${oracleContext.expectedLabel}`,
                metaText: 'Using the oracle pubkey you provided. The DLC messages embed the same pubkey.',
                titleText: extractedOraclePubkey ? `Oracle pubkey embedded in DLC messages: ${extractedOraclePubkey}` : '',
                displayTitle: 'Provided by you for comparison.',
                proofValid: true,
                proofDetail: 'Provided oracle pubkey matches the one embedded in the DLC messages.',
            };
        }

        return {
            badgeTone: 'red',
            badgeIcon: 'ph-fill ph-warning-circle text-red-600',
            badgeText: 'Does not match provided oracle pubkey',
            metaText: extractedOraclePubkey
                ? `Using the oracle pubkey you provided. The DLC messages embed a different pubkey: ${extractedOraclePubkey}.`
                : 'Using the oracle pubkey you provided. The DLC messages did not expose an oracle pubkey.',
            titleText: extractedOraclePubkey ? `Oracle pubkey embedded in DLC messages: ${extractedOraclePubkey}` : '',
            displayTitle: 'Provided by you for comparison.',
            proofValid: false,
            proofDetail: extractedOraclePubkey
                ? 'Provided oracle pubkey does not match the one embedded in the DLC messages.'
                : 'Provided oracle pubkey could not be compared because no oracle pubkey was extracted from the DLC messages.',
        };
    }

    // No pubkey provided - show informational status (not validated)
    if (knownMatch) {
        return {
            badgeTone: 'blue',
            badgeIcon: 'ph-fill ph-info text-blue-600',
            badgeText: `Detected: ${knownMatch.label}`,
            metaText: `Oracle pubkey derived from the DLC messages appears to be ${knownMatch.label}. Select this oracle above to validate.`,
            titleText: extractedOraclePubkey ? `Oracle pubkey embedded in DLC messages: ${extractedOraclePubkey}` : '',
            displayTitle: 'Derived from the DLC messages.',
            proofValid: null,
            proofDetail: `Detected ${knownMatch.label} but no pubkey provided for validation.`,
        };
    }

    return {
        badgeTone: 'gray',
        badgeIcon: 'ph-fill ph-info text-gray-500',
        badgeText: 'Unknown oracle - verify independently',
        metaText: 'Oracle pubkey derived from the DLC messages. Not a known oracle.',
        titleText: extractedOraclePubkey ? `Oracle pubkey embedded in DLC messages: ${extractedOraclePubkey}` : '',
        displayTitle: 'Derived from the DLC messages.',
        proofValid: null,
        proofDetail: 'No oracle pubkey was provided for comparison. Verify independently if needed.',
    };
}

function renderOracleTrust(result, oracleContext) {
    const badge = document.getElementById('oracleMatchBadge');
    const meta = document.getElementById('oraclePubkeyMeta');
    const display = document.getElementById('oraclePubkeyDisplay');
    if (result.error) {
        badge.classList.add('hidden');
        meta.textContent = '-';
        meta.title = '';
        display.title = '';
        return;
    }
    const trustState = getOracleTrustState(result, oracleContext);

    let badgeClass = 'inline-flex items-center gap-1.5 px-2.5 py-1 rounded-card text-[11px] font-medium';
    if (trustState.badgeTone === 'green') {
        badgeClass += ' bg-green-50 text-green-700';
    } else if (trustState.badgeTone === 'red') {
        badgeClass += ' bg-red-50 text-red-700';
    } else if (trustState.badgeTone === 'blue') {
        badgeClass += ' bg-blue-50 text-blue-700';
    } else {
        badgeClass += ' bg-gray-100 text-gray-600';
    }

    display.title = trustState.displayTitle;
    badge.className = badgeClass;
    badge.innerHTML = `<i class="${trustState.badgeIcon} text-sm"></i> ${escapeHtml(trustState.badgeText)}`;
    badge.classList.remove('hidden');
    meta.textContent = trustState.metaText;
    meta.title = trustState.titleText;
}

// Copy on click for all .copy-trigger elements
function initCopyTriggers() {
    document.querySelectorAll('.copy-trigger').forEach(trigger => {
        // Remove old listeners by cloning
        const newTrigger = trigger.cloneNode(true);
        trigger.parentNode.replaceChild(newTrigger, trigger);

        newTrigger.addEventListener('click', async () => {
            const textToCopy = newTrigger.getAttribute('data-copy');
            if (!textToCopy) return;
            try {
                await navigator.clipboard.writeText(textToCopy);
                const icon = newTrigger.querySelector('.copy-icon');
                if (icon) {
                    const orig = icon.className;
                    icon.className = 'ph-bold ph-check copy-icon copied ml-1.5 transition-opacity';
                    setTimeout(() => { icon.className = orig; }, 2000);
                }
            } catch (err) {
                console.error('Failed to copy:', err);
            }
        });
    });
}

// Set copy data on a trigger's parent
function setCopyData(elementId, value) {
    const el = document.getElementById(elementId);
    if (!el) return;
    const trigger = el.closest('.copy-trigger');
    if (trigger) trigger.setAttribute('data-copy', value || '');
}

let lastTvcEvidence = null;

function createTvcChallenge() {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return `dlc-verify-${Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('')}`;
}

function normalizeMessageHex(value) {
    return String(value || '').trim().replace(/^0x/i, '').replace(/\s+/g, '');
}

function togglePolicyPanel() {
    const toggle = document.getElementById('policyToggle');
    const panel = document.getElementById('policyInputPanel');
    const oracleContextLabel = document.getElementById('oracleInputContextLabel');
    panel.classList.toggle('hidden', !toggle.checked);
    toggle.setAttribute('aria-expanded', String(toggle.checked));
    oracleContextLabel.textContent = toggle.checked ? 'Included when provided' : 'Client-side trust check';
}

function togglePolicyEventInputs() {
    const mode = document.getElementById('policyEventMode').value;
    document.getElementById('policyEventIdFields').classList.toggle('hidden', mode !== 'event-id');
    document.getElementById('policyRepaymentFields').classList.toggle('hidden', mode !== 'repayment');
}

function inputValue(id) {
    return document.getElementById(id).value.trim();
}

function optionalUnsignedInteger(id, label) {
    const value = inputValue(id);
    if (!value) return undefined;
    if (!/^\d+$/.test(value)) throw new Error(`${label} must be a non-negative integer`);
    const parsed = Number(value);
    if (!Number.isSafeInteger(parsed)) throw new Error(`${label} is too large`);
    return parsed;
}

function buildPolicy(oracleContext) {
    const policy = {};
    const lenderRole = inputValue('policyLenderRole');
    const expectedNetwork = inputValue('policyNetwork');
    const lenderFundingPubkey = inputValue('policyLenderFundingPubkey');
    const lenderPayoutAddress = inputValue('policyLenderPayoutAddress');
    const totalCollateral = inputValue('policyTotalCollateral');
    const eventMode = inputValue('policyEventMode');
    const cetLocktime = optionalUnsignedInteger('policyCetLocktime', 'Expected CET locktime');
    const refundLocktime = optionalUnsignedInteger('policyRefundLocktime', 'Expected refund locktime');
    const lenderOutcomesText = inputValue('policyLenderOutcomes');

    if (lenderRole) policy.lenderRole = lenderRole;
    if (expectedNetwork) policy.network = expectedNetwork;
    if (oracleContext.expectedPubkey) policy.expectedOraclePubkey = oracleContext.expectedPubkey;

    if (lenderFundingPubkey) {
        const normalized = lenderFundingPubkey.toLowerCase().replace(/^0x/, '').replace(/\s+/g, '');
        if (!/^[0-9a-f]{66}$/.test(normalized)) {
            throw new Error('Expected lender funding pubkey must be a 33-byte compressed pubkey (66 hex chars)');
        }
        policy.expectedLenderFundingPubkey = normalized;
    }
    if (lenderPayoutAddress) policy.expectedLenderPayoutAddress = lenderPayoutAddress;
    if (totalCollateral) {
        if (!/^\d+$/.test(totalCollateral)) throw new Error('Expected collateral must be a non-negative satoshi amount');
        policy.expectedTotalCollateralSats = totalCollateral;
    }

    if ((lenderFundingPubkey || lenderPayoutAddress || lenderOutcomesText) && !lenderRole) {
        throw new Error('Select whether the lender is the offerer or accepter for lender-specific checks');
    }

    if (eventMode === 'event-id') {
        const expectedEventId = inputValue('policyExpectedEventId');
        if (!expectedEventId) throw new Error('Enter the expected oracle event ID');
        policy.oracleEvent = { expectedEventId };
    } else if (eventMode === 'repayment') {
        const eventIdPreimage = {
            eventType: inputValue('policyEventType'),
            loanId: inputValue('policyLoanId'),
            repaymentAddress: inputValue('policyRepaymentAddress'),
            repaymentAmount: inputValue('policyRepaymentAmount'),
        };
        if (Object.values(eventIdPreimage).some((value) => !value)) {
            throw new Error('Event type, loan ID, repayment address, and repayment amount are all required to derive the event ID');
        }
        policy.oracleEvent = { eventIdPreimage };
    }

    if (cetLocktime !== undefined) policy.expectedCetLocktime = cetLocktime;
    if (refundLocktime !== undefined) policy.expectedRefundLocktime = refundLocktime;

    if (lenderOutcomesText) {
        let lenderOutcomes;
        try {
            lenderOutcomes = JSON.parse(lenderOutcomesText);
        } catch (_err) {
            throw new Error('Expected lender outcomes must be valid JSON');
        }
        if (!Array.isArray(lenderOutcomes) || lenderOutcomes.some((item) =>
            !item || typeof item.outcome !== 'string' || typeof item.lenderPayoutSats !== 'string' || !/^\d+$/.test(item.lenderPayoutSats))) {
            throw new Error('Expected lender outcomes must be an array with outcome and decimal-string lenderPayoutSats fields');
        }
        policy.expectedLenderOutcomes = lenderOutcomes.map((item) => ({
            outcome: item.outcome,
            lenderPayoutSats: item.lenderPayoutSats,
        }));
    }

    return policy;
}

function humanizeStatus(value) {
    if (!value) return '-';
    return String(value).replace(/_/g, ' ').replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function formatPolicyValue(value) {
    if (value === null) return 'null';
    if (typeof value === 'object') return JSON.stringify(value);
    return String(value);
}

function renderPolicyResults(policyResult) {
    const card = document.getElementById('policyResultsCard');
    if (!policyResult) {
        card.classList.add('hidden');
        return;
    }

    card.classList.remove('hidden');
    document.getElementById('policyCoverageDisplay').textContent = humanizeStatus(policyResult.policyCoverage);
    document.getElementById('policyCryptoDisplay').textContent = humanizeStatus(policyResult.cryptographicVerification);
    document.getElementById('policyVerdictDisplay').textContent = humanizeStatus(policyResult.verdict);

    const badge = document.getElementById('policyStatusBadge');
    if (policyResult.policyVerification === 'fail') {
        badge.className = 'inline-flex items-center gap-1.5 bg-red-50 text-red-700 px-3 py-1 rounded-card text-xs font-medium';
        badge.innerHTML = '<i class="ph-bold ph-x"></i> Policy mismatch';
    } else if (policyResult.policyVerification === 'pass' && policyResult.policyCoverage === 'complete') {
        badge.className = 'inline-flex items-center gap-1.5 bg-green-50 text-green-700 px-3 py-1 rounded-card text-xs font-medium';
        badge.innerHTML = '<i class="ph-bold ph-check"></i> Policy verified';
    } else if (policyResult.policyVerification === 'pass') {
        badge.className = 'inline-flex items-center gap-1.5 bg-blue-50 text-blue-700 px-3 py-1 rounded-card text-xs font-medium';
        badge.innerHTML = '<i class="ph-bold ph-check"></i> Supplied checks passed';
    } else {
        badge.className = 'inline-flex items-center gap-1.5 bg-gray-100 text-gray-600 px-3 py-1 rounded-card text-xs font-medium';
        badge.innerHTML = '<i class="ph-bold ph-minus"></i> No expectations';
    }

    const labels = {
        'network': 'Network',
        'oracle-pubkey': 'Oracle pubkey',
        'lender-funding-pubkey': 'Lender funding pubkey',
        'lender-payout-address': 'Lender payout address',
        'refund-pays-lender-address': 'Refund pays lender address',
        'total-collateral-sats': 'Total collateral',
        'oracle-event-id': 'Oracle event ID',
        'cet-locktime': 'CET locktime',
        'refund-locktime': 'Refund locktime',
    };
    const checks = policyResult.checks || [];
    const list = document.getElementById('policyChecksList');
    const empty = document.getElementById('policyNoChecks');
    list.innerHTML = '';
    empty.classList.toggle('hidden', checks.length > 0);

    for (const check of checks) {
        const passed = check.status === 'pass';
        const label = labels[check.id] || (check.id.startsWith('lender-outcome:')
            ? `Lender payout: ${check.id.slice('lender-outcome:'.length)}`
            : humanizeStatus(check.id));
        const row = document.createElement('div');
        row.className = `border rounded-card p-3 ${passed ? 'border-green-200 bg-green-50/50' : 'border-red-200 bg-red-50/50'}`;
        row.innerHTML = `
            <div class="flex items-start gap-3">
                <span class="w-5 h-5 rounded-full ${passed ? 'bg-green-100 text-green-600' : 'bg-red-100 text-red-600'} flex items-center justify-center shrink-0 mt-0.5">
                    <i class="ph-bold ${passed ? 'ph-check' : 'ph-x'} text-[11px]"></i>
                </span>
                <div class="min-w-0 flex-1">
                    <div class="text-sm font-medium text-gray-900">${escapeHtml(label)}</div>
                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-1 mt-2 text-xs">
                        <div class="min-w-0"><span class="text-gray-500">Expected</span><div class="font-mono text-gray-700 break-all">${escapeHtml(formatPolicyValue(check.expected))}</div></div>
                        <div class="min-w-0"><span class="text-gray-500">Decoded</span><div class="font-mono text-gray-700 break-all">${escapeHtml(formatPolicyValue(check.actual))}</div></div>
                    </div>
                </div>
            </div>`;
        list.appendChild(row);
    }

    document.getElementById('verificationDigestDisplay').textContent = policyResult.verificationDigest || '-';
    setCopyData('verificationDigestDisplay', policyResult.verificationDigest || '');
    document.getElementById('attestationPayloadDisplay').textContent = JSON.stringify(policyResult.attestationPayload, null, 2);
}

async function doVerify() {
    const offerHex = normalizeMessageHex(document.getElementById('offerHex').value);
    const acceptHex = normalizeMessageHex(document.getElementById('acceptHex').value);
    const signHex = normalizeMessageHex(document.getElementById('signHex').value);
    if (!offerHex || !acceptHex) { alert('Please provide both offer and accept hex'); return; }

    lastTvcEvidence = null;
    document.getElementById('tvcEvidenceCard').classList.add('hidden');

    let oracleContext;
    let policy = null;
    const policyEnabled = document.getElementById('policyToggle').checked;
    try {
        oracleContext = getOracleSelectionContext();
        if (policyEnabled) policy = buildPolicy(oracleContext);
    } catch (err) {
        alert(err.message);
        return;
    }

    document.getElementById('loadingOverlay').classList.remove('hidden');
    document.getElementById('verifyBtn').disabled = true;

    try {
        const payload = {
            offer: offerHex,
            accept: acceptHex,
            network: document.getElementById('networkSelect').value,
            challenge: createTvcChallenge(),
        };
        if (signHex) {
            payload.signHex = signHex;
        }
        if (policyEnabled) {
            payload.policy = policy;
        } else if (oracleContext.expectedPubkey) {
            payload.policy = { expectedOraclePubkey: oracleContext.expectedPubkey };
        }
        const response = await fetch('/api/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const envelope = await response.json();
        if (!response.ok) {
            throw new Error(envelope.error || `Verification request failed (${response.status})`);
        }
        if (!envelope.result || !envelope.proof || !envelope.execution) {
            throw new Error('Verification response did not include Turnkey TEE evidence');
        }
        displayResults(envelope.result, oracleContext, policyEnabled ? envelope.policyResult : null);
        if (envelope.result.error) {
            lastTvcEvidence = null;
            document.getElementById('tvcEvidenceCard').classList.add('hidden');
        } else {
            displayTvcEvidence(envelope, payload);
        }
    } catch (err) {
        lastTvcEvidence = null;
        document.getElementById('tvcEvidenceCard').classList.add('hidden');
        document.getElementById('errorMessage').textContent = `Error: ${err.message}`;
        document.getElementById('errorMessage').classList.remove('hidden');
        document.getElementById('inputSection').classList.add('hidden');
        document.getElementById('resultsSection').classList.remove('hidden');
        document.getElementById('headerEditBtn').classList.remove('hidden');
    } finally {
        document.getElementById('loadingOverlay').classList.add('hidden');
        document.getElementById('verifyBtn').disabled = false;
    }
}

function displayTvcEvidence(envelope, request) {
    lastTvcEvidence = {
        request,
        execution: envelope.execution,
        policyResult: envelope.policyResult,
        proof: envelope.proof,
    };
    const challenge = envelope.execution.challenge || '-';
    const publicKey = envelope.proof.publicKey || '-';
    document.getElementById('tvcSignedVerdictDisplay').textContent = envelope.execution.signedVerdict || '-';
    document.getElementById('tvcChallengeDisplay').textContent = truncateHex(challenge, 18, 12);
    document.getElementById('tvcProofKeyDisplay').textContent = truncateHex(publicKey, 18, 12);
    setCopyData('tvcChallengeDisplay', challenge);
    setCopyData('tvcProofKeyDisplay', publicKey);
    document.getElementById('tvcEvidenceCard').classList.remove('hidden');
    initCopyTriggers();
}

function downloadTvcEvidence() {
    if (!lastTvcEvidence) return;
    const blob = new Blob([JSON.stringify(lastTvcEvidence, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `dlc-verify-tvc-proof-${Date.now()}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
}

function displayResults(result, oracleContext = { expectedPubkey: null, expectedLabel: 'provided oracle pubkey' }, policyResult = null) {
    document.getElementById('inputSection').classList.add('hidden');
    document.getElementById('resultsSection').classList.remove('hidden');
    document.getElementById('headerEditBtn').classList.remove('hidden');

    // Error
    if (result.error) {
        document.getElementById('errorMessage').textContent = `Error: ${result.error}`;
        document.getElementById('errorMessage').classList.remove('hidden');
    } else {
        document.getElementById('errorMessage').classList.add('hidden');
    }

    // Contract type & validity
    document.getElementById('contractTypeDisplay').textContent = result.contractType || 'Unknown';
    const oracleTrustState = result.error ? null : getOracleTrustState(result, oracleContext);
    const hasPubkeyMismatch = oracleContext.expectedPubkey && oracleTrustState && !oracleTrustState.proofValid;
    const badge = document.getElementById('validityBadge');
    const standardVerificationPassedWithoutSign = !policyResult
        && result.verificationStatus === 'incomplete'
        && Array.isArray(result.verificationIncomplete)
        && result.verificationIncomplete.length === 1
        && result.verificationIncomplete[0] === 'dlc-sign-not-provided';
    const overallStatus = policyResult
        ? policyResult.verdict
        : standardVerificationPassedWithoutSign
            ? 'pass'
            : result.verificationStatus;
    if (overallStatus === 'pass' && !hasPubkeyMismatch) {
        badge.className = 'inline-flex items-center gap-2 bg-green-50 border border-green-200 text-green-700 px-4 py-2 rounded-card text-sm font-medium whitespace-nowrap self-start';
        badge.innerHTML = policyResult
            ? '<i class="ph-fill ph-check-circle text-green-600 text-lg"></i> Verified'
            : '<i class="ph-fill ph-check-circle text-green-600 text-lg"></i> Valid Cryptography';
    } else if (overallStatus === 'incomplete' || hasPubkeyMismatch) {
        badge.className = 'inline-flex items-center gap-2 bg-amber-50 border border-amber-200 text-amber-700 px-4 py-2 rounded-card text-sm font-medium whitespace-nowrap self-start';
        badge.innerHTML = hasPubkeyMismatch
            ? '<i class="ph-fill ph-warning-circle text-amber-600 text-lg"></i> Oracle Pubkey Mismatch'
            : '<i class="ph-fill ph-warning-circle text-amber-600 text-lg"></i> Partial Verification';
    } else {
        badge.className = 'inline-flex items-center gap-2 bg-red-50 border border-red-200 text-red-700 px-4 py-2 rounded-card text-sm font-medium whitespace-nowrap self-start';
        badge.innerHTML = '<i class="ph-fill ph-x-circle text-red-600 text-lg"></i> Verification Failed';
    }

    renderPolicyResults(policyResult);

    // Collateral
    document.getElementById('totalCollateralDisplay').textContent = result.totalCollateral ? formatSats(result.totalCollateral) : '-';
    document.getElementById('offerCollateralDisplay').textContent = result.offerCollateral ? formatSats(result.offerCollateral) : '-';
    document.getElementById('acceptCollateralDisplay').textContent = result.acceptCollateral ? formatSats(result.acceptCollateral) : '-';

    // Parameters
    const feeRate = result.feeRatePerVb ? `${result.feeRatePerVb} sats/vbyte` : '-';
    document.getElementById('feeRateDisplay').textContent = feeRate;
    setCopyData('feeRateDisplay', feeRate);

    const cetLock = result.cetLocktime ? formatLocktimeToDate(result.cetLocktime) : '-';
    document.getElementById('cetLocktimeDisplay').textContent = cetLock;
    setCopyData('cetLocktimeDisplay', cetLock);

    const refundLock = result.refundLocktime ? formatLocktimeToDate(result.refundLocktime) : '-';
    document.getElementById('refundLocktimeDisplay').textContent = refundLock;
    const refundMode = result.contractFlagsError
        ? `UNSUPPORTED: ${result.contractFlagsError}`
        : result.refundMode === 'accepter'
            ? 'all collateral to the accepter (contract_flags 0x01)'
            : result.refundMode === 'each-party'
                ? 'each party gets its collateral back (contract_flags 0x00)'
                : '-';
    document.getElementById('refundModeDisplay').textContent = refundMode;
    setCopyData('refundLocktimeDisplay', refundLock);

    document.getElementById('offererPubkeyDisplay').textContent = result.offererFundingPubkey || '-';
    setCopyData('offererPubkeyDisplay', result.offererFundingPubkey || '');

    document.getElementById('accepterPubkeyDisplay').textContent = result.accepterFundingPubkey || '-';
    setCopyData('accepterPubkeyDisplay', result.accepterFundingPubkey || '');

    document.getElementById('oracleEventIdDisplay').textContent = result.oracleEventId || '-';
    setCopyData('oracleEventIdDisplay', result.oracleEventId || '');

    // Outcomes tree
    const tree = document.getElementById('outcomesTree');
    // Clear previous outcomes (keep the label)
    tree.querySelectorAll('.outcome-card').forEach(el => el.remove());

    if (result.outcomes && result.outcomes.length > 0) {
        for (const outcome of result.outcomes) {
            const offererFormatted = formatSats(outcome.offererSats);
            const accepterFormatted = formatSats(outcome.accepterSats);
            const div = document.createElement('div');
            div.className = 'outcome-card';
            div.innerHTML = `
                <div class="bg-gray-50 border border-gray-200 rounded-card p-4 hover:border-gray-300 transition-colors">
                    <div class="font-mono text-sm font-medium text-gray-900 mb-3 bg-white border border-gray-100 inline-block px-2 py-1 rounded-sm">${escapeHtml(outcome.label)}</div>
                    <div class="space-y-2">
                        <div class="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-1">
                            <span class="text-sm text-gray-500 flex items-center gap-2"><div class="w-2 h-2 rounded-full bg-blue-500"></div> Offerer Receives</span>
                            <div class="copy-trigger inline-flex items-center rounded-sm px-1 py-0.5 group" data-copy="${escapeAttr(offererFormatted)}">
                                <span class="copy-text font-mono text-sm text-blue-600 transition-colors">${escapeHtml(offererFormatted)}</span>
                                <i class="ph ph-copy copy-icon ml-1.5 text-gray-400 opacity-0 transition-opacity"></i>
                            </div>
                        </div>
                        <div class="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-1">
                            <span class="text-sm text-gray-500 flex items-center gap-2"><div class="w-2 h-2 rounded-full bg-gray-400"></div> Accepter Receives</span>
                            <div class="copy-trigger inline-flex items-center rounded-sm px-1 py-0.5 group" data-copy="${escapeAttr(accepterFormatted)}">
                                <span class="copy-text font-mono text-sm text-gray-700 transition-colors">${escapeHtml(accepterFormatted)}</span>
                                <i class="ph ph-copy copy-icon ml-1.5 text-gray-400 opacity-0 transition-opacity"></i>
                            </div>
                        </div>
                    </div>
                </div>
            `;
            tree.appendChild(div);
        }
    } else {
        const div = document.createElement('div');
        div.className = 'outcome-card';
        div.innerHTML = '<p class="text-sm text-gray-500">No enumerated outcomes</p>';
        tree.appendChild(div);
    }

    // Oracle
    const extractedOraclePubkey = result.extractedOraclePubkey || result.oraclePubkey || '';
    const oraclePubkeyForDisplay = oracleContext.expectedPubkey || extractedOraclePubkey || '-';
    document.getElementById('oraclePubkeyDisplay').textContent = oraclePubkeyForDisplay || '-';
    setCopyData('oraclePubkeyDisplay', oraclePubkeyForDisplay || '');
    document.getElementById('oracleEventIdDisplay2').textContent = result.oracleEventId || '-';
    setCopyData('oracleEventIdDisplay2', result.oracleEventId || '');
    renderOracleTrust(result, oracleContext);

    // Maturity from oracle event ID or refund locktime
    const maturityText = result.cetLocktime ? formatLocktimeToDate(result.cetLocktime) : '-';
    document.getElementById('maturityDateDisplay').textContent = maturityText;
    setCopyData('maturityDateDisplay', maturityText);

    const oracleBadge = document.getElementById('oracleSigBadge');
    if (result.oracleSigValid) {
        oracleBadge.className = 'inline-flex items-center gap-1.5 bg-green-50 text-green-700 px-3 py-1 rounded-card text-xs font-medium';
        oracleBadge.innerHTML = '<i class="ph-fill ph-shield-check text-green-600 text-sm"></i> Announcement Sig Valid';
    } else {
        oracleBadge.className = 'inline-flex items-center gap-1.5 bg-red-50 text-red-700 px-3 py-1 rounded-card text-xs font-medium';
        oracleBadge.innerHTML = '<i class="ph-fill ph-shield-warning text-red-600 text-sm"></i> Sig Invalid';
    }

    // Cryptographic proofs
    setProofStep('oracleSig', result.oracleSigValid,
        result.oracleSigValid ? 'Schnorr signature verified against oracle pubkey.' : (result.oracleSigError || 'Verification failed'));
    setProofStep('oracleEvent', result.oracleEventMatchesContract,
        result.oracleEventMatchesContract ? 'The signed oracle event lists exactly the contract outcomes.' : (result.oracleEventError || 'Not checked'));
    setProofStep('locktimes', result.locktimesValid,
        result.locktimesValid ? 'CET locktime is at or before oracle maturity; refund locktime is after it.' : (result.locktimeError || 'Not checked'));
    setProofStep('encoding', result.canonicalEncoding,
        result.canonicalEncoding ? 'Every message re-serializes byte for byte with no unknown records.' : (result.encodingError || 'Not checked'));

    setProofStep('fundTx', !!result.fundTxId,
        result.fundTxId ? 'Generated identical 2-of-2 multisig funding output independently.' : 'Not reconstructed');

    // Oracle Pubkey Match - only show when user provided a pubkey
    const oraclePubkeyProofStep = document.getElementById('oraclePubkeyProofStep');
    if (oracleContext.expectedPubkey) {
        oraclePubkeyProofStep.classList.remove('hidden');
        if (oracleTrustState) {
            setProofStep('oraclePubkey', oracleTrustState.proofValid, oracleTrustState.proofDetail);
        } else {
            setProofStep('oraclePubkey', null, '-');
        }
    } else {
        oraclePubkeyProofStep.classList.add('hidden');
    }

    const accepterSignaturesValid = result.adaptorValid === false || result.refundSigValid === false
        ? false
        : result.adaptorValid === true && result.refundSigValid === true
            ? true
            : null;
    if (accepterSignaturesValid === true) {
        setProofStep('adaptorSig', true, `Verified ${result.adaptorTotalCount} CET adaptor signatures and the refund signature.`);
    } else if (accepterSignaturesValid === false) {
        setProofStep('adaptorSig', false, result.adaptorError || result.refundSigError || 'Signature verification failed');
    } else {
        setProofStep('adaptorSig', null, result.adaptorSigVerificationNote || 'Not available');
    }

    // Sign message verification steps
    const contractIdMatchStep = document.getElementById('contractIdMatchProofStep');
    const signAdaptorStep = document.getElementById('signAdaptorProofStep');
    const signWasSupplied = result.signAvailable || result.signAdaptorError || result.signRefundSigError;
    if (signWasSupplied) {
        contractIdMatchStep.classList.remove('hidden');
        signAdaptorStep.classList.remove('hidden');

        if (result.signContractIdMatches === true) {
            setProofStep('contractIdMatch', true, 'Sign contract ID matches computed contract ID.');
        } else if (result.signContractIdMatches === false) {
            setProofStep('contractIdMatch', false, `Mismatch: sign has ${result.signContractId}, expected ${result.contractId}`);
        } else {
            setProofStep('contractIdMatch', null, 'Could not verify.');
        }

        const offererSignaturesValid = result.signAdaptorValid === false || result.signRefundSigValid === false
            ? false
            : result.signAdaptorValid === true && result.signRefundSigValid === true
                ? true
                : null;
        if (offererSignaturesValid === true) {
            setProofStep('signAdaptor', true, `Verified ${result.signAdaptorTotalCount} CET adaptor signatures and the refund signature.`);
        } else if (offererSignaturesValid === false) {
            setProofStep('signAdaptor', false, result.signAdaptorError || result.signRefundSigError || 'Signature verification failed');
        } else {
            setProofStep('signAdaptor', null, 'Not verified');
        }
    } else {
        contractIdMatchStep.classList.add('hidden');
        signAdaptorStep.classList.add('hidden');
    }

    // Identifiers & Scripts
    document.getElementById('networkDisplay').textContent = result.network || '-';
    const mismatchEl = document.getElementById('networkMismatch');
    if (result.chainHashNetwork && result.network && result.chainHashNetwork !== result.network) {
        mismatchEl.textContent = `Offer chainHash declares ${result.chainHashNetwork}, but addresses are rendered as ${result.network}. The witness programs are identical — only the bech32 prefix differs.`;
        mismatchEl.classList.remove('hidden');
    } else if (result.chainHashNetwork === null) {
        mismatchEl.textContent = `Offer chainHash matches no known network. Addresses are rendered as ${result.network}.`;
        mismatchEl.classList.remove('hidden');
    } else {
        mismatchEl.classList.add('hidden');
    }
    document.getElementById('contractIdDisplay').textContent = result.contractId || '-';
    setCopyData('contractIdDisplay', result.contractId || '');

    document.getElementById('fundTxIdDisplay').textContent = result.fundTxId || '-';
    setCopyData('fundTxIdDisplay', result.fundTxId || '');

    document.getElementById('fundingAddressDisplay').textContent = result.fundingAddress || '-';
    setCopyData('fundingAddressDisplay', result.fundingAddress || '');

    for (const field of ['offererPayoutAddress', 'offererChangeAddress', 'accepterPayoutAddress', 'accepterChangeAddress']) {
        document.getElementById(field + 'Display').textContent = result[field] || '-';
        setCopyData(field + 'Display', result[field] || '');
    }

    document.getElementById('witnessScriptDisplay').textContent = result.witnessScript || '-';
    setCopyData('witnessScriptDisplay', result.witnessScript || '');

    // Re-init copy triggers for dynamically added elements
    initCopyTriggers();
}

function setProofStep(prefix, valid, detail) {
    const iconWrap = document.getElementById(`${prefix}IconWrap`);
    const icon = document.getElementById(`${prefix}Icon`);
    const detailEl = document.getElementById(`${prefix}Detail`);

    if (valid === true) {
        iconWrap.className = 'w-6 h-6 rounded-full bg-green-100 flex items-center justify-center shrink-0 mt-0.5 border-2 border-white ring-2 ring-white';
        icon.className = 'ph-bold ph-check text-green-600 text-xs';
        detailEl.className = 'text-xs text-green-600 mt-1 leading-relaxed';
    } else if (valid === false) {
        iconWrap.className = 'w-6 h-6 rounded-full bg-red-100 flex items-center justify-center shrink-0 mt-0.5 border-2 border-white ring-2 ring-white';
        icon.className = 'ph-bold ph-x text-red-600 text-xs';
        detailEl.className = 'text-xs text-red-600 mt-1 leading-relaxed';
    } else {
        iconWrap.className = 'w-6 h-6 rounded-full bg-gray-100 flex items-center justify-center shrink-0 mt-0.5 border-2 border-white ring-2 ring-white';
        icon.className = 'ph-bold ph-minus text-gray-400 text-xs';
        detailEl.className = 'text-xs text-gray-500 mt-1 leading-relaxed';
    }
    detailEl.textContent = detail;
}

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function escapeAttr(str) {
    return str.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/'/g, '&#39;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function resetToInput() {
    lastTvcEvidence = null;
    document.getElementById('tvcEvidenceCard').classList.add('hidden');
    document.getElementById('inputSection').classList.remove('hidden');
    document.getElementById('resultsSection').classList.add('hidden');
    document.getElementById('headerEditBtn').classList.add('hidden');
    document.getElementById('errorMessage').classList.add('hidden');
}

// Init copy triggers on page load
document.addEventListener('DOMContentLoaded', () => {
    populateOraclePresetOptions();
    togglePolicyPanel();
    togglePolicyEventInputs();
    const oracleInput = document.getElementById('oraclePubkeyInput');
    if (oracleInput) {
        oracleInput.addEventListener('input', syncOraclePresetFromInput);
    }
    initCopyTriggers();
});

// Event wiring. Inline handlers are not allowed by the Content-Security-Policy.
document.addEventListener('DOMContentLoaded', () => {
    const on = (id, event, handler) => {
        const el = document.getElementById(id);
        if (el) el.addEventListener(event, handler);
    };
    on('resetToInputBtn', 'click', resetToInput);
    on('oraclePreset', 'change', syncOracleInputFromPreset);
    on('policyToggle', 'change', togglePolicyPanel);
    on('policyEventMode', 'change', togglePolicyEventInputs);
    on('verifyBtn', 'click', doVerify);
    on('downloadTvcEvidenceBtn', 'click', downloadTvcEvidence);
});
