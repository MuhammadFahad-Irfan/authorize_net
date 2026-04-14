/**
 * Authorize.net Accept Hosted - Backend
 * ------------------------------------------------------------
 * Implements a secure hosted payment flow:
 *   1. POST /create-invoice         -> create an invoice record
 *   2. POST /get-payment-token      -> get Accept Hosted form token from Authorize.net
 *   3. POST /payment-success        -> redirect/iframe handler; verifies txn on the server
 *   4. GET  /invoice/:id            -> return invoice details
 *   5. GET  /iframe-communicator    -> static helper page Authorize.net posts to for iframe mode
 *
 * NO card data ever touches this backend. The card form is hosted on
 * accept.authorize.net and only returns an opaque transId we verify server-side.
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const path = require('path');
const crypto = require('crypto');
const ApiContracts = require('authorizenet').APIContracts;
const ApiControllers = require('authorizenet').APIControllers;
const SDKConstants = require('authorizenet').Constants;

const {
  AUTH_NET_LOGIN_ID,
  AUTH_NET_TRANSACTION_KEY,
  PORT = 4000,
  FRONTEND_URL = 'http://localhost:5173',
  BACKEND_URL = 'http://localhost:4000',
} = process.env;

const AUTHORIZE_API_LOGIN_ID=AUTH_NET_LOGIN_ID
const AUTHORIZE_TRANSACTION_KEY=AUTH_NET_TRANSACTION_KEY
if (!AUTHORIZE_API_LOGIN_ID || !AUTHORIZE_TRANSACTION_KEY) {
  console.warn('[WARN] AUTHORIZE_API_LOGIN_ID / AUTHORIZE_TRANSACTION_KEY not set. Copy .env.example to .env and fill them in.');
}

const app = express();
app.use(cors({ origin: FRONTEND_URL, credentials: true }));
app.use(express.json());
// Authorize.net posts the redirect/iframe message as application/x-www-form-urlencoded
app.use(express.urlencoded({ extended: true }));
app.use(morgan('dev'));

// ------------------------------------------------------------
// Tiny in-memory "database" for invoices.
// Replace with SQLite/Postgres in production.
// ------------------------------------------------------------
const invoices = new Map();

function createInvoiceRecord({ amount, description }) {
  const id = 'INV-' + crypto.randomBytes(4).toString('hex').toUpperCase();
  const invoice = {
    id,
    amount: Number(amount).toFixed(2),
    description: description || 'Payment',
    status: 'pending', // pending | paid | failed
    transactionId: null,
    createdAt: new Date().toISOString(),
  };
  invoices.set(id, invoice);
  return invoice;
}

// Helper to build the Authorize.net merchant auth object
function merchantAuth() {
  const m = new ApiContracts.MerchantAuthenticationType();
  m.setName(AUTHORIZE_API_LOGIN_ID);
  m.setTransactionKey(AUTHORIZE_TRANSACTION_KEY);
  return m;
}

// ------------------------------------------------------------
// 1) Create invoice
// ------------------------------------------------------------
app.post('/create-invoice', (req, res) => {
  const { amount, description } = req.body || {};
  const num = Number(amount);
  if (!num || num <= 0) {
    return res.status(400).json({ error: 'amount must be a positive number' });
  }
  const invoice = createInvoiceRecord({ amount: num, description });
  console.log('[invoice] created', invoice.id, invoice.amount);
  res.json({ invoiceId: invoice.id, invoice });
});

// ------------------------------------------------------------
// 2) Get Accept Hosted payment token
//    Calls Authorize.net `getHostedPaymentPageRequest`
// ------------------------------------------------------------
app.post('/get-payment-token', (req, res) => {
  const { invoiceId } = req.body || {};
  const invoice = invoices.get(invoiceId);
  if (!invoice) return res.status(404).json({ error: 'invoice not found' });
  if (invoice.status === 'paid') return res.status(400).json({ error: 'invoice already paid' });

  // Build the transactionRequest (authCapture for this amount)
  const txnRequest = new ApiContracts.TransactionRequestType();
  txnRequest.setTransactionType(ApiContracts.TransactionTypeEnum.AUTHCAPTURETRANSACTION);
  txnRequest.setAmount(invoice.amount);

  // Attach our invoice id as the order reference so we can correlate the return
  const order = new ApiContracts.OrderType();
  order.setInvoiceNumber(invoice.id);
  order.setDescription(invoice.description);
  txnRequest.setOrder(order);

  // ---- Accept Hosted settings (JSON-encoded strings, per spec) ----
  const settings = [];

  const pushSetting = (name, value) => {
    const s = new ApiContracts.SettingType();
    s.setSettingName(name);
    s.setSettingValue(typeof value === 'string' ? value : JSON.stringify(value));
    settings.push(s);
  };

  // Return URL: Authorize.net redirects the browser here after payment
  pushSetting('hostedPaymentReturnOptions', {
    showReceipt: false,
    url: `https://4038-182-176-108-166.ngrok-free.app/payment-success?invoiceId=${invoice.id}`,
    urlText: 'Continue',
    cancelUrlText: 'Cancel',
  });

  // Button shown at bottom of the hosted form
  pushSetting('hostedPaymentButtonOptions', { text: 'Pay Now' });

  // Which fields to collect on the hosted form
  pushSetting('hostedPaymentPaymentOptions', {
    cardCodeRequired: true,
    showCreditCard: true,
    showBankAccount: false,
  });

  // Security options
  pushSetting('hostedPaymentSecurityOptions', { captcha: false });

  // Shipping / billing / order / customer display
  pushSetting('hostedPaymentShippingAddressOptions', { show: false, required: false });
  pushSetting('hostedPaymentBillingAddressOptions', { show: true, required: false });
  pushSetting('hostedPaymentOrderOptions', { show: true, merchantName: 'Demo Merchant' });
  pushSetting('hostedPaymentCustomerOptions', { showEmail: false, requiredEmail: false });

  // IFrame communicator: the hosted page posts messages (resize/transact/cancel)
  // to this URL. It must be same-origin with the iframe's parent to postMessage out.
  pushSetting('hostedPaymentIFrameCommunicatorUrl', {
    url: `${FRONTEND_URL}/iframe-communicator.html`,
  });

  const settingList = new ApiContracts.ArrayOfSetting();
  settingList.setSetting(settings);

  const request = new ApiContracts.GetHostedPaymentPageRequest();
  request.setMerchantAuthentication(merchantAuth());
  request.setTransactionRequest(txnRequest);
  request.setHostedPaymentSettings(settingList);

  const ctrl = new ApiControllers.GetHostedPaymentPageController(request.getJSON());
  // Point at sandbox
  ctrl.setEnvironment(SDKConstants.endpoint.sandbox);

  ctrl.execute(() => {
    const apiResponse = ctrl.getResponse();
    const response = new ApiContracts.GetHostedPaymentPageResponse(apiResponse);
    if (!response) return res.status(500).json({ error: 'null response from Authorize.net' });

    const resultCode = response.getMessages().getResultCode();
    if (resultCode !== ApiContracts.MessageTypeEnum.OK) {
      const msg = response.getMessages().getMessage()[0];
      console.error('[authnet] token error', msg.getCode(), msg.getText());
      return res.status(502).json({ error: msg.getText(), code: msg.getCode() });
    }

    const token = response.getToken();
    console.log('[authnet] token issued for', invoice.id);
    res.json({
      token,
      invoiceId: invoice.id,
      // The URL the frontend must POST the token to inside the iframe
      paymentPageUrl: 'https://accept.authorize.net/payment/payment',
    });
  });
});

// ------------------------------------------------------------
// 3) Payment success handler
//    Authorize.net redirects the browser here (full-page POST) with
//    x-www-form-urlencoded fields including an opaque transId we verify.
//    We then 302-redirect the user to the frontend result page.
// ------------------------------------------------------------
async function verifyTransaction(transId) {
  return new Promise((resolve, reject) => {
    const request = new ApiContracts.GetTransactionDetailsRequest();
    request.setMerchantAuthentication(merchantAuth());
    request.setTransId(transId);

    const ctrl = new ApiControllers.GetTransactionDetailsController(request.getJSON());
    ctrl.setEnvironment(SDKConstants.endpoint.sandbox);
    ctrl.execute(() => {
      const apiResponse = ctrl.getResponse();
      const response = new ApiContracts.GetTransactionDetailsResponse(apiResponse);
      if (!response) return reject(new Error('null response'));
      if (response.getMessages().getResultCode() !== ApiContracts.MessageTypeEnum.OK) {
        const m = response.getMessages().getMessage()[0];
        return reject(new Error(`${m.getCode()}: ${m.getText()}`));
      }
      resolve(response.getTransaction());
    });
  });
}

app.post('/payment-success', async (req, res) => {
  // Authorize.net posts the result back. The exact field names from Accept Hosted
  // return include `transId` (and optionally `response`/`responseCode`).
  const invoiceId = req.query.invoiceId || req.body.invoiceId;
  const transId = req.body.transId || req.body.transactionId || req.query.transId;

  const invoice = invoices.get(invoiceId);
  if (!invoice) return res.status(404).send('invoice not found');

  if (!transId) {
    invoice.status = 'failed';
    console.warn('[payment-success] no transId; marking failed', invoiceId);
    return res.redirect(`${FRONTEND_URL}/result?status=failed&invoiceId=${invoiceId}`);
  }

  try {
    const txn = await verifyTransaction(transId);
    const status = txn.getTransactionStatus();
    const settledAmount = txn.getAuthAmount();

    // Guard: amount must match what we created the invoice for
    if (Number(settledAmount).toFixed(2) !== Number(invoice.amount).toFixed(2)) {
      invoice.status = 'failed';
      console.error('[payment-success] amount mismatch', settledAmount, invoice.amount);
      return res.redirect(`${FRONTEND_URL}/result?status=failed&invoiceId=${invoiceId}&reason=amount`);
    }

    const okStatuses = ['capturedPendingSettlement', 'settledSuccessfully', 'authorizedPendingCapture'];
    if (okStatuses.includes(status)) {
      invoice.status = 'paid';
      invoice.transactionId = transId;
      console.log('[payment-success] invoice paid', invoiceId, transId);
      return res.redirect(`${FRONTEND_URL}/result?status=success&invoiceId=${invoiceId}&transId=${transId}`);
    }

    invoice.status = 'failed';
    console.warn('[payment-success] unexpected status', status);
    return res.redirect(`${FRONTEND_URL}/result?status=failed&invoiceId=${invoiceId}&reason=${status}`);
  } catch (err) {
    console.error('[payment-success] verify error', err.message);
    invoice.status = 'failed';
    return res.redirect(`${FRONTEND_URL}/result?status=failed&invoiceId=${invoiceId}&reason=verify`);
  }
});

// GET variant so browsers that follow the redirect without a body still land somewhere sane
app.get('/payment-success', (req, res) => {
  const { invoiceId } = req.query;
  res.redirect(`${FRONTEND_URL}/result?status=unknown&invoiceId=${invoiceId || ''}`);
});

// ------------------------------------------------------------
// 4) Invoice lookup
// ------------------------------------------------------------
app.get('/invoice/:id', (req, res) => {
  const invoice = invoices.get(req.params.id);
  if (!invoice) return res.status(404).json({ error: 'not found' });
  res.json(invoice);
});

app.get('/health', (_req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`[backend] listening on ${BACKEND_URL} (port ${PORT})`);
  console.log(`[backend] frontend expected at ${FRONTEND_URL}`);
});
