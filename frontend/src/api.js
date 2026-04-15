const BASE ='https://9d7a-182-176-108-166.ngrok-free.app';

async function post(path, body) {
  const r = await fetch(BASE + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || r.statusText);
  return r.json();
}

async function get(path) {
  const r = await fetch(BASE + path);
  if (!r.ok) throw new Error(r.statusText);
  return r.json();
}

export const api = {
  createInvoice: (amount, description) => post('/create-invoice', { amount, description }),
  getPaymentToken: (invoiceId) => post('/get-payment-token', { invoiceId }),
  getInvoice: (id) => get(`/invoice/${id}`),
};
