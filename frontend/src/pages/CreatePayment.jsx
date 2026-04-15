import React, { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api.js';

/**
 * CreatePayment
 * -------------
 * 1. User enters amount + description
 * 2. We call backend /create-invoice then /get-payment-token
 * 3. We open a modal containing an iframe
 * 4. Inside that iframe we submit an auto-POST form to
 *    https://accept.authorize.net/payment/payment with the token
 * 5. The hosted page posts messages (via iframe-communicator.html) which we
 *    receive as window `message` events and act on.
 */
export default function CreatePayment() {
  const [amount, setAmount] = useState('25.00');
  const [description, setDescription] = useState('Test order');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [modal, setModal] = useState(null); // { token, invoiceId, paymentPageUrl }
  const [iframeHeight, setIframeHeight] = useState(650);
  const formRef = useRef(null);
  const navigate = useNavigate();

  // Auto-submit the hidden form once the modal (and iframe) are mounted
  useEffect(() => {
    if (modal && formRef.current) {
      formRef.current.submit();
    }
  }, [modal]);

  // Listen for messages from the hosted payment iframe
  useEffect(() => {
    function onMessage(e) {
      if (e.origin !== window.location.origin) return; // iframe-communicator is same-origin
      const data = e.data || {};
      if (!data.action) return;

      switch (data.action) {
        case 'resizeWindow': {
          const h = parseInt(data.height, 10);
          if (!Number.isNaN(h)) setIframeHeight(h);
          break;
        }
        case 'successfulSave':
          // Profile save only - not a transaction
          break;
        case 'cancel':
          setModal(null);
          navigate(`/result?status=cancel&invoiceId=${modal?.invoiceId || ''}`);
          break;
        case 'transactResponse': {
          // Payment completed inside the iframe. The authoritative verification
          // happens server-side via /payment-success, but the hosted page also
          // hits that URL as part of its return flow. Close the modal and
          // bounce the user to the result page which re-fetches the invoice.
          setModal(null);
          navigate(`/result?invoiceId=${modal?.invoiceId || ''}&status=pending`);
          break;
        }
        default:
          break;
      }
    }
    window.addEventListener('message', onMessage);
    return () => window.removeEventListener('message', onMessage);
  }, [modal, navigate]);

  // async function handlePay(e) {
  //   e.preventDefault();
  //   setError(null);
  //   setLoading(true);
  //   try {
  //     const { invoiceId } = await api.createInvoice(Number(amount), description);
  //     const { token, paymentPageUrl } = await api.getPaymentToken(invoiceId);
  //     setModal({ token, invoiceId, paymentPageUrl });
  //   } catch (err) {
  //     setError(err.message || 'Failed to start payment');
  //   } finally {
  //     setLoading(false);
  //   }
  // }

   async function handlePay(e) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const id = 'INV-' + Date.now().toString(36).toUpperCase();
      const { token, invoiceId, paymentPageUrl } = await api.getPaymentToken({
        id,
        amount: Number(amount),
        description,
      });
      setModal({ token, invoiceId, paymentPageUrl });
    } catch (err) {
      setError(err.message || 'Failed to start payment');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="container">
      <div className="card">
        <h1>Accept Hosted Demo</h1>
        <p className="muted">
          Enter an amount and pay with Authorize.net&apos;s hosted form. Your card
          details never touch this server.
        </p>

        <form onSubmit={handlePay} className="form">
          <label>
            Amount (USD)
            <input
              type="number"
              step="0.01"
              min="0.01"
              value={amount}
              onChange={(e) => setAmount(e.target.value)}
              required
            />
          </label>
          <label>
            Description
            <input
              type="text"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
          </label>
          <button type="submit" disabled={loading}>
            {loading ? 'Starting…' : 'Pay Now'}
          </button>
          {error && <div className="error">{error}</div>}
        </form>
      </div>

      {modal && (
        <div className="modal-backdrop" onClick={() => setModal(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <span>Secure Payment</span>
              <button className="close" onClick={() => setModal(null)}>×</button>
            </div>
            <iframe
              name="authnet_iframe"
              title="Authorize.net Hosted Payment"
              style={{ width: '100%', height: iframeHeight, border: 0 }}
            />
            {/* Hidden auto-submit form targets the iframe above */}
            <form
              ref={formRef}
              method="POST"
              action={modal.paymentPageUrl}
              target="authnet_iframe"
              style={{ display: 'none' }}
            >
              <input type="hidden" name="token" value={modal.token} />
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
