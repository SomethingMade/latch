/**
 * Latch — identity verification backend (Didit integration)
 *
 * Three endpoints:
 *  - createVerificationSession (callable) — admin starts a new verification, we call
 *    Didit's Create Session API, store the session in Firestore, return the link.
 *  - diditWebhook (HTTPS)                 — Didit calls this on every status change.
 *    We verify the HMAC signature, then update the matching Firestore doc.
 *  - refreshSessionDecision (callable)    — manual "check now" fallback that polls
 *    Didit directly, for the rare case a webhook was missed.
 *
 * Secrets (set with `firebase functions:secrets:set NAME`):
 *  - DIDIT_API_KEY         — x-api-key for verification.didit.me
 *  - DIDIT_WEBHOOK_SECRET  — secret_shared_key from the webhook destination you
 *                            create in the Didit Business Console
 *  - DIDIT_WORKFLOW_ID     — the workflow to run sessions against
 */

const { onCall, onRequest, HttpsError } = require("firebase-functions/v2/https");
const { defineSecret } = require("firebase-functions/params");
const logger = require("firebase-functions/logger");
const admin = require("firebase-admin");
const crypto = require("crypto");

admin.initializeApp();
const db = admin.firestore();

const DIDIT_API_KEY = defineSecret("DIDIT_API_KEY");
const DIDIT_WEBHOOK_SECRET = defineSecret("DIDIT_WEBHOOK_SECRET");
const DIDIT_WORKFLOW_ID = defineSecret("DIDIT_WORKFLOW_ID");

const DIDIT_BASE_URL = "https://verification.didit.me";
const WEBHOOK_TOLERANCE_SECONDS = 300; // reject anything older than 5 minutes

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Throws unless the caller is signed in and listed in the `admins` collection. */
async function assertIsAdmin(request) {
  if (!request.auth) {
    throw new HttpsError("unauthenticated", "Sign in required.");
  }
  const adminDoc = await db.collection("admins").doc(request.auth.uid).get();
  if (!adminDoc.exists) {
    throw new HttpsError("permission-denied", "This account is not authorized for Latch.");
  }
}

/** Masks an ID/passport number for anything that isn't the raw compliance record. */
function maskIdNumber(idNumber) {
  if (!idNumber) return null;
  const digits = String(idNumber);
  if (digits.length <= 4) return "••••";
  return `${"•".repeat(digits.length - 4)}${digits.slice(-4)}`;
}

// ---------------------------------------------------------------------------
// createVerificationSession
// ---------------------------------------------------------------------------

exports.createVerificationSession = onCall(
  { secrets: [DIDIT_API_KEY, DIDIT_WORKFLOW_ID], cors: true },
  async (request) => {
    await assertIsAdmin(request);

    const { fullName, firstName, lastName, email, idNumber, phone, vendorRef } =
      request.data || {};

    if (!idNumber || !String(idNumber).trim()) {
      throw new HttpsError("invalid-argument", "An ID number is required.");
    }

    const [derivedFirst, ...rest] = (fullName || "").trim().split(/\s+/);
    const derivedLast = rest.join(" ");

    const payload = {
      workflow_id: DIDIT_WORKFLOW_ID.value(),
      vendor_data: vendorRef || request.auth.uid,
      metadata: { created_by: request.auth.uid },
      contact_details: email
        ? { email, send_notification_emails: true, email_lang: "en" }
        : undefined,
      expected_details: {
        first_name: firstName || derivedFirst || undefined,
        last_name: lastName || derivedLast || undefined,
        identification_number: String(idNumber).trim(),
      },
    };

    const diditRes = await fetch(`${DIDIT_BASE_URL}/v3/session/`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": DIDIT_API_KEY.value(),
      },
      body: JSON.stringify(payload),
    });

    if (!diditRes.ok) {
      const errBody = await diditRes.text();
      logger.error("Didit session creation failed", { status: diditRes.status, errBody });
      throw new HttpsError("internal", "Didit rejected the session request.");
    }

    const session = await diditRes.json();

    await db
      .collection("verifications")
      .doc(session.session_id)
      .set({
        sessionId: session.session_id,
        sessionToken: session.session_token,
        workflowId: session.workflow_id,
        url: session.url,
        status: session.status || "Not Started",
        vendorData: session.vendor_data || null,
        applicantName: fullName || [firstName, lastName].filter(Boolean).join(" ") || null,
        email: email || null,
        phone: phone || null,
        idNumberMasked: maskIdNumber(idNumber),
        idNumberLast4: String(idNumber).trim().slice(-4),
        decision: null,
        createdBy: request.auth.uid,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      });

    return {
      sessionId: session.session_id,
      url: session.url,
      status: session.status || "Not Started",
    };
  }
);

// ---------------------------------------------------------------------------
// diditWebhook
// ---------------------------------------------------------------------------

exports.diditWebhook = onRequest(
  { secrets: [DIDIT_WEBHOOK_SECRET] },
  async (req, res) => {
    if (req.method !== "POST") {
      res.status(405).send("Method not allowed");
      return;
    }

    const signatureHeader = req.headers["x-signature"];
    const timestampHeader = req.headers["x-timestamp"];
    const rawBody = req.rawBody; // Buffer — Functions v2 preserves this before JSON parsing

    if (!signatureHeader || !timestampHeader || !rawBody) {
      res.status(400).send("Missing webhook headers or body.");
      return;
    }

    const timestamp = parseInt(timestampHeader, 10);
    const now = Math.floor(Date.now() / 1000);
    if (!timestamp || Math.abs(now - timestamp) > WEBHOOK_TOLERANCE_SECONDS) {
      logger.warn("Rejected webhook: stale or invalid timestamp", { timestamp, now });
      res.status(400).send("Stale timestamp.");
      return;
    }

    const expectedSignature = crypto
      .createHmac("sha256", DIDIT_WEBHOOK_SECRET.value())
      .update(rawBody)
      .digest("hex");

    const signatureValid =
      expectedSignature.length === String(signatureHeader).length &&
      crypto.timingSafeEqual(Buffer.from(expectedSignature), Buffer.from(String(signatureHeader)));

    if (!signatureValid) {
      logger.warn("Rejected webhook: signature mismatch");
      res.status(401).send("Invalid signature.");
      return;
    }

    const event = req.body; // safe to trust now that the signature checked out
    const { session_id: sessionId, status, webhook_type: webhookType, decision } = event;

    if (!sessionId) {
      res.status(400).send("Missing session_id.");
      return;
    }

    const docRef = db.collection("verifications").doc(sessionId);

    await docRef.set(
      {
        sessionId,
        status: status || null,
        decision: decision || null,
        lastWebhookType: webhookType || null,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      },
      { merge: true }
    );

    // Audit trail — every webhook delivery, kept as its own record.
    await docRef.collection("events").add({
      webhookType: webhookType || null,
      status: status || null,
      decision: decision || null,
      receivedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    res.status(200).send("ok");
  }
);

// ---------------------------------------------------------------------------
// refreshSessionDecision — manual fallback, polls Didit directly
// ---------------------------------------------------------------------------

exports.refreshSessionDecision = onCall(
  { secrets: [DIDIT_API_KEY], cors: true },
  async (request) => {
    await assertIsAdmin(request);

    const { sessionId } = request.data || {};
    if (!sessionId) {
      throw new HttpsError("invalid-argument", "sessionId is required.");
    }

    const diditRes = await fetch(`${DIDIT_BASE_URL}/v3/session/${sessionId}/decision/`, {
      headers: { "x-api-key": DIDIT_API_KEY.value() },
    });

    if (!diditRes.ok) {
      throw new HttpsError("internal", "Could not fetch the session decision from Didit.");
    }

    const decision = await diditRes.json();

    await db
      .collection("verifications")
      .doc(sessionId)
      .set(
        {
          status: decision.status || null,
          decision,
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        },
        { merge: true }
      );

    return { status: decision.status || null };
  }
);
