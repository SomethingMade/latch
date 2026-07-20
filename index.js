/**
 * Latch — Cloud Functions backend
 *
 * Security boundary:
 *   - DIDIT_API_KEY, DIDIT_WEBHOOK_SECRET, DIDIT_WORKFLOW_ID are Firebase
 *     secrets (Google Secret Manager under the hood). They are only ever
 *     read inside these functions, on the server. The browser never sees
 *     them.
 *   - createVerificationSession is a callable function gated to signed-in
 *     users listed in the /admins collection.
 *   - diditWebhook verifies Didit's HMAC signature before trusting any
 *     payload, and re-fetches the decision from Didit's API rather than
 *     trusting the webhook body alone.
 *   - Firestore rules (see firestore.rules) make /verifications read-only
 *     from the client — only the Admin SDK (these functions) can write.
 */

const { onCall, onRequest, HttpsError } = require("firebase-functions/v2/https");
const { defineSecret } = require("firebase-functions/params");
const admin = require("firebase-admin");
const crypto = require("crypto");

admin.initializeApp();
const db = admin.firestore();

const DIDIT_API_KEY = defineSecret("DIDIT_API_KEY");
const DIDIT_WEBHOOK_SECRET = defineSecret("DIDIT_WEBHOOK_SECRET");
const DIDIT_WORKFLOW_ID = defineSecret("DIDIT_WORKFLOW_ID");

const DIDIT_BASE_URL = "https://verification.didit.me";

async function isAdmin(uid) {
  if (!uid) return false;
  const doc = await db.collection("admins").doc(uid).get();
  return doc.exists;
}

/**
 * Callable from the dashboard. Creates a Didit verification session and
 * a matching Firestore doc, then returns the hosted verification URL for
 * the browser to open.
 */
exports.createVerificationSession = onCall(
  { secrets: [DIDIT_API_KEY, DIDIT_WORKFLOW_ID] },
  async (request) => {
    if (!request.auth) {
      throw new HttpsError("unauthenticated", "Sign in required.");
    }
    if (!(await isAdmin(request.auth.uid))) {
      throw new HttpsError("permission-denied", "Not an authorized admin.");
    }

    const label = (request.data && request.data.label) || "";
    const vendorData = label.trim() || `session-${Date.now()}`;
    const projectId = process.env.GCLOUD_PROJECT;
    const callbackUrl = `https://us-central1-${projectId}.cloudfunctions.net/diditWebhook`;

    const diditRes = await fetch(`${DIDIT_BASE_URL}/v3/session/`, {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
        "x-api-key": DIDIT_API_KEY.value(),
      },
      body: JSON.stringify({
        workflow_id: DIDIT_WORKFLOW_ID.value(),
        vendor_data: vendorData,
        callback: callbackUrl,
      }),
    });

    if (!diditRes.ok) {
      const errText = await diditRes.text();
      console.error("Didit session creation failed", diditRes.status, errText);
      throw new HttpsError("internal", "Could not create a Didit session.");
    }

    const session = await diditRes.json();

    await db
      .collection("verifications")
      .doc(session.session_id)
      .set({
        sessionId: session.session_id,
        sessionNumber: session.session_number || null,
        label: vendorData,
        status: session.status || "Not Started",
        url: session.url,
        decision: null,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        createdBy: request.auth.uid,
      });

    return { sessionId: session.session_id, url: session.url };
  }
);

/**
 * Public HTTPS endpoint Didit calls when a session's status changes.
 * Verifies the HMAC signature, then re-fetches the full decision so the
 * dashboard is always showing Didit's authoritative record, not just
 * whatever the webhook body happened to contain.
 */
exports.diditWebhook = onRequest(
  { secrets: [DIDIT_WEBHOOK_SECRET, DIDIT_API_KEY] },
  async (req, res) => {
    try {
      const signature = req.header("x-signature");
      const timestamp = req.header("x-timestamp");
      const rawBody = req.rawBody ? req.rawBody.toString("utf8") : JSON.stringify(req.body);

      if (!signature) {
        res.status(401).send("Missing signature");
        return;
      }

      const expected = crypto
        .createHmac("sha256", DIDIT_WEBHOOK_SECRET.value())
        .update(rawBody, "utf8")
        .digest("hex");

      const sigBuf = Buffer.from(signature, "utf8");
      const expBuf = Buffer.from(expected, "utf8");
      const validSig =
        sigBuf.length === expBuf.length && crypto.timingSafeEqual(sigBuf, expBuf);

      if (!validSig) {
        console.warn("Rejected webhook: bad signature");
        res.status(401).send("Invalid signature");
        return;
      }

      if (timestamp) {
        const ageSeconds = Math.abs(Date.now() / 1000 - Number(timestamp));
        if (ageSeconds > 300) {
          res.status(401).send("Stale webhook");
          return;
        }
      }

      const payload = JSON.parse(rawBody);
      const sessionId = payload.session_id;
      if (!sessionId) {
        res.status(400).send("Missing session_id");
        return;
      }

      // Re-fetch from Didit rather than trusting the webhook body as final.
      let decision = null;
      const decisionRes = await fetch(
        `${DIDIT_BASE_URL}/v3/session/${sessionId}/decision/`,
        { headers: { "x-api-key": DIDIT_API_KEY.value() } }
      );
      if (decisionRes.ok) {
        decision = await decisionRes.json();
      }

      await db
        .collection("verifications")
        .doc(sessionId)
        .set(
          {
            status: (decision && decision.status) || payload.status || "Unknown",
            decision: decision || payload,
            updatedAt: admin.firestore.FieldValue.serverTimestamp(),
          },
          { merge: true }
        );

      res.status(200).send("OK");
    } catch (err) {
      console.error("Webhook processing error", err);
      res.status(500).send("Internal error");
    }
  }
);
