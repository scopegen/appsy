import { createHmac, timingSafeEqual } from "node:crypto";
import { authenticate } from "./shopify.server";

type WebhookSession = Awaited<
  ReturnType<typeof authenticate.webhook>
>["session"];

export interface VerifiedWebhook {
  shop: string;
  topic: string;
  payload: unknown;
  session: WebhookSession;
}

// For the webhooks that need no Admin API access: app/uninstalled and the compliance topics.
//
// Shopify's library (authenticate.webhook) first renews the store's offline token when it has
// expired (expiring offline tokens last an hour). Once a store has uninstalled Appsy, Shopify
// refuses that renewal (401 invalid_grant, "This request requires an active refresh_token") and
// the library answers 500 before the handler runs: Shopify retried 8 times, the store was never
// marked uninstalled and its data never erased (Shopify's review stores, 13 November 2026).
// Checked 2026-11-17: library 4.0.3 only lets 401 invalid_request through, not invalid_grant.
//
// So when the library fails with a 500, the webhook is verified the way Shopify's docs describe
// (HMAC-SHA256 of the raw body with the app's client secret, base64, compared in constant time
// with X-Shopify-Hmac-SHA256) and handled without a session.
export async function authenticateWebhook(
  request: Request,
): Promise<VerifiedWebhook> {
  const copy = request.clone();
  try {
    const { shop, topic, payload, session } =
      await authenticate.webhook(request);
    return { shop, topic, payload, session };
  } catch (error) {
    if (!(error instanceof Response) || error.status !== 500) throw error;
    const verified = await verifySignature(copy);
    if (!verified) throw error;
    console.warn(
      `${verified.topic} webhook for ${verified.shop}: the store's token couldn't be renewed, so it's handled without one.`,
    );
    return verified;
  }
}

async function verifySignature(
  request: Request,
): Promise<VerifiedWebhook | null> {
  const secret = process.env.SHOPIFY_API_SECRET;
  const signature = request.headers.get("X-Shopify-Hmac-Sha256");
  const topic = request.headers.get("X-Shopify-Topic");
  const shop = request.headers.get("X-Shopify-Shop-Domain");
  if (!secret || !signature || !topic || !shop) return null;

  const rawBody = await request.text();
  const expected = Buffer.from(
    createHmac("sha256", secret).update(rawBody).digest("base64"),
    "utf8",
  );
  const given = Buffer.from(signature, "utf8");
  // timingSafeEqual throws on buffers of different lengths.
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) {
    return null;
  }

  let payload: unknown;
  try {
    payload = JSON.parse(rawBody);
  } catch {
    return null;
  }
  // The signature covers the body, not the headers: a store the body names must be the
  // header's (shop_domain in the compliance webhooks, myshopify_domain in app/uninstalled).
  const body = payload && typeof payload === "object" ? payload : {};
  const named =
    (body as { shop_domain?: unknown }).shop_domain ??
    (body as { myshopify_domain?: unknown }).myshopify_domain;
  if (named !== undefined && named !== shop) return null;

  return {
    shop,
    // As Shopify's library writes topics: APP_UNINSTALLED, SHOP_REDACT…
    topic: topic.toUpperCase().replace(/\/|\./g, "_"),
    payload,
    session: undefined,
  };
}
