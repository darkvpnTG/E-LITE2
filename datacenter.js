const ALLOWED_ORIGIN = "https://darkvpntg.com";
const API_URL = "https://api.police-privacy.net/v0a2158/reg/dact/ISP/Private/activity";

function cors(origin) {
  const allowed = origin === ALLOWED_ORIGIN ? origin : ALLOWED_ORIGIN;
  return {
    "Access-Control-Allow-Origin": allowed,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Vary": "Origin"
  };
}
function json(data, status, origin) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...cors(origin) }
  });
}

export default {
  async fetch(request) {
    const origin = request.headers.get("Origin") || "";
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors(origin) });
    }
    if (request.method !== "POST") return json({ error: "Method not allowed" }, 405, origin);
    if (origin && origin !== ALLOWED_ORIGIN) return json({ error: "Origin not allowed" }, 403, origin);

    try {
      const body = await request.json();
      const publicKey = String(body.publicKey || "");
      const installId = String(body.installId || "");
      if (!/^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/.test(publicKey) || installId.length < 16) {
        return json({ error: "Invalid registration data" }, 400, origin);
      }

      const fcmToken = installId + ":APA91b" + crypto.randomUUID().replace(/-/g, "") + crypto.randomUUID().replace(/-/g, "");
      const payload = {
        key: publicKey,
        install_id: installId,
        fcm_token: fcmToken,
        tos: new Date().toISOString(),
        model: "Android",
        serial_number: installId,
        locale: "en_US"
      };

      const upstream = await fetch(API_URL, {
        method: "POST",
        headers: {
          "User-Agent": "okhttp/3.12.1",
          "CF-Client-Version": "a-6.10-2158",
          "Content-Type": "application/json"
        },
        body: JSON.stringify(payload)
      });

      const raw = await upstream.text();
      let result;
      try { result = JSON.parse(raw); } catch { result = null; }
      if (!upstream.ok || !result?.id || !result?.token) {
        return json({
          error: "Cloudflare registration was rejected. The unofficial registration API may have changed or limited this request.",
          status: upstream.status
        }, 502, origin);
      }

      // The private key is generated in the user's browser and is never sent to this Worker.
      return json({
        id: result.id,
        token: result.token,
        account: result.account || null,
        config: result.config || null
      }, 200, origin);
    } catch (error) {
      return json({ error: "Worker error: " + String(error?.message || error) }, 500, origin);
    }
  }
};
