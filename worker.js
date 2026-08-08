import { AwsClient } from "aws4fetch";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const objectKey = decodeURIComponent(url.pathname.slice(1));

    if (!objectKey) {
      return new Response("Missing object key", { status: 400 });
    }

    const b2 = new AwsClient({
      accessKeyId: env.B2_KEY_ID,
      secretAccessKey: env.B2_APPLICATION_KEY,
      region: env.B2_REGION,
      service: "s3",
    });

    const b2Url =
      `https://${env.B2_ENDPOINT}/${env.B2_BUCKET}/${objectKey}`;

    // ─────────────────────────────
    // GET / HEAD — video playback
    // ─────────────────────────────
    if (request.method === "GET" || request.method === "HEAD") {
      const headers = {};

      const range = request.headers.get("Range");
      if (range) {
        headers["Range"] = range;
      }

      const signedRequest = await b2.sign(b2Url, {
        method: request.method,
        headers,
      });

      const response = await fetch(signedRequest);

      const responseHeaders = new Headers();

      for (const name of [
        "content-type",
        "content-length",
        "content-range",
        "accept-ranges",
        "etag",
        "cache-control",
      ]) {
        const value = response.headers.get(name);
        if (value) {
          responseHeaders.set(name, value);
        }
      }

      responseHeaders.set("Access-Control-Allow-Origin", "*");
      responseHeaders.set("Access-Control-Allow-Headers", "Range");

      if (!responseHeaders.has("accept-ranges")) {
        responseHeaders.set("accept-ranges", "bytes");
      }

      return new Response(
        request.method === "HEAD" ? null : response.body,
        {
          status: response.status,
          headers: responseHeaders,
        }
      );
    }

    // ─────────────────────────────
    // PUT — authenticated upload
    // ─────────────────────────────
    if (request.method === "PUT") {
      const authHeader =
        request.headers.get("Authorization") || "";

      const token = authHeader.replace(/^Bearer\s+/i, "");

      if (!token) {
        return json(
          { error: "Not authenticated" },
          401
        );
      }

      // Verify the user's Supabase session.
      const userCheck = await fetch(
        `${env.SUPABASE_URL}/auth/v1/user`,
        {
          headers: {
            Authorization: `Bearer ${token}`,
            apikey: env.SUPABASE_ANON_KEY,
          },
        }
      );

      if (!userCheck.ok) {
        return json(
          { error: "Invalid or expired session" },
          401
        );
      }

      const user = await userCheck.json();
      const uid = user.id;

      // Users may only upload into their own folder.
      if (
        !objectKey.startsWith(`videos/${uid}_`) &&
        !objectKey.startsWith(`images/${uid}_`)
      ) {
        return json(
          { error: "Invalid storage path" },
          403
        );
      }

      const contentType =
        request.headers.get("Content-Type") ||
        "application/octet-stream";

      const signedRequest = await b2.sign(b2Url, {
        method: "PUT",
        headers: {
          "Content-Type": contentType,
        },
        body: request.body,
      });

      const response = await fetch(signedRequest);

      if (!response.ok) {
        const detail = await response.text();

        return json(
          {
            error: "Upload to storage failed",
            detail,
          },
          502
        );
      }

      return json({
        success: true,
        objectKey,
      });
    }

    // ─────────────────────────────
    // CORS preflight
    // ─────────────────────────────
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, HEAD, PUT, OPTIONS",
          "Access-Control-Allow-Headers": "Authorization, Content-Type, Range",
        },
      });
    }

    return new Response("Method not allowed", {
      status: 405,
    });
  },
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
    },
  });
}
