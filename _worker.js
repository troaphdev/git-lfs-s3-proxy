import { AwsClient } from "aws4fetch";

const HOMEPAGE = "https://github.com/milkey-mouse/git-lfs-s3-proxy"; // Or your fork
const EXPIRY = 3600; // Default expiry for signed URLs in seconds

const METHOD_FOR = {
  "upload": "PUT",
  "download": "GET",
};

// Signs a request for an S3 object operation
async function signS3Request(s3Client, bucketName, objectKey, httpMethod, expiresIn) {
  const requestUrl = new URL(`https://${s3Client.host || s3Client.serviceHost}/${bucketName}/${objectKey}`);
  requestUrl.searchParams.set("X-Amz-Expires", expiresIn.toString());

  const signedRequest = await s3Client.sign(
    new Request(requestUrl.toString(), { method: httpMethod }),
    { aws: { signQuery: true } } // Sign by adding params to query string
  );
  return signedRequest.url;
}

// Parses Basic authentication from the Authorization header
function parseAuthorization(req) {
  const auth = req.headers.get("Authorization");
  if (!auth) {
    // Unauthorized if no Authorization header
    throw new Response("Authorization header required.", { status: 401 });
  }

  const [scheme, encoded] = auth.split(" ");
  if (scheme !== "Basic" || !encoded) {
    // Bad Request if not Basic auth or no credentials
    throw new Response("Invalid Authorization scheme or missing credentials.", { status: 400 });
  }

  try {
    const buffer = Uint8Array.from(atob(encoded), c => c.charCodeAt(0));
    const decoded = new TextDecoder().decode(buffer).normalize();
    const index = decoded.indexOf(":");
    if (index === -1 || /[\0-\x1F\x7F]/.test(decoded)) {
      // Bad Request if format is not user:pass or contains control characters
      throw new Response("Invalid Basic auth format.", { status: 400 });
    }
    return { user: decoded.slice(0, index), pass: decoded.slice(index + 1) };
  } catch (e) {
    // Bad Request if decoding fails (e.g., invalid base64)
    throw new Response("Invalid base64 encoding in Authorization header.", { status: 400 });
  }
}

async function handleLFSRequest(req, env) {
  const url = new URL(req.url);

  // Redirect root GET requests to the project homepage
  if (url.pathname === "/" && req.method === "GET") {
    return Response.redirect(HOMEPAGE, 302);
  }
  if (url.pathname === "/" && req.method !== "GET") {
    return new Response("Method Not Allowed at root. Only GET is supported.", { status: 405, headers: { "Allow": "GET" } });
  }

  // LFS batch API endpoint check
  if (!url.pathname.endsWith("/objects/batch")) {
    // Not Found for any other paths
    return new Response("Endpoint not found. Expecting LFS batch API path.", { status: 404 });
  }

  // LFS batch API only accepts POST
  if (req.method !== "POST") {
    return new Response("Method Not Allowed. LFS batch API requires POST.", { status: 405, headers: { "Allow": "POST" } });
  }

  // Validate LFS MIME types (optional, can be strict)
  const acceptHeader = req.headers.get("Accept");
  const contentTypeHeader = req.headers.get("Content-Type");
  if (!acceptHeader || !acceptHeader.startsWith("application/vnd.git-lfs+json") ||
      !contentTypeHeader || !contentTypeHeader.startsWith("application/vnd.git-lfs+json")) {
    // Not Acceptable if headers don't match LFS spec
    // return new Response("Invalid LFS MIME types in Accept or Content-Type headers.", { status: 406 });
    // For broader compatibility, we might allow it but log a warning if logging was implemented.
  }

  let s3AuthOptions;
  try {
    const { user, pass } = parseAuthorization(req);
    s3AuthOptions = { accessKeyId: user, secretAccessKey: pass };
  } catch (e) {
    return e; // Return the Response object thrown by parseAuthorization
  }
  
  // Expected path structure: /<S3_ENDPOINT_HOST>/<BUCKET_NAME>/objects/batch
  // Example: /your-account.r2.cloudflarestorage.com/your-bucket/objects/batch
  const pathSegments = url.pathname.substring(1).split("/"); // Remove leading slash and split

  if (pathSegments.length < 4 || pathSegments[pathSegments.length - 1] !== "batch" || pathSegments[pathSegments.length - 2] !== "objects") {
    return new Response("Invalid LFS URL path structure. Expected /<S3_ENDPOINT_HOST>/<BUCKET_NAME>/objects/batch", { status: 400 });
  }

  const s3EndpointHost = pathSegments[0];
  const bucketName = pathSegments[1];
  
  // Add the S3 endpoint host to the S3 client options
  // aws4fetch will use this host. It defaults to HTTPS.
  const s3ClientOptions = { ...s3AuthOptions, host: s3EndpointHost, service: "s3" };
  // Region might also be needed for some S3 providers, but R2 is region-agnostic for its global endpoint.
  // If region was needed, it could be parsed from path or set if fixed: e.g. s3ClientOptions.region = "auto";

  const s3 = new AwsClient(s3ClientOptions);
  const effectiveExpiry = env.EXPIRY || EXPIRY;

  let requestPayload;
  try {
    requestPayload = await req.json();
  } catch (e) {
    return new Response("Invalid JSON payload for LFS batch request.", { status: 400 });
  }

  const { objects, operation, ref, hash_algo } = requestPayload;
  if (!objects || !operation || !Array.isArray(objects)) {
      return new Response("Missing or invalid 'objects' or 'operation' in LFS request payload.", { status: 400 });
  }
  
  const httpMethodForS3 = METHOD_FOR[operation];
  if (!httpMethodForS3) {
    return new Response(`Unsupported LFS operation: ${operation}`, { status: 400 });
  }

  const responseObjects = await Promise.all(objects.map(async ({ oid, size }) => {
    if (!oid || typeof size !== 'number') {
        // Log an error or skip this object if oid/size is invalid
        console.error(`Invalid object in batch: oid=${oid}, size=${size}`); // Requires worker logging
        return { oid, size, error: { code: 422, message: "Unprocessable Entity: Missing oid or invalid size." } };
    }
    try {
      const href = await signS3Request(s3, bucketName, oid, httpMethodForS3, effectiveExpiry);
      return {
        oid,
        size,
        authenticated: true, // This client handles auth, so LFS client doesn't need to.
        actions: {
          [operation]: {
            href: href,
            expires_in: effectiveExpiry,
            // header: { "Authorization": "..." } // Not needed for pre-signed URLs
          },
        },
      };
    } catch (e) {
        console.error(`Error signing URL for oid ${oid}: ${e.message}`); // Requires worker logging
        return { oid, size, error: { code: 500, message: `Failed to generate signed URL for ${oid}: ${e.message}` } };
    }
  }));

  const responsePayload = {
    transfer: "basic", // We are providing direct pre-signed URLs
    objects: responseObjects,
    hash_algo: hash_algo || "sha256", // Reflect back or default
  };

  return new Response(JSON.stringify(responsePayload), {
    status: 200, // LFS Batch API typically returns 200 even if some objects have errors
    headers: {
      "Cache-Control": "no-cache, no-store, must-revalidate",
      "Pragma": "no-cache",
      "Expires": "0",
      "Content-Type": "application/vnd.git-lfs+json",
    },
  });
}

export default {
  async fetch(request, env, ctx) {
    try {
      return await handleLFSRequest(request, env);
    } catch (e) {
      // Catch any unhandled errors from handleLFSRequest or its utility functions
      if (e instanceof Response) {
        return e; // If it's already a Response object (e.g., from parseAuthorization), forward it
      }
      // For other unexpected errors, return a generic 500
      console.error(`Unhandled error: ${e.message}\nStack: ${e.stack}`); // Requires worker logging
      return new Response(`Internal Server Error: ${e.message}`, { status: 500 });
    }
  },
};
