import { isIP } from "node:net";

function fail(description, message) {
  throw new Error(`${description}: ${message}`);
}

function isLoopbackIp(hostname) {
  if (hostname === "[::1]") return true;
  if (isIP(hostname) !== 4) return false;
  return hostname.split(".", 1)[0] === "127";
}

/**
 * Validate an origin that will receive a Convex deploy credential. Plain HTTP
 * is safe only over a numeric loopback address; other targets require HTTPS.
 */
export function validateAuthenticatedConvexOrigin(value, description) {
  let origin;
  try {
    origin = new URL(value);
  } catch {
    fail(description, "must be a valid URL");
  }
  if (
    origin.username !== "" ||
    origin.password !== "" ||
    origin.pathname !== "/" ||
    origin.search !== "" ||
    origin.hash !== ""
  ) {
    fail(description, "must be an origin without credentials, path, query, or fragment");
  }
  if (origin.protocol === "http:") {
    if (!isLoopbackIp(origin.hostname)) {
      fail(description, "must use HTTPS unless its host is a numeric loopback address");
    }
    return origin;
  }
  if (origin.protocol !== "https:") {
    fail(description, "must use HTTPS unless its host is a numeric loopback address");
  }
  return origin;
}
