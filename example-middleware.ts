import { next } from "@vercel/functions";

const AUTH_SERVICE_URL =
  process.env.AUTH_SERVICE_URL ?? "https://auth.outboundendurance.com";

function redirectToAuth(request: Request, path: "/login" | "/subscribe") {
  const destination = new URL(path, AUTH_SERVICE_URL);
  destination.searchParams.set("returnTo", request.url);
  return Response.redirect(destination);
}

function getSessionCookie(request: Request) {
  const cookies = request.headers.get("cookie")?.split(";") ?? [];
  const sessionCookieNames = [
    "__Secure-better-auth.session_token",
    "better-auth.session_token",
  ];

  for (const name of sessionCookieNames) {
    const cookie = cookies.find((item) => item.trim().startsWith(`${name}=`));
    const value = cookie?.slice(cookie.indexOf("=") + 1).trim();
    if (value) {
      return { name, value };
    }
  }

  return undefined;
}

export default async function proxy(request: Request) {
  const sessionCookie = getSessionCookie(request);

  if (!sessionCookie) {
    return redirectToAuth(request, "/login");
  }

  let response: Response;
  try {
    response = await fetch(new URL("/api/access", AUTH_SERVICE_URL), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        access: "paid",
        cookie: {
          name: sessionCookie.name,
          value: sessionCookie.value,
        },
      }),
      cache: "no-store",
    });
  } catch (error) {
    console.error("Could not verify access with the auth service.", error);
    return new Response("Unable to verify access.", { status: 503 });
  }

  if (response.status === 401) {
    return redirectToAuth(request, "/login");
  }

  if (response.status === 403) {
    return redirectToAuth(request, "/subscribe");
  }

  if (!response.ok) {
    console.error(
      "Auth service could not verify access.",
      `Unexpected status: ${response.status}`,
    );
    return new Response("Unable to verify access.", { status: 503 });
  }

  let result: unknown;
  try {
    result = await response.json();
  } catch (error) {
    console.error("Auth service returned an invalid access response.", error);
    return new Response("Unable to verify access.", { status: 503 });
  }

  if (
    typeof result === "object" &&
    result !== null &&
    "accessType" in result &&
    result.accessType === "paid" &&
    "hasAccess" in result &&
    result.hasAccess === true
  ) {
    return next();
  }

  return new Response("Unable to verify access.", { status: 503 });
}

export const config = {
  matcher: ["/protected/:path*"],
};
