import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

export async function middleware(request: NextRequest) {
	const { pathname } = request.nextUrl;

	// Skip middleware for admin routes, API routes, and static assets
	// This must be checked FIRST to avoid redirect loops
	if (
		pathname.startsWith("/admin") ||
		pathname.startsWith("/api") ||
		pathname.startsWith("/_next") ||
		pathname.startsWith("/favicon.ico") ||
		pathname.startsWith("/demo.mp4")
	) {
		return NextResponse.next();
	}

	// Only protect fumadocs routes
	const isFumadocsRoute =
		pathname.startsWith("/docs") ||
		pathname === "/" ||
		pathname.startsWith("/llms.txt") ||
		pathname.startsWith("/llms.mdx") ||
		pathname.startsWith("/llms-full.txt") ||
		pathname.startsWith("/docs-og");

	// If not a fumadocs route, allow access
	if (!isFumadocsRoute) {
		return NextResponse.next();
	}

	// Protect fumadocs routes
	if (isFumadocsRoute) {
		try {
			// Create headers with cookies from the request
			const headers = new Headers();
			const cookieHeader = request.headers.get("cookie");
			if (cookieHeader) {
				headers.set("cookie", cookieHeader);
			}
			// Copy other relevant headers
			headers.set("user-agent", request.headers.get("user-agent") || "");

			// Construct API URL using request.nextUrl which is Edge Runtime compatible
			const url = request.nextUrl.clone();
			url.pathname = "/api/users/me";
			url.search = "";

			// Verify user authentication by calling Payload's /api/users/me endpoint
			const authResponse = await fetch(url.toString(), {
				method: "GET",
				headers,
			});

			// If not authenticated, redirect to login
			if (!authResponse.ok || authResponse.status === 401 || authResponse.status === 403) {
				const loginUrl = request.nextUrl.clone();
				loginUrl.pathname = "/admin/login";
				loginUrl.searchParams.set("redirect", pathname);
				return NextResponse.redirect(loginUrl);
			}

			// Parse the user data - Payload might return it in different formats
			const contentType = authResponse.headers.get("content-type");
			if (!contentType || !contentType.includes("application/json")) {
				// Unexpected response format, deny access
				const loginUrl = request.nextUrl.clone();
				loginUrl.pathname = "/admin/login";
				loginUrl.searchParams.set("redirect", pathname);
				return NextResponse.redirect(loginUrl);
			}

			const responseData = await authResponse.json();

			// Handle different response structures from Payload
			// Payload's /api/users/me typically returns the user object directly
			let user = responseData;
			if (responseData && typeof responseData === "object") {
				if ("user" in responseData && responseData.user) {
					user = responseData.user;
				} else if ("docs" in responseData && Array.isArray(responseData.docs) && responseData.docs.length > 0) {
					user = responseData.docs[0];
				} else if ("doc" in responseData && responseData.doc) {
					user = responseData.doc;
				}
			}

			// Check if we have a valid user object with an id
			if (!user || typeof user !== "object" || !("id" in user)) {
				const loginUrl = request.nextUrl.clone();
				loginUrl.pathname = "/admin/login";
				loginUrl.searchParams.set("redirect", pathname);
				return NextResponse.redirect(loginUrl);
			}

			// Check if user has admin or owner role (same as Payload admin access)
			// If role is missing, null, undefined, or not admin/owner, deny access
			const userRole = user.role;
			const hasAdminAccess = userRole === "owner" || userRole === "admin";

			if (!hasAdminAccess) {
				// User is authenticated but doesn't have admin access
				// Return 403 Forbidden instead of redirecting to prevent loops
				// If user is not logged in at all, they'll be caught by the earlier 401/403 check
				return new NextResponse("Forbidden: Admin or Owner access required", {
					status: 403,
				});
			}

			// User is authenticated and has admin access, allow access
			return NextResponse.next();
		} catch (error) {
			// If there's an error (e.g., network issue, JSON parse error), redirect to login
			const loginUrl = request.nextUrl.clone();
			loginUrl.pathname = "/admin/login";
			loginUrl.searchParams.set("redirect", pathname);
			return NextResponse.redirect(loginUrl);
		}
	}

	// Allow other routes
	return NextResponse.next();
}

export const config = {
	matcher: [
		/*
		 * Match all request paths except for the ones starting with:
		 * - _next/static (static files)
		 * - _next/image (image optimization files)
		 * - favicon.ico (favicon file)
		 * - public folder
		 */
		"/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp|ico|css|js)$).*)",
	],
};
