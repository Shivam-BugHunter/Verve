const jwt = require("jsonwebtoken");
const User = require("../models/User");

const JWT_SECRET = process.env.JWT_SECRET || "verve-dev-secret-change-me";

function authMiddleware(req, res, next) {
    const header = req.headers.authorization;
    if (!header || !header.startsWith("Bearer ")) {
        return res.status(401).json({ error: "No token provided" });
    }

    const token = header.split(" ")[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch {
        return res.status(401).json({ error: "Invalid or expired token" });
    }
}
/**
 * Socket.IO authentication middleware.
 *
 * Handles two token shapes:
 *  1. Embed token  — contains { version, tenantId, roomId, role, guestId, guestName }
 *     Sets socket.embedContext; skips DB lookup.
 *  2. Regular user token — contains { id, email, name }
 *     Fetches fresh user record from DB to prevent stale name display.
 *
 * Embed tokens and regular tokens are mutually exclusive:
 *  - An embed socket cannot join standard user rooms (enforced in join-room).
 *  - A regular socket cannot join tenant rooms (enforced in join-room).
 */
async function socketAuthMiddleware(socket, next) {
    const token = socket.handshake.auth?.token;
    if (!token) {
        return next(new Error("Authentication required"));
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);

        // ── Embed token path ─────────────────────────────────────────────
        if (decoded.tenantId) {
            // Constraint 3: enforce known token version; reject unknown formats
            if (decoded.version !== 1) {
                return next(new Error("Unsupported embed token version"));
            }
            // Constraint 11: embed sockets are bound to the room in the token;
            //                enforcement happens again in join-room for defence-in-depth.
            if (!decoded.roomId || !decoded.guestId || !decoded.guestName) {
                return next(new Error("Malformed embed token"));
            }

            socket.user = {
                id:    decoded.guestId,
                name:  decoded.guestName,
                email: null,
            };
            socket.embedContext = {
                tenantId: decoded.tenantId,
                roomId:   decoded.roomId,
                role:     decoded.role || "participant",
                version:  decoded.version,
            };
            return next();
        }

        // ── Regular user token path ──────────────────────────────────────
        // Always fetches from DB — prevents stale JWTs causing wrong display names
        const dbUser = await User.findById(decoded.id).select("name email").lean();
        if (!dbUser) {
            return next(new Error("User not found — please register or log in again"));
        }

        socket.user = {
            id:    decoded.id,
            name:  dbUser.name,
            email: dbUser.email,
        };
        // Explicitly clear embedContext so regular sockets cannot bypass isolation
        socket.embedContext = null;
        next();
    } catch {
        next(new Error("Invalid or expired token"));
    }
}

module.exports = { authMiddleware, socketAuthMiddleware, JWT_SECRET };
