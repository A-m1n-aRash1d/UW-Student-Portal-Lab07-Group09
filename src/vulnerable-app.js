const express = require("express");
const { users, results } = require("./data");
const path = require("path");

const app = express();
app.use(express.json());

// Middleware to mock authentication based on the token
const auth = (req, res, next) => {
    const header = req.headers.authorization || "";
    if (header.startsWith("Bearer ")) {
        const token = header.slice(7);
        const userId = {
            "student-token": 1001,
            "bilal-token": 1002,
            "teacher-token": 2001,
            "admin-token": 9001
        }[token];
        req.user = users.find(u => u.id === userId);
    }
    next();
};
app.use(auth);

// ==========================================
// V1 - Missing authentication (Public route)
// ==========================================
app.get("/api/public-results/:id", (req, res) => {
    // No auth check here!
    res.json(results.find(r => r.studentId === Number(req.params.id)));
});

// ==========================================
// V2 - IDOR: Logged-in user can request ANY student ID
// ==========================================
app.get("/api/results/:id", (req, res) => {
    if (!req.user) return res.status(401).json({ message: "Login required" });
    // No ownership check! Just returns whatever ID is requested
    res.json(results.find(r => r.studentId === Number(req.params.id)));
});

// ==========================================
// V3 - Missing function-level check
// ==========================================
app.get("/api/admin/users", (req, res) => {
    if (!req.user) return res.status(401).json({ message: "Login required" });
    // No role check! Any authenticated user can see the list
    res.json(users);
});

// ==========================================
// V4 - Client-supplied role is trusted
// ==========================================
app.get("/api/admin/stats", (req, res) => {
    // Trusts the X-Role header sent by the client!
    if (req.headers["x-role"] === "admin")
        return res.json({ totalUsers: users.length });
    res.status(403).json({ message: "Access denied" });
});

// ==========================================
// V5 - Mass Assignment
// ==========================================
app.put("/api/profile", (req, res) => {
    if (!req.user) return res.status(401).json({ message: "Login required" });
    // Danger: Object.assign copies EVERYTHING from req.body, including "role"
    Object.assign(req.user, req.body);
    res.json(req.user);
});

// ==========================================
// V6 - Path Traversal
// ==========================================
app.get("/api/download", (req, res) => {
    if (!req.user) return res.status(401).json({ message: "Login required" });
    // No role check, no path validation. Directly concatenates filename.
    const file = req.query.file || "summary.txt";
    res.sendFile(path.join(__dirname, "reports", file));
});

// ==========================================
// V7 - Missing authorization on delete
// ==========================================
app.delete("/api/admin/users/:id", (req, res) => {
    if (!req.user) return res.status(401).json({ message: "Login required" });
    // No role check! Any authenticated user can delete another user
    const userIndex = users.findIndex(u => u.id === Number(req.params.id));
    if (userIndex === -1) return res.status(404).json({ message: "User not found" });
    users.splice(userIndex, 1);
    res.json({ message: "User deleted" });
});

module.exports = app;