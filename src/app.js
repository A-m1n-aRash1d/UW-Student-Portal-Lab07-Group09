const express = require("express");
const path = require("path");
const { users, results } = require("./data");
const { authenticate, authorize, authorizeOwnerOr } = require("./auth");

const app = express();
app.use(express.json());

// V1 & V2 Fix: Protected route requires authentication AND ownership/permission
app.get("/api/results/:studentId", authenticate, authorizeOwnerOr("view_all_results"), (req, res) => {
    const result = results.find(r => r.studentId === Number(req.params.studentId));
    if (!result) return res.status(404).json({ message: "Result not found" });
    res.json(result);
});

// V3 Fix: Requires 'view_admin_panel' permission
app.get("/api/admin/users", authenticate, authorize("view_admin_panel"), (req, res) => {
    res.json(users);
});

// V4 Fix: Role is read from server-side record, not headers.
app.get("/api/admin/stats", authenticate, authorize("view_admin_panel"), (req, res) => {
    res.json({ totalUsers: users.length });
});

// V5 Fix: Mass Assignment prevented. We ONLY update the 'name' field.
app.put("/api/profile", authenticate, authorize("update_own_profile"), (req, res) => {
    if (typeof req.body.name === "string") {
        req.user.name = req.body.name;
    }
    res.json({ id: req.user.id, name: req.user.name, role: req.user.role });
});

const fs = require("fs");

// V6 Fix: Path Traversal blocked using strict absolute path validation
app.get("/api/download", authenticate, authorize("download_reports"), (req, res) => {
    const requestedFile = req.query.file || "summary.txt";
    const safeFile = path.basename(requestedFile); 
    
    // Resolve the absolute path
    const reportsDir = path.resolve(__dirname, "reports");
    const filePath = path.resolve(reportsDir, safeFile);
    
    // Strict check: Ensure the file path starts with the reports directory
    if (!filePath.startsWith(reportsDir + path.sep)) {
        return res.status(403).json({ message: "Access denied: Path traversal detected" });
    }
    
    // Ensure file exists before sending
    if (!fs.existsSync(filePath)) {
        return res.status(404).json({ message: "File not found" });
    }

    res.sendFile(filePath);
});

// V7 Fix: Destructive action requires 'manage_users' permission
app.delete("/api/admin/users/:id", authenticate, authorize("manage_users"), (req, res) => {
    const userIndex = users.findIndex(u => u.id === Number(req.params.id));
    if (userIndex === -1) return res.status(404).json({ message: "User not found" });
    users.splice(userIndex, 1);
    res.json({ message: "User deleted securely" });
});

module.exports = app;