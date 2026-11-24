const request = require("supertest");
const app = require("../src/vulnerable-app");

test("V1: Missing authentication allows access to public results", async () => {
  const res = await request(app).get("/api/public-results/1001");
  expect(res.status).toBe(200);
});

test("V2: IDOR allows student to read another student's result", async () => {
  const res = await request(app)
    .get("/api/results/1002")
    .set("Authorization", "Bearer student-token");
  expect(res.status).toBe(200);
  expect(res.body.studentId).toBe(1002);
});

test("V3: Missing function-level check allows student to see admin users", async () => {
  const res = await request(app)
    .get("/api/admin/users")
    .set("Authorization", "Bearer student-token");
  expect(res.status).toBe(200);
  expect(Array.isArray(res.body)).toBe(true);
});

test("V4: Role tampering works by sending X-Role header", async () => {
  const res = await request(app)
    .get("/api/admin/stats")
    .set("X-Role", "admin");
  expect(res.status).toBe(200);
});

test("V5: Mass assignment allows user to change their role to admin", async () => {
  const res = await request(app)
    .put("/api/profile")
    .set("Authorization", "Bearer student-token")
    .send({ role: "admin" });
  expect(res.status).toBe(200);
  expect(res.body.role).toBe("admin");
});