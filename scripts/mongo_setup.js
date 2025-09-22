const dbName = "defensedb";
const predictions = db.getSiblingDB(dbName).getCollection("phishing_predictions");
const metrics = db.getSiblingDB(dbName).getCollection("metrics");
predictions.createIndex({ ts: -1 });
predictions.createIndex({ label: 1, ts: -1 });
metrics.createIndex({ ts: -1 });
// TTL example (90 days):
// predictions.createIndex({ ts: 1 }, { expireAfterSeconds: 60 * 60 * 24 * 90 });
print("Indexes created.");
