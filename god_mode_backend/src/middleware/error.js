export function notFound(_req, res) {
  return res.status(404).json({ message: "Route not found" });
}

export function errorHandler(err, _req, res, _next) {
  console.error("[ERROR]", err);
  return res.status(500).json({ message: "Internal server error" });
}

