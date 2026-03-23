export function notFoundHandler(_req, res) {
  return res.status(404).json({ message: "Route not found" });
}

export function errorHandler(error, _req, res, _next) {
  const statusCode = Number(error.statusCode || 500);
  const message = statusCode >= 500 ? "Internal server error" : error.message;

  if (statusCode >= 500) {
    console.error("[ERROR]", error);
  }

  return res.status(statusCode).json({ message });
}

