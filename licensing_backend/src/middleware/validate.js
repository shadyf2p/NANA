export function validateBody(schema) {
  return (req, res, next) => {
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({
        message: "Invalid request payload",
        errors: parsed.error.issues.map((i) => ({
          field: i.path.join("."),
          issue: i.message
        }))
      });
    }
    req.body = parsed.data;
    return next();
  };
}

