export function validate(schema) {
  return (req, res, next) => {
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({
        message: "Invalid payload",
        errors: parsed.error.issues.map((x) => ({ field: x.path.join("."), issue: x.message }))
      });
    }
    req.body = parsed.data;
    return next();
  };
}

