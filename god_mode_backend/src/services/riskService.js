export function computeRisk({
  previousRiskScore,
  ipChanged,
  hwidMismatch,
  failByIp,
  failByKey,
  failByHwid,
  requestFrequency,
  geoCountry
}) {
  let risk = Number(previousRiskScore || 0);
  if (ipChanged) risk += 8;
  if (hwidMismatch) risk += 35;

  risk += Math.min(20, Math.floor((Number(failByIp || 0)) / 5));
  risk += Math.min(20, Math.floor((Number(failByKey || 0)) / 4));
  risk += Math.min(20, Math.floor((Number(failByHwid || 0)) / 4));
  risk += Math.min(12, Math.floor((Number(requestFrequency || 0)) / 15));

  // Optional geo signal if upstream proxy provides country header.
  if (geoCountry && geoCountry !== "UNKNOWN") {
    const unusualGeo = ["TOR", "A1", "A2"].includes(String(geoCountry).toUpperCase());
    if (unusualGeo) risk += 10;
  }

  if (risk < 0) risk = 0;
  if (risk > 100) risk = 100;
  return risk;
}

export function shouldAutoSuspend(riskScore) {
  return Number(riskScore || 0) >= 85;
}

