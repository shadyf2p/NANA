import { dbQuery } from "../config/mysql.js";

export async function getActivePolicyByPlan(planCode) {
  const rows = await dbQuery(
    `SELECT id, plan_code, version, policy_json
     FROM execution_policies
     WHERE plan_code = :planCode AND is_active = 1
     ORDER BY version DESC
     LIMIT 1`,
    { planCode }
  );
  return rows[0] || null;
}

