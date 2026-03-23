import { getActivePolicyByPlan } from "../models/policyModel.js";

function buildRotatingSnippetInstruction({ riskScore }) {
  const epochSlice = Math.floor(Date.now() / 60000); // rotate every minute
  const snippetId = `policy-snippet-${epochSlice % 17}`;
  // Client should map snippet_id to pre-shipped bytecode table or secure fetch flow.
  return {
    op: "runtime.snippet",
    snippet_id: snippetId,
    mode: riskScore >= 70 ? "strict" : "normal",
    ttl_seconds: 120
  };
}

export async function buildExecutionInstructions({ planCode, riskScore, context = {} }) {
  const policy = await getActivePolicyByPlan(planCode);
  let instructions = [];
  let policyVersion = 0;

  if (policy?.policy_json?.instructions && Array.isArray(policy.policy_json.instructions)) {
    instructions = policy.policy_json.instructions;
    policyVersion = Number(policy.version || 0);
  }

  // Graceful degradation when risk grows.
  if (riskScore >= 60) {
    instructions = [
      ...instructions,
      { op: "feature.toggle", feature: "bulk_automation", enabled: false },
      { op: "runtime.set", key: "max_parallel_jobs", value: 1 },
      { op: "runtime.set", key: "telemetry_level", value: "strict" }
    ];
  }

  if (riskScore >= 40 || Number(context.requestFrequency || 0) > 40) {
    instructions = [
      ...instructions,
      { op: "feature.toggle", feature: "market_scanner", enabled: true },
      { op: "runtime.set", key: "heartbeat_seconds", value: 45 }
    ];
  }

  instructions = [
    ...instructions,
    buildRotatingSnippetInstruction({ riskScore })
  ];

  return { policyVersion, instructions };
}

