import { insertLicense, banByHash, listLicenses } from "../models/licenseModel.js";
import { listVerifyLogs } from "../models/logModel.js";
import { sha256Hex } from "../utils/hash.js";

export async function createKey(req, res) {
  const { licenseKeyPlain, expireAt, planCode } = req.body;
  const exp = new Date(expireAt);
  if (Number.isNaN(exp.getTime()) || exp.getTime() <= Date.now()) {
    return res.status(400).json({ message: "expireAt must be a future ISO date" });
  }

  const keyHash = sha256Hex(licenseKeyPlain.trim().toUpperCase());
  try {
    await insertLicense({
      licenseKeyHash: keyHash,
      planCode: planCode.toLowerCase(),
      expireAt: exp,
      createdBy: req.admin.id
    });
  } catch (err) {
    if (String(err?.code || "") === "ER_DUP_ENTRY") {
      return res.status(409).json({ message: "License key already exists" });
    }
    throw err;
  }

  return res.status(201).json({
    ok: true,
    data: {
      licenseKeyHash: keyHash,
      expireAt: exp.toISOString(),
      planCode: planCode.toLowerCase(),
      status: "active"
    }
  });
}

export async function banKey(req, res) {
  const keyHash = sha256Hex(req.body.licenseKeyPlain.trim().toUpperCase());
  const affected = await banByHash(keyHash);
  if (!affected) return res.status(404).json({ message: "License not found" });
  return res.json({ ok: true, message: "License banned", licenseKeyHash: keyHash });
}

export async function listKeys(req, res) {
  const limit = Math.min(Math.max(Number(req.query.limit || 50), 1), 500);
  const page = Math.max(Number(req.query.page || 1), 1);
  const offset = (page - 1) * limit;
  const rows = await listLicenses({ limit, offset });
  return res.json({ ok: true, page, limit, data: rows });
}

export async function getLogs(req, res) {
  const limit = Math.min(Math.max(Number(req.query.limit || 100), 1), 500);
  const page = Math.max(Number(req.query.page || 1), 1);
  const offset = (page - 1) * limit;
  const rows = await listVerifyLogs({ limit, offset });
  return res.json({ ok: true, page, limit, data: rows });
}

