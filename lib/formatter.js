function normalizePayload(payload) {
  if (Array.isArray(payload)) {
    return payload.map(normalizePayload);
  }
  if (payload && typeof payload === "object") {
    return Object.fromEntries(
      Object.entries(payload).map(([key, value]) => [key, normalizePayload(value)]),
    );
  }
  return payload;
}

function formatJson(payload) {
  return JSON.stringify(normalizePayload(payload), null, 2);
}

function formatText(payload) {
  if (typeof payload === "string") {
    return payload;
  }
  return JSON.stringify(normalizePayload(payload), null, 2);
}

module.exports = {
  formatJson,
  formatText,
  normalizePayload,
};
