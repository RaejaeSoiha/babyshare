// JSON-backed local account storage. Direct-transfer metadata is ephemeral.
const fs = require("fs");
const path = require("path");
const { DATA_DIR, IS_PRODUCTION } = require("../config");

const USERS_FILE = path.join(DATA_DIR, "users.json");

function readJson(file, fallback, description) {
  if (!fs.existsSync(file)) {
    if (IS_PRODUCTION && description === "user store") {
      throw new Error("Production user store is missing. Bootstrap an administrator before startup.");
    }
    return fallback;
  }

  try {
    const value = JSON.parse(fs.readFileSync(file, "utf8"));
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid shape");
    return value;
  } catch {
    throw new Error(`Unable to read ${description}; restore a valid backup before startup.`);
  }
}

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const temporary = `${file}.${process.pid}.${Date.now()}.tmp`;
  fs.writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  fs.renameSync(temporary, file);
}

function loadUsers() {
  // Never create a predictable administrator account. Existing installations
  // retain their users.json; a new production installation must bootstrap one.
  return readJson(USERS_FILE, {}, "user store");
}

function saveUsers(users) {
  writeJson(USERS_FILE, users);
}

module.exports = {
  USERS_FILE,
  loadUsers,
  saveUsers,
};
