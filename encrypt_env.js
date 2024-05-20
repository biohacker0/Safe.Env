const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const os = require("os");

function getProjectName() {
  return path.basename(process.cwd());
}

function getKeyDirectory(projectName) {
  const homeDir = os.homedir();
  return path.join(homeDir, ".env_keys", projectName);
}

function loadKey(keyPath) {
  if (!fs.existsSync(keyPath)) {
    throw new Error(
      "Encryption key not found. Please ensure the key is present."
    );
  }
  return JSON.parse(fs.readFileSync(keyPath, "utf8"));
}

function saveKey(keyData, keyPath) {
  fs.mkdirSync(path.dirname(keyPath), { recursive: true });
  fs.writeFileSync(keyPath, JSON.stringify(keyData, null, 4), { mode: 0o600 });
}

function generateValidationToken() {
  return crypto.randomBytes(16).toString("hex");
}

function encryptFile(filePath, key) {
  if (!fs.existsSync(filePath)) {
    throw new Error(
      `${filePath} does not exist. Please create the file and try again.`
    );
  }

  const data = fs.readFileSync(filePath, "utf8");
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(
    "aes-256-cbc",
    Buffer.from(key, "hex"),
    iv
  );
  let encrypted = cipher.update(data, "utf8", "hex");
  encrypted += cipher.final("hex");
  const result = iv.toString("hex") + ":" + encrypted;
  fs.writeFileSync(filePath, result, { mode: 0o600 });
}

function decryptFile(filePath, key) {
  if (!fs.existsSync(filePath)) {
    throw new Error(`${filePath} does not exist. Cannot decrypt.`);
  }

  const data = fs.readFileSync(filePath, "utf8");
  const [ivHex, encryptedText] = data.split(":");
  const iv = Buffer.from(ivHex, "hex");
  const decipher = crypto.createDecipheriv(
    "aes-256-cbc",
    Buffer.from(key, "hex"),
    iv
  );
  let decrypted = decipher.update(encryptedText, "hex", "utf8");
  decrypted += decipher.final("utf8");
  fs.writeFileSync(filePath, decrypted, { mode: 0o600 });
}

function getGitUser() {
  try {
    const username = require("child_process")
      .execSync("git config user.name")
      .toString()
      .trim();
    const email = require("child_process")
      .execSync("git config user.email")
      .toString()
      .trim();
    return `${username} <${email}>`;
  } catch (err) {
    throw new Error(
      "Git is not configured properly. Please set up git with your username and email."
    );
  }
}

function validateKey(keyData, metadata) {
  if (keyData.validation_token !== metadata.validation_token) {
    throw new Error(
      `Validation failed. The key used is not compatible with the metadata. Last encrypted by: ${metadata.last_encrypted_by} at ${metadata.timestamp}`
    );
  }
}

function updateMetadata(keyPath, rotated = false) {
  const keyData = loadKey(keyPath);
  const metadata = {
    last_encrypted_by: getGitUser(),
    key_path: keyPath,
    key_status: rotated ? "rotated" : "stable",
    validation_token: keyData.validation_token,
    timestamp: new Date().toISOString(),
  };
  fs.writeFileSync(".env.encrypt", JSON.stringify(metadata, null, 4), {
    mode: 0o600,
  });
}

function main() {
  const args = process.argv.slice(2);
  if (
    args.length === 0 ||
    !["encrypt", "decrypt", "rotate"].includes(args[0])
  ) {
    console.log("Usage: node encrypt_env.js [encrypt|decrypt|rotate]");
    return;
  }

  const action = args[0];
  const projectName = getProjectName();
  const keyDir = getKeyDirectory(projectName);
  const keyPath = path.join(keyDir, "env_key.json");
  const envFilePath = ".env";
  const metadataFilePath = ".env.encrypt";

  try {
    if (action === "encrypt") {
      let keyData;
      if (!fs.existsSync(keyPath)) {
        const validationToken = generateValidationToken();
        const key = crypto.randomBytes(32).toString("hex");
        keyData = { key, validation_token: validationToken };
        saveKey(keyData, keyPath);
      } else {
        keyData = loadKey(keyPath);
      }

      encryptFile(envFilePath, keyData.key);
      updateMetadata(keyPath, false);
      console.log("File encrypted and metadata saved.");
    } else if (action === "decrypt") {
      const keyData = loadKey(keyPath);
      const metadata = JSON.parse(fs.readFileSync(metadataFilePath, "utf8"));
      validateKey(keyData, metadata);

      decryptFile(envFilePath, keyData.key);
      console.log("File decrypted.");
    } else if (action === "rotate") {
      const newKey = crypto.randomBytes(32).toString("hex");
      const validationToken = generateValidationToken();
      const keyData = { key: newKey, validation_token: validationToken };
      saveKey(keyData, keyPath);
      encryptFile(envFilePath, newKey);
      updateMetadata(keyPath, true);
      console.log(
        "Encryption key rotated, file re-encrypted, and metadata updated."
      );
    }
  } catch (error) {
    console.error(error.message);
  }
}

main();
