// WARNING: This file is a TEST FIXTURE for security-audit scanner validation.
// It contains intentionally fake secrets that match real vendor formats.
// DO NOT use any values from this file. They are not real credentials.

const config = {
  // Critical: AWS Access Key ID (matches AKIA + base32 format)
  aws: {
    accessKeyId: "AKIAIOSFODNN7EXAMPLE",
    secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    region: "us-east-1"
  },

  // High: GitHub PAT (matches ghp_ + 36 chars)
  github: {
    token: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234"
  },

  // High: Slack Bot Token (matches xoxb- + numeric segments)
  slack: {
    botToken: "xoxb-0000000000000-0000000000000-fakefakefakefake"
  },

  // High: Database connection string with credentials
  database: {
    url: "postgres://admin:SuperSecret123@prod-db.example.com:5432/myapp"
  },

  // High: Generic password assignment
  smtp: {
    password: "SmtpP@ssw0rd!2026"
  },

  // Critical: Stripe test secret key (uses sk_test_ to avoid GitHub push protection)
  stripe: {
    secretKey: "sk_test_fakefakefakefakefakefake"
  }
};

  // Medium: Hex-encoded HMAC key (entropy detection — hex charset threshold)
  hmac: {
    secret: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4"
  }
};

module.exports = config;
