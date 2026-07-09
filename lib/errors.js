class SonicCliError extends Error {}

class SonicApiError extends SonicCliError {}

class OAuthLoginError extends SonicCliError {}

module.exports = {
  OAuthLoginError,
  SonicApiError,
  SonicCliError,
};
