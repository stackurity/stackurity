### Changed

- **AI providers' keys in a server's configuration file are medium, not low.** An OpenAI, Anthropic, Gemini, OpenRouter, Groq, xAI or Hugging Face key, or a setting named for Mistral, DeepSeek, Cohere, LiteLLM and other AI providers, found in a `.env` or other configuration file on a server is now graded medium: a stolen AI key is resold and runs up the provider's bill within hours. It still raises no alert (the file is where keys belong), but it gets a rotate-by date (30 days by default) and its own one-line reason on the dashboard, the API and MCP. Other keys and passwords kept in configuration files stay low (medium when every account can read the file). See [Leaked keys](docs/leaked-keys.md#severity-and-exposure).

### Upgrading

- The agent grades leaks, so existing AI keys move from low to medium on each server's first scan after its agent is upgraded. No migration.
