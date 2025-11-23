Create your `.env`:

```sh
# Get from WhatsApp chat
OPENROUTER_API_KEY=
# Model to use for browsing https://openrouter.ai/models
MODEL=openai/gpt-4o-mini
# URL of the website to browse
TARGET_URL=https://honeypot-nine.vercel.app
```

Single instance:

```sh
docker build -t benign-user .
docker run --env-file .env benign-user
# Override the env file
docker run --env-file .env benign-user --url "https://neuralmarket.vercel.app"
```

Or deploy your army of benign minions:

```sh
docker-compose build && docker-compose up --scale benign-user=10
```
