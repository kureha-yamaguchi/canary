FROM node:22-bullseye

RUN apt-get update && apt-get install -y curl git python3 ca-certificates \
  && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://claude.ai/install.sh | bash
ENV PATH="/root/.local/bin:${PATH}"

WORKDIR /site
# COPY site/ /site/

# RUN npm install  # or pnpm install, etc.

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 3000
ENTRYPOINT ["/entrypoint.sh"]
