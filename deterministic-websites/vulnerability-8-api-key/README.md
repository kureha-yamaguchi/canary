# Honeypot Website - def/acc Hackathon

This is a **honeypot website** that exposes security vulnerabilities to detect and log attack attempts. It serves as both a public-facing hackathon event website and a security research tool.

## Honeypot Vulnerabilities

This honeypot exposes **Vulnerability ID 8: "Sensitive Data Exposure - Client Side"** in three different ways:

1. **JavaScript Code Exposure** - API key visible in client-side JavaScript
2. **HTML Data Attributes** - API key stored in HTML data attributes
3. **Server-Side Rendered HTML** - API key embedded in server-rendered React props

📖 **See [docs/vulnerability-mapping.txt](docs/vulnerability-mapping.txt) for complete vulnerability mapping and MITRE ATT&CK technique details.**

## Getting Started

First, run the development server:

```bash
npm run dev
# or
yarn dev
# or
pnpm dev
# or
bun dev
```

Open [http://localhost:3000](http://localhost:3000) with your browser to see the result.

You can start editing the page by modifying `app/page.tsx`. The page auto-updates as you edit the file.

This project uses [`next/font`](https://nextjs.org/docs/app/building-your-application/optimizing/fonts) to automatically optimize and load [Geist](https://vercel.com/font), a new font family for Vercel.

## Learn More

To learn more about Next.js, take a look at the following resources:

- [Next.js Documentation](https://nextjs.org/docs) - learn about Next.js features and API.
- [Learn Next.js](https://nextjs.org/learn) - an interactive Next.js tutorial.

You can check out [the Next.js GitHub repository](https://github.com/vercel/next.js) - your feedback and contributions are welcome!

## Deploy on Vercel

The easiest way to deploy your Next.js app is to use the [Vercel Platform](https://vercel.com/new?utm_medium=default-template&filter=next.js&utm_source=create-next-app&utm_campaign=create-next-app-readme) from the creators of Next.js.

Check out our [Next.js deployment documentation](https://nextjs.org/docs/app/building-your-application/deploying) for more details.
