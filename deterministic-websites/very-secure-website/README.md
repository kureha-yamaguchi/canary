Not so much a vulnerability, but this will report any "active scanning", i.e. when an attacker is looking for resources that may be exposed on a site that shouldn't be, or which might offer an entrypoint for an attack. It simply reports any request that goes to a route that isn't the homepage (`/`) of the app. This is more of a baseline of how many attacks are being attempted rather than checking a success rate.

To run, add the following to `.env.local`:

```
# Get from the supabase console
NEXT_PUBLIC_SUPABASE_URL=""
SUPABASE_SERVICE_KEY=""
```

Then:

```
pnpm dev
```

To apply this vulnerability to other websites, you can just copy the `proxy.ts` file into the site. This will record every request that goes to any route other than the homepage. You can optionally add the `[...slug]/route.ts` to return a success to the caller, but it's not required (they'll get a 404, but we'll still record the attempt).
