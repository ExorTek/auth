# web

Documentation site for [`@exortek/auth`](https://github.com/ExorTek/auth),
served at [auth.memet.dev](https://auth.memet.dev).

Built with **Next.js 16** and **Nextra 4** (App Router). Content lives in
`content/` as MDX; the sidebar order comes from `_meta.js` files next to
the content.

## Develop

```bash
yarn install          # from the repo root, once
yarn web:dev          # http://localhost:3000
```

Content edits hot-reload; layout / component edits require a page refresh.

## Build

```bash
yarn web:build
yarn workspace web start
```

The build script chains `next build` with `pagefind` so the search
index is regenerated on every deploy. `public/_pagefind/` is a build
artifact — git-ignored and rebuilt from the shipped HTML each time.

## Layout

```
web/
├── app/
│   ├── layout.jsx              # root layout — wires <Layout> from Nextra
│   ├── not-found.jsx           # 404 page
│   └── [[...mdxPath]]/page.jsx # catch-all: renders MDX via nextra/pages
├── content/
│   ├── index.mdx               # /
│   ├── _meta.js                # top-level sidebar order
│   └── crypto/
│       ├── index.mdx           # /crypto
│       ├── random.mdx          # /crypto/random
│       ├── hash.mdx            # /crypto/hash
│       ├── cipher.mdx          # /crypto/cipher
│       ├── sign.mdx            # /crypto/sign
│       ├── encode.mdx          # /crypto/encode
│       ├── binary.mdx          # /crypto/binary
│       ├── errors.mdx          # /crypto/errors
│       └── _meta.js            # /crypto sidebar order
├── mdx-components.jsx          # global MDX component registry
└── next.config.mjs             # Nextra config — Shiki theme pair etc.
```

## Nextra patch

`nextra-theme-docs@4.6.1` has a `LayoutPropsSchema.children` validation
bug ([issue #5008](https://github.com/shuding/nextra/issues/5008), fix
merged in [PR #4990](https://github.com/shuding/nextra/pull/4990)). Until
that fix ships in `4.6.2+`, the local patch at
`.yarn/patches/nextra-theme-docs-npm-4.6.1-*.patch` marks the schema's
`children` field optional. Yarn applies it automatically on `yarn install`.

Remove the patch and the `nextra-theme-docs` entry from `web/package.json`
once the upstream release lands.

## Editing content

- MDX files render as pages at the path implied by their location.
- Sidebar order and labels come from `_meta.js` in the same directory.
- Custom components go in `mdx-components.jsx` and become globally
  available inside MDX.
- Nextra components (`Callout`, `Tabs`, `Steps`, `Cards`, `FileTree`)
  are imported directly from `nextra/components`.

## Deployment

Hosted on Vercel — deploys on push to `master`. Domain configured at the
Vercel project level, not in this repo.
