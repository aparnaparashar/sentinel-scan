# Netra - Agentless Windows Vulnerability Scanner 

( Demo Video - https://drive.google.com/file/d/1xyhDyXzM-5FtZM3h2M_qsIBy2MBVL-6N/view?usp=drive_link )

## Overview

Netra is a front-end for an agentless Windows vulnerability assessment toolkit. This repository contains the UI built with Vite + React + Tailwind and a set of embedded PowerShell scan scripts (light & deep) shown in the app.


## Quick start

Prerequisites
- Node.js (recommended LTS, 18+)
- npm

Install and run the dev server:

```bash
npm install
npm run dev
```

Open http://localhost:8080/ in your browser.

Build for production:

```bash
npm run build
```

Preview the build:

```bash
npm run preview
```

## Important files

- `index.html` - HTML entry and metadata
- `src/main.tsx` - React entry (project expects a `src` folder)
- `src/pages/Index.tsx` - Home / hero page
- `src/components/Navbar.tsx` - Navigation (Home, Architecture, Scan, Report)
- `vite.config.ts` - Vite configuration (lovable-tagger removed)
- `package.json` - scripts and dependencies

## Scripts and filenames

- Exported scan filenames shown in the UI: `Netra-Light.ps1`, `Netra-Deep.ps1`.
- When copying/downloading from the UI, those filenames will be used.

## License & responsibility

This repository contains scripts that are intended for authorized security assessment only. Use only on systems you own or are explicitly authorized to test.

