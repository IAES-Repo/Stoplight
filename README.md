# Infrastructure Diagram Web App

An interactive, data‑driven infrastructure / services overview built with React + TypeScript + Vite.

Features

- Responsive grid of hosts (cards) with their services.
- Color‑coded service categories (Infrastructure, Ingestion, Processing, Handling, Docker).
- Click a host or an individual service to open a slide‑in details drawer.
- Category filter chips to focus on specific service types.
- Accessible (keyboard focus on host cards, Enter activates; semantic roles; focus styles).
- Modern dark UI with CSS variables and easy theming.

Project Structure (key parts)

- `src/App.tsx` Main UI, sample data, drawer logic.
- `src/App.css` Component & layout styles/theme tokens.
- `.github/copilot-instructions.md` Guidance for AI code suggestions.

Getting Started

```bash
npm install
npm run dev
```

Visit the printed local URL (usually <http://localhost:5173>).

Customizing Data

Replace the `hosts` array in `src/App.tsx` with real infrastructure data. Suggested model:

```ts
interface Service { id: string; name: string; port?: string; category: Category; description?: string }
interface HostNode { id: string; name: string; ip: string; services: Service[]; notes?: string }
```

You can externalize this to `src/data/diagram.ts` and import it.

Adding Links / Relationships

A future enhancement could include a lightweight edge list:

```ts
interface Link { fromServiceId: string; toServiceId: string; label?: string }
```

Then render SVG arrows behind the cards using their DOM positions.

Theming

Adjust CSS variables at the top of `src/App.css`. Add a light theme by toggling a class on `body` and overriding the tokens.

Build & Preview

```bash
npm run build
npm run preview
```

License

Internal / proprietary (update as appropriate).
