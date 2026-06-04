# html-slides

A GitHub Pages portal for Louise's HTML slide decks.

## Structure

- `index.html` - slide portal homepage
- `slides.json` - metadata for cards, categories, and search
- `slides/` - HTML slide files
- `assets/luohanguo/` - shared image assets for editable decks

## Add a new slide

1. Add the HTML file into `slides/`
2. If it uses local assets, place them under `assets/` and update paths
3. Add one item into `slides.json`
4. Commit and push

## Type grouping & New badge

- The homepage groups decks into product/direction **types** via each item's `category`
  field. Use one of: `GitHub Copilot`, `Azure`, `AI Product & Practice`.
  The single "Filter by type" dropdown and the on-page sections both come from this field.
- Decks are sorted by `updated` (newest first), both within a type and across types.
- A `New` badge is shown automatically when `updated` is within the last 14 days; it
  disappears on its own afterwards (no manual flag needed).
