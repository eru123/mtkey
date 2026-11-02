# MTKey 2.0 — Design Specification

Target stack: Tauri 2, Vite 8, React 19, TypeScript, Tailwind CSS v4, shadcn/ui.
Platforms: macOS, Windows, Linux — pixel-identical.
This document is the single source of truth for the UI. Every value an implementer needs is here. Where a decision was required, one recommendation is made and it is final.

---

## 1. Design concept & principles

### Concept: "The Instrument"

MTKey looks like a piece of bench lab equipment, not a web dashboard. Three ideas carry it:

- **Chassis.** A matte graphite shell divided into panels by 1px hairlines. No drop shadows inside the window, no gradients, no glass. Panels are engraved with small uppercase labels (`INPUT`, `OUTPUT`, `PARAMETERS`) the way instruments silkscreen their faceplates.
- **Signal path.** Data flows downhill: input at the top, parameters in the middle, output at the bottom. You read the workbench the way you read a signal chain. The accent color is the instrument's trace color — the one saturated hue on the chassis, reserved for live signal: focus, selection, links, active state.
- **Lamps.** Instruments tell the truth with lamps. Every state is visible somewhere: a computing shimmer, an amber warning lamp, a green "key pair verified" lamp, a red error lamp, a self-test pill in the status bar. Nothing succeeds or fails silently.

The status bar along the bottom (slug id, operation state, self-test pill) is the identity signature of the app — small, terminal-like, always on.

### Five principles

1. **Instrument, not dashboard.** Calm matte chassis, hairline borders, one accent. No marketing surfaces inside the window.
2. **Signal flows downhill.** Input → parameters → output, top to bottom, one column. Direction is always an explicit segmented control; the app teaches one-way functions by showing a single locked "Hash" position.
3. **Density with air.** 32px controls (28px in dense zones), 12px layout rhythm, compact type. Density comes from consistency, not from cramming.
4. **Learning is one click away and invisible by default.** The Learn dock is closed until asked for. It never covers the output.
5. **Nothing hides its state.** Computing, error, warning, verified, truncated — each has a visible, named presentation. No spinners where a sentence belongs.

---

## 2. Layout

### Zone map

```
┌────────────────────────────────────────────────────────────────────┐
│                          native titlebar                            │
├───────────────┬────────────────────────────────────────────────────┤
│  METHOD RAIL  │                    WORKBENCH                       │
│   200px       │                    flex-1 (min 380px)              │
│  (48px when   │                                                    │
│  collapsed)   │                                                    │
├───────────────┴────────────────────────────────────────────────────┤
│  STATUS BAR — 24px, full width                                     │
└────────────────────────────────────────────────────────────────────┘
Learn dock: 320px, pushes as a third column between workbench and window edge.
```

- **Method rail** (left): wordmark, filter input, 6 category groups with their methods, footer (collapse, settings, version). Scrolls independently.
- **Workbench** (center): method header → parameter card → input card → output card, stacked vertically in one scrollable column. The output card grows to fill leftover height; everything above it is content-sized.
- **Learn dock** (right): contextual explainer. Pushes content (it is a flex sibling, not an overlay), so input and output stay fully visible while reading.
- **Status bar** (bottom, fixed): method slug, operation state, self-test pill, theme toggle.

### (a) Main window — default 960 × 640

```
┌──────────────────────────────────────────────────────────────────────┐
│  MTKey — Base64                                     ◇   □   ✕       │  native
├────────────┬─────────────────────────────────────────────────────────┤
│ MTKEY      │ ┌ METHOD HEADER ────────────────────────────────────┐  │
│ ⌕ filter…  │ │ [braces] Base64        Blurb text, one line, tru… │  │
│            │ │                          [Encode │ Decode] [Learn]↗│  │  48px
│ ENCODING 7 │ └────────────────────────────────────────────────────┘  │
│ ▸Base64  ◂ │ ┌ PARAMETERS ────────────────────────────────────── ┐  │
│  Base32    │ │ (varies per method; empty card hidden)            │  │
│  Base58    │ └───────────────────────────────────────────────────┘  │
│  Hex       │ ┌ INPUT ──────────────────────────────────────────┐ ⮅ │
│  URL       │ │                                                  │  │
│  Binary    │ │  mono textarea, min-height 96px, grows           │  │
│  Morse     │ │                                                  │  │
│ CLASSICAL 7│ └──────────────────────────────────────────────────┘   │
│  Caesar    │ ┌ OUTPUT ──────────────────────────────── [⧉ Copy] ┐  │
│  ROT13     │ │ ⬤ note: RSA-2048 with OAEP/SHA-256   128 chars    │  │
│  …         │ │ ▲ warning: ECB is here for learning why it is…    │  │
│            │ │                                                  │  │
│ HASH 12    │ │  mono, readonly, fills remaining height,           │  │
│  …         │ │  scrolls internally                               │  │
│ MODERN 7   │ │                                                  │  │
│  …         │ └───────────────────────────────────────────────────┘  │
│ DEFUSE 4   │                                                         │
│ TOKENS 2   │                                                         │
├────────────┴─────────────────────────────────────────────────────────┤
│ ● aes-256-gcm   ● Ready (2 ms)            ● 38/38 self-test   ☾     │  24px
└──────────────────────────────────────────────────────────────────────┘
      ↑ 200px                ↑ 760px (flex)
```

Measurements at 960px: rail 200, workbench 760, status bar 24. Method header 48px tall. Parameter card padding 12. Input/output cards padding 12, internal gap 8. Swap button (⮅, `ArrowUpDown`) sits in the gap between input and output cards, right-aligned, 28×28 ghost button.

### (b) Minimum window — 780 × 540

Below 840px viewport width the rail auto-collapses to a 48px icon column (categories as icon buttons with method flyout on click; user can also toggle manually with Ctrl/Cmd+B at any size). Everything else is unchanged — the single-column workbench is width-immune.

```
┌──────────────────────────────────────────────────────────────────────┐
│  MTKey — AES-256-GCM                                 ◇   □   ✕      │
├────┬─────────────────────────────────────────────────────────────────┤
│ ⌕  │ ┌ METHOD HEADER ────────────────────────────────────────── ┐  │
│    │ │ [lock-keyhole] AES-256-…  Blurb, truncated har…          │  │
│ {} │ │                        [Encrypt │ Decrypt] [Learn] ↗     │  │
│    │ └──────────────────────────────────────────────────────────┘  │
│ ≡  │ ┌ PARAMETERS ─────────────────────────────────────────────┐  │
│    │ │ Key (secret) [🎲]        IV  [🎲]      [16 ▾] [32 ▾]…    │  │
│ ﬁ  │ └──────────────────────────────────────────────────────────┘  │
│    │ ┌ INPUT ────────────────────────────────────────────────┐ ⮅  │
│ 🔒 │ │  mono textarea, min-height 72px at min size            │   │
│    │ └────────────────────────────────────────────────────────┘   │
│ ⚡  │ ┌ OUTPUT ───────────────────────────────────── [⧉ Copy] ┐   │
│ 🎟 │ │  mono, readonly, internal scroll                        │   │
│    │ └─────────────────────────────────────────────────────────┘   │
├────┴─────────────────────────────────────────────────────────────────┤
│ ● aes-256-gcm   ● Computing…             ● 38/38 self-test    ☾     │
└──────────────────────────────────────────────────────────────────────┘
  ↑ 48px         ↑ 732px
```

(Emoji above only stand in for lucide icons in this wireframe — the real UI uses lucide icons exclusively.)

At minimum size: input min-height drops 96 → 72px, blurb truncates earlier, parameter grid drops 2 → 1 column below 560px workbench width. Nothing is removed.

### (c) Learn dock open — pushed layout

Rule: when the dock is open and viewport width < 960px, the rail force-collapses to 48px. Workbench floor is 380px; at 780px minimum with dock open: 48 + 412 + 320 = 780.

```
┌──────────────────────────────────────────────────────────────────────┐
│  MTKey — Vigenère                                     ◇   □   ✕     │
├────────────┬───────────────────────────────────┬─────────────────────┤
│ MTKEY      │ ┌ METHOD HEADER ────────────────┐ │ LEARN          [✕] │
│ ⌕ filter…  │ │ [scroll] Vigenère   [E│D][L]↗ │ │                    │
│            │ └────────────────────────────────┘ │ Vigenère           │
│ ENCODING 7 │ ┌ PARAMETERS ───────────────────┐  │ ─────────────      │
│  Base64    │ │ Key (secret) [🎲]             │  │ Paragraph one,     │
│  …         │ └────────────────────────────────┘ │ 13px/1.6 body.     │
│ CLASSICAL 7│ ┌ INPUT ──────────────────────┐ ⮅ │                    │
│ ▸Vigenère◂ │ │ …                            │  │ Paragraph two.     │
│  …         │ └───────────────────────────────┘  │                    │
│ …          │ ┌ OUTPUT ──────────── [⧉ Copy] ┐  │ [Read on           │
│            │ │ …                              │ │  Wikipedia ↗]      │
│            │ └────────────────────────────────┘ │                    │
├────────────┴───────────────────────────────────┴─────────────────────┤
│ ● vigenere   ● Ready (1 ms)               ● 38/38 self-test    ☾     │
└──────────────────────────────────────────────────────────────────────┘
  ↑ 200px (at 960+)        ↑ flex, ≥380px           ↑ 320px
```

Dock internals: title row 32px (title + close), body 13px/1.6 with 12px paragraph gap, footer link button. The dock has a 1px hairline on its left edge only. It opens with a 200ms slide-in and closes with 200ms slide-out (disabled under reduced motion).

---

## 3. Design tokens

### Rules for implementers

- All colors are OKLCH CSS variables defined once in `src/styles/globals.css`. Components use Tailwind/shadcn classes only (`bg-background`, `text-muted-foreground`, `border-border`…). **No hex, no raw oklch, no alpha suffixes in component code.** Soft semantic surfaces are pre-baked tokens (they already contain the alpha).
- Fonts are bundled (offline app, identical rendering on all three OSes): **Inter Variable** (UI) and **JetBrains Mono Variable** (crypto data). No system font stack.

### globals.css — base theme (dark, default)

```css
@import "tailwindcss";
@import "tw-animate-css";

:root {
  /* chassis — graphite */
  --background:            oklch(0.17 0.006 260);
  --foreground:            oklch(0.93 0.004 260);
  --card:                  oklch(0.20 0.006 260);
  --card-foreground:       oklch(0.93 0.004 260);
  --popover:               oklch(0.21 0.006 260);
  --popover-foreground:    oklch(0.93 0.004 260);
  --secondary:             oklch(0.25 0.007 260);
  --secondary-foreground:  oklch(0.90 0.004 260);
  --muted:                 oklch(0.24 0.006 260);
  --muted-foreground:      oklch(0.68 0.010 260);
  --accent:                oklch(0.27 0.008 260);   /* hover surface, NOT the brand accent */
  --accent-foreground:     oklch(0.93 0.004 260);
  --border:                oklch(0.29 0.007 260);
  --input:                 oklch(0.31 0.008 260);
  --ring:                  oklch(0.80 0.130 185);   /* trace cyan = --primary */

  /* trace — the single brand accent */
  --primary:               oklch(0.80 0.130 185);
  --primary-foreground:    oklch(0.18 0.030 185);

  /* lamps — semantic */
  --destructive:           oklch(0.70 0.190 25);
  --destructive-foreground:oklch(0.985 0 0);
  --destructive-solid:     oklch(0.55 0.200 26);    /* solid fills only */
  --destructive-solid-foreground: oklch(0.985 0 0);
  --destructive-soft:      oklch(0.70 0.190 25 / 0.10);
  --destructive-soft-foreground: oklch(0.75 0.160 25);

  --warning:               oklch(0.76 0.150 78);    /* amber lamp */
  --warning-foreground:    oklch(0.24 0.050 78);
  --warning-soft:          oklch(0.76 0.150 78 / 0.10);
  --warning-soft-foreground: oklch(0.85 0.120 82);

  --success:               oklch(0.72 0.150 155);
  --success-foreground:    oklch(0.20 0.040 155);
  --success-soft:          oklch(0.72 0.150 155 / 0.10);
  --success-soft-foreground: oklch(0.80 0.130 155);

  /* overlays */
  --overlay-shadow:        0 8px 24px oklch(0 0 0 / 0.35);
  --scrim:                 oklch(0 0 0 / 0.45);

  /* shape */
  --radius:                0.5rem;                  /* 8px — see radius table */

  /* sidebar aliases (rail), keeps shadcn sidebar primitive usable */
  --sidebar:                var(--background);
  --sidebar-foreground:     var(--foreground);
  --sidebar-primary:        var(--primary);
  --sidebar-primary-foreground: var(--primary-foreground);
  --sidebar-accent:         var(--accent);
  --sidebar-accent-foreground: var(--accent-foreground);
  --sidebar-border:         var(--border);
  --sidebar-ring:           var(--ring);
}

.light {
  /* chassis — paper lab notebook */
  --background:            oklch(0.977 0.002 260);
  --foreground:            oklch(0.22 0.010 260);
  --card:                  oklch(1.000 0 0);
  --card-foreground:       oklch(0.22 0.010 260);
  --popover:               oklch(1.000 0 0);
  --popover-foreground:    oklch(0.22 0.010 260);
  --secondary:             oklch(0.945 0.004 260);
  --secondary-foreground:  oklch(0.25 0.010 260);
  --muted:                 oklch(0.955 0.003 260);
  --muted-foreground:      oklch(0.470 0.015 260);
  --accent:                oklch(0.930 0.008 240);
  --accent-foreground:     oklch(0.22 0.010 260);
  --border:                oklch(0.895 0.005 260);
  --input:                 oklch(0.880 0.006 260);
  --ring:                  oklch(0.500 0.100 195);

  --primary:               oklch(0.500 0.100 195);
  --primary-foreground:    oklch(0.985 0 0);

  --destructive:           oklch(0.500 0.190 26);
  --destructive-foreground:oklch(0.985 0 0);
  --destructive-solid:     oklch(0.500 0.190 26);
  --destructive-solid-foreground: oklch(0.985 0 0);
  --destructive-soft:      oklch(0.500 0.190 26 / 0.07);
  --destructive-soft-foreground: oklch(0.480 0.170 26);

  --warning:               oklch(0.760 0.150 78);
  --warning-foreground:    oklch(0.240 0.050 78);
  --warning-soft:          oklch(0.760 0.150 78 / 0.12);
  --warning-soft-foreground: oklch(0.420 0.100 70);

  --success:               oklch(0.720 0.150 155);
  --success-foreground:    oklch(0.200 0.040 155);
  --success-soft:          oklch(0.720 0.150 155 / 0.12);
  --success-soft-foreground: oklch(0.400 0.110 155);

  --overlay-shadow:        0 8px 24px oklch(0 0 0 / 0.12);
  --scrim:                 oklch(0 0 0 / 0.30);

  --sidebar:                var(--background);
  --sidebar-foreground:     var(--foreground);
  --sidebar-primary:        var(--primary);
  --sidebar-primary-foreground: var(--primary-foreground);
  --sidebar-accent:         var(--accent);
  --sidebar-accent-foreground: var(--accent-foreground);
  --sidebar-border:         var(--border);
  --sidebar-ring:           var(--ring);
}
```

Dark is default: `<html class="dark">` ships; theme switch swaps `dark` ⇄ `light` (persisted via Tauri store; a "System" option follows `prefers-color-scheme`).

### Accent rationale

The accent is a **trace cyan-teal** — oklch(0.80 0.13 185) dark / oklch(0.50 0.10 195) light. It is the color of a VFD/oscilloscope trace on a dark instrument, which is the concept; it is not the hacker-green cliché; and it is spectrally far from both the amber warning lamp and the red error lamp, so signal / caution / failure never collide. It appears only on: focus ring, selected method indicator, direction toggle active segment, links, primary buttons, and the output caret/highlight. Nowhere else.

### @theme inline mapping (Tailwind v4)

```css
@theme inline {
  --color-background: var(--background);
  --color-foreground: var(--foreground);
  --color-card: var(--card);
  --color-card-foreground: var(--card-foreground);
  --color-popover: var(--popover);
  --color-popover-foreground: var(--popover-foreground);
  --color-primary: var(--primary);
  --color-primary-foreground: var(--primary-foreground);
  --color-secondary: var(--secondary);
  --color-secondary-foreground: var(--secondary-foreground);
  --color-muted: var(--muted);
  --color-muted-foreground: var(--muted-foreground);
  --color-accent: var(--accent);
  --color-accent-foreground: var(--accent-foreground);
  --color-destructive: var(--destructive);
  --color-destructive-foreground: var(--destructive-foreground);
  --color-destructive-solid: var(--destructive-solid);
  --color-destructive-solid-foreground: var(--destructive-solid-foreground);
  --color-destructive-soft: var(--destructive-soft);
  --color-destructive-soft-foreground: var(--destructive-soft-foreground);
  --color-warning: var(--warning);
  --color-warning-foreground: var(--warning-foreground);
  --color-warning-soft: var(--warning-soft);
  --color-warning-soft-foreground: var(--warning-soft-foreground);
  --color-success: var(--success);
  --color-success-foreground: var(--success-foreground);
  --color-success-soft: var(--success-soft);
  --color-success-soft-foreground: var(--success-soft-foreground);
  --color-border: var(--border);
  --color-input: var(--input);
  --color-ring: var(--ring);
  --color-scrim: var(--scrim);
  --color-sidebar: var(--sidebar);
  --color-sidebar-foreground: var(--sidebar-foreground);
  --color-sidebar-primary: var(--sidebar-primary);
  --color-sidebar-primary-foreground: var(--sidebar-primary-foreground);
  --color-sidebar-accent: var(--sidebar-accent);
  --color-sidebar-accent-foreground: var(--sidebar-accent-foreground);
  --color-sidebar-border: var(--sidebar-border);
  --color-sidebar-ring: var(--sidebar-ring);

  --font-sans: "Inter Variable", "Inter", sans-serif;
  --font-mono: "JetBrains Mono Variable", "JetBrains Mono", monospace;

  /* compact type scale (overrides Tailwind defaults) */
  --text-2xs:            0.625rem;   /* 10px  */
  --text-2xs--line-height: 1.3;
  --text-xs:             0.6875rem;  /* 11px  */
  --text-xs--line-height: 1.35;
  --text-sm:             0.75rem;    /* 12px  */
  --text-sm--line-height: 1.45;
  --text-base:           0.8125rem;  /* 13px  — UI base */
  --text-base--line-height: 1.5;
  --text-lg:             0.875rem;   /* 14px  */
  --text-lg--line-height: 1.5;
  --text-xl:             0.9375rem;  /* 15px  — headings */
  --text-xl--line-height: 1.35;
  --text-2xl:            1.125rem;   /* 18px  — learn dock H1 only */
  --text-2xl--line-height: 1.3;

  --radius-sm: calc(var(--radius) - 4px);   /* 4px  badges, kbd, lamps    */
  --radius-md: calc(var(--radius) - 2px);   /* 6px  inputs, buttons, tabs */
  --radius-lg: var(--radius);               /* 8px  cards, dock, dialogs  */
  --radius-xl: calc(var(--radius) + 4px);   /* 12px command palette       */

  --shadow-overlay: var(--overlay-shadow);
}

@utility text-mono {
  font-family: var(--font-mono);
  font-size: 0.78125rem;      /* 12.5px */
  line-height: 1.65;
}
```

### Type scale (exact)

| Token | px | rem | Line | Weight | Used for |
|---|---|---|---|---|---|
| text-2xl | 18 | 1.125 | 1.3 | 600 | Learn dock article title |
| text-xl | 15 | 0.9375 | 1.35 | 600 | Workbench method name, dialog titles |
| text-lg | 14 | 0.875 | 1.5 | 400/500 | Dialog body, emphasized rows |
| text-base | 13 | 0.8125 | 1.5 | 400 | **UI base** — body, buttons, rail items, inputs |
| text-sm | 12 | 0.75 | 1.45 | 400 | Blurbs, hints, secondary text |
| text-xs | 11 | 0.6875 | 1.35 | 500 | Engraved labels (uppercase, `tracking-wide` 0.06em), badges, status bar |
| text-2xs | 10 | 0.625 | 1.3 | 500 | Kbd, meta counts only |
| text-mono | 12.5 | 0.78125 | 1.65 | 400 | **All** crypto input, output, keys, slugs, JWT/JWKS, self-test vectors |

Engraved panel labels (`INPUT`, `OUTPUT`, `PARAMETERS`, category names): `text-xs`, uppercase, `letter-spacing: 0.06em`, `text-muted-foreground`, weight 500.

### Radius, borders, spacing

| Token / rule | Value | Used for |
|---|---|---|
| radius-sm | 4px | Badges, kbd, state dots, segmented indicator |
| radius-md | 6px | Buttons, inputs, textareas, selects, tabs |
| radius-lg | 8px | Cards, learn dock, dialogs, popover |
| radius-xl | 12px | Command palette only |
| Border | **1px solid `--border` everywhere.** No 2px borders, no borderless floating panels | all panels |
| Focus | `outline: 2px solid var(--ring); outline-offset: 2px` on `:focus-visible` | all interactive |
| Spacing unit | 4px (`--spacing` default). Layout rhythm multiples of **12**: card padding 12, section gaps 12, column gaps 12; half-rhythm 6 for intra-card gaps; 4 for icon-to-label |
| Control heights | 32px default, 28px dense (see §4) | — |
| Shadows | `--overlay-shadow` on popover/dialog/command palette only. None inside the window | — |

---

## 4. Component inventory

All are shadcn/ui primitives with the compact overrides below. Sizes in px; heights via tokens `h-8` (32) / `h-7` (28).

| Component | shadcn primitive | Compact override | Where |
|---|---|---|---|
| Button | `button` | `h-8` (32) default, `h-7` (28) sm + all toolbar/icon use; `px-3` default, `px-2` sm; `text-base`; icon buttons `size-7` square; radius-md | Workbench actions, dialogs, Learn button |
| IconButton | `button` variant=ghost size=icon | `size-7` (28×28); copy, dice, reveal, swap, collapse, theme | Field headers, toolbars |
| Input | `input` | `h-8`, `px-2.5`, `text-base`, radius-md; `font-mono text-mono` variant for key/hex/value fields | Parameter fields |
| SecretInput | `input` type=password + Eye/EyeOff icon slot + dice slot | same 32px; masked dots in mono; reveal button 24px inside right padding 28px | Keys, passwords, salts (§5) |
| Textarea | `textarea` | `text-mono`; input card: min-h-24 (96px, 72px at min window), auto-grow to 40vh then internal scroll; readonly output variant: no resize, tab-size 4 | Input/output |
| Select | `select` | trigger `h-8` workbench / `h-7` dialogs; items `h-7`, `text-sm`; content radius-lg | Dropdown params (key size, hash for HMAC, byte length) |
| Tabs (direction toggle) | `tabs` | height 28; `text-sm` medium; active segment `bg-primary text-primary-foreground`; inactive `text-muted-foreground`; radius-sm indicator; 1–3 positions (JWT uses 3) | Method header |
| Tooltip | `tooltip` | `text-xs`, `px-2 py-1`, radius-sm, delay 500ms; content includes optional `Kbd` | Icon buttons, truncated blurb, aliases |
| Dialog | `dialog` | content radius-lg, max-w-md (self-test max-w-lg), `--overlay-shadow`; header `text-xl` | Self-test, shortcuts, confirm |
| CommandDialog | `command` (dialog) | radius-xl, `--overlay-shadow`, input `h-9`, items `h-8` `text-base`, group labels engraved style | Ctrl/Cmd+K palette |
| Badge | `badge` | `h-5` (20px), `text-xs` medium, `px-1.5`, radius-sm, `tabular-nums`; variants: `secondary` (category, counts), `outline` (length/size), `warning-soft` + dot, `success-soft` + dot | Output meta, rail counts |
| Card | `card` | padding 12 (`p-3`), gap 6, radius-lg, 1px border, no shadow | Parameters, input, output |
| ScrollArea | `scroll-area` | 8px scrollbar thumb `--border`, hover `--input`, radius-full, 2px margin | Rail list, workbench column, output, learn body, self-test list |
| Separator | `separator` | 1px `--border` | Card subdivisions, status bar groups |
| Label | `label` | engraved style: `text-xs` uppercase tracking-wide muted; optional right-aligned hint `text-2xs` | Field labels, panel headers |
| Switch | `switch` | `h-4 w-7` track, thumb 12px, unchecked `--input` track, checked `--primary` | Settings popover |
| Popover | `popover` | radius-lg, `--overlay-shadow`, `w-64`, content rows `h-8` | Settings menu, dice length menu |
| Alert (BenchMessage) | custom div on tokens (Alert pattern) | radius-md, 1px border, `px-3 py-2`, `text-sm`, icon 14px; variants note/warning/error/success (§5) | Output banners, field validation |
| Kbd | custom | `text-2xs` mono, `px-1`, radius-sm, 1px `--border` border, `bg-secondary` | Tooltips, palette footer, shortcuts dialog |
| Spinner | `LoaderCircle` lucide, `animate-spin`, 14px | — | Computing state, dice generation |
| EmptyState | custom | centered in output card, `text-sm text-muted-foreground`, icon 20px, optional action button | Output placeholder, palette no-match |
| FieldRow | custom wrapper | label row 18px + control 32px + optional hint row 14px; gap 4 | Parameter grid |
| ParamGrid | custom | `grid gap-3`; 2 columns ≥ 560px workbench width, else 1; PEM/multiline fields span full row | Parameters card |
| StateDot | custom | 6px circle radius-full | Status bar, badges |

Lucide icons used (complete map): `binary` is reserved for the Binary *method context only*; category icons in §8. Actions: `Search`, `Dices`, `Copy`, `Check`, `ArrowUpDown` (swap), `BookOpen` (learn), `ExternalLink` (Wikipedia), `Eye` / `EyeOff`, `Settings2`, `Sun`, `Moon`, `LoaderCircle`, `Info`, `TriangleAlert`, `CircleCheck`, `CircleX`, `FlaskConical` (self-test), `Keyboard` (shortcuts), `PanelLeftClose` / `PanelLeftOpen` (rail), `X` (close), `ChevronDown` (select), `ArrowRight` (palette enter hint).

---

## 5. Interaction spec

### Live update

- Input and parameter changes debounce **120ms**, then run async in the crypto core with a sequence token; stale results are discarded (last-write-wins, no queue).
- Heavy operations (PBKDF2 at 100k rounds, RSA sign/verify, RSA pair generation) get a **500ms** trailing debounce and show the computing state instead of freezing.
- While computing, the output header shows a `LoaderCircle` spinner + "Computing…" and the status bar center lamp reads `● Computing…`. Status bar shows last completed run's duration: `● Ready (2 ms)`.
- **Ctrl/Cmd+Enter** bypasses debounce and runs immediately.

### Direction toggle

- Two-way methods: segmented control with custom labels, defaults to the encode-side position. Switching direction swaps which textarea is logically "source" but does **not** move text; it re-runs immediately on the current input.
- One-way methods (all Hash, Defuse Legacy v1): the control renders a **single locked segment** ("Hash" / "Decrypt"), `aria-disabled`, muted styling — the app teaches that there is no un-hashing.
- Label table:

| Methods | Segments |
|---|---|
| Encoding category (7) | Encode / Decode |
| Classical category (7, incl. XOR) | Encrypt / Decrypt |
| Hash category (12) | Hash (locked) |
| AES-256-GCM, AES-CBC, AES-ECB, DES, 3DES, RSA Encrypt, Defuse Authenticated, Defuse With Password | Encrypt / Decrypt |
| RSA Signature | Sign / Verify |
| Defuse Key Tool | Wrap / Unlock |
| Defuse Legacy v1 | Decrypt (locked) |
| JWT | Decode / Sign / Verify (three positions) |
| JWKS | Build / Inspect |

### Dice buttons

- `Dices` ghost icon button (24px) inside the field's right slot. Click generates material **into that field only**, replacing content, and triggers a normal re-run.
- Fields with a length choice (hex key, IV, salt, base64 bytes) show a small caret: the button opens a 24px popover menu (`16 B`, `32 B`, `64 B`), default 32 B, remembered per field.
- Password dice: 20-char alphanumeric (unambiguous set), always secret-masked.
- Defuse key dice: generates a valid encoding key with correct checksum; field immediately validates green.
- **RSA pair dice** (either key field on RSA methods): both key fields enter loading together — disabled, `LoaderCircle` overlay, status bar `● Generating RSA-2048 pair…`; ~0.2–1.5s. On completion both fields fill, a success BenchMessage appears under them ("Key pair generated and verified"), and the pair passes live validation. Key-size popover: 1024 / 2048 (default) / 4096.

### Secret fields

- Rendered as password-type inputs in mono; masked dots. `Eye`/`EyeOff` 24px toggle in the right slot (before the dice button when both exist). Reveal state is per-field and resets to masked on method switch and on dice regeneration.
- Secrets are never echoed in the output, status bar, self-test, or learn content.

### Copy feedback

- Copy button (`Copy` → output; also Ctrl/Cmd+Shift+C): icon and label swap to `Check` "Copied" in `--success`-foreground for **1200ms**, then revert. Status bar: `● Copied to clipboard`. Copies the **full** value even when display is truncated. No toast system exists in the app — all feedback is inline.

### Swap button

- Two-way methods only: `ArrowUpDown` 28px ghost button in the gap between input and output cards, right-aligned. Click moves the output text into the input, clears the output, **flips the direction segment** (Encode↔Decrypt etc.), and re-runs. Parameters are untouched. One-way methods hide the button entirely.

### Errors, notes, warnings

Presented as a **BenchMessage** banner strip inside the output card, above the output text. All are full user-friendly sentences from the crypto core — the UI never shows raw exception text or codes.

- **note** (neutral): `bg-muted`, muted foreground, `Info` icon. Example: "RSA-2048 with OAEP/SHA-256".
- **warning** (amber): `bg-warning-soft`, `text-warning-soft-foreground`, `TriangleAlert` icon in `--warning`, 1px left border 2px in `--warning`. Example: "ECB is here for learning why it is dangerous."
- **error** (red): replaces the output content area; `bg-destructive-soft`, `text-destructive-soft-foreground`, `CircleX` icon in `--destructive`. Example: "Integrity check failed. Either the key/password is wrong or the ciphertext was modified."
- **success** (green, field-level only): `bg-success-soft`, `CircleCheck` icon. Example: "Key pair verified."

### Field validation (live)

- Debounced 300ms, shown as a hint line under the field: success (`--success-soft-foreground` + `CircleCheck` 12px), neutral hint (`text-muted-foreground`), or error (`--destructive-soft-foreground` + `CircleX`).
- RSA pasted pairs: "Key pair verified." / "These two keys do NOT belong to the same pair."
- Defuse keys: checksum validated — "Key checksum is valid." / "Key checksum does not match. The key was copied incompletely."
- Key-length hints while typing: "16 hex characters (8 bytes)". Validation never blocks typing or running; only the core's final error can fail a run.

### Empty states

- App start: **Base64** selected, input empty. Output card shows EmptyState: `BookOpen` icon 20px + "Type or paste something. Output appears here as you type." Input card placeholder: "Input".
- Palette with no match: "No method matches “xyz”."
- Self-test never run this session: status pill reads `● self-test: not run`; the dialog copy: "The self-test hasn't run this session. It checks 38 known-answer vectors, including PHP cross-language ones."
- Learn dock has content for every method — no empty case.

### Method switching & state persistence

**Per-method state persists in memory for the session**: each method keeps its own input, parameters, direction, and reveal flags in a store keyed by method id. Switching away and back restores everything exactly. Nothing is written to disk (privacy; whiteboard, not vault). App relaunch starts fresh with Base64 / empty input.

### Keyboard map

| Keys | Action |
|---|---|
| Ctrl/Cmd+K | Open command palette (search by name, alias, category) |
| Esc | Close topmost layer: palette → dialog → learn dock; else clear palette query |
| Ctrl/Cmd+Enter | Run now (bypass debounce) |
| Ctrl/Cmd+Shift+C | Copy output |
| Ctrl/Cmd+Shift+X | Swap (two-way methods only) |
| Ctrl/Cmd+J | Toggle learn dock |
| Ctrl/Cmd+B | Collapse / expand method rail |
| ↑ / ↓ | Move selection in rail (roving focus); in palette, move highlighted item |
| Enter | In rail/search/palette: select method |
| Home / End | First / last method in rail |
| ? (Shift+/) | Shortcuts dialog (only when focus is not in a text field) |
| Tab | DOM order: rail → method header → parameters → input → output → status bar |

Ctrl/Cmd = platform modifier (`event.metaKey || event.ctrlKey`). All shortcuts listed in the `?` dialog and in palette footer hints.

### Long outputs

- Output textarea scrolls **internally** (own ScrollArea), never grows the page. Line wrapping off (`whitespace-pre`, horizontal scroll) for ciphertext/keys; JWT/JWKS and PEM keep wrapping on.
- Display cap **512 KB**: beyond it show first 512 KB plus a note banner "Display truncated at 512 KB. Copy copies the full result." Copy always copies everything.
- Output header always shows a length badge (`text-xs`, `tabular-nums`): "1 284 chars" / "546 B" for binary-ish outputs.

---

## 6. Accessibility

- **Focus**: `:focus-visible` only, `outline: 2px solid var(--ring)` with 2px offset, never removed. Focus order follows DOM (table in §5). Dialogs and the palette trap focus; Esc restores it to the trigger.
- **Method list**: rail is `role="listbox"` with `role="group"` + `aria-labelledby` per category; items are `role="option"` with `aria-selected`. Roving `tabindex` — one item in the rail is tabbable; ↑/↓/Home/End move it; type-ahead jumps by first letter.
- **Output updates**: output region is `role="status"` `aria-live="polite"`. Announcements are throttled to 1/s and say "Output updated", "Computing", or the error sentence — never the output content itself.
- **Direction toggle**: `role="tablist"` semantics via Tabs primitive; the locked single-segment state carries `aria-disabled="true"` and a tooltip "One-way function: there is no un-hashing."
- **Contrast commitments** (WCAG AA, both themes): foreground/background ≥ 10:1; `muted-foreground` on background ≥ 4.6:1; `primary` as text/link on background ≥ 5:1; `warning-soft-foreground`, `destructive-soft-foreground`, `success-soft-foreground` on their soft surfaces ≥ 4.6:1; engraved 11px labels are muted-foreground, never lighter. Icon-only buttons always have an `aria-label` and a tooltip.
- **Reduced motion**: `@media (prefers-reduced-motion: reduce)` — dock slide, palette scale-in, and spinner replaced by a static "Computing…" text; opacity transitions cut to 0ms. No parallax, none exists anyway.
- **Screen readers**: copy button announces "Output copied to clipboard"; dice announces what it generated ("Generated 32 random bytes"); swap announces "Direction switched to Decode".

---

## 7. App identity

- **Window title**: `MTKey — {Method}` (e.g. `MTKey — Vigenère`). Default window `MTKey`. Native titlebar on all platforms; no custom decorations.
- **Window**: default 960×640, minimum 780×540, size and position remembered across launches (tauri-plugin-window-state).
- **Tagline** (shown in the palette footer and the shortcuts/about dialog): **"A quiet workbench for ciphers, hashes and tokens."**
- **Empty-state microcopy** (exact strings):
  - Output placeholder: "Type or paste something. Output appears here as you type."
  - Palette no-match: "No method matches “{query}”."
  - Self-test idle: "The self-test hasn't run this session."
  - Learn button label: "Learn". Wikipedia link label: "Read on Wikipedia".
- **Icon concept (1024×1024)**: a rounded square, corner radius 226px (22%), in the dark chassis graphite `oklch(0.17 0.006 260)`. Centered motif, engraved like an instrument faceplate: a **keyhole** (circle + descending stem, stroke ~72px, round caps) in the trace cyan `oklch(0.80 0.13 185)`, with three short horizontal **signal trace** dashes entering from the left edge and terminating at the keyhole's circle, suggesting data flowing into a lock. One 28px amber lamp dot (`--warning` amber) sits in the lower-right quadrant corner, inset 128px — the instrument's warning light. No text, no gradient, no gloss. Exports: full-bleed 1024 plus macOS padding variant.

---

## 8. The method list

Rail order is fixed (simple → complex, canonical). Groups show engraved label + count badge. Selected item: `bg-accent`, 2px `--primary` bar on the left inset edge, `text-foreground`; unselected `text-muted-foreground`, hover `bg-accent/50` → use `bg-accent` at rest on hover. Items are 28px, `text-base`, one line, ellipsized. When the rail filter is active, groups flatten into a single matched list; each result shows its category as a trailing `text-2xs` muted tag.

| # | Category (icon, lucide) | Methods in order |
|---|---|---|
| 1 | Encoding — `braces` | Base64, Base32, Base58, Hex, URL, Binary, Morse |
| 2 | Classical — `scroll` | Caesar, ROT13, Atbash, Vigenère, Rail Fence, Playfair, XOR |
| 3 | Hash — `fingerprint` | MD5, SHA-1, SHA-256, SHA-384, SHA-512, SHA-3-256, HMAC-MD5, HMAC-SHA-1, HMAC-SHA-256, HMAC-SHA-512, CRC-32, PBKDF2 |
| 4 | Modern — `lock-keyhole` | AES-256-GCM, AES-CBC, AES-ECB, DES, Triple DES, RSA Encrypt (OAEP), RSA Signature |
| 5 | Defuse PHP — `plug` | Authenticated (key), With Password, Key Tool, Legacy v1 Decrypt |
| 6 | Tokens — `ticket` | JWT, JWKS |

- **Method ids** (slugs, used by status bar, `--run`, palette): `base64`, `base32`, `base58`, `hex`, `url`, `binary`, `morse`, `caesar`, `rot13`, `atbash`, `vigenere`, `rail-fence`, `playfair`, `xor`, `md5`, `sha1`, `sha256`, `sha384`, `sha512`, `sha3-256`, `hmac-md5`, `hmac-sha1`, `hmac-sha256`, `hmac-sha512`, `crc32`, `pbkdf2`, `aes-256-gcm`, `aes-cbc`, `aes-ecb`, `des`, `3des`, `rsa-encrypt`, `rsa-signature`, `defuse-key`, `defuse-password`, `defuse-keytool`, `defuse-legacy`, `jwt`, `jwks`.
- **Selected method display**: workbench header shows the category icon in a 24px muted chip, method name (`text-xl` 600), one-line blurb (`text-sm` muted, tooltip carries the full text), the direction segmented control, the `Learn` button (`BookOpen` + label, ghost 28px), and the Wikipedia `ExternalLink` icon button (28px, opens in system browser). Status bar shows the slug in mono.
- **Aliases** are search-only (palette + rail filter); they appear as muted secondary text inside palette rows, never in the rail.

### Command palette contents (Ctrl/Cmd+K)

1. Group per category (order above), each item: name + alias (muted) + category icon 14px. Enter selects and closes.
2. Actions group (after methods): "Toggle theme", "Run self-test", "Toggle learn panel", "Collapse method rail".
3. Footer: kbd hints — `↑↓` navigate, `↵` open, `esc` close.

### Settings & self-test

Settings is a popover from the rail footer gear (`Settings2`) and contains: Theme segmented control (Light / Dark / System, `Switch`-style rows 32px), "Run self-test" (`FlaskConical`), "Keyboard shortcuts" (`Keyboard`), version line "MTKey 2.0.0".
Self-test is a dialog (`max-w-lg`): summary header "38/38 passed in 812 ms" (or "37/38 — 1 failed"), a table-dense list (`h-7` rows, mono case names, `CircleCheck` green / `CircleX` red), and a Re-run button. **Hidden access**: the self-test pill in the status bar (`● 38/38 self-test`, clickable, `text-xs`) opens the same dialog — the instrument's lamp is the diagnostics switch.
